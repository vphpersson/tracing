package tracing

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	motmedelContext "github.com/Motmedel/utils_go/pkg/context"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/errors/types/empty_error"
	"github.com/Motmedel/utils_go/pkg/errors/types/nil_error"
	"github.com/Motmedel/utils_go/pkg/schema"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

var (
	cachedBootTime      time.Time
	cachedBootTimeErr   error
	cachedBootTimeOnce  sync.Once
)

var ianaProtocolNumberToText = map[string]string{
	"1":   "icmp",
	"2":   "igmp",
	"6":   "tcp",
	"17":  "udp",
	"47":  "gre",
	"50":  "esp",
	"51":  "ah",
	"88":  "eigrp",
	"89":  "ospf",
	"115": "l2tp",
}

func GetBootTime() (time.Time, error) {
	cachedBootTimeOnce.Do(func() {
		var ts unix.Timespec
		if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
			cachedBootTimeErr = fmt.Errorf("clock gettime: %w", err)
			return
		}
		cachedBootTime = time.Now().Add(-time.Duration(ts.Nano()) * time.Nanosecond)
	})
	return cachedBootTime, cachedBootTimeErr
}

func ConvertEbpfTimestamp(timestamp uint64, bootTime time.Time) time.Time {
	return bootTime.Add(time.Duration(timestamp) * time.Nanosecond)
}

func ConvertEbpfTimestampToIso8601(timestamp uint64, bootTime time.Time) string {
	return ConvertEbpfTimestamp(timestamp, bootTime).UTC().Format("2006-01-02T15:04:05.999999999Z")
}

func RunMapReceiver[T any](ctx context.Context, ebpfMap *ebpf.Map, callback func(*T)) error {
	if ebpfMap == nil {
		return nil_error.New("ebpf map")
	}

	ringbufReader, err := ringbuf.NewReader(ebpfMap)
	if err != nil {
		return motmedelErrors.NewWithTrace(fmt.Errorf("ringbuf new reader: %w", err))
	}

	var closedByContext atomic.Bool

	defer func() {
		if closedByContext.Load() {
			return
		}
		if err := ringbufReader.Close(); err != nil {
			slog.WarnContext(
				motmedelContext.WithError(
					ctx,
					motmedelErrors.NewWithTrace(
						fmt.Errorf("ringbuf reader close: %w", err),
						ringbufReader,
					),
				),
				"An error occurred when closing a ringbuf reader.",
			)
		}
	}()

	go func() {
		<-ctx.Done()
		closedByContext.Store(true)
		ringbufReader.Close()
	}()

	for {
		record, err := ringbufReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}

			return motmedelErrors.NewWithTrace(fmt.Errorf("ringbuf read: %w", err), ringbufReader)
		}

		if callback != nil {
			go func() {
				var event T

				err := binary.Read(bytes.NewBuffer(record.RawSample), binary.NativeEndian, &event)
				if err != nil {
					slog.ErrorContext(
						motmedelContext.WithError(
							ctx,
							motmedelErrors.NewWithTrace(
								fmt.Errorf("binary read: %w", err),
								record.RawSample,
							),
						),
						"An error occurred when parsing a record.",
					)
					return
				}

				callback(&event)
			}()
		}
	}
}

func RunTracingMapReceiver[T any](ctx context.Context, program *ebpf.Program, ebpfMap *ebpf.Map, callback func(*T)) error {
	if program == nil {
		return nil
	}

	if ebpfMap == nil {
		return nil_error.New("ebpf map")
	}

	tracingLink, err := link.AttachTracing(link.TracingOptions{Program: program})
	if err != nil {
		return motmedelErrors.NewWithTrace(fmt.Errorf("link attach tracing: %w", err))
	}
	defer func() {
		if err := tracingLink.Close(); err != nil {
			slog.WarnContext(
				motmedelContext.WithError(
					ctx,
					motmedelErrors.NewWithTrace(
						fmt.Errorf("tracing link close: %w", err),
						tracingLink,
					),
				),
				"An error occurred when closing a tracing link.",
			)
		}
	}()

	if err = RunMapReceiver(ctx, ebpfMap, callback); err != nil {
		return fmt.Errorf("run map receiver: %w", err)
	}

	return nil
}

func RunTracepointMapReceiver[T any](
	ctx context.Context,
	program *ebpf.Program,
	group string,
	name string,
	ebpfMap *ebpf.Map,
	callback func(*T),
) error {
	if program == nil {
		return nil
	}

	if group == "" {
		return empty_error.New("group")
	}

	if name == "" {
		return empty_error.New("name")
	}

	if ebpfMap == nil {
		return nil_error.New("ebpf map")
	}

	tracepointLink, err := link.Tracepoint(group, name, program, nil)
	if err != nil {
		return motmedelErrors.NewWithTrace(fmt.Errorf("link tracepoint: %w", err))
	}
	defer func() {
		if err := tracepointLink.Close(); err != nil {
			slog.WarnContext(
				motmedelContext.WithError(
					ctx,
					motmedelErrors.NewWithTrace(
						fmt.Errorf("tracepoint link close: %w", err),
						tracepointLink,
					),
				),
				"An error occurred when closing a tracepoint link.",
			)
		}
	}()

	if err = RunMapReceiver(ctx, ebpfMap, callback); err != nil {
		return fmt.Errorf("run map receiver: %w", err)
	}

	return nil
}

func IpAddressFromEbpf(ipAddress [16]byte, addressFamily uint16) string {
	switch addressFamily {
	case syscall.AF_INET:
		return net.IPv4(ipAddress[0], ipAddress[1], ipAddress[2], ipAddress[3]).String()
	case syscall.AF_INET6:
		return net.IP(ipAddress[:]).String()
	}

	return ""
}

func EnrichWithSourceUser(base *schema.Base, userId uint32) {
	if base == nil {
		return
	}

	ecsSource := base.Source
	if ecsSource == nil {
		ecsSource = &schema.Target{}
		base.Source = ecsSource
	}

	ecsSourceUser := ecsSource.User
	if ecsSourceUser == nil {
		ecsSourceUser = &schema.User{}
		ecsSource.User = ecsSourceUser
	}
	ecsSourceUser.Id = strconv.Itoa(int(userId))
}

func EnrichWithConnectionInformation(
	base *schema.Base,
	sourceIp [16]byte,
	sourcePort uint16,
	destinationIp [16]byte,
	destinationPort uint16,
	addressFamily uint16,
) {
	if base == nil {
		return
	}

	ecsSource := base.Source
	if ecsSource == nil {
		ecsSource = &schema.Target{}
		base.Source = ecsSource
	}
	ecsSource.Ip = IpAddressFromEbpf(sourceIp, addressFamily)
	ecsSource.Port = int(sourcePort)

	ecsDestination := base.Destination
	if ecsDestination == nil {
		ecsDestination = &schema.Target{}
		base.Destination = ecsDestination
	}
	ecsDestination.Ip = IpAddressFromEbpf(destinationIp, addressFamily)
	ecsDestination.Port = int(destinationPort)

	if addressFamily == syscall.AF_INET || addressFamily == syscall.AF_INET6 {
		ecsNetwork := base.Network
		if ecsNetwork == nil {
			ecsNetwork = &schema.Network{}
			base.Network = ecsNetwork
		}

		switch addressFamily {
		case syscall.AF_INET:
			ecsNetwork.Type = "ipv4"
		case syscall.AF_INET6:
			ecsNetwork.Type = "ipv6"
		}
	}
}

func EnrichWithConnectionInformationTransport(
	base *schema.Base,
	sourceIp [16]byte,
	sourcePort uint16,
	destinationIp [16]byte,
	destinationPort uint16,
	addressFamily uint16,
	transportNumber uint8,
) {
	if base == nil {
		return
	}

	EnrichWithConnectionInformation(base, sourceIp, sourcePort, destinationIp, destinationPort, addressFamily)

	if transportNumber == 0 {
		return
	}

	ecsNetwork := base.Network
	if ecsNetwork == nil {
		ecsNetwork = &schema.Network{}
		base.Network = ecsNetwork
	}

	transportNumberString := strconv.Itoa(int(transportNumber))

	ecsNetwork.IanaNumber = transportNumberString
	ecsNetwork.Transport = ianaProtocolNumberToText[transportNumberString]
}

func EnrichWithProcessInformation(
	base *schema.Base,
	processId uint32,
	processTitle [16]byte,
	parentProcessId uint32,
	userId uint32,
	groupId uint32,
) {
	if base == nil {
		return
	}

	ecsProcess := base.Process
	if ecsProcess == nil {
		ecsProcess = &schema.Process{}
		base.Process = ecsProcess
	}

	ecsProcess.Pid = int(processId)
	ecsProcess.Title = string(bytes.TrimRight(processTitle[:], "\x00"))

	ecsProcessUser := ecsProcess.User
	if ecsProcessUser == nil {
		ecsProcessUser = &schema.User{}
		ecsProcess.User = ecsProcessUser
	}

	ecsProcessUser.Id = strconv.Itoa(int(userId))

	ecsProcessGroup := ecsProcess.Group
	if ecsProcessGroup == nil {
		ecsProcessGroup = &schema.Group{}
		ecsProcess.Group = ecsProcessGroup
	}

	ecsProcessGroup.Id = strconv.Itoa(int(groupId))

	ecsProcessParent := ecsProcess.Parent
	if ecsProcessParent == nil {
		ecsProcessParent = &schema.Process{}
		ecsProcess.Parent = ecsProcessParent
	}

	ecsProcessParent.Pid = int(parentProcessId)
}
