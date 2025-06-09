package tracing

/*
   #include <time.h>
   static unsigned long long get_nsecs(void) {
       struct timespec ts;
       clock_gettime(CLOCK_BOOTTIME, &ts);
       return (unsigned long long)ts.tv_sec * 1000000000UL + ts.tv_nsec;
   }
*/
import "C"
import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/Motmedel/ecs_go/ecs"
	motmedelContext "github.com/Motmedel/utils_go/pkg/context"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	tracingErrors "github.com/vphpersson/tracing/pkg/errors"
	"log/slog"
	"net"
	"strconv"
	"syscall"
	"time"
)

var cachedBootTime time.Time

func GetBootTime() time.Time {
	if !cachedBootTime.IsZero() {
		return cachedBootTime
	}
	cachedBootTime = time.Now().Add(-(time.Duration(uint64(C.get_nsecs())) * time.Nanosecond))
	return cachedBootTime
}

func ConvertEbpfTimestamp(timestamp uint64, bootTime time.Time) time.Time {
	return bootTime.Add(time.Duration(timestamp) * time.Nanosecond)
}

func ConvertEbpfTimestampToIso8601(timestamp uint64, bootTime time.Time) string {
	return ConvertEbpfTimestamp(timestamp, bootTime).UTC().Format("2006-01-02T15:04:05.999999999Z")
}

func RunMapReceiver[T any](ctx context.Context, ebpfMap *ebpf.Map, callback func(*T)) error {
	if ebpfMap == nil {
		return tracingErrors.ErrNilEbpfMap
	}

	ringbufReader, err := ringbuf.NewReader(ebpfMap)
	if err != nil {
		return motmedelErrors.NewWithTrace(fmt.Errorf("ringbuf new reader: %w", err))
	}
	defer func() {
		if err := ringbufReader.Close(); err != nil {
			slog.WarnContext(
				motmedelContext.WithErrorContextValue(
					ctx,
					motmedelErrors.NewWithTrace(
						fmt.Errorf("ringbuf reader close: %w", ringbufReader.Close()),
						ringbufReader,
					),
				),
				"An error occurred when closing a ringbuf reader.",
			)
		}
	}()

	go func() {
		<-ctx.Done()
		if err := ringbufReader.Close(); err != nil {
			slog.WarnContext(
				motmedelContext.WithErrorContextValue(
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

				err := binary.Read(bytes.NewBuffer(record.RawSample), binary.BigEndian, &event)
				if err != nil {
					slog.ErrorContext(
						motmedelContext.WithErrorContextValue(
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
		return tracingErrors.ErrNilEbpfMap
	}

	tracingLink, err := link.AttachTracing(link.TracingOptions{Program: program})
	if err != nil {
		return motmedelErrors.NewWithTrace(fmt.Errorf("link attach tracing: %w", err))
	}
	defer func() {
		if err := tracingLink.Close(); err != nil {
			slog.WarnContext(
				motmedelContext.WithErrorContextValue(
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
		return tracingErrors.ErrEmptyGroup
	}

	if name == "" {
		return tracingErrors.ErrEmptyName
	}

	if ebpfMap == nil {
		return tracingErrors.ErrNilEbpfMap
	}

	tracepointLink, err := link.Tracepoint(group, name, program, nil)
	if err != nil {
		return motmedelErrors.NewWithTrace(fmt.Errorf("link tracepoint: %w", err))
	}
	defer func() {
		if err := tracepointLink.Close(); err != nil {
			slog.WarnContext(
				motmedelContext.WithErrorContextValue(
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

func EnrichWithSourceUser(base *ecs.Base, userId uint32) {
	if base == nil {
		return
	}

	ecsSource := base.Source
	if ecsSource == nil {
		ecsSource = &ecs.Target{}
		base.Source = ecsSource
	}

	ecsSourceUser := ecsSource.User
	if ecsSourceUser == nil {
		ecsSourceUser = &ecs.User{}
		ecsSource.User = ecsSourceUser
	}
	ecsSourceUser.Id = strconv.Itoa(int(userId))
}

func EnrichWithConnectionInformation(
	base *ecs.Base,
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
		ecsSource = &ecs.Target{}
		base.Source = ecsSource
	}
	ecsSource.Ip = IpAddressFromEbpf(sourceIp, addressFamily)
	ecsSource.Port = int(sourcePort)

	ecsDestination := base.Destination
	if ecsDestination == nil {
		ecsDestination = &ecs.Target{}
		base.Destination = ecsDestination
	}
	ecsDestination.Ip = IpAddressFromEbpf(destinationIp, addressFamily)
	ecsDestination.Port = int(destinationPort)

	if addressFamily == syscall.AF_INET || addressFamily == syscall.AF_INET6 {
		ecsNetwork := base.Network
		if ecsNetwork == nil {
			ecsNetwork = &ecs.Network{}
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
	base *ecs.Base,
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
		ecsNetwork = &ecs.Network{}
		base.Network = ecsNetwork
	}

	transportNumberString := strconv.Itoa(int(transportNumber))

	ecsNetwork.IanaNumber = transportNumberString
	// TODO: Fix when dependency works.
	//ecsNetwork.Transport = packet_logging.IanaProtocolNumberToText[transportNumberString]
}

func EnrichWithProcessInformation(
	base *ecs.Base,
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
		ecsProcess = &ecs.Process{}
		base.Process = ecsProcess
	}

	ecsProcess.Pid = int(processId)
	ecsProcess.Title = string(bytes.TrimRight(processTitle[:], "\x00"))

	ecsProcessUser := ecsProcess.User
	if ecsProcessUser == nil {
		ecsProcessUser = &ecs.User{}
		ecsProcess.User = ecsProcessUser
	}

	ecsProcessUser.Id = strconv.Itoa(int(userId))

	ecsProcessGroup := ecsProcess.Group
	if ecsProcessGroup == nil {
		ecsProcessGroup = &ecs.Group{}
		ecsProcess.Group = ecsProcessGroup
	}

	ecsProcessGroup.Id = strconv.Itoa(int(groupId))

	ecsProcessParent := ecsProcess.Parent
	if ecsProcessParent == nil {
		ecsProcessParent = &ecs.Process{}
		ecsProcess.Parent = ecsProcessParent
	}

	ecsProcessParent.Pid = int(parentProcessId)
}
