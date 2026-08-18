package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"iter"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	altshiftLog "github.com/altshiftab/utils_go/pkg/log"
	altshiftErrorLogger "github.com/altshiftab/utils_go/pkg/log/error_logger"
	schemaLog "github.com/altshiftab/utils_go/pkg/schema/log"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vphpersson/tracing/pkg/tracing_service"
	connectTracing "github.com/vphpersson/tracing/pkg/tracing_service/connect"
	connectLatencyTracing "github.com/vphpersson/tracing/pkg/tracing_service/connect_latency"
	destroyConnectionTracing "github.com/vphpersson/tracing/pkg/tracing_service/destroy_connection"
	execveTracing "github.com/vphpersson/tracing/pkg/tracing_service/execve"
	freePacketTracing "github.com/vphpersson/tracing/pkg/tracing_service/free_packet"
	tcpErrorTracing "github.com/vphpersson/tracing/pkg/tracing_service/tcp_error"
	tcpIcmpErrorTracing "github.com/vphpersson/tracing/pkg/tracing_service/tcp_icmp_error"
	tcpResetTracing "github.com/vphpersson/tracing/pkg/tracing_service/tcp_reset"
	tcpRetransmissionTracing "github.com/vphpersson/tracing/pkg/tracing_service/tcp_retransmission"
	tcpSetStateTracing "github.com/vphpersson/tracing/pkg/tracing_service/tcp_set_state"
	"golang.org/x/sync/errgroup"
)

const dataset = "tracing"

// newLogger makes the logger the service reports its own diagnostics with.
func newLogger(writer io.Writer) *altshiftErrorLogger.Logger {
	return &altshiftErrorLogger.Logger{
		Logger: slog.New(
			&altshiftLog.ContextHandler{
				Next: slog.NewJSONHandler(
					writer,
					&slog.HandlerOptions{
						AddSource:   false,
						Level:       slog.LevelInfo,
						ReplaceAttr: schemaLog.ReplaceAttr,
					},
				),
				Extractors: []altshiftLog.ContextExtractor{
					&altshiftLog.ErrorContextExtractor{},
				},
			},
		).With(slog.Group("event", slog.String("dataset", dataset))),
	}
}

// newEventHandler makes the handler the traced events themselves are written
// with. It carries no dataset of its own: each tracer names the dataset the
// event belongs to.
func newEventHandler(writer io.Writer) slog.Handler {
	return slog.NewJSONHandler(
		writer,
		&slog.HandlerOptions{
			AddSource:   false,
			Level:       slog.LevelInfo,
			ReplaceAttr: schemaLog.ReplaceAttr,
		},
	)
}

func main() {
	logger := newLogger(os.Stdout)
	slog.SetDefault(logger.Logger)

	eventHandler := newEventHandler(os.Stdout)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errGroup, errGroupCtx := errgroup.WithContext(ctx)

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stopper
		cancel()
	}()

	if err := rlimit.RemoveMemlock(); err != nil {
		logger.FatalWithExitingMessage(
			"An error occurred when removing the memory lock.",
			fmt.Errorf("rlimit remove mem lock: %w", err),
		)
	}

	var objs tracing_service.BpfObjects
	if err := tracing_service.LoadBpfObjects(&objs, nil); err != nil {
		logger.FatalWithExitingMessage(
			"An error occurred when loading objects.",
			fmt.Errorf("load bpf objects: %w", err),
			objs,
		)
	}
	defer func() {
		if err := objs.Close(); err != nil {
			logger.Warning(
				"An error occurred when closing the objects.",
				altshiftErrors.NewWithTrace(fmt.Errorf("close bpf objects: %w", err), objs),
			)
		}
	}()

	iterators := []iter.Seq2[*tracing_service.EventResult, error]{
		destroyConnectionTracing.Run(
			errGroupCtx,
			objs.NfCtHelperDestroy,
			objs.DestroyConnectionEvents,
		),
		tcpRetransmissionTracing.Run(
			errGroupCtx,
			objs.TcpRetransmitSkb,
			objs.TcpRetransmissionEvents,
		),
		tcpRetransmissionTracing.RunSynack(
			errGroupCtx,
			objs.TcpRetransmitSynack,
			objs.TcpRetransmissionSynackEvents,
		),
		tcpSetStateTracing.Run(
			errGroupCtx,
			objs.TraceInetSockSetState,
			objs.TcpSetStateEvents,
		),
		tcpErrorTracing.Run(
			errGroupCtx,
			objs.TcpDoneWithError,
			objs.TcpErrorEvents,
		),
		tcpResetTracing.Run(
			errGroupCtx,
			objs.TcpReset,
			objs.TcpResetEvents,
		),
		tcpIcmpErrorTracing.Run(
			errGroupCtx,
			objs.TcpV4Err,
			objs.TcpV6Err,
			objs.TcpIcmpErrorEvents,
		),
		connectTracing.Run(
			errGroupCtx,
			objs.TcpConnect,
			objs.ConnectEvents,
		),
		connectLatencyTracing.Run(
			errGroupCtx,
			objs.TcpFinishConnect,
			objs.ConnectLatencyEvents,
		),
		//openTracing.Run(
		//	errGroupCtx,
		//	objs.TraceOpenat,
		//	objs.FileOpenEvents,
		//),
		freePacketTracing.Run(
			errGroupCtx,
			objs.TraceKfreeSkb,
			objs.PacketDropEvents,
			objs.PacketDropReasonFilter,
		),
		execveTracing.Run(
			errGroupCtx,
			objs.EnterExecve,
			objs.ExecveEvents,
		),
	}

	var printMutex sync.Mutex
iteratorsLoop:
	for _, iterator := range iterators {
		select {
		case <-errGroupCtx.Done():
			break iteratorsLoop
		default:
			errGroup.Go(
				func() error {
					for result, err := range iterator {
						if err != nil {
							return fmt.Errorf("iterator: %w", err)
						}
						if result == nil || result.Base == nil {
							continue
						}

						base := result.Base

						attrs := tracing_service.BaseToSlogAttrs(base)
						attrs = append(attrs, result.Attrs...)

						eventTime, _ := time.Parse(time.RFC3339Nano, base.Timestamp)
						record := slog.NewRecord(eventTime, slog.LevelInfo, base.Message, 0)
						record.AddAttrs(attrs...)

						printMutex.Lock()
						_ = eventHandler.Handle(context.Background(), record)
						printMutex.Unlock()
					}

					return nil
				},
			)
		}
	}

	if err := errGroup.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		logger.FatalWithExitingMessage(
			"An error occurred when running a tracer.",
			fmt.Errorf("errgroup wait: %w", err),
		)
	}
}
