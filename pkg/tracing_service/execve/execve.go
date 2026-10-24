package execve

import (
	"bytes"
	"context"
	"fmt"
	altshiftContext "github.com/altshiftab/utils_go/pkg/context"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	"github.com/altshiftab/utils_go/pkg/schema"
	altshiftStrings "github.com/altshiftab/utils_go/pkg/strings"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vphpersson/tracing/pkg/tracing"
	"github.com/vphpersson/tracing/pkg/tracing_service"
	"iter"
	"log/slog"
	"path/filepath"
	"sync"
	"time"
)

// execveatVariant marks an event of an execveat call, which runs a file by descriptor as well as by path.
const execveatVariant = 1

func EnrichWithExecveEvent(base *schema.Base, event *tracing_service.BpfExecveEvent) error {
	if base == nil {
		return nil
	}

	if event == nil {
		return nil
	}

	bootTime, err := tracing.GetBootTime()
	if err != nil {
		return fmt.Errorf("get boot time: %w", err)
	}

	base.Timestamp = tracing.ConvertEbpfTimestampToIso8601(event.TimestampNs, bootTime)

	tracing.EnrichWithProcessInformation(
		base,
		event.ProcessId,
		event.ProcessTitle,
		event.ParentProcessId,
		event.UserId,
		event.GroupId,
	)

	executable := string(bytes.TrimRight(event.Filename[:], "\x00"))

	// An exec by descriptor alone that failed has no path; its argv[0] is all there is of what was run.
	first := executable
	if first == "" && event.Argc > 0 {
		first = string(bytes.TrimRight(event.Argv[0][:], "\x00"))
	}
	argvStrings := []string{first}
	for i := uint32(1); i < event.Argc && int(i) < len(event.Argv); i++ {
		argString := string(bytes.TrimRight(event.Argv[i][:], "\x00"))
		if argString != "" {
			argvStrings = append(argvStrings, argString)
		}
	}

	ecsProcess := base.Process
	if ecsProcess == nil {
		ecsProcess = &schema.Process{}
		base.Process = ecsProcess
	}

	// process.title from bpf_get_current_comm is the pre-exec comm, which
	// is the parent's title, not the new process's.
	parentTitle := ecsProcess.Title
	ecsProcess.Title = ""

	ecsProcess.Args = argvStrings
	ecsProcess.ArgsCount = len(argvStrings)
	ecsProcess.CommandLine = altshiftStrings.ShellJoin(argvStrings)
	ecsProcess.Executable = executable
	if executable != "" {
		ecsProcess.Name = filepath.Base(executable)
	}
	ecsProcess.Thread = &schema.ProcessThread{Id: int(event.ThreadId)}

	if event.SyscallVariant == execveatVariant && base.Event != nil {
		base.Event.Action = "execveat"
		base.Event.Reason = "An execveat call was made."
	}

	ecsProcessParent := ecsProcess.Parent
	if ecsProcessParent == nil {
		ecsProcessParent = &schema.Process{}
		ecsProcess.Parent = ecsProcessParent
	}

	ecsProcessParent.Title = parentTitle

	parentExeName := string(bytes.TrimRight(event.ParentExecutableName[:], "\x00"))
	if parentExeName != "" {
		ecsProcessParent.Name = parentExeName
	}

	parentCmdlineRaw := bytes.TrimRight(event.ParentCommandLine[:], "\x00")
	if len(parentCmdlineRaw) > 0 {
		parentCommandLine := string(bytes.ReplaceAll(parentCmdlineRaw, []byte{0}, []byte{' '}))
		ecsProcessParent.CommandLine = parentCommandLine

		if ecsProcessParent.Executable == "" {
			if idx := bytes.IndexByte(parentCmdlineRaw, 0); idx > 0 {
				ecsProcessParent.Executable = string(parentCmdlineRaw[:idx])
			} else {
				ecsProcessParent.Executable = string(parentCmdlineRaw)
			}
			ecsProcessParent.Name = filepath.Base(ecsProcessParent.Executable)
		}
	}

	parentExe := ecsProcessParent.Executable
	if parentExe == "" {
		parentExe = ecsProcessParent.Name
	}
	if parentExe == "" {
		parentExe = ecsProcessParent.Title
	}

	base.Message = fmt.Sprintf("execve: %s -> %s", parentExe, ecsProcess.Executable)

	return nil
}

// Run reports execve and execveat calls with what they returned. enterProgram and enterAtProgram read the arguments
// on entry and exitProgram submits the event on exit; the failed attempts of a PATH search are folded into the exec
// that worked (see collapser), so a failure is reported up to lookupWindow after it happened. dropsMap counts the
// events the eBPF side lost, which are logged.
func Run(
	ctx context.Context,
	enterProgram *ebpf.Program,
	enterAtProgram *ebpf.Program,
	exitProgram *ebpf.Program,
	ebpfMap *ebpf.Map,
	dropsMap *ebpf.Map,
) iter.Seq2[*tracing_service.EventResult, error] {
	return func(yield func(*tracing_service.EventResult, error) bool) {
		if enterProgram == nil {
			yield(nil, altshiftErrors.NewWithTrace(nil_error.New("enter program")))
			return
		}

		if enterAtProgram == nil {
			yield(nil, altshiftErrors.NewWithTrace(nil_error.New("enter at program")))
			return
		}

		if exitProgram == nil {
			yield(nil, altshiftErrors.NewWithTrace(nil_error.New("exit program")))
			return
		}

		if ebpfMap == nil {
			yield(nil, altshiftErrors.NewWithTrace(nil_error.New("ebpf map")))
			return
		}

		// The enter of execve is attached by the receiver below. A successful execveat exits through
		// sys_exit_execve, a failed one through sys_exit_execveat, so the exit program goes on both.
		for _, tracepoint := range []struct {
			name    string
			program *ebpf.Program
		}{
			{name: "sys_enter_execveat", program: enterAtProgram},
			{name: "sys_exit_execve", program: exitProgram},
			{name: "sys_exit_execveat", program: exitProgram},
		} {
			tracepointLink, err := link.Tracepoint("syscalls", tracepoint.name, tracepoint.program, nil)
			if err != nil {
				yield(nil, altshiftErrors.NewWithTrace(fmt.Errorf("link tracepoint: %w", err), tracepoint.name))
				return
			}
			defer func() {
				if err := tracepointLink.Close(); err != nil {
					slog.WarnContext(
						altshiftContext.WithError(ctx, altshiftErrors.NewWithTrace(fmt.Errorf("tracepoint link close: %w", err), tracepoint.name)),
						"An error occurred when closing a tracepoint link.",
					)
				}
			}()
		}

		var mu sync.Mutex
		receiverCtx, cancelReceiver := context.WithCancel(ctx)
		defer cancelReceiver()

		lookups := newCollapser()
		stopped := false

		// emit yields results until the consumer stops; the caller holds mu.
		emit := func(results []*tracing_service.EventResult) {
			for _, result := range results {
				if stopped || !yield(result, nil) {
					stopped = true
					cancelReceiver()
					return
				}
			}
		}

		// A lookup no later exec ends is a failure once its window has passed, which on a quiet host only the
		// clock can tell. The same loop reports execve events the kernel side lost.
		expiryDone := make(chan struct{})
		var expiryWaitGroup sync.WaitGroup
		expiryWaitGroup.Go(func() {
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()
			drops := newDropCounter(dropsMap)
			for tick := 1; ; tick++ {
				select {
				case <-expiryDone:
					return
				case now := <-ticker.C:
					mu.Lock()
					if !stopped {
						emit(lookups.expire(now, false))
					}
					mu.Unlock()
					if tick%60 == 0 {
						drops.report(ctx)
					}
				}
			}
		})
		stopExpiry := func() {
			close(expiryDone)
			expiryWaitGroup.Wait()
		}

		// In order: the collapser relies on a process's attempts arriving as it made them.
		err := tracing.RunTracepointOrderedMapReceiver(
			receiverCtx,
			enterProgram,
			"syscalls",
			"sys_enter_execve",
			ebpfMap,
			func(event *tracing_service.BpfExecveEvent) {
				if receiverCtx.Err() != nil {
					return
				}

				if event == nil {
					return
				}

				base := &schema.Base{
					Event: &schema.Event{
						Kind:     "event",
						Category: []string{"process"},
						Type:     []string{"start"},
						Action:   "execve",
						Module:   "tracing",
						Reason:   "An execve call was made.",
						Dataset:  "tracing.execve",
					},
				}

				if err := EnrichWithExecveEvent(base, event); err != nil {
					mu.Lock()
					defer mu.Unlock()
					if !stopped {
						yield(nil, fmt.Errorf("enrich with execve event: %w", err))
						stopped = true
					}
					cancelReceiver()
					return
				}

				mu.Lock()
				defer mu.Unlock()
				if receiverCtx.Err() != nil {
					return
				}
				emit(lookups.add(&attempt{
					result:     &tracing_service.EventResult{Base: base},
					threadId:   event.ThreadId,
					executable: base.Process.Executable,
					errno:      errnoOf(event.ReturnValue),
					receivedAt: time.Now(),
				}))
			},
		)
		stopExpiry()

		// The receiver returns once tracing stops: the lookups still waiting then get no exec that worked.
		mu.Lock()
		defer mu.Unlock()
		if stopped {
			return
		}
		if err != nil {
			yield(nil, fmt.Errorf("run tracing map receiver: %w", err))
			stopped = true
			return
		}
		emit(lookups.expire(time.Now(), true))
	}
}

// dropCounter reports the execve events the eBPF side counted as lost, by where they were lost.
type dropCounter struct {
	ebpfMap  *ebpf.Map
	reported [len(dropPlaces)]uint64
}

// The places the eBPF side counts a lost execve event, by index in the execve_drops map. unstaged_failure is a failed
// call with no staged entry, as one refused before the entry tracepoint has (a seccomp filter returning an errno).
var dropPlaces = [4]string{"stage", "evicted", "ringbuf", "unstaged_failure"}

func newDropCounter(ebpfMap *ebpf.Map) *dropCounter {
	return &dropCounter{ebpfMap: ebpfMap}
}

// report logs a warning when events have been lost since the last report.
func (d *dropCounter) report(ctx context.Context) {
	if d == nil || d.ebpfMap == nil {
		return
	}

	var lost []any
	for index := range dropPlaces {
		var perCpu []uint64
		if err := d.ebpfMap.Lookup(uint32(index), &perCpu); err != nil {
			slog.WarnContext(
				altshiftContext.WithError(ctx, altshiftErrors.NewWithTrace(fmt.Errorf("ebpf map lookup: %w", err), index)),
				"The lost execve events could not be read.",
			)
			return
		}

		var total uint64
		for _, count := range perCpu {
			total += count
		}
		if total > d.reported[index] {
			lost = append(lost, slog.Uint64(dropPlaces[index], total-d.reported[index]))
			d.reported[index] = total
		}
	}

	if len(lost) > 0 {
		slog.WarnContext(ctx, "execve events were lost on the kernel side.", slog.Group("tracing", slog.Group("execve", slog.Group("lost", lost...))))
	}
}
