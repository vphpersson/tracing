package execve

import (
	"fmt"
	"log/slog"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/altshiftab/utils_go/pkg/schema"
	"github.com/vphpersson/tracing/pkg/tracing_service"
	"golang.org/x/sys/unix"
)

const (
	// lookupWindow is how long, since its last attempt was received, a lookup waits for the attempt that works. Its
	// attempts follow each other within microseconds, but an exec can take far longer than that between entry and
	// exit (a debugger's stop, a cold binary), and events are received at exit.
	lookupWindow = 2 * time.Second

	// maxLookupAttempts bounds a lookup: a PATH has tens of entries, so more attempts than this are a process
	// failing the same exec in a loop, reported as a failure each time the bound is reached.
	maxLookupAttempts = 64
)

// attempt is one execve call with what it returned.
type attempt struct {
	result     *tracing_service.EventResult
	threadId   uint32
	executable string
	errno      syscall.Errno
	receivedAt time.Time
}

// collapser turns execve calls into events: the failed attempts of an execvp-style PATH search become the path
// misses of the exec that worked, and attempts that no exec followed become one failure. Attempts are grouped by
// thread, in the order the thread made them. It is not safe for concurrent use.
type collapser struct {
	pending map[uint32][]*attempt
}

func newCollapser() *collapser {
	return &collapser{pending: make(map[uint32][]*attempt)}
}

// add takes the attempts in the order they were made and returns the events that are complete.
func (c *collapser) add(a *attempt) []*tracing_service.EventResult {
	if a == nil || a.result == nil || a.result.Base == nil {
		return nil
	}

	results := c.expire(a.receivedAt, false)

	group := c.pending[a.threadId]
	if len(group) > 0 && !sameLookup(group, a) {
		results = append(results, failure(group))
		group = nil
	}

	if a.errno == 0 {
		delete(c.pending, a.threadId)
		return append(results, success(a, group))
	}

	group = append(group, a)
	if len(group) >= maxLookupAttempts {
		delete(c.pending, a.threadId)
		return append(results, failure(group))
	}
	c.pending[a.threadId] = group
	return results
}

// sameLookup reports whether a continues the lookup of group: the same command looked for in another directory,
// or, after ENOEXEC, the interpreter execvp falls back to for a script with no #! line.
func sameLookup(group []*attempt, a *attempt) bool {
	if group[len(group)-1].errno == syscall.ENOEXEC && a.errno == 0 {
		return true
	}
	return filepath.Base(group[0].executable) == filepath.Base(a.executable)
}

// expire returns a failure for each lookup whose last attempt was received more than the window before now, or for
// every pending lookup when all is set, in the order the lookups ended.
func (c *collapser) expire(now time.Time, all bool) []*tracing_service.EventResult {
	var expired [][]*attempt
	for threadId, group := range c.pending {
		if all || now.Sub(group[len(group)-1].receivedAt) > lookupWindow {
			expired = append(expired, group)
			delete(c.pending, threadId)
		}
	}

	slices.SortFunc(expired, func(a, b []*attempt) int {
		return a[len(a)-1].receivedAt.Compare(b[len(b)-1].receivedAt)
	})

	results := make([]*tracing_service.EventResult, 0, len(expired))
	for _, group := range expired {
		results = append(results, failure(group))
	}
	return results
}

// success is the event of an exec that worked, carrying the paths its lookup tried first.
func success(a *attempt, misses []*attempt) *tracing_service.EventResult {
	a.result.Base.Event = withOutcome(a.result.Base.Event, "success")
	addPathMisses(a.result, misses)
	return a.result
}

// failure is the event of a lookup that never found what it looked for: its last attempt, with the error that
// attempt got and the paths tried before it.
func failure(group []*attempt) *tracing_service.EventResult {
	last := group[len(group)-1]
	base := last.result.Base

	base.Event = withOutcome(base.Event, "failure")
	base.Event.Reason = "An execve call failed."

	code := errnoCode(last.errno)
	base.Error = &schema.Error{Code: code, Message: last.errno.Error()}
	base.Message = strings.Replace(base.Message, "execve: ", fmt.Sprintf("execve failed (%s): ", code), 1)

	addPathMisses(last.result, group[:len(group)-1])
	return last.result
}

func withOutcome(event *schema.Event, outcome string) *schema.Event {
	if event == nil {
		event = &schema.Event{}
	}
	event.Outcome = outcome
	return event
}

// addPathMisses records where a lookup looked before the attempt the event is about, as tracing.execve.path_misses.
func addPathMisses(result *tracing_service.EventResult, misses []*attempt) {
	if len(misses) == 0 {
		return
	}

	paths := make([]string, 0, len(misses))
	for _, miss := range misses {
		paths = append(paths, miss.executable)
	}
	result.Attrs = append(result.Attrs, slog.Group("tracing", slog.Group("execve", slog.Any("path_misses", paths))))
}

// errnoCode names an errno as the C constant ("ENOENT"), or by number when it has no name.
func errnoCode(errno syscall.Errno) string {
	if name := unix.ErrnoName(errno); name != "" {
		return name
	}
	return strconv.Itoa(int(errno))
}

// errnoOf is the errno an execve return value carries, or 0 for success.
func errnoOf(returnValue int64) syscall.Errno {
	if returnValue >= 0 {
		return 0
	}
	return syscall.Errno(-returnValue)
}
