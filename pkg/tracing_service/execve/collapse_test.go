package execve

import (
	"slices"
	"syscall"
	"testing"
	"time"

	"github.com/altshiftab/utils_go/pkg/schema"
	"github.com/vphpersson/tracing/pkg/tracing_service"
)

var start = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

// call is an execve attempt by thread threadId, received at offset after start.
func call(threadId uint32, executable string, errno syscall.Errno, offset time.Duration) *attempt {
	return &attempt{
		result: &tracing_service.EventResult{Base: &schema.Base{
			Event:   &schema.Event{Action: "execve", Type: []string{"start"}},
			Message: "execve: /usr/bin/zsh -> " + executable,
			Process: &schema.Process{Executable: executable},
		}},
		threadId:   threadId,
		executable: executable,
		errno:      errno,
		receivedAt: start.Add(offset),
	}
}

// pathMisses reads tracing.execve.path_misses back out of a result's attributes.
func pathMisses(result *tracing_service.EventResult) []string {
	for _, attr := range result.Attrs {
		if attr.Key != "tracing" {
			continue
		}
		for _, inner := range attr.Value.Group() {
			if inner.Key != "execve" {
				continue
			}
			for _, field := range inner.Value.Group() {
				if field.Key == "path_misses" {
					paths, _ := field.Value.Any().([]string)
					return paths
				}
			}
		}
	}
	return nil
}

type expected struct {
	executable string
	outcome    string
	errorCode  string
	misses     int
	firstMiss  string
}

func TestCollapser(t *testing.T) {
	t.Parallel()

	var failureLoop []*attempt
	for i := range 70 {
		failureLoop = append(failureLoop, call(1, "/opt/missing/x", syscall.ENOENT, time.Duration(i)*time.Microsecond))
	}

	testCases := []struct {
		name     string
		calls    []*attempt
		expireAt time.Duration
		expected []expected
	}{
		{
			name:     "an exec with no lookup",
			calls:    []*attempt{call(1, "/usr/bin/ls", 0, 0)},
			expected: []expected{{executable: "/usr/bin/ls", outcome: "success"}},
		},
		{
			name: "a PATH search",
			calls: []*attempt{
				call(1, "/usr/local/sbin/ls", syscall.ENOENT, 0),
				call(1, "/usr/local/bin/ls", syscall.ENOENT, 10*time.Microsecond),
				call(1, "/usr/bin/ls", 0, 20*time.Microsecond),
			},
			expected: []expected{{executable: "/usr/bin/ls", outcome: "success", misses: 2, firstMiss: "/usr/local/sbin/ls"}},
		},
		{
			name: "permission denied, then found",
			calls: []*attempt{
				call(1, "/opt/tool/x", syscall.EACCES, 0),
				call(1, "/usr/bin/x", 0, 10*time.Microsecond),
			},
			expected: []expected{{executable: "/usr/bin/x", outcome: "success", misses: 1, firstMiss: "/opt/tool/x"}},
		},
		{
			name: "a script with no #! line, run through the interpreter",
			calls: []*attempt{
				call(1, "./build.sh", syscall.ENOEXEC, 0),
				call(1, "/bin/sh", 0, 10*time.Microsecond),
			},
			expected: []expected{{executable: "/bin/sh", outcome: "success", misses: 1, firstMiss: "./build.sh"}},
		},
		{
			name: "a slow exec does not end another thread's lookup",
			calls: []*attempt{
				call(1, "/usr/local/bin/gdb", syscall.ENOENT, 0),
				call(2, "/usr/bin/true", 0, 200*time.Millisecond),
				call(1, "/usr/bin/gdb", 0, 300*time.Millisecond),
			},
			expected: []expected{
				{executable: "/usr/bin/true", outcome: "success"},
				{executable: "/usr/bin/gdb", outcome: "success", misses: 1, firstMiss: "/usr/local/bin/gdb"},
			},
		},
		{
			name: "not found anywhere, ended by another thread's exec after the window",
			calls: []*attempt{
				call(1, "/usr/local/bin/curl", syscall.ENOENT, 0),
				call(1, "/usr/bin/curl", syscall.ENOENT, 10*time.Microsecond),
				call(2, "/usr/bin/true", 0, 3*time.Second),
			},
			expected: []expected{
				{executable: "/usr/bin/curl", outcome: "failure", errorCode: "ENOENT", misses: 1, firstMiss: "/usr/local/bin/curl"},
				{executable: "/usr/bin/true", outcome: "success"},
			},
		},
		{
			name: "another command in the same thread",
			calls: []*attempt{
				call(1, "/usr/bin/wget", syscall.ENOENT, 0),
				call(1, "/usr/bin/curl", 0, time.Millisecond),
			},
			expected: []expected{
				{executable: "/usr/bin/wget", outcome: "failure", errorCode: "ENOENT"},
				{executable: "/usr/bin/curl", outcome: "success"},
			},
		},
		{
			name: "a miss outside the window is a separate exec",
			calls: []*attempt{
				call(1, "/usr/local/bin/ls", syscall.ENOENT, 0),
				call(1, "/usr/bin/ls", 0, 3*time.Second),
			},
			expected: []expected{
				{executable: "/usr/local/bin/ls", outcome: "failure", errorCode: "ENOENT"},
				{executable: "/usr/bin/ls", outcome: "success"},
			},
		},
		{
			name: "lookups of two threads interleaved",
			calls: []*attempt{
				call(1, "/usr/local/bin/ls", syscall.ENOENT, 0),
				call(2, "/usr/local/bin/cat", syscall.ENOENT, 1*time.Microsecond),
				call(2, "/usr/bin/cat", 0, 2*time.Microsecond),
				call(1, "/usr/bin/ls", 0, 3*time.Microsecond),
			},
			expected: []expected{
				{executable: "/usr/bin/cat", outcome: "success", misses: 1, firstMiss: "/usr/local/bin/cat"},
				{executable: "/usr/bin/ls", outcome: "success", misses: 1, firstMiss: "/usr/local/bin/ls"},
			},
		},
		{
			name:     "a failure loop is reported at the bound, not held without end",
			calls:    failureLoop,
			expireAt: time.Minute,
			expected: []expected{
				{executable: "/opt/missing/x", outcome: "failure", errorCode: "ENOENT", misses: maxLookupAttempts - 1, firstMiss: "/opt/missing/x"},
				{executable: "/opt/missing/x", outcome: "failure", errorCode: "ENOENT", misses: 70 - maxLookupAttempts - 1, firstMiss: "/opt/missing/x"},
			},
		},
		{
			name:     "a failure still pending is expired by the clock",
			calls:    []*attempt{call(1, "/usr/bin/nc", syscall.ENOENT, 0)},
			expireAt: 3 * time.Second,
			expected: []expected{{executable: "/usr/bin/nc", outcome: "failure", errorCode: "ENOENT"}},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			lookups := newCollapser()
			var results []*tracing_service.EventResult
			for _, a := range testCase.calls {
				results = append(results, lookups.add(a)...)
			}
			if testCase.expireAt != 0 {
				results = append(results, lookups.expire(start.Add(testCase.expireAt), false)...)
				if len(lookups.pending) != 0 {
					t.Errorf("lookups left pending after expiry: %d", len(lookups.pending))
				}
			}

			if len(results) != len(testCase.expected) {
				t.Fatalf("got %d events, want %d", len(results), len(testCase.expected))
			}
			for i, want := range testCase.expected {
				base := results[i].Base
				if base.Process.Executable != want.executable {
					t.Errorf("event %d: executable %q, want %q", i, base.Process.Executable, want.executable)
				}
				if base.Event.Outcome != want.outcome {
					t.Errorf("event %d: outcome %q, want %q", i, base.Event.Outcome, want.outcome)
				}
				var code string
				if base.Error != nil {
					code = base.Error.Code
				}
				if code != want.errorCode {
					t.Errorf("event %d: error code %q, want %q", i, code, want.errorCode)
				}
				misses := pathMisses(results[i])
				if len(misses) != want.misses {
					t.Errorf("event %d: %d path misses, want %d", i, len(misses), want.misses)
				}
				if want.firstMiss != "" && (len(misses) == 0 || misses[0] != want.firstMiss) {
					t.Errorf("event %d: path misses %v, want them to start with %q", i, misses, want.firstMiss)
				}
			}
		})
	}
}

func TestFailureMessage(t *testing.T) {
	t.Parallel()

	lookups := newCollapser()
	lookups.add(call(1, "/usr/bin/nc", syscall.ENOENT, 0))
	results := lookups.expire(start, true)
	if len(results) != 1 {
		t.Fatalf("got %d events, want 1", len(results))
	}

	base := results[0].Base
	if want := "execve failed (ENOENT): /usr/bin/zsh -> /usr/bin/nc"; base.Message != want {
		t.Errorf("message %q, want %q", base.Message, want)
	}
	if want := "no such file or directory"; base.Error.Message != want {
		t.Errorf("error message %q, want %q", base.Error.Message, want)
	}
}

func TestErrno(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		returnValue int64
		errno       syscall.Errno
		code        string
	}{
		{name: "success", returnValue: 0, errno: 0},
		{name: "not found", returnValue: -int64(syscall.ENOENT), errno: syscall.ENOENT, code: "ENOENT"},
		{name: "permission denied", returnValue: -int64(syscall.EACCES), errno: syscall.EACCES, code: "EACCES"},
		{name: "no name", returnValue: -4000, errno: 4000, code: "4000"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			errno := errnoOf(testCase.returnValue)
			if errno != testCase.errno {
				t.Fatalf("errnoOf(%d) = %d, want %d", testCase.returnValue, errno, testCase.errno)
			}
			if errno != 0 {
				if code := errnoCode(errno); code != testCase.code {
					t.Errorf("errnoCode(%d) = %q, want %q", errno, code, testCase.code)
				}
			}
		})
	}
}

// The thread is what a lookup belongs to: two threads of one process looking up the same command at once are two
// lookups, which the tgid-keyed version merged.
func TestCollapserThreadsOfOneProcess(t *testing.T) {
	t.Parallel()

	lookups := newCollapser()
	var results []*tracing_service.EventResult
	results = append(results, lookups.add(call(10, "/usr/local/bin/ls", syscall.ENOENT, 0))...)
	results = append(results, lookups.add(call(11, "/usr/local/bin/ls", syscall.ENOENT, time.Microsecond))...)
	results = append(results, lookups.add(call(11, "/usr/bin/ls", 0, 2*time.Microsecond))...)
	results = append(results, lookups.add(call(10, "/usr/bin/ls", 0, 3*time.Microsecond))...)

	if len(results) != 2 {
		t.Fatalf("got %d events, want 2", len(results))
	}
	for i, result := range results {
		if misses := pathMisses(result); !slices.Equal(misses, []string{"/usr/local/bin/ls"}) {
			t.Errorf("event %d: path misses %v, want one miss each", i, misses)
		}
	}
}
