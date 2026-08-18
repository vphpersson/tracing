package execve

import (
	"strings"
	"testing"

	"github.com/altshiftab/utils_go/pkg/schema"
	"github.com/vphpersson/tracing/pkg/tracing_service"
)

// filenameBytes copies a string into the null-padded fixed-width field the eBPF
// programs report a filename in.
func filenameBytes(value string) [1024]uint8 {
	var out [1024]uint8
	copy(out[:], value)
	return out
}

func TestEnrichGuards(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name  string
		base  *schema.Base
		event *tracing_service.BpfExecveEvent
	}{
		{name: "nil base", base: nil, event: &tracing_service.BpfExecveEvent{}},
		{name: "nil event", base: &schema.Base{}, event: nil},
		{name: "both nil", base: nil, event: nil},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if err := EnrichWithExecveEvent(testCase.base, testCase.event); err != nil {
				t.Errorf("expected no error, got %v", err)
			}

			if testCase.base != nil && testCase.base.Timestamp != "" {
				t.Error("expected base to be left untouched")
			}
		})
	}
}

func TestEnrichWithExecveEvent(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name             string
		filename         string
		argv             []string
		argc             uint32
		processId        uint32
		expectedArgsPart string
	}{
		{
			name:      "executable with no arguments",
			filename:  "/usr/bin/true",
			argc:      1,
			processId: 4242,
		},
		{
			name:             "executable with arguments",
			filename:         "/usr/bin/ls",
			argv:             []string{"", "-l", "/tmp"},
			argc:             3,
			processId:        4243,
			expectedArgsPart: "-l",
		},
		{
			name:      "argc beyond the recorded argv is not read past",
			filename:  "/usr/bin/ls",
			argv:      []string{"", "-l"},
			argc:      99,
			processId: 4244,
		},
		{
			name:      "empty filename",
			filename:  "",
			argc:      0,
			processId: 4245,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			event := &tracing_service.BpfExecveEvent{
				TimestampNs: 1_000_000_000,
				ProcessId:   testCase.processId,
				Filename:    filenameBytes(testCase.filename),
				Argc:        testCase.argc,
			}
			for i, arg := range testCase.argv {
				if i < len(event.Argv) {
					copy(event.Argv[i][:], arg)
				}
			}

			base := &schema.Base{}
			if err := EnrichWithExecveEvent(base, event); err != nil {
				t.Fatalf("expected no error, got %v", err)
			}

			if base.Timestamp == "" {
				t.Error("expected a timestamp")
			}

			if base.Process == nil {
				t.Fatal("expected process to be set")
			}

			if base.Process.Pid != int(testCase.processId) {
				t.Errorf("expected pid %d, got %d", testCase.processId, base.Process.Pid)
			}

			if testCase.filename != "" && !strings.Contains(base.Process.Executable, testCase.filename) {
				t.Errorf("expected executable to contain %q, got %q", testCase.filename, base.Process.Executable)
			}

			if testCase.expectedArgsPart != "" {
				joined := strings.Join(base.Process.Args, " ")
				if !strings.Contains(joined, testCase.expectedArgsPart) {
					t.Errorf("expected args to contain %q, got %q", testCase.expectedArgsPart, joined)
				}
			}
		})
	}
}
