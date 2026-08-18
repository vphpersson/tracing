package open

import (
	"testing"

	"github.com/altshiftab/utils_go/pkg/schema"
	"github.com/vphpersson/tracing/pkg/tracing_service"
)

func TestEnrichGuards(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name  string
		base  *schema.Base
		event *tracing_service.BpfFileOpenEvent
	}{
		{name: "nil base", base: nil, event: &tracing_service.BpfFileOpenEvent{}},
		{name: "nil event", base: &schema.Base{}, event: nil},
		{name: "both nil", base: nil, event: nil},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			_, err := EnrichWithFileOpenEvent(testCase.base, testCase.event)
			if err != nil {
				t.Errorf("expected no error, got %v", err)
			}

			if testCase.base != nil && testCase.base.Timestamp != "" {
				t.Error("expected base to be left untouched")
			}
		})
	}
}

func TestEnrichPopulatesTheDocument(t *testing.T) {
	t.Parallel()

	event := &tracing_service.BpfFileOpenEvent{TimestampNs: 1_000_000_000, ProcessId: 4242, Flags: 0, Mode: 0}

	base := &schema.Base{}
	_, err := EnrichWithFileOpenEvent(base, event)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if base.Timestamp == "" {
		t.Error("expected a timestamp")
	}
}
