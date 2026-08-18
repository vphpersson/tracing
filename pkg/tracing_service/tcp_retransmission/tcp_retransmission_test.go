package tcp_retransmission

import (
	"testing"

	"github.com/altshiftab/utils_go/pkg/schema"
	"github.com/vphpersson/tracing/pkg/tracing_service"
)

// ipv4Address builds the address form the eBPF programs report for AF_INET
// sockets, where the four octets occupy the front of the 16-byte field.
func ipv4Address(a byte, b byte, c byte, d byte) [16]byte {
	return [16]byte{a, b, c, d}
}

func TestEnrichGuards(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name  string
		base  *schema.Base
		event *tracing_service.BpfTcpRetransmissionEvent
	}{
		{name: "nil base", base: nil, event: &tracing_service.BpfTcpRetransmissionEvent{}},
		{name: "nil event", base: &schema.Base{}, event: nil},
		{name: "both nil", base: nil, event: nil},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			err := EnrichWithTcpRetransmissionEvent(testCase.base, testCase.event)
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

	event := &tracing_service.BpfTcpRetransmissionEvent{TimestampNs: 1_000_000_000, SourceAddress: ipv4Address(192, 0, 2, 1), DestinationAddress: ipv4Address(198, 51, 100, 2), SourcePort: 54321, DestinationPort: 443, AddressFamily: 2, State: 1}

	base := &schema.Base{}
	err := EnrichWithTcpRetransmissionEvent(base, event)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if base.Timestamp == "" {
		t.Error("expected a timestamp")
	}
}
