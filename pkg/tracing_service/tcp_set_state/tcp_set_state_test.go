package tcp_set_state

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

func TestStateName(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		state    uint16
		expected string
	}{
		{name: "established", state: 1, expected: "ESTABLISHED"},
		{name: "syn sent", state: 2, expected: "SYN_SENT"},
		{name: "time wait", state: 6, expected: "TIME_WAIT"},
		{name: "listen", state: 10, expected: "LISTEN"},
		{name: "new syn recv", state: 12, expected: "NEW_SYN_RECV"},
		{name: "zero falls back to the number", state: 0, expected: "0"},
		{name: "unknown state falls back to the number", state: 99, expected: "99"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := stateName(testCase.state); got != testCase.expected {
				t.Errorf("expected %q, got %q", testCase.expected, got)
			}
		})
	}
}

func TestEnrichWithTcpSetStateEventGuards(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name  string
		base  *schema.Base
		event *tracing_service.BpfTcpSetStateEvent
	}{
		{name: "nil base", base: nil, event: &tracing_service.BpfTcpSetStateEvent{}},
		{name: "nil event", base: &schema.Base{}, event: nil},
		{name: "both nil", base: nil, event: nil},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if err := EnrichWithTcpSetStateEvent(testCase.base, testCase.event); err != nil {
				t.Errorf("expected no error, got %v", err)
			}

			if testCase.base != nil && testCase.base.Timestamp != "" {
				t.Error("expected base to be left untouched")
			}
		})
	}
}

func TestEnrichWithTcpSetStateEvent(t *testing.T) {
	t.Parallel()

	event := &tracing_service.BpfTcpSetStateEvent{
		TimestampNs:        1_000_000_000,
		SourceAddress:      ipv4Address(192, 0, 2, 1),
		DestinationAddress: ipv4Address(198, 51, 100, 2),
		SourcePort:         54321,
		DestinationPort:    443,
		AddressFamily:      2,
		OldState:           2,
		NewState:           1,
	}

	base := &schema.Base{}
	if err := EnrichWithTcpSetStateEvent(base, event); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if base.Timestamp == "" {
		t.Error("expected a timestamp")
	}

	if base.Source == nil || base.Source.Ip != "192.0.2.1" || base.Source.Port != 54321 {
		t.Errorf("expected source 192.0.2.1:54321, got %+v", base.Source)
	}

	if base.Destination == nil || base.Destination.Ip != "198.51.100.2" || base.Destination.Port != 443 {
		t.Errorf("expected destination 198.51.100.2:443, got %+v", base.Destination)
	}

	if base.Message == "" {
		t.Error("expected a message")
	}
}
