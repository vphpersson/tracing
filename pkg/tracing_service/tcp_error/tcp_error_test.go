package tcp_error

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
		event *tracing_service.BpfTcpErrorEvent
	}{
		{name: "nil base", base: nil, event: &tracing_service.BpfTcpErrorEvent{}},
		{name: "nil event", base: &schema.Base{}, event: nil},
		{name: "both nil", base: nil, event: nil},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			err := EnrichWithTcpErrorEvent(testCase.base, testCase.event)
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

	event := &tracing_service.BpfTcpErrorEvent{TimestampNs: 1_000_000_000, SourceAddress: ipv4Address(192, 0, 2, 1), DestinationAddress: ipv4Address(198, 51, 100, 2), SourcePort: 54321, DestinationPort: 443, AddressFamily: 2, State: 1, Err: 110}

	base := &schema.Base{}
	err := EnrichWithTcpErrorEvent(base, event)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if base.Timestamp == "" {
		t.Error("expected a timestamp")
	}
}

func TestErrnoName(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		err      int32
		expected string
	}{
		{name: "timed out", err: 110, expected: "ETIMEDOUT"},
		{name: "connection reset", err: 104, expected: "ECONNRESET"},
		{name: "connection refused", err: 111, expected: "ECONNREFUSED"},
		{name: "host unreachable", err: 113, expected: "EHOSTUNREACH"},
		{name: "network unreachable", err: 101, expected: "ENETUNREACH"},
		{name: "broken pipe", err: 32, expected: "EPIPE"},
		{name: "connection aborted", err: 103, expected: "ECONNABORTED"},
		{name: "unknown positive errno falls back to the number", err: 4095, expected: "4095"},
		// sk_err always holds a positive errno; a negative value must not be
		// converted, or it would become a nonsense unsigned value.
		{name: "zero is reported as a number", err: 0, expected: "0"},
		{name: "negative is reported as a number", err: -110, expected: "-110"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := errnoName(testCase.err); got != testCase.expected {
				t.Errorf("expected %q, got %q", testCase.expected, got)
			}
		})
	}
}
