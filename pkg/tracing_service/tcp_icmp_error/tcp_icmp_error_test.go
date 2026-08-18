package tcp_icmp_error

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
		event *tracing_service.BpfTcpIcmpErrorEvent
	}{
		{name: "nil base", base: nil, event: &tracing_service.BpfTcpIcmpErrorEvent{}},
		{name: "nil event", base: &schema.Base{}, event: nil},
		{name: "both nil", base: nil, event: nil},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			err := EnrichWithTcpIcmpErrorEvent(testCase.base, testCase.event)
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

	event := &tracing_service.BpfTcpIcmpErrorEvent{TimestampNs: 1_000_000_000, SourceAddress: ipv4Address(192, 0, 2, 1), DestinationAddress: ipv4Address(198, 51, 100, 2), SourcePort: 54321, DestinationPort: 443, AddressFamily: 2, IcmpType: 3, IcmpCode: 1}

	base := &schema.Base{}
	err := EnrichWithTcpIcmpErrorEvent(base, event)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if base.Timestamp == "" {
		t.Error("expected a timestamp")
	}
}

func TestClassify(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name              string
		family            uint16
		icmpType          uint8
		icmpCode          uint8
		expectedErrnoCode string
	}{
		{name: "v4 net unreachable", family: 2, icmpType: 3, icmpCode: 0, expectedErrnoCode: errnoNetUnreach},
		{name: "v4 host unreachable", family: 2, icmpType: 3, icmpCode: 1, expectedErrnoCode: errnoHostUnreach},
		{name: "v4 port unreachable", family: 2, icmpType: 3, icmpCode: 3, expectedErrnoCode: errnoConnRefused},
		{name: "v4 fragmentation needed", family: 2, icmpType: 3, icmpCode: 4, expectedErrnoCode: errnoMsgSize},
		{name: "v4 admin prohibited", family: 2, icmpType: 3, icmpCode: 13, expectedErrnoCode: errnoHostUnreach},
		{name: "v4 non unreachable type has no errno", family: 2, icmpType: 11, icmpCode: 0, expectedErrnoCode: ""},
		{name: "v6 net unreachable", family: 10, icmpType: 1, icmpCode: 0, expectedErrnoCode: errnoNetUnreach},
		{name: "v6 address unreachable", family: 10, icmpType: 1, icmpCode: 3, expectedErrnoCode: errnoHostUnreach},
		{name: "v6 port unreachable", family: 10, icmpType: 1, icmpCode: 4, expectedErrnoCode: errnoConnRefused},
		{name: "v6 packet too big", family: 10, icmpType: 2, icmpCode: 0, expectedErrnoCode: errnoMsgSize},
		{name: "unknown family yields nothing", family: 99, icmpType: 3, icmpCode: 1, expectedErrnoCode: ""},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			_, _, errnoCode := classify(testCase.family, testCase.icmpType, testCase.icmpCode)
			if errnoCode != testCase.expectedErrnoCode {
				t.Errorf("expected errno code %q, got %q", testCase.expectedErrnoCode, errnoCode)
			}
		})
	}
}
