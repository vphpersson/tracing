package free_packet

import (
	"strings"
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
		event *tracing_service.BpfPacketDropEvent
	}{
		{name: "nil base", base: nil, event: &tracing_service.BpfPacketDropEvent{}},
		{name: "nil event", base: &schema.Base{}, event: nil},
		{name: "both nil", base: nil, event: nil},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			_, err := EnrichWithPacketFreedEvent(testCase.base, testCase.event, nil)
			if err != nil {
				t.Errorf("expected no error, got %v", err)
			}

			if testCase.base != nil && testCase.base.Timestamp != "" {
				t.Error("expected base to be left untouched")
			}
		})
	}
}

func TestEnrichWithPacketFreedEvent(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name            string
		reason          uint16
		reasonNames     map[uint16]string
		expectedMessage string
	}{
		{
			name:            "known reason is named",
			reason:          4,
			reasonNames:     map[uint16]string{4: "NOT_SPECIFIED"},
			expectedMessage: "NOT_SPECIFIED",
		},
		{
			name:            "unknown reason falls back to the number",
			reason:          9999,
			reasonNames:     map[uint16]string{4: "NOT_SPECIFIED"},
			expectedMessage: "9999",
		},
		{
			name:            "nil reason table falls back to the number",
			reason:          7,
			reasonNames:     nil,
			expectedMessage: "7",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			event := &tracing_service.BpfPacketDropEvent{
				TimestampNs:        1_000_000_000,
				Reason:             testCase.reason,
				SourceAddress:      ipv4Address(192, 0, 2, 1),
				DestinationAddress: ipv4Address(198, 51, 100, 2),
				SourcePort:         54321,
				DestinationPort:    443,
				AddressFamily:      2,
				TransportProtocol:  6,
			}

			base := &schema.Base{}
			if _, err := EnrichWithPacketFreedEvent(base, event, testCase.reasonNames); err != nil {
				t.Fatalf("expected no error, got %v", err)
			}

			if base.Timestamp == "" {
				t.Error("expected a timestamp")
			}

			if base.Source == nil || base.Source.Ip != "192.0.2.1" {
				t.Errorf("expected source 192.0.2.1, got %+v", base.Source)
			}

			if !strings.Contains(base.Message, testCase.expectedMessage) {
				t.Errorf("expected the message to contain %q, got %q", testCase.expectedMessage, base.Message)
			}
		})
	}
}
