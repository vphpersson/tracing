package tracing_service

import (
	"slices"
	"testing"

	"github.com/altshiftab/utils_go/pkg/schema"
)

func TestIsIPv4MappedIPv6(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		addr     [16]byte
		expected bool
	}{
		{
			name:     "zero address",
			addr:     [16]byte{},
			expected: false,
		},
		{
			name:     "ipv4 mapped 192.0.2.1",
			addr:     [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 1},
			expected: true,
		},
		{
			name:     "ipv4 mapped all zero suffix",
			addr:     [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0},
			expected: true,
		},
		{
			name:     "native ipv6",
			addr:     [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			expected: false,
		},
		{
			name:     "non zero byte inside the first ten breaks the prefix",
			addr:     [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, 0xff, 192, 0, 2, 1},
			expected: false,
		},
		{
			name:     "only one of the ffff bytes set",
			addr:     [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0, 192, 0, 2, 1},
			expected: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := IsIPv4MappedIPv6(testCase.addr); got != testCase.expected {
				t.Errorf("expected %v, got %v", testCase.expected, got)
			}
		})
	}
}

func TestBaseToSlogAttrs(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		base          *schema.Base
		expectedKeys  []string
		expectedEmpty bool
	}{
		{
			name:          "nil base",
			base:          nil,
			expectedEmpty: true,
		},
		{
			name:          "empty base",
			base:          &schema.Base{},
			expectedEmpty: true,
		},
		{
			name:         "event only",
			base:         &schema.Base{Event: &schema.Event{Action: "tcp_connect"}},
			expectedKeys: []string{"event"},
		},
		{
			name: "source and destination",
			base: &schema.Base{
				Source:      &schema.Target{Ip: "192.0.2.1"},
				Destination: &schema.Target{Ip: "198.51.100.2"},
			},
			expectedKeys: []string{"source", "destination"},
		},
		{
			name: "several namespaces keep their declared order",
			base: &schema.Base{
				Event:       &schema.Event{Action: "tcp_connect"},
				Source:      &schema.Target{Ip: "192.0.2.1"},
				Destination: &schema.Target{Ip: "198.51.100.2"},
				Network:     &schema.Network{Transport: "tcp"},
			},
			expectedKeys: []string{"event", "source", "destination", "network"},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			attrs := BaseToSlogAttrs(testCase.base)

			if testCase.expectedEmpty {
				if len(attrs) != 0 {
					t.Errorf("expected no attributes, got %d", len(attrs))
				}
				return
			}

			var keys []string
			for _, attr := range attrs {
				keys = append(keys, attr.Key)
			}

			if !slices.Equal(keys, testCase.expectedKeys) {
				t.Errorf("expected keys %v, got %v", testCase.expectedKeys, keys)
			}
		})
	}
}
