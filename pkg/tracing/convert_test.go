package tracing

import (
	"math"
	"testing"
)

func TestClampInt64(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		value    uint64
		expected int64
	}{
		{name: "zero", value: 0, expected: 0},
		{name: "small value passes through", value: 12345, expected: 12345},
		{name: "largest exact value", value: math.MaxInt64, expected: math.MaxInt64},
		{name: "one past the range saturates", value: math.MaxInt64 + 1, expected: math.MaxInt64},
		{name: "all bits set saturates rather than wrapping to -1", value: math.MaxUint64, expected: math.MaxInt64},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := ClampInt64(testCase.value); got != testCase.expected {
				t.Errorf("expected %d, got %d", testCase.expected, got)
			}
		})
	}
}

func TestClampInt(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		value    uint64
		expected int
	}{
		{name: "zero", value: 0, expected: 0},
		{name: "small value passes through", value: 4096, expected: 4096},
		{name: "largest exact value", value: math.MaxInt, expected: math.MaxInt},
		{name: "all bits set saturates rather than wrapping to -1", value: math.MaxUint64, expected: math.MaxInt},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := ClampInt(testCase.value); got != testCase.expected {
				t.Errorf("expected %d, got %d", testCase.expected, got)
			}
		})
	}
}

func TestClampUint16(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		value    uint64
		expected uint16
	}{
		{name: "zero", value: 0, expected: 0},
		{name: "small value passes through", value: 443, expected: 443},
		{name: "largest exact value", value: math.MaxUint16, expected: math.MaxUint16},
		{name: "one past the range saturates instead of truncating to zero", value: math.MaxUint16 + 1, expected: math.MaxUint16},
		{name: "all bits set saturates", value: math.MaxUint64, expected: math.MaxUint16},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := ClampUint16(testCase.value); got != testCase.expected {
				t.Errorf("expected %d, got %d", testCase.expected, got)
			}
		})
	}
}
