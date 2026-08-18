package tracing

import "math"

// The kernel reports counters, byte totals and nanosecond timestamps as unsigned
// values, while ECS and Go's time package want signed ones. A plain conversion
// wraps a large unsigned value to a negative number, which reads as a perfectly
// plausible — and completely wrong — counter downstream. These clamp instead, so
// an implausible value stays implausible rather than turning into a negative one.

// ClampInt64 converts an unsigned kernel value to int64, saturating at the
// maximum rather than wrapping negative.
func ClampInt64(value uint64) int64 {
	if value > math.MaxInt64 {
		return math.MaxInt64
	}

	return int64(value)
}

// ClampInt converts an unsigned kernel value to int, saturating at the maximum
// rather than wrapping negative.
func ClampInt(value uint64) int {
	if value > math.MaxInt {
		return math.MaxInt
	}

	return int(value)
}

// ClampUint16 converts an unsigned kernel value to uint16, saturating at the
// maximum rather than truncating to an unrelated value.
func ClampUint16(value uint64) uint16 {
	if value > math.MaxUint16 {
		return math.MaxUint16
	}

	return uint16(value)
}
