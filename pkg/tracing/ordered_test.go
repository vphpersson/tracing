package tracing

import (
	"slices"
	"sync"
	"testing"
)

func TestOrderedDelivery(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		order    []uint64
		failed   []uint64
		expected []uint64
	}{
		{name: "in order", order: []uint64{0, 1, 2}, expected: []uint64{0, 1, 2}},
		{name: "reversed", order: []uint64{2, 1, 0}, expected: []uint64{0, 1, 2}},
		{name: "a gap held until filled", order: []uint64{1, 3, 0, 2}, expected: []uint64{0, 1, 2, 3}},
		{name: "a record that failed to decode is skipped", order: []uint64{2, 0, 1}, failed: []uint64{1}, expected: []uint64{0, 2}},
		{name: "nothing after a gap that never fills", order: []uint64{1, 2}, expected: nil},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			var got []uint64
			delivery := newOrderedDelivery(func(seq *uint64) { got = append(got, *seq) })
			for _, seq := range testCase.order {
				if slices.Contains(testCase.failed, seq) {
					delivery.deliver(seq, nil)
					continue
				}
				value := seq
				delivery.deliver(seq, &value)
			}

			if !slices.Equal(got, testCase.expected) {
				t.Errorf("delivered %v, want %v", got, testCase.expected)
			}
		})
	}
}

func TestOrderedDeliveryConcurrent(t *testing.T) {
	t.Parallel()

	const records = 2000
	var got []uint64
	delivery := newOrderedDelivery(func(seq *uint64) { got = append(got, *seq) })

	// 7919 is prime, so i*7919 mod records visits every record once, out of order.
	var wg sync.WaitGroup
	for i := range uint64(records) {
		seq := i * 7919 % records
		wg.Go(func() { delivery.deliver(seq, &seq) })
	}
	wg.Wait()

	if len(got) != records {
		t.Fatalf("delivered %d records, want %d", len(got), records)
	}
	if !slices.IsSorted(got) {
		t.Error("records were delivered out of order")
	}
}
