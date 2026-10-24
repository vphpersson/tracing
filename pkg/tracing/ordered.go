package tracing

import "sync"

// orderedDelivery hands records to a callback in the order they were read from the ring buffer, though they are
// decoded concurrently: a record is delivered once every record read before it has been. The ring buffer keeps the
// order in which events were submitted, so one process's events arrive in the order it caused them.
type orderedDelivery[T any] struct {
	mu       sync.Mutex
	next     uint64
	ready    map[uint64]*T
	callback func(*T)
}

func newOrderedDelivery[T any](callback func(*T)) *orderedDelivery[T] {
	return &orderedDelivery[T]{ready: make(map[uint64]*T), callback: callback}
}

// deliver records that the record numbered seq has been decoded as event, or could not be when event is nil, and
// runs the callback on each record that is now next in order. The callback runs with the delivery locked, one record
// at a time.
func (o *orderedDelivery[T]) deliver(seq uint64, event *T) {
	o.mu.Lock()
	defer o.mu.Unlock()

	o.ready[seq] = event
	for {
		next, ok := o.ready[o.next]
		if !ok {
			return
		}
		delete(o.ready, o.next)
		o.next++
		if next != nil && o.callback != nil {
			o.callback(next)
		}
	}
}
