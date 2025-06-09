package errors

import "errors"

var (
	ErrNilEbpfProgram = errors.New("nil ebpf program")
	ErrNilEbpfMap = errors.New("nil ebpf map")
	ErrEmptyGroup = errors.New("empty group")
	ErrEmptyName  = errors.New("empty name")
)
