package machine

import (
	"fmt"
)

type IOFunc func(port uint64, bytes []byte) error

type PortIO interface {
	In(uint64, []byte) error
	Out(uint64, []byte) error
}

type portIOError struct {
}

func (p *portIOError) In(port uint64, bytes []byte) error {
	return fmt.Errorf("%w: unexpected io port 0x%x, read handler", ErrUnexpectedExitReason, port)
}
func (p *portIOError) Out(port uint64, bytes []byte) error {
	return fmt.Errorf("%w: unexpected io port 0x%x, write handler", ErrUnexpectedExitReason, port)
}

type portIOCF9 struct {
}

func (p *portIOCF9) In(port uint64, bytes []byte) error { return nil }

func (p *portIOCF9) Out(port uint64, bytes []byte) error {
	if len(bytes) == 1 && bytes[0] == 0xe {
		return fmt.Errorf("write 0xe to cf9: %w", ErrWriteToCF9)
	}

	return fmt.Errorf("write %#x to cf9: %w", bytes, ErrWriteToCF9)
}

type portIOPS2 struct {
}

func (p *portIOPS2) In(port uint64, bytes []byte) error {
	bytes[0] = 0x20
	return nil
}

func (p *portIOPS2) Out(port uint64, bytes []byte) error { return nil }

type Device interface {
	PortIO
	IOPort() uint64
	Size() uint64
}
