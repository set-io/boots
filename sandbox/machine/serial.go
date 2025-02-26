package machine

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
)

const (
	COM1Addr = 0x03f8
)

type SerialIRQInjector interface {
	InjectSerialIRQ() error
}

type Serial struct {
	IER         byte
	LCR         byte
	inputChan   chan byte
	irqInjector SerialIRQInjector
}

func NewSerial(irqInjector SerialIRQInjector) (*Serial, error) {
	s := &Serial{
		IER: 0, LCR: 0,
		inputChan:   make(chan byte, 10000),
		irqInjector: irqInjector,
	}
	return s, nil
}

func (s *Serial) GetInputChan() chan<- byte {
	return s.inputChan
}

func (s *Serial) dlab() bool {
	return s.LCR&0x80 != 0
}

func (s *Serial) In(port uint64, values []byte) error {
	port -= COM1Addr

	switch {
	case port == 0 && !s.dlab():
		if len(s.inputChan) > 0 {
			values[0] = <-s.inputChan
		}
	case port == 0 && s.dlab():
		values[0] = 0xc
	case port == 1 && !s.dlab():
		values[0] = s.IER
	case port == 1 && s.dlab():
		values[0] = 0x0
	case port == 2:
	case port == 3:
	case port == 4:
	case port == 5:
		values[0] |= 0x20
		values[0] |= 0x40
		if len(s.inputChan) > 0 {
			values[0] |= 0x1
		}
	case port == 6:
		break
	}
	return nil
}

func (s *Serial) Out(port uint64, values []byte) error {
	port -= COM1Addr

	var err error

	switch {
	case port == 0 && !s.dlab():
		fmt.Printf("%c", values[0])
	case port == 0 && s.dlab():
	case port == 1 && !s.dlab():
		s.IER = values[0]
		if s.IER != 0 {
			err = s.irqInjector.InjectSerialIRQ()
		}
	case port == 1 && s.dlab():
	case port == 2:
	case port == 3:
		s.LCR = values[0]
	case port == 4:
	default:
		break
	}
	return err
}

func (s *Serial) Start(in bufio.Reader, restoreMode func(), irqInject func() error) error {
	var before byte = 0

	for {
		b, err := in.ReadByte()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				return err
			}
			break
		}
		s.GetInputChan() <- b

		if len(s.GetInputChan()) > 0 {
			if err := irqInject(); err != nil {
				log.Printf("InjectSerialIRQ: %v\n", err)
			}
		}
		if before == 0x1 && b == 'x' {
			restoreMode()
			break
		}
		before = b
	}
	return io.EOF
}
