//nolint:dupl
package machine

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"unsafe"
)

type irqLevel struct {
	IRQ   uint32
	Level uint32
}

func IRQLineStatus(vmFd P, irq, level uint32) error {
	irqLev := irqLevel{
		IRQ:   irq,
		Level: level,
	}
	_, err := Ioctl(vmFd,
		IIOWR(kvmIRQLineStatus, P(unsafe.Sizeof(irqLevel{}))), P(Ptr(&irqLev)))
	return err
}

func CreateIRQChip(vmFd P) error {
	_, err := Ioctl(vmFd, IIO(kvmCreateIRQChip), 0)
	return err
}

type pitConfig struct {
	Flags uint32
	_     [15]uint32
}

func CreatePIT2(vmFd P) error {
	pit := pitConfig{
		Flags: 0,
	}
	_, err := Ioctl(vmFd,
		IIOW(kvmCreatePIT2, P(unsafe.Sizeof(pitConfig{}))), P(Ptr(&pit)))
	return err
}

type PITChannelState struct {
	Count         uint32
	LatchedCount  uint16
	CountLatched  uint8
	StatusLatched uint8
	Status        uint8
	ReadState     uint8
	WriteState    uint8
	WriteLatch    uint8
	RWMode        uint8
	Mode          uint8
	BCD           uint8
	Gate          uint8
	CountLoadTime int64
}

type PITState2 struct {
	Channels [3]PITChannelState
	Flags    uint32
	_        [9]uint32
}

func GetPIT2(vmFd P, pstate *PITState2) error {
	_, err := Ioctl(vmFd,
		IIOR(kvmGetPIT2, P(unsafe.Sizeof(PITState2{}))),
		P(Ptr(pstate)))
	return err
}

func SetPIT2(vmFd P, pstate *PITState2) error {
	_, err := Ioctl(vmFd,
		IIOW(kvmSetPIT2, P(unsafe.Sizeof(PITState2{}))), P(Ptr(pstate)))
	return err
}

type PICState struct {
	LastIRR                uint8
	IRR                    uint8
	IMR                    uint8
	ISR                    uint8
	PriorityAdd            uint8
	IRQBase                uint8
	ReadRegSelect          uint8
	Poll                   uint8
	SpecialMask            uint8
	InitState              uint8
	AutoEOI                uint8
	RotateOnAutoEOI        uint8
	SpecialFullyNestedMode uint8
	Init4                  uint8
	ELCR                   uint8
	ELCRMask               uint8
}

type IRQChip struct {
	ChipID uint32
	_      uint32
	Chip   [512]byte
}

func GetIRQChip(vmFd P, irqc *IRQChip) error {
	_, err := Ioctl(vmFd,
		IIOWR(kvmGetIRQChip, P(unsafe.Sizeof(IRQChip{}))),
		P(Ptr(irqc)))
	return err
}

func SetIRQChip(vmFd P, irqc *IRQChip) error {
	_, err := Ioctl(vmFd,
		IIOR(kvmSetIRQChip, P(unsafe.Sizeof(IRQChip{}))), P(Ptr(irqc)))
	return err
}

type IRQRoutingIRQChip struct {
	IRQChip uint32
	Pin     uint32
}

type IRQRoutingEntry struct {
	GSI   uint32
	Type  uint32
	Flags uint32
	_     uint32
	IRQRoutingIRQChip
}

type IRQRouting struct {
	Nr      uint32
	Flags   uint32
	Entries []IRQRoutingEntry
}

func (r *IRQRouting) Bytes() ([]byte, error) {
	var buf bytes.Buffer

	if err := binary.Write(&buf, binary.LittleEndian, r.Nr); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.LittleEndian, r.Flags); err != nil {
		return nil, err
	}
	for _, entry := range r.Entries {
		if err := binary.Write(&buf, binary.LittleEndian, entry); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

func NewIRQRouting(data []byte) (*IRQRouting, error) {
	r := IRQRouting{}

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, data); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if err := binary.Read(&buf, binary.LittleEndian, &r.Nr); err != nil {
		return nil, err
	}
	if err := binary.Read(&buf, binary.LittleEndian, &r.Flags); err != nil {
		return nil, err
	}

	r.Entries = make([]IRQRoutingEntry, r.Nr)

	if err := binary.Read(&buf, binary.LittleEndian, &r.Entries); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return &r, nil
}

func SetGSIRouting(vmFd P, irqR *IRQRouting) error {
	data, err := irqR.Bytes()
	if err != nil {
		return err
	}
	_, err = Ioctl(vmFd,
		IIOW(kvmSetGSIRouting, P(unsafe.Sizeof(irqR))), P(Ptr(&data[0])))
	return err
}

func InjectInterrupt(vCpuFd P, intr uint32) error {
	_, err := Ioctl(vCpuFd, IIOW(kvmInterrupt, 4), P(intr))
	return err
}

const LAPICRegSize = 0x400

type LAPICState struct {
	Regs [LAPICRegSize]byte
}

func GetLocalAPIC(vCpuFd P, lapic *LAPICState) error {
	_, err := Ioctl(vCpuFd,
		IIOR(kvmGetLAPIC, P(unsafe.Sizeof(LAPICState{}))),
		P(Ptr(lapic)))

	return err
}

func SetLocalAPIC(vCpuFd P, lapic *LAPICState) error {
	_, err := Ioctl(vCpuFd,
		IIOW(kvmSetLAPIC, P(unsafe.Sizeof(LAPICState{}))),
		P(Ptr(lapic)))

	return err
}

func ReInjectControl(vmFd P, mode uint8) error {
	tmp := struct {
		pitReinject uint8
		_           [31]byte
	}{
		pitReinject: mode,
	}
	_, err := Ioctl(vmFd,
		IIO(kvmReinjectControl), P(Ptr(&tmp)))
	return err
}
