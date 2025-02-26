package machine

import "unsafe"

type Regs struct {
	RAX    uint64
	RBX    uint64
	RCX    uint64
	RDX    uint64
	RSI    uint64
	RDI    uint64
	RSP    uint64
	RBP    uint64
	R8     uint64
	R9     uint64
	R10    uint64
	R11    uint64
	R12    uint64
	R13    uint64
	R14    uint64
	R15    uint64
	RIP    uint64
	RFLAGS uint64
}

func GetRegs(vCpuFd P) (*Regs, error) {
	regs := &Regs{}
	_, err := Ioctl(vCpuFd, IIOR(kvmGetRegs, P(unsafe.Sizeof(Regs{}))), P(Ptr(regs)))
	return regs, err
}

func SetRegs(vCpuFd P, regs *Regs) error {
	_, err := Ioctl(vCpuFd, IIOW(kvmSetRegs, P(unsafe.Sizeof(Regs{}))), P(Ptr(regs)))
	return err
}

type Sregs struct {
	CS              Segment
	DS              Segment
	ES              Segment
	FS              Segment
	GS              Segment
	SS              Segment
	TR              Segment
	LDT             Segment
	GDT             Descriptor
	IDT             Descriptor
	CR0             uint64
	CR2             uint64
	CR3             uint64
	CR4             uint64
	CR8             uint64
	EFER            uint64
	ApicBase        uint64
	InterruptBitmap [(numInterrupts + 63) / 64]uint64
}

func GetSregs(vCpuFd P) (*Sregs, error) {
	sregs := &Sregs{}
	_, err := Ioctl(vCpuFd, IIOR(kvmGetSregs, P(unsafe.Sizeof(Sregs{}))), P(Ptr(sregs)))
	return sregs, err
}

func SetSregs(vCpuFd P, sregs *Sregs) error {
	_, err := Ioctl(vCpuFd, IIOW(kvmSetSregs, P(unsafe.Sizeof(Sregs{}))), P(Ptr(sregs)))
	return err
}

type Segment struct {
	Base     uint64
	Limit    uint32
	Selector uint16
	Typ      uint8
	Present  uint8
	DPL      uint8
	DB       uint8
	S        uint8
	L        uint8
	G        uint8
	AVL      uint8
	Unusable uint8
	_        uint8
}

type Descriptor struct {
	Base  uint64
	Limit uint16
	_     [3]uint16
}

type DebugRegs struct {
	DB    [4]uint64
	DR6   uint64
	DR7   uint64
	Flags uint64
	_     [9]uint64
}

func GetDebugRegs(vCpuFd P, dregs *DebugRegs) error {
	_, err := Ioctl(vCpuFd,
		IIOR(kvmGetDebugRegs, P(unsafe.Sizeof(DebugRegs{}))),
		P(Ptr(dregs)))
	return err
}

func SetDebugRegs(vCpuFd P, dregs *DebugRegs) error {
	_, err := Ioctl(vCpuFd,
		IIOW(kvmSetDebugRegs, P(unsafe.Sizeof(DebugRegs{}))),
		P(Ptr(dregs)))
	return err
}

type XRC struct {
	XRC   uint32
	_     uint32
	Value uint64
}

type XCRS struct {
	NrXRCS    uint32
	Flags     uint32
	Registers [16]XRC
	_         [16]uint64
}

func GetXCRS(vCpuFd P, xcrs *XCRS) error {
	_, err := Ioctl(vCpuFd,
		IIOR(kvmGetXCRS, P(unsafe.Sizeof(XCRS{}))),
		P(Ptr(xcrs)))
	return err
}

func SetXCRS(vCpuFd P, xcrs *XCRS) error {
	_, err := Ioctl(vCpuFd,
		IIOW(kvmSetXCRS, P(unsafe.Sizeof(XCRS{}))),
		P(Ptr(xcrs)))
	return err
}

type SRegs2 struct {
	CS       Segment
	DS       Segment
	ES       Segment
	FS       Segment
	GS       Segment
	SS       Segment
	TR       Segment
	LDT      Segment
	GDT      Descriptor
	IDT      Descriptor
	CR0      uint64
	CR2      uint64
	CR3      uint64
	CR4      uint64
	CR8      uint64
	EFER     uint64
	APICBase uint64
	Flags    uint64
	PDptrs   [4]uint64
}

func GetSRegs2(vCpuFd P, sreg *SRegs2) error {
	_, err := Ioctl(vCpuFd,
		IIOR(kvmGetSRegs2, P(unsafe.Sizeof(SRegs2{}))),
		P(Ptr(sreg)))
	return err
}

func SetSRegs2(vCpuFd P, sreg *SRegs2) error {
	_, err := Ioctl(vCpuFd,
		IIOW(kvmSetSRegs2, P(unsafe.Sizeof(SRegs2{}))),
		P(Ptr(sreg)))
	return err
}
