package machine

import (
	"encoding/binary"
	"fmt"
	"log"

	"golang.org/x/arch/x86/x86asm"
)

func (m *Machine) Args(cpu int, r *Regs, nargs int) ([]P, error) {
	if _, err := m.kvm.CPUToFD(cpu); err != nil {
		return nil, err
	}

	sp := r.RSP

	switch nargs {
	case 6:
		w1, err := m.ReadWord(cpu, sp+0x28)
		if err != nil {
			return nil, err
		}

		w2, err := m.ReadWord(cpu, sp+0x30)
		if err != nil {
			return nil, err
		}
		return []P{P(r.RCX), P(r.RDX), P(r.R8), P(r.R9), P(w1), P(w2)}, nil
	case 5:
		w1, err := m.ReadWord(cpu, sp+0x28)
		if err != nil {
			return nil, err
		}
		return []P{P(r.RCX), P(r.RDX), P(r.R8), P(r.R9), P(w1)}, nil
	case 4:
		return []P{P(r.RCX), P(r.RDX), P(r.R8), P(r.R9)}, nil
	case 3:
		return []P{P(r.RCX), P(r.RDX), P(r.R8)}, nil
	case 2:
		return []P{P(r.RCX), P(r.RDX)}, nil
	case 1:
		return []P{P(r.RCX)}, nil
	}
	return []P{}, fmt.Errorf("args(%d):%w", nargs, ErrBadArg)
}

func (m *Machine) Pointer(inst *x86asm.Inst, r *Regs, arg uint) (P, error) {
	if arg >= uint(len(inst.Args)) {
		return 0, fmt.Errorf("pointer(..,%d): only %d args:%w", arg, len(inst.Args), ErrBadArgType)
	}

	mem, ok := inst.Args[arg].(x86asm.Mem)
	if !ok {
		return 0, fmt.Errorf("arg %d is not a memory argument:%w", arg, ErrBadArgType)
	}

	if debug {
		type Mem struct {
			Segment Regs
			Base    Regs
			Scale   uint8
			Index   Regs
			Disp    int64
		}
		log.Printf("ARG[%d] %q m is %#x\n", arg, inst.Args[arg], mem)
	}

	b, err := GetReg(r, mem.Base)
	if err != nil {
		return 0, fmt.Errorf("base reg %v in %v:%w", mem.Base, mem, ErrBadRegister)
	}

	addr := *b + uint64(mem.Disp)

	x, err := GetReg(r, mem.Index)
	if err == nil {
		addr += uint64(mem.Scale) * (*x)
	}

	if debug {
		if v, ok := inst.Args[0].(*x86asm.Mem); ok {
			log.Printf("computed addr is %#x, %+v\n", addr, v)
		}
	}
	return P(addr), nil
}

func (m *Machine) Pop(cpu int, r *Regs) (uint64, error) {
	cpc, err := m.ReadWord(cpu, r.RSP)
	if err != nil {
		return 0, err
	}
	r.RSP += 8
	return cpc, nil
}

func (m *Machine) Inst(cpu int) (*x86asm.Inst, *Regs, string, error) {
	r, err := m.GetRegs(cpu)
	if err != nil {
		return nil, nil, "", fmt.Errorf("Inst:Getregs:%w", err)
	}

	pc := r.RIP
	if debug {
		log.Printf("Inst: pc %#x, sp %#x\n", pc, r.RSP)
	}
	insn := make([]byte, 16)
	if _, err := m.ReadBytes(cpu, insn, pc); err != nil {
		return nil, nil, "", fmt.Errorf("reading PC at #%x:%w", pc, err)
	}

	d, err := x86asm.Decode(insn, 64)
	if err != nil {
		return nil, nil, "", fmt.Errorf("decoding %#02x:%w", insn, err)
	}
	return &d, r, x86asm.GNUSyntax(d, r.RIP, nil), nil
}

func Asm(d *x86asm.Inst, pc uint64) string {
	return "\"" + x86asm.GNUSyntax(*d, pc, nil) + "\""
}

func CallInfo(inst *x86asm.Inst, r *Regs) string {
	l := fmt.Sprintf("%s[", show("", r))
	for _, a := range inst.Args {
		l += fmt.Sprintf("%v,", a)
	}
	l += fmt.Sprintf("(%#x, %#x, %#x, %#x)", r.RCX, r.RDX, r.R8, r.R9)
	return l
}

func (m *Machine) WriteWord(cpu int, vaddr uint64, word uint64) error {
	pa, err := m.VtoP(cpu, vaddr)
	if err != nil {
		return err
	}

	var b [8]byte

	binary.LittleEndian.PutUint64(b[:], word)
	_, err = m.phyMem.WriteAt(b[:], pa)
	return err
}

func (m *Machine) ReadBytes(cpu int, b []byte, vaddr uint64) (int, error) {
	pa, err := m.VtoP(cpu, vaddr)
	if err != nil {
		return -1, err
	}
	return m.phyMem.ReadAt(b, pa)
}

func (m *Machine) ReadWord(cpu int, vaddr uint64) (uint64, error) {
	var b [8]byte
	if _, err := m.ReadBytes(cpu, b[:], vaddr); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(b[:]), nil
}
