package boots

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"reflect"
	"runtime"
	"syscall"
	"unsafe"
	"time"
	"math/bits"
	"os/exec"
	"io/ioutil"
	"bufio"
	"os/signal"

	"golang.org/x/arch/x86/x86asm"
)

const (
	bootParamAddr = 0x10000
	cmdlineAddr   = 0x20000

	initrdAddr  = 0xf000000
	highMemBase = 0x100000

	serialIRQ    = 4
	virtioNetIRQ = 9
	virtioBlkIRQ = 10

	pageTableBase = 0x30_000

	MinMemSize = 1 << 25
)

const (
	CR0xPE = 1
	CR0xMP = (1 << 1)
	CR0xEM = (1 << 2)
	CR0xTS = (1 << 3)
	CR0xET = (1 << 4)
	CR0xNE = (1 << 5)
	CR0xWP = (1 << 16)
	CR0xAM = (1 << 18)
	CR0xNW = (1 << 29)
	CR0xCD = (1 << 30)
	CR0xPG = (1 << 31)

	CR4xVME        = 1
	CR4xPVI        = (1 << 1)
	CR4xTSD        = (1 << 2)
	CR4xDE         = (1 << 3)
	CR4xPSE        = (1 << 4)
	CR4xPAE        = (1 << 5)
	CR4xMCE        = (1 << 6)
	CR4xPGE        = (1 << 7)
	CR4xPCE        = (1 << 8)
	CR4xOSFXSR     = (1 << 8)
	CR4xOSXMMEXCPT = (1 << 10)
	CR4xUMIP       = (1 << 11)
	CR4xVMXE       = (1 << 13)
	CR4xSMXE       = (1 << 14)
	CR4xFSGSBASE   = (1 << 16)
	CR4xPCIDE      = (1 << 17)
	CR4xOSXSAVE    = (1 << 18)
	CR4xSMEP       = (1 << 20)
	CR4xSMAP       = (1 << 21)

	EFERxSCE = 1
	EFERxLME = (1 << 8)
	EFERxLMA = (1 << 10)
	EFERxNXE = (1 << 11)

	PDE64xPRESENT  = 1
	PDE64xRW       = (1 << 1)
	PDE64xUSER     = (1 << 2)
	PDE64xACCESSED = (1 << 5)
	PDE64xDIRTY    = (1 << 6)
	PDE64xPS       = (1 << 7)
	PDE64xG        = (1 << 8)
)

const (
	portRange = 0x10000
	RedZone   = "\xB8\xBE\xBA\xFE\xCA\x90\x0F\x0B"
)

type Machine struct {
	phyMem  *PhysMemory
	kvm     *KVM
	pci     *PCI
	serial  *Serial
	devices []DeviceIO
	ports   [portRange]PortIO
}

func New(cpus int, memSize int) (*Machine, error) {
	if memSize < MinMemSize {
		return nil, fmt.Errorf("memory size %d:%w", memSize, ErrMemTooSmall)
	}

	CheckSystemLimits()

	m := &Machine{
		phyMem: NewPhysMemory(memSize),
	}

	m.pci = NewPCI(NewBridge())

	var err error

	m.kvm, err = NewKVM(cpus)
	if err != nil {
		return nil, fmt.Errorf("new kvm error: %w", err)
	}

	if err := m.kvm.Init(m.phyMem); err != nil {
		return nil, fmt.Errorf("init kvm error: %w", err)
	}

	for i := highMemBase; i < int(m.phyMem.Len()); i += len(RedZone) {
		m.phyMem.CopyStart(uint64(i), []byte(RedZone))
	}
	return m, nil
}

func (m *Machine) AddIf(ifName, net string) error {
	netTypes := map[string]uint16{
		"tap": syscall.IFF_TAP,
		"tun": syscall.IFF_TUN,
	}
	ioIf, err := NewIf(ifName, netTypes[net])
	if err != nil {
		return err
	}
	v := NewNet(virtioNetIRQ, m, ioIf, m.phyMem)
	go v.TxThreadEntry()
	go v.RxThreadEntry()
	m.pci.Devices = append(m.pci.Devices, v)
	return nil
}

func (m *Machine) AddDisk(diskPath string) error {
	v, err := NewBlk(diskPath, virtioBlkIRQ, m, m.phyMem)
	if err != nil {
		return err
	}
	go v.IOThreadEntry()
	m.pci.Devices = append(m.pci.Devices, v)
	return nil
}

func (m *Machine) SetupRegs(rip, bp uint64, amd64 bool) error {
	for _, cpu := range m.kvm.vCpuFdList() {
		if err := m.initRegs(cpu, rip, bp); err != nil {
			return err
		}
		if err := m.initSregs(cpu, amd64); err != nil {
			return err
		}
	}
	return nil
}

func (m *Machine) LoadPVH(kern, initrd *os.File, cmdline string) error {
	edbaVal := uint32(EBDAStarted >> 4)
	edbaBytes := make([]byte, 4)

	putLe32(edbaBytes, edbaVal)
	m.phyMem.CopyStart(EBDAPointer, edbaBytes)
	e, err := NewEBDA(m.kvm.vCpuLen())
	if err != nil {
		return err
	}

	eb, err := e.Bytes()
	if err != nil {
		return err
	}

	m.phyMem.CopyStart(EBDAStarted, eb)
	gdt := CreateGDT()
	m.phyMem.CopyStart(BootGDTStart, gdt.Bytes())
	m.phyMem.CopyStart(BootIDTStart, []byte{0x0})
	fwElf, err := elf.NewFile(kern)
	if err != nil {
		return err
	}

	ripAddr := fwElf.Entry

	for _, entry := range fwElf.Progs {
		if entry.Type == elf.PT_LOAD {
			_, err := entry.ReadAt(m.phyMem.GetFromStart(entry.Paddr), 0)
			if err != nil && !errors.Is(err, io.EOF) {
				return err
			}
		} else if entry.Type == elf.PT_NOTE {
			if entry.Filesz == 0 {
				return ErrPTNoteHasNoFSize
			}

			addr, _ := ParsePVHEntry(kern, entry)

			if fwElf.Entry != uint64(addr) {
				ripAddr = uint64(addr)
			}
		}
		continue
	}

	for _, cpu := range m.kvm.vCpuFdList() {
		if err := InitRegs(cpu, ripAddr); err != nil {
			return err
		}
		if err := InitSRegs(cpu, gdt); err != nil {
			return err
		}
	}

	PVHStartInfo := NewStartInfo(EBDAStarted, cmdlineAddr)

	if initrd != nil {
		initrdSize, err := initrd.ReadAt(m.phyMem.GetFromStart(initrdAddr), 0)
		if err != nil && initrdSize == 0 && !errors.Is(err, io.EOF) {
			return fmt.Errorf("initrd: (%v, %w)", initrdSize, err)
		}

		m.phyMem.CopyStart(cmdlineAddr, []byte(cmdline))
		m.phyMem.SetZero(cmdlineAddr + len(cmdline))

		ramDiskMod := NewModListEntry(initrdAddr, uint64(initrdSize), 0)

		PVHStartInfo.NrModules += 1
		PVHStartInfo.ModlistPAddr = PVHModListStart

		ramDiskModBytes, err := ramDiskMod.Bytes()
		if err != nil {
			return err
		}
		m.phyMem.CopyStart(PVHModListStart, ramDiskModBytes)
		m.AddDevice(&DeviceNoop{Port: 0x80, Psize: 0x30})
	} else {
		m.AddDevice(&PostCode{})
	}

	memMapEntries := make([]*HVMMemMapTableEntry, 0)
	memMapEntries = append(memMapEntries,
		NewMemMapTableEntry(0,
			EBDAStarted,
			E820Ram),
		NewMemMapTableEntry(
			HighRAMStart,
			m.phyMem.Len()-HighRAMStart,
			E820Ram))

	PVHStartInfo.MemMapEntries = uint32(len(memMapEntries))

	var memOffset uint64 = PVHMemMapStart

	for _, entry := range memMapEntries {
		b, err := entry.Bytes()
		if err != nil {
			return err
		}
		m.phyMem.CopyStart(memOffset, b)
		memOffset += uint64(len(b))
	}

	PVHStartInfoBytes, err := PVHStartInfo.Bytes()
	if err != nil {
		return err
	}
	m.phyMem.CopyStart(PVHInfoStart, PVHStartInfoBytes)

	if m.serial, err = NewSerial(m); err != nil {
		return err
	}

	m.AddDevice(&FWDebug{})
	m.AddDevice(NewCMOS(0xC000000, 0x0))
	m.AddDevice(NewACPIPMTimer())
	m.initIOPortHandlers()
	return nil
}

func (m *Machine) LoadLinux(kernel, initrd io.ReaderAt, params string) error {
	var (
		DefaultKernelAddr = uint64(highMemBase)
		err               error
	)

	ebda, err := NewEBDA(m.kvm.vCpuLen())
	if err != nil {
		return err
	}
	ebdaBytes, err := ebda.Bytes()
	if err != nil {
		return err
	}
	m.phyMem.CopyStart(EBDAStarted, ebdaBytes)

	var initrdSize int
	if initrd.(*os.File) != nil {
		initrdSize, err = initrd.ReadAt(m.phyMem.GetFromStart(initrdAddr), 0)
		if err != nil && initrdSize == 0 && !errors.Is(err, io.EOF) {
			return fmt.Errorf("initrd: (%v, %w)", initrdSize, err)
		}
	}

	m.phyMem.CopyStart(cmdlineAddr, []byte(params))
	m.phyMem.SetZero(cmdlineAddr + len(params))

	var isElfFile bool

	k, err := elf.NewFile(kernel)
	if err == nil {
		isElfFile = true
	}

	kp := &KernParam{}

	if !isElfFile {
		kp, err = NewKernParam(kernel)
		if err != nil {
			return err
		}
	}

	kp.AddE820Entry(
		RealModeIvtBegin,
		EBDAStarted-RealModeIvtBegin,
		E820Ram,
	)
	kp.AddE820Entry(
		EBDAStarted,
		VGARAMBegin-EBDAStarted,
		E820Reserved,
	)
	kp.AddE820Entry(
		MBBIOSBegin,
		MBBIOSEnd-MBBIOSBegin,
		E820Reserved,
	)
	kp.AddE820Entry(
		highMemBase,
		m.phyMem.Len()-highMemBase,
		E820Ram,
	)

	kp.Hdr.VidMode = 0xFFFF
	kp.Hdr.TypeOfLoader = 0xFF
	kp.Hdr.RamdiskImage = initrdAddr
	kp.Hdr.RamdiskSize = uint32(initrdSize)
	kp.Hdr.LoadFlags |= CanUseHeap | LoadedHigh | KeepSegments
	kp.Hdr.HeapEndPtr = 0xFE00
	kp.Hdr.ExtLoaderVer = 0
	kp.Hdr.CmdlinePtr = cmdlineAddr
	kp.Hdr.CmdlineSize = uint32(len(params) + 1)

	bpBytes, err := kp.Bytes()
	if err != nil {
		return err
	}
	m.phyMem.CopyStart(bootParamAddr, bpBytes)

	var (
		amd64    bool
		kernSize int
	)

	switch isElfFile {
	case false:
		setupSz := int(kp.Hdr.SetupSects+1) * 512
		kernSize, err = kernel.ReadAt(m.phyMem.GetFromStart(DefaultKernelAddr), int64(setupSz))
		if err != nil && !errors.Is(err, io.EOF) {
			return fmt.Errorf("kernel: (%v, %w)", kernSize, err)
		}
	case true:
		if k.Class == elf.ELFCLASS64 {
			amd64 = true
		}
		DefaultKernelAddr = k.Entry

		for i, p := range k.Progs {
			if p.Type != elf.PT_LOAD {
				continue
			}
			if debug {
				log.Printf("Load elf segment @%#x from file %#x %#x bytes\n", p.Paddr, p.Off, p.Filesz)
			}
			n, err := p.ReadAt(m.phyMem.GetFromStart(p.Paddr), 0)
			if !errors.Is(err, io.EOF) || uint64(n) != p.Filesz {
				return fmt.Errorf("reading ELF prog %d@%#x: %d/%d bytes, err %w", i, p.Paddr, n, p.Filesz, err)
			}
			kernSize += n
		}
	}

	if kernSize == 0 {
		return ErrZeroSizeKernel
	}
	if err := m.SetupRegs(DefaultKernelAddr, bootParamAddr, amd64); err != nil {
		return err
	}
	if m.serial, err = NewSerial(m); err != nil {
		return err
	}
	m.AddDevice(NewCMOS(0xC000_0000, 0x0))
	m.AddDevice(&DeviceNoop{Port: 0x80, Psize: 0xA0})
	m.initIOPortHandlers()
	return nil
}

func (m *Machine) GetInputChan() chan<- byte {
	return m.serial.GetInputChan()
}

func (m *Machine) GetRegs(cpu int) (*Regs, error) {
	fd, err := m.kvm.CPUToFD(cpu)
	if err != nil {
		return nil, err
	}
	return GetRegs(fd)
}

func (m *Machine) GetSRegs(cpu int) (*Sregs, error) {
	fd, err := m.kvm.CPUToFD(cpu)
	if err != nil {
		return nil, err
	}
	return GetSregs(fd)
}

func (m *Machine) SetRegs(cpu int, r *Regs) error {
	fd, err := m.kvm.CPUToFD(cpu)
	if err != nil {
		return err
	}
	return SetRegs(fd, r)
}

func (m *Machine) SetSRegs(cpu int, s *Sregs) error {
	fd, err := m.kvm.CPUToFD(cpu)
	if err != nil {
		return err
	}
	return SetSregs(fd, s)
}

func (m *Machine) initRegs(vcpufd P, rip, bp uint64) error {
	regs, err := GetRegs(vcpufd)
	if err != nil {
		return err
	}

	regs.RFLAGS = 2
	regs.RIP = rip
	regs.RSI = bp
	if err := SetRegs(vcpufd, regs); err != nil {
		return err
	}
	return nil
}

func (m *Machine) initSregs(vCpuFd P, amd64 bool) error {
	sregs, err := GetSregs(vCpuFd)
	if err != nil {
		return err
	}

	if !amd64 {
		sregs.CS.Base, sregs.CS.Limit, sregs.CS.G = 0, 0xFFFFFFFF, 1
		sregs.DS.Base, sregs.DS.Limit, sregs.DS.G = 0, 0xFFFFFFFF, 1
		sregs.FS.Base, sregs.FS.Limit, sregs.FS.G = 0, 0xFFFFFFFF, 1
		sregs.GS.Base, sregs.GS.Limit, sregs.GS.G = 0, 0xFFFFFFFF, 1
		sregs.ES.Base, sregs.ES.Limit, sregs.ES.G = 0, 0xFFFFFFFF, 1
		sregs.SS.Base, sregs.SS.Limit, sregs.SS.G = 0, 0xFFFFFFFF, 1

		sregs.CS.DB, sregs.SS.DB = 1, 1
		sregs.CR0 |= 1

		if err := SetSregs(vCpuFd, sregs); err != nil {
			return err
		}
		return nil
	}

	high64k := m.phyMem.Get(pageTableBase, pageTableBase+0x6000)
	for i := range high64k {
		high64k[i] = 0
	}
	copy(high64k, []byte{
		0x03,
		0x10 | uint8((pageTableBase>>8)&0xff),
		uint8((pageTableBase >> 16) & 0xff),
		uint8((pageTableBase >> 24) & 0xff), 0, 0, 0, 0,
	})
	for i := uint64(0); i < 4; i++ {
		ptb := pageTableBase + (i+2)*0x1000
		copy(high64k[int(i*8)+0x1000:],
			[]byte{
				/*0x80 |*/ 0x63,
				uint8((ptb >> 8) & 0xff),
				uint8((ptb >> 16) & 0xff),
				uint8((ptb >> 24) & 0xff), 0, 0, 0, 0,
			})
	}
	for i := uint64(0); i < 0x1_0000_0000; i += 0x2_00_000 {
		ptb := i | 0xe3
		ix := int((i/0x2_00_000)*8 + 0x2000)
		copy(high64k[ix:], []byte{
			uint8(ptb),
			uint8((ptb >> 8) & 0xff),
			uint8((ptb >> 16) & 0xff),
			uint8((ptb >> 24) & 0xff), 0, 0, 0, 0,
		})
	}

	if debug {
		log.Printf("Page tables: %s\n", hex.Dump(m.phyMem.Get(pageTableBase, pageTableBase+0x3000)))
	}

	sregs.CR3 = uint64(pageTableBase)
	sregs.CR4 = CR4xPAE
	sregs.CR0 = CR0xPE | CR0xMP | CR0xET | CR0xNE | CR0xWP | CR0xAM | CR0xPG
	sregs.EFER = EFERxLME | EFERxLMA

	seg := Segment{
		Base:     0,
		Limit:    0xffffffff,
		Selector: 1 << 3,
		Typ:      11,
		Present:  1,
		DPL:      0,
		DB:       0,
		S:        1,
		L:        1,
		G:        1,
		AVL:      0,
	}

	sregs.CS = seg
	seg.Typ = 3
	seg.Selector = 2 << 3
	sregs.DS, sregs.ES, sregs.FS, sregs.GS, sregs.SS = seg, seg, seg, seg, seg

	if err := SetSregs(vCpuFd, sregs); err != nil {
		return err
	}
	return nil
}

func (m *Machine) SingleStep(onOff bool) error {
	for cpu := 0; cpu < m.kvm.vCpuLen(); cpu++ {
		if err := m.kvm.SingleStep(cpu, onOff); err != nil {
			return fmt.Errorf("single step %d:%w", cpu, err)
		}
	}
	return nil
}

func (m *Machine) RunInfiniteLoop(cpu int) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	for {
		isContinue, err := m.RunOnce(cpu)
		if isContinue {
			if err != nil {
				fmt.Printf("%v\r\n", err)
			}
			continue
		}
		if err != nil {
			return err
		}
	}
}

func (m *Machine) RunOnce(cpu int) (bool, error) {
	fd, err := m.kvm.CPUToFD(cpu)
	if err != nil {
		return false, err
	}

	_ = Run(fd)
	exit := m.kvm.GetExitReasonByCpu(cpu)

	switch exit {
	case EXITHLT:
		return false, err
	case EXITIO:
		var f IOFunc
		direction, size, port, count, offset := m.kvm.GetIOByCpu(cpu)
		switch direction {
		case EXITIOIN:
			f = m.ports[port].In
		case EXITIOOUT:
			f = m.ports[port].Out
		default:
			panic(fmt.Errorf("EXITIO direction error, is: %d", direction))
		}

		b := (*(*[100]byte)(Ptr(P(Ptr(m.kvm.RunDataByCpu(cpu))) + P(offset))))[0:size]
		for i := 0; i < int(count); i++ {
			if err := f(port, b); err != nil {
				return false, err
			}
		}
		return true, err
	case EXITUNKNOWN:
		return true, err
	case EXITINTR:
		return true, nil
	case EXITDEBUG:
		return false, ErrDebug
	case EXITDCR,
		EXITEXCEPTION,
		EXITFAILENTRY,
		EXITHYPERCALL,
		EXITINTERNALERROR,
		EXITIRQWINDOWOPEN,
		EXITMMIO,
		EXITNMI,
		EXITS390RESET,
		EXITS390SIEIC,
		EXITSETTPR,
		EXITSHUTDOWN,
		EXITTPRACCESS:
		if err != nil {
			return false, err
		}
		return false, fmt.Errorf("%w: %s", ErrUnexpectedExitReason, exit.String())
	default:
		if err != nil {
			return false, err
		}
		r, _ := m.GetRegs(cpu)
		s, _ := m.GetSRegs(cpu)
		return false, fmt.Errorf("%w: %v: regs:\n%s",
			ErrUnexpectedExitReason,
			m.kvm.GetExitReasonByCpu(cpu).String(), show("", &s, &r))
	}
}

func (m *Machine) registerPortIO(start, end uint64, io PortIO) {
	for i := start; i < end; i++ {
		m.ports[i] = io
	}
}

func (m *Machine) initIOPortHandlers() {
	m.registerPortIO(0, 0x10000, &portIOError{})
	m.registerPortIO(0xcf9, 0xcfa, &portIOCF9{})
	m.registerPortIO(0x3c0, 0x3db, &PortIONoop{})
	m.registerPortIO(0x3b4, 0x3b6, &PortIONoop{})
	m.registerPortIO(0x2f8, 0x300, &PortIONoop{})
	m.registerPortIO(0x3e8, 0x3f0, &PortIONoop{})
	m.registerPortIO(0x2e8, 0x2f0, &PortIONoop{})
	m.registerPortIO(0xcfe, 0xcff, &PortIONoop{})
	m.registerPortIO(0xcfa, 0xcfc, &PortIONoop{})
	m.registerPortIO(0xc000, 0xd000, &PortIONoop{})
	m.registerPortIO(0x60, 0x70, &portIOPS2{})
	m.registerPortIO(0xed, 0xee, &PortIONoop{})
	m.registerPortIO(COM1Addr, COM1Addr+8, m.serial)
	m.registerPortIO(0xcf8, 0xcf9, m.pci)
	m.registerPortIO(0xcfc, 0xd00, &PCIConf{m.pci})

	for _, dev := range m.devices {
		m.registerPortIO(dev.IOPort(), dev.IOPort()+dev.Size(), dev)
	}
	for _, dev := range m.pci.Devices {
		m.registerPortIO(dev.IOPort(), dev.IOPort()+dev.Size(), dev)
	}
}

func (m *Machine) InjectSerialIRQ() error {
	if err := IRQLineStatus(m.kvm.GetVmFd(), serialIRQ, 0); err != nil {
		return err
	}
	if err := IRQLineStatus(m.kvm.GetVmFd(), serialIRQ, 1); err != nil {
		return err
	}
	return nil
}

func (m *Machine) VirtualIONetIRQ() error {
	if err := IRQLineStatus(m.kvm.GetVmFd(), virtioNetIRQ, 0); err != nil {
		return err
	}
	if err := IRQLineStatus(m.kvm.GetVmFd(), virtioNetIRQ, 1); err != nil {
		return err
	}
	return nil
}

func (m *Machine) VirtualIOBlkIRQ() error {
	if err := IRQLineStatus(m.kvm.GetVmFd(), virtioBlkIRQ, 0); err != nil {
		return err
	}
	if err := IRQLineStatus(m.kvm.GetVmFd(), virtioBlkIRQ, 1); err != nil {
		return err
	}
	return nil
}

func showOne(indent string, in interface{}) string {
	var ret string

	s := reflect.ValueOf(in).Elem()
	typeOfT := s.Type()

	for i := 0; i < s.NumField(); i++ {
		f := s.Field(i)
		if f.Kind() == reflect.String {
			ret += fmt.Sprintf(indent+"%s %s = %s\n", typeOfT.Field(i).Name, f.Type(), f.Interface())
		} else {
			ret += fmt.Sprintf(indent+"%s %s = %#x\n", typeOfT.Field(i).Name, f.Type(), f.Interface())
		}
	}

	return ret
}

func show(indent string, l ...interface{}) string {
	var ret string
	for _, i := range l {
		ret += showOne(indent, i)
	}
	return ret
}

func (m *Machine) VtoP(cpu int, vaddr uint64) (int64, error) {
	fd, err := m.kvm.CPUToFD(cpu)
	if err != nil {
		return 0, err
	}
	t := &Translation{
		LinearAddress: vaddr,
	}
	if err := Translate(fd, t); err != nil {
		return -1, err
	}
	if t.Valid == 0 || t.PhysicalAddress > m.phyMem.Len() {
		return -1, fmt.Errorf("%#x:valid not set:%w", vaddr, ErrBadVA)
	}
	return int64(t.PhysicalAddress), nil
}

func GetReg(r *Regs, reg x86asm.Reg) (*uint64, error) {
	if reg == x86asm.RAX {
		return &r.RAX, nil
	}
	if reg == x86asm.RCX {
		return &r.RCX, nil
	}
	if reg == x86asm.RDX {
		return &r.RDX, nil
	}
	if reg == x86asm.RBX {
		return &r.RBX, nil
	}
	if reg == x86asm.RSP {
		return &r.RSP, nil
	}
	if reg == x86asm.RBP {
		return &r.RBP, nil
	}
	if reg == x86asm.RSI {
		return &r.RSI, nil
	}
	if reg == x86asm.RDI {
		return &r.RDI, nil
	}
	if reg == x86asm.R8 {
		return &r.R8, nil
	}
	if reg == x86asm.R9 {
		return &r.R9, nil
	}
	if reg == x86asm.R10 {
		return &r.R10, nil
	}
	if reg == x86asm.R11 {
		return &r.R11, nil
	}
	if reg == x86asm.R12 {
		return &r.R12, nil
	}
	if reg == x86asm.R13 {
		return &r.R13, nil
	}
	if reg == x86asm.R14 {
		return &r.R14, nil
	}
	if reg == x86asm.R15 {
		return &r.R15, nil
	}
	if reg == x86asm.RIP {
		return &r.RIP, nil
	}
	return nil, fmt.Errorf("register %v%w", reg, ErrUnsupported)
}

func (m *Machine) VCPU(cpu, traceCount int) error {
	trace := traceCount > 0

	var err error

	for tc := 0; ; tc++ {
		err = m.RunInfiniteLoop(cpu)
		if err == nil {
			continue
		}
		if !errors.Is(err, ErrDebug) {
			return fmt.Errorf("CPU %d: %w", cpu, err)
		}
		if err := m.SingleStep(trace); err != nil {
			return fmt.Errorf("setting trace to %v:%v", trace, err)
		}
		if tc%traceCount != 0 {
			continue
		}
		_, r, s, err := m.Inst(cpu)
		if err != nil {
			return fmt.Errorf("disassembling after debug exit:%v", err)
		} else {
			return fmt.Errorf("%#x:%s\r\n", r.RIP, s)
		}
	}
}

func (m *Machine) GetSerial() *Serial {
	return m.serial
}

func (m *Machine) AddDevice(dev DeviceIO) {
	m.devices = append(m.devices, dev)
}

func (m *Machine) Halt() {
	m.phyMem.Free()
}

const (
	MagicSignature = 0x53726448

	LoadedHigh   = uint8(1 << 0)
	KeepSegments = uint8(1 << 6)
	CanUseHeap   = uint8(1 << 7)

	EddMbrSigMax = 16
	E820Max      = 128
	E820Ram      = 1
	E820Reserved = 2

	RealModeIvtBegin = 0x00000000
	EBDAStarted      = 0x0009fc00
	VGARAMBegin      = 0x000a0000
	MBBIOSBegin      = 0x000f0000
	MBBIOSEnd        = 0x000fffff
)

type E820Entry struct {
	Addr uint64
	Size uint64
	Type uint32
}

type KernParam struct {
	Padding             [0x1e8]uint8
	E820Entries         uint8
	EddbufEntries       uint8
	EddMbrSigBufEntries uint8
	KdbStatus           uint8
	Padding2            [5]uint8
	Hdr                 SetupHeader
	Padding3            [0x290 - 0x1f1 - unsafe.Sizeof(SetupHeader{})]uint8
	Padding4            [0x3d]uint8
	EddMbrSigBuffer     [EddMbrSigMax]uint8
	E820Map             [E820Max]E820Entry
}

type SetupHeader struct {
	SetupSects          uint8
	RootFlags           uint16
	SysSize             uint32
	RAMSize             uint16
	VidMode             uint16
	RootDev             uint16
	BootFlag            uint16
	Jump                uint16
	Header              uint32
	Version             uint16
	ReadModeSwitch      uint32
	StartSysSeg         uint16
	KernelVersion       uint16
	TypeOfLoader        uint8
	LoadFlags           uint8
	SetupMoveSize       uint16
	Code32Start         uint32
	RamdiskImage        uint32
	RamdiskSize         uint32
	BootsectKludge      uint32
	HeapEndPtr          uint16
	ExtLoaderVer        uint8
	ExtLoaderType       uint8
	CmdlinePtr          uint32
	InitrdAddrMax       uint32
	KernelAlignment     uint32
	RelocatableKernel   uint8
	MinAlignment        uint8
	XloadFlags          uint16
	CmdlineSize         uint32
	HardwareSubarch     uint32
	HardwareSubarchData uint64
	PayloadOffset       uint32
	PayloadLength       uint32
	SetupData           uint64
	PrefAddress         uint64
	InitSize            uint32
	HandoverOffset      uint32
	KernelInfoOffset    uint32
}

func NewKernParam(r io.ReaderAt) (*KernParam, error) {
	k := &KernParam{}

	reader := io.NewSectionReader(r, 0x1f1, 0x1000)
	if err := binary.Read(reader, binary.LittleEndian, &(k.Hdr)); err != nil {
		return k, err
	}
	if err := k.isValid(); err != nil {
		return k, err
	}
	return k, nil
}

func (k *KernParam) isValid() error {
	if k.Hdr.Header != MagicSignature {
		return ErrSignatureNotMatch
	}
	if k.Hdr.Version < 0x0206 {
		return fmt.Errorf("%w: 0x%x", ErrOldProtocolVersion, k.Hdr.Version)
	}
	return nil
}

func (k *KernParam) AddE820Entry(addr, size uint64, typ uint32) {
	i := k.E820Entries
	k.E820Map[i] = E820Entry{
		Addr: addr,
		Size: size,
		Type: typ,
	}
	k.E820Entries = i + 1
}

func (k *KernParam) Bytes() ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.LittleEndian, k); err != nil {
		return []byte{}, err
	}
	return buf.Bytes(), nil
}

type PostCode struct{}

func (p *PostCode) In(port uint64, data []byte) error {
	return nil
}

func (p *PostCode) Out(port uint64, data []byte) error {
	if len(data) != 1 {
		return ErrDataLenInvalid
	}

	if data[0] == '\000' {
		fmt.Printf("\r\n")
	} else {
		fmt.Printf("%c", data[0])
	}

	return nil
}

func (p *PostCode) IOPort() uint64 { return 0x80 }
func (p *PostCode) Size() uint64   { return 0x1 }

func DebugEnabled() { debug = true }

type ACPIPMTimer struct {
	Start time.Time
}

const (
	pmTimerFreqHz  uint64 = 3_579_545
	nanosPerSecond uint64 = 1_000_000_000
)

func NewACPIPMTimer() *ACPIPMTimer {
	return &ACPIPMTimer{
		Start: time.Now(),
	}
}

func (a *ACPIPMTimer) In(base uint64, data []byte) error {
	if len(data) != 4 {
		return ErrDataLenInvalid
	}

	since := time.Since(a.Start)
	nanos := since.Nanoseconds()
	counter := (nanos * int64(pmTimerFreqHz)) / int64(nanosPerSecond)
	counter32 := uint32(counter & 0xFFFF_FFFF)

	counterBytes := make([]byte, 4)
	putLe32(counterBytes, counter32)
	copy(data[0:], counterBytes)
	return nil
}

func (a *ACPIPMTimer) Out(base uint64, data []byte) error {
	return nil
}

func (a *ACPIPMTimer) IOPort() uint64 {
	return 0x608
}

func (a *ACPIPMTimer) Size() uint64 {
	return 0x4
}

type ACPIShutDown struct {
	Port       uint64
	ExitEvent  chan int
	ResetEvent chan int
}

func NewACPIShutDownEvent() *ACPIShutDown {
	return &ACPIShutDown{}
}

func (a *ACPIShutDown) Read(base uint64, data []byte) error {
	data[0] = 0
	return nil
}

func (a *ACPIShutDown) Write(base uint64, data []byte) error {
	if data[0] == 1 {
		log.Println("ACPI Reboot signaled")
	}
	S5SleepVal := uint8(5)
	SleepStatusENBit := uint8(5)
	SleepValBit := uint8(2)

	if data[0] == (S5SleepVal<<SleepValBit)|(1<<SleepStatusENBit) {
		a.ExitEvent <- 1
		log.Println("ACPI Shutdown signalled")
	}
	return nil
}

func (a *ACPIShutDown) IOPort() uint64 {
	return 0x600
}

func (a *ACPIShutDown) Size() uint64 {
	return 0x8
}

type TRPAccessCtl struct {
	Enable uint32
	Flags  uint32
	_      [8]uint32
}

func TRPAccessReporting(vCpuFd P, ctl *TRPAccessCtl) error {
	_, err := Ioctl(vCpuFd,
		IIOWR(kvmTRPAccessReporting, P(unsafe.Sizeof(TRPAccessCtl{}))), P(Ptr(ctl)))
	return err
}

type bridge struct{}

func (br bridge) GetDeviceHeader() DeviceHeader {
	return DeviceHeader{
		DeviceID:      0x0d57,
		VendorID:      0x8086,
		HeaderType:    1,
		SubsystemID:   0,
		InterruptLine: 0,
		InterruptPin:  0,
		BAR:           [6]uint32{},
		Command:       0,
	}
}

func (br bridge) In(port uint64, bytes []byte) error {
	return ErrBridgeNotPermit
}

func (br bridge) Out(port uint64, bytes []byte) error {
	return ErrBridgeNotPermit
}

func (br bridge) IOPort() uint64 {
	return 0
}

func (br bridge) Size() uint64 {
	return 0x10
}

func NewBridge() PCIDevice {
	return &bridge{}
}

//go:generate stringer -type=Cap
type Cap uint8

const (
	CapIRQChip                  Cap = 0
	CapHLT                      Cap = 1
	CapMMUShadowCacheControl    Cap = 2
	CapUserMemory               Cap = 3
	CapSetTSSAddr               Cap = 4
	CapVAPIC                    Cap = 6
	CapEXTCPUID                 Cap = 7
	CapClockSource              Cap = 8
	CapNRVCPUS                  Cap = 9  /* returns recommended max vcpus per vm */
	CapNRMemSlots               Cap = 10 /* returns max memory slots per vm */
	CapPIT                      Cap = 11
	CapNopIODelay               Cap = 12
	CapPVMMU                    Cap = 13
	CapMPState                  Cap = 14
	CapCoalescedMMIO            Cap = 15
	CapSyncMMU                  Cap = 16 /* Changes to host mmap are reflected in guest */
	CapIOMMU                    Cap = 18
	CapDestroyMemoryRegionWorks Cap = 21
	CapUserNMI                  Cap = 22
	CapSetGuestDebug            Cap = 23
	CapReinjectControl          Cap = 24
	CapIRQRouting               Cap = 25
	CapIRQInjectStatus          Cap = 26
	CapAssignDevIRQ             Cap = 29
	CapJoinMemoryRegionsWorks   Cap = 30
	CapMCE                      Cap = 31
	CapIRQFD                    Cap = 32
	CapPIT2                     Cap = 33
	CapSetBootCPUID             Cap = 34
	CapPITState2                Cap = 35
	CapIOEventFD                Cap = 36
	CapSetIdentityMapAddr       Cap = 37
	CapXENHVM                   Cap = 38
	CapAdjustClock              Cap = 39
	CapInternalErrorData        Cap = 40
	CapVCPUEvents               Cap = 41
	CapS390PSW                  Cap = 42
	CapPPCSegState              Cap = 43
	CapHyperV                   Cap = 44
	CapHyperVVAPIC              Cap = 45
	CapHyperVSPIN               Cap = 46
	CapPCISEgment               Cap = 47
	CapPPCPairedSingles         Cap = 48
	CapINTRShadow               Cap = 49
	CapDebugRegs                Cap = 50
	CapX86RobustSinglestep      Cap = 51
	CapPPCOSI                   Cap = 52
	CapPPCUnsetIRQ              Cap = 53
	CapEnableCap                Cap = 54
	CapXSave                    Cap = 55
	CapXCRS                     Cap = 56
	CapPPCGetPVInfo             Cap = 57
	CapPPCIRQLevel              Cap = 58
	CapASYNCPF                  Cap = 59
	CapTSCControl               Cap = 60
	CapGetTSCkHz                Cap = 61
	CapPPCBookeSREGS            Cap = 62
	CapSPAPRTCE                 Cap = 63
	CapPPCSMT                   Cap = 64
	CapPPCRMA                   Cap = 65
	CapMAXVCPUS                 Cap = 66 /* returns max vcpus per vm */
	CapPPCHIOR                  Cap = 67
	CapPPCPAPR                  Cap = 68
	CapSWTLB                    Cap = 69
	CapONEREG                   Cap = 70
	CapS390GMap                 Cap = 71
	CapTSCDeadlineTimer         Cap = 72
	CapS390UControl             Cap = 73
	CapSyncRegs                 Cap = 74
	CapPCI23                    Cap = 75
	CapKVMClockCtrl             Cap = 76
	CapSignalMSI                Cap = 77
	CapPPCGetSMMUInfo           Cap = 78
	CapS390COW                  Cap = 79
	CapPPCAllocHTAB             Cap = 80
	CapReadOnlyMEM              Cap = 81
	CapIRQFDResample            Cap = 82
	CapPPCBokkeWatchdog         Cap = 83
	CapPPCHTABFD                Cap = 84
	CapS390CSSSupport           Cap = 85
	CapPPCEPR                   Cap = 86
	CapARMPSCI                  Cap = 87
	CapARMSetDeviceAddr         Cap = 88
	CapDeviceCtrl               Cap = 89
	CapIRQMPIC                  Cap = 90
	CapPPCRTAS                  Cap = 91
	CapIRQXICS                  Cap = 92
	CapARMEL132BIT              Cap = 93
	CapSPAPRMultiTCE            Cap = 94
	CapEXTEmulCPUID             Cap = 95
	CapHyperVTIME               Cap = 96
	CapIOAPICPolarityIgnored    Cap = 97
	CapEnableCAPVM              Cap = 98
	CapS390IRQCHIP              Cap = 99
	CapIOEVENTFDNoLength        Cap = 100
	CapVMAttributes             Cap = 101
	CapARMPSCI02                Cap = 102
	CapPPCFixupHCALL            Cap = 103
	CapPPCEnableHCALL           Cap = 104
	CapCheckExtentionVM         Cap = 105
	CapS390UserSIGP             Cap = 106
	CapS390VectorRegisters      Cap = 107
	CapS390MemOp                Cap = 108
	CapS390UserSTSI             Cap = 109
	CapS390SKEYS                Cap = 110
	CapMIPSFPU                  Cap = 111
	CapMIPSMSA                  Cap = 112
	CapS390InjectIRQ            Cap = 113
	CapS390IRQState             Cap = 114
	CapPPCHWRNG                 Cap = 115
	CapDisableQuirks            Cap = 116
	CapX86SMM                   Cap = 117
	CapMultiAddressSpace        Cap = 118
	CapGuestDebugHWBPS          Cap = 119
	CapGuestDebugHWWPS          Cap = 120
	CapSplitIRQChip             Cap = 121
	CapIOEventFDAnyLength       Cap = 122
	CapHyperVSYNIC              Cap = 123
	CapS390RI                   Cap = 124
	CapSPAPRTCE64               Cap = 125
	CapARMPMUV3                 Cap = 126
	CapVCPUAttributes           Cap = 127
	CapMAXVCPUID                Cap = 128
	CapX2APICAPI                Cap = 129
	CapS390UserINSTR0           Cap = 130
	CapMSIDEVID                 Cap = 131
	CapPPCHTM                   Cap = 132
	CapSPAPRResizeHPT           Cap = 133
	CapPPCMMURADIX              Cap = 134
	CapPPCMMUHASHV3             Cap = 135
	CapImmediateExit            Cap = 136
	CapMIPSVZ                   Cap = 137
	CapMIPSTE                   Cap = 138
	CapMIPS64BIT                Cap = 139
	CapS390GS                   Cap = 140
	CapS390AIS                  Cap = 141
	CapSPAPRTCEVFIO             Cap = 142
	CapX86DisableExits          Cap = 143
	CapARMUserIRQ               Cap = 144
	CapS390CMMAMigration        Cap = 145
	CapPPCFWNMI                 Cap = 146
	CapPPCSMTPossible           Cap = 147
	CapHyperVSYNIC2             Cap = 148
	CapHyperVVPIndex            Cap = 149
	CapS390AISMigration         Cap = 150
	CapPPCGetCPUChar            Cap = 151
	CapS390BPB                  Cap = 152
	CapGETMSRFeatures           Cap = 153
	CapHyperVEventFD            Cap = 154
	CapHyperVTLBFlush           Cap = 155
	CapS390HPage1M              Cap = 156
	CapNestedState              Cap = 157
	CapARMInjectSErrorESR       Cap = 158
	CapMSRPlatformInfo          Cap = 159
	CapPPCNestedHV              Cap = 160
	CapHyperVSendIPI            Cap = 161
	CapCoalescedPIO             Cap = 162
	CapHyperVEnlightenedVMCS    Cap = 163
	CapExceptionPayload         Cap = 164
	CapARMVMIPASize             Cap = 165
	CapManualDirtyLogProtect    Cap = 166 /* Obsolete */
	CapHyerVCPUID               Cap = 167
	CapManualDirtyLogProtect2   Cap = 168
	CapPPCIRQXive               Cap = 169
	CapARMSVE                   Cap = 170
	CapARMPTRAuthAddress        Cap = 171
	CapARMPTRAuthGeneric        Cap = 172
	CapPMUEventFilter           Cap = 173
	CapARMIRQLineLayout2        Cap = 174
	CapHyperVDirectTLBFlush     Cap = 175
	CapPPCGuestDebugSStep       Cap = 176
	CapARMNISVToUser            Cap = 177
	CapARMInjectEXTDABT         Cap = 178
	CapS390VCPUResets           Cap = 179
	CapS390Protected            Cap = 180
	CapPPCSecureGuest           Cap = 181
	CapHALTPoll                 Cap = 182
	CapASYNCPFInt               Cap = 183
	CapLastCPU                  Cap = 184
	CapSmallerMaxPhyAddr        Cap = 185
	CapS390DIAG318              Cap = 186
	CapStealTime                Cap = 187
	CapX86UserSpaceMSR          Cap = 188
	CapX86MSRFilter             Cap = 189
	CapEnforcePVFeatureCPUID    Cap = 190
	CapSysHyperVCPUID           Cap = 191
	CapDirtyLogRing             Cap = 192
	CapX86BusLockExit           Cap = 193
	CapPPCDAWR1                 Cap = 194
	CapSetGuestDebug2           Cap = 195
	CapSGXAttribute             Cap = 196
	CapVMCopyEncContextFrom     Cap = 197
	CapPTPKVM                   Cap = 198
	CapHyperVEnforceCPUID       Cap = 199
	CapSREGS2                   Cap = 200
	CapEXitHyperCall            Cap = 201
	CapPPCRPTInvalidate         Cap = 202
	CapBinaryStatsFD            Cap = 203
	CapExitOnEmulationFailure   Cap = 204
	CapARMMTE                   Cap = 205
	CapVMMoveEncContextFrom     Cap = 206
	CapVMGPABits                Cap = 207
	CapXSave2                   Cap = 208
	CapSysAttributes            Cap = 209
	CapPPCAILMode3              Cap = 210
	CapS390MemOpExtention       Cap = 211
	CapPMUCap                   Cap = 212
	CapDisableQuirks2           Cap = 213
	CapVMTSCControl             Cap = 214
	CapSystemEventData          Cap = 215
	CapARMSystemSuspend         Cap = 216
	CapS390ProtectedDump        Cap = 217
	CapX86TripleFaultEvent      Cap = 218
	CapX86NotifyVMExit          Cap = 219
	CapVMDisableNXHugePages     Cap = 220
	CapS390ZPCIOP               Cap = 221
	CapS390CPUTOPOLOGY          Cap = 222
	CapDirtyLogRingACQRel       Cap = 223
)

func KVMCapabilities() error {
	X86Items := []Cap{
		CapIRQChip,
		CapUserMemory,
		CapSetTSSAddr,
		CapEXTCPUID,
		CapMPState,
		CapCoalescedMMIO,
		CapUserNMI,
		CapSetGuestDebug,
		CapReinjectControl,
		CapIRQRouting,
		CapMCE,
		CapIRQFD,
		CapPIT2,
		CapSetBootCPUID,
		CapPITState2,
		CapIOEventFD,
		CapAdjustClock,
		CapVCPUEvents,
		CapINTRShadow,
		CapDebugRegs,
		CapEnableCap,
		CapXSave,
		CapXCRS,
		CapTSCControl,
		CapONEREG,
		CapKVMClockCtrl,
		CapSignalMSI,
		CapDeviceCtrl,
		CapEXTEmulCPUID,
		CapVMAttributes,
		CapX86SMM,
		CapX86DisableExits,
		CapGETMSRFeatures,
		CapNestedState,
		CapCoalescedPIO,
		CapManualDirtyLogProtect2,
		CapPMUEventFilter,
		CapX86UserSpaceMSR,
		CapX86MSRFilter,
		CapX86BusLockExit,
		CapSREGS2,
		CapBinaryStatsFD,
		CapXSave2,
		CapSysAttributes,
		CapVMTSCControl,
		CapX86TripleFaultEvent,
		CapX86NotifyVMExit,
	}

	ile, err := os.Open(kvmDev)
	if err != nil {
		return err
	}
	defer ile.Close()

	fd := ile.Fd()
	for _, item := range X86Items {
		res, err := CheckExtension(P(fd), item)
		if err != nil {
			return err
		}
		fmt.Printf("%-30s: %t\n", item, (res != 0))
	}
	return nil
}

func ProbeCPUID() error {
	kvmFile, err := os.Open(kvmDev)
	if err != nil {
		return err
	}
	defer kvmFile.Close()

	kvmFd := kvmFile.Fd()

	cpuid := CPUID{
		Nent:    100,
		Entries: make([]CPUIDEntry2, 100),
	}
	if err := GetSupportedCPUID(P(kvmFd), &cpuid); err != nil {
		return err
	}
	for _, e := range cpuid.Entries {
		fmt.Printf("0x%08x 0x%02x: eax=0x%08x ebx=0x%08x ecx=0x%08x edx=0x%08x (flag:%x)\n",
			e.Function, e.Index, e.Eax, e.Ebx, e.Ecx, e.Edx, e.Flags)
	}
	return nil
}

func CheckExtension(kvmFd P, c Cap) (P, error) {
	return Ioctl(kvmFd, IIO(kvmCheckExtension), P(c))
}

const (
	indexMask   = uint8(0x7F)
	indexOffset = uint64(0x70)
	dataOffset  = uint64(0x71)
	dataLen     = uint64(128)
)

type CMOS struct {
	Index uint8
	Data  []uint8
}

func NewCMOS(memBelow4G, memAbove4G uint64) *CMOS {
	cmos := &CMOS{
		Index: 0,
		Data:  make([]uint8, dataLen),
	}

	extMem := uint16(0xBC00)

	cmos.Data[0x34] = uint8(extMem)
	cmos.Data[0x35] = uint8(extMem >> 8)
	cmos.Data[0x5b] = 0
	cmos.Data[0x5c] = 0
	cmos.Data[0x5d] = 0
	return cmos
}

func (c *CMOS) In(base uint64, data []byte) error {
	if len(data) != 1 {
		return ErrDataLenInvalid
	}

	var d uint8

	switch base {
	case indexOffset:
		data[0] = c.Index
	case dataOffset:
		dt := time.Now()
		secs := dt.Second()
		min := dt.Minute()
		hour := dt.Hour()
		weekd := dt.Weekday()
		day := dt.Day()
		month := dt.Month()
		year := dt.Year()

		switch c.Index {
		case 0x00:
			d = toBCD(uint8(secs))
		case 0x02:
			d = toBCD(uint8(min))
		case 0x04:
			d = toBCD(uint8(hour))
		case 0x06:
			d = toBCD(uint8(weekd))
		case 0x07:
			d = toBCD(uint8(day))
		case 0x08:
			d = toBCD(uint8(month))
		case 0x09:
			d = toBCD(uint8(year % 100))
		case 0x0A:
			d = 1<<5 | 0<<7
		case 0x0D:
			d = 1 << 7
		case 0x32:
			d = toBCD((uint8(year+1900) / 100))
		default:
			d = c.Data[c.Index&indexMask]
		}
		data[0] = d
	}
	return nil
}

func (c *CMOS) Out(base uint64, data []byte) error {
	if len(data) != 1 {
		return ErrDataLenInvalid
	}

	switch base {
	case indexOffset:
		c.Index = data[0]
	case dataOffset:
		if c.Index == 0x8F && data[0] == 0 {
		} else {
			c.Data[c.Index&indexMask] = data[0]
		}
	}
	return nil
}

func toBCD(v uint8) uint8 {
	return ((v / 100) << 4) | (v % 10)
}

func (c *CMOS) IOPort() uint64 {
	return 0x70
}

func (c *CMOS) Size() uint64 {
	return 0x2
}

func cpuid_low(arg1, arg2 uint32) (eax, ebx, ecx, edx uint32) // implemented in cpuid.s

func cpuid(leaf uint32) (uint32, uint32, uint32, uint32) {
	return cpuid_low(leaf, 0)
}

type CPUIDPatch struct {
	Function uint32
	Index    uint32
	Flags    uint32
	EAXBit   uint8
	EBXBit   uint8
	ECXBit   uint8
	EDXBit   uint8
}

var errInvalidPatchset = errors.New("invalid patch. Only 1 bit allowed")

func Patch(ids *CPUID, patches []*CPUIDPatch) error {
	for _, id := range ids.Entries {
		for _, patch := range patches {
			if bits.OnesCount8(patch.EAXBit)+
				bits.OnesCount8(patch.EBXBit)+
				bits.OnesCount8(patch.ECXBit)+
				bits.OnesCount8(patch.EDXBit)+
				bits.OnesCount32(patch.Flags) != 1 {
				return errInvalidPatchset
			}

			if id.Function == patch.Function && id.Index == patch.Index {
				id.Flags |= 1 << patch.Flags
				id.Eax |= 1 << patch.EAXBit
				id.Ebx |= 1 << patch.EBXBit
				id.Ecx |= 1 << patch.ECXBit
				id.Edx |= 1 << patch.EDXBit
			}
		}
	}
	return nil
}

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

type DeviceIO interface {
	PortIO
	IOPort() uint64
	Size() uint64
}

const (
	maxVCPUs             = 64
	apicDefaultPhysBase  = 0xfee00000
	apicBaseAddrStep     = 0x00400000
	mpfIntelSignature    = (('_' << 24) | ('P' << 16) | ('M' << 8) | '_')
	mpcTableSignature    = (('P' << 24) | ('M' << 16) | ('C' << 8) | 'P')
	mpEntryTypeProcessor = 0
	cpuFlagEnabled       = 1
	cpuFlagBP            = 2
	cpuStepping          = uint32(0x600)
	cpuFeatureAPIC       = uint32(0x200)
	cpuFeatureFPU        = uint32(0x001)
	mpAPICVersion        = uint8(0x14)
)

type (
	EBDA struct {
		_        [16 * 3]uint8
		mpfIntel mpfIntel
		mpcTable mpcTable
	}

	mpfIntel struct {
		signature     uint32
		physPtr       uint32
		length        uint8
		specification uint8
		checkSum      uint8
		_             uint8 // padding feature1
		_             uint8
		_             uint8
		_             uint8
		_             uint8
	}

	mpcTable struct {
		signature uint32
		length    uint16
		spec      uint8
		checkSum  uint8
		OEMId     [8]uint8
		ProdID    [12]uint8
		_         uint32
		_         uint16
		oemCount  uint16
		lapic     uint32
		_         uint32
		mpcCPU    [maxVCPUs]mpcCPU
	}
)

func (e *EBDA) Bytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	if err := binary.Write(buf, binary.LittleEndian, e); err != nil {
		return []byte{}, err
	}

	return buf.Bytes(), nil
}

func NewEBDA(nCPUs int) (*EBDA, error) {
	e := &EBDA{}

	mpfIntel, err := newMPFIntel()
	if err != nil {
		return e, err
	}
	e.mpfIntel = *mpfIntel
	mpcTable, err := newMPCTable(nCPUs)
	if err != nil {
		return e, err
	}
	e.mpcTable = *mpcTable
	return e, nil
}

func newMPFIntel() (*mpfIntel, error) {
	m := &mpfIntel{}
	m.signature = mpfIntelSignature
	m.length = 1
	m.specification = 4
	m.physPtr = EBDAStarted + 0x40

	var err error

	m.checkSum, err = m.calcCheckSum()
	if err != nil {
		return m, err
	}

	m.checkSum ^= uint8(0xff)
	m.checkSum++
	return m, nil
}

func (m *mpfIntel) calcCheckSum() (uint8, error) {
	bytes, err := m.bytes()
	if err != nil {
		return 0, err
	}

	tmp := uint32(0)
	for _, b := range bytes {
		tmp += uint32(b)
	}
	return uint8(tmp & 0xff), nil
}

func (m *mpfIntel) bytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	if err := binary.Write(buf, binary.LittleEndian, m); err != nil {
		return []byte{}, err
	}
	return buf.Bytes(), nil
}

func apicAddr(apic uint32) uint32 {
	return apicDefaultPhysBase + apic*apicBaseAddrStep
}

func newMPCTable(nCPUs int) (*mpcTable, error) {
	m := &mpcTable{}
	m.signature = mpcTableSignature
	m.length = uint16(unsafe.Sizeof(mpcTable{}))
	m.spec = 4
	m.lapic = apicAddr(0)
	m.OEMId = [8]byte{0x42, 0x4F, 0x4F, 0x54, 0x53, 0x00, 0x00, 0x00} // "BOOTS   "
	m.oemCount = maxVCPUs

	if nCPUs > maxVCPUs {
		return nil, fmt.Errorf("the number of vCPUs must be less than or equal to %d", maxVCPUs)
	}

	var err error

	for i := 0; i < nCPUs; i++ {
		m.mpcCPU[i] = *newMPCCpu(i)
	}

	m.checkSum, err = m.calcCheckSum()
	if err != nil {
		return m, err
	}

	m.checkSum ^= uint8(0xff)
	m.checkSum++
	return m, nil
}

func (m *mpcTable) calcCheckSum() (uint8, error) {
	bytes, err := m.bytes()
	if err != nil {
		return 0, err
	}

	tmp := uint32(0)
	for _, b := range bytes {
		tmp += uint32(b)
	}
	return uint8(tmp & 0xff), nil
}

func (m *mpcTable) bytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	if err := binary.Write(buf, binary.LittleEndian, m); err != nil {
		return []byte{}, err
	}
	return buf.Bytes(), nil
}

type mpcCPU struct {
	typ         uint8
	apicID      uint8
	apicVer     uint8
	cpuFlag     uint8
	sig         uint32
	featureFlag uint32
	_           [2]uint32
}

func newMPCCpu(i int) *mpcCPU {
	m := &mpcCPU{}

	f := uint8(cpuFlagEnabled)

	if i == 0 {
		f |= cpuFlagBP
	}

	m.typ = mpEntryTypeProcessor
	m.apicID = uint8(i)
	m.apicVer = mpAPICVersion
	m.cpuFlag = f
	m.sig = (cpuStepping << 16)
	m.featureFlag = cpuFeatureAPIC | cpuFeatureFPU
	return m
}

var (
	ErrInvalidSel           = errors.New("queue sel is invalid")
	ErrIONotPermit          = errors.New("IO is not permitted for virtio device")
	ErrNoTxPacket           = errors.New("no packet for tx")
	ErrNoRxPacket           = errors.New("no packet for rx")
	ErrVQNotInit            = errors.New("vq not initialized")
	ErrNoRxBuf              = errors.New("no buffer found for rx")
	ErrZeroSizeKernel       = errors.New("kernel is 0 bytes")
	ErrBadVA                = errors.New("bad virtual address")
	ErrBadCPU               = errors.New("bad cpu number")
	ErrUnsupported          = errors.New("unsupported")
	ErrMemTooSmall          = errors.New("mem request must be at least 1<<20")
	ErrNotELF64File         = errors.New("file is not ELF64")
	ErrPTNoteHasNoFSize     = errors.New("elf program PT_NOTE has file size equal zero")
	ErrBridgeNotPermit      = errors.New("IO is not permitted for PCI bridge")
	ErrSignatureNotMatch    = errors.New("signature not match in bzImage")
	ErrOldProtocolVersion   = errors.New("old protocol version")
	ErrAlign                = errors.New("alignment is not a power of 2")
	ErrPVHEntryNotFound     = errors.New("no pvh entry found")
	ErrDataLenInvalid       = errors.New("invalid data size on port")
	ErrWriteToCF9           = errors.New("power cycle via 0xcf9")
	ErrUnexpectedExitReason = errors.New("unexpected kvm exit reason")
	ErrDebug                = errors.New("debug exit")
	ErrBadRegister          = errors.New("bad register")
	ErrBadArg               = errors.New("arg count must be in range 1..6")
	ErrBadArgType           = errors.New("bad arg type")
)

type FWDebug struct{}

func (f *FWDebug) In(port uint64, data []byte) error {
	if len(data) == 1 {
		data[0] = 0xE9
	} else {
		return ErrDataLenInvalid
	}
	return nil
}

func (f *FWDebug) Out(port uint64, data []byte) error {
	if len(data) == 1 {
		if data[0] == '\000' {
			fmt.Printf("\r\n")
		} else {
			fmt.Printf("%c", data[0])
		}
	} else {
		return ErrDataLenInvalid
	}
	return nil
}

func (f *FWDebug) IOPort() uint64 {
	return 0x402
}

func (f *FWDebug) Size() uint64 {
	return 0x1
}

type X86MCE struct {
	Status    uint64
	Addr      uint64
	Misc      uint64
	MCGStatus uint64
	Bank      uint8
	_         [7]uint8
	_         [3]uint64
}

func X86SetupMCE(vCpuFd P, mceCap *uint64) error {
	_, err := Ioctl(vCpuFd,
		IIOW(kvmX86SetupMCE, P(unsafe.Sizeof(mceCap))),
		P(Ptr(mceCap)))
	return err
}

func X86GetMCECapSupported(kvmFd P, mceCap *uint64) error {
	_, err := Ioctl(kvmFd,
		IIOR(kvmX86GetMCECapSupported, P(unsafe.Sizeof(mceCap))),
		P(Ptr(mceCap)))
	return err
}

func GdtEntry(flags uint16, base uint32, limit uint32) uint64 {
	return (uint64(base)&0xFF000000)<<(56-24) |
		(uint64(flags)&0x0000F0FF)<<40 |
		(uint64(limit)&0x000F0000)<<(48-16) |
		(uint64(base)&0x00FFFFFF)<<16 |
		(uint64(limit) & 0x0000FFFF)
}

func getBase(entry uint64) uint64 {
	return ((entry & 0xFF00000000000000) >> 32) | ((entry & 0x000000FF00000000) >> 16) | (entry&0x00000000FFFF0000)>>16
}

func getG(entry uint64) uint8 {
	return uint8((entry & 0x0080000000000000) >> 55)
}

func getDB(entry uint64) uint8 {
	return uint8((entry & 0x0040000000000000) >> 54)
}

func getL(entry uint64) uint8 {
	return uint8((entry & 0x0020000000000000) >> 53)
}

func getAVL(entry uint64) uint8 {
	return uint8((entry & 0x0010000000000000) >> 52)
}

func getP(entry uint64) uint8 {
	return uint8((entry & 0x0000800000000000) >> 47)
}

func getDPL(entry uint64) uint8 {
	return uint8((entry & 0x0000600000000000) >> 45)
}

func getS(entry uint64) uint8 {
	return uint8((entry & 0x0000100000000000) >> 44)
}

func getType(entry uint64) uint8 {
	return uint8((entry & 0x00000F0000000000) >> 40)
}

func getLimit(entry uint64) uint32 {
	l := uint32(((((entry) & 0x000F000000000000) >> 32) | ((entry) & 0x000000000000FFFF)))
	g := getG(entry)

	switch g {
	case 0:
		return l
	default:
		return (l << 12) | 0xFFFF
	}
}

func SegmentFromGDT(entry uint64, tableIndex uint8) Segment {
	var unused uint8

	u := getP(entry)

	switch u {
	case 0:
		unused = 1
	default:
		unused = 0
	}

	return Segment{
		Base:     getBase(entry),
		Limit:    getLimit(entry),
		Selector: uint16(tableIndex) * 8,
		Typ:      getType(entry),
		Present:  getP(entry),
		DPL:      getDPL(entry),
		DB:       getDB(entry),
		S:        getS(entry),
		L:        getL(entry),
		G:        getG(entry),
		AVL:      getAVL(entry),
		Unusable: unused,
	}
}

const (
	ifNameSize = 0x10
)

type If struct {
	fd int
}

type ifReq struct {
	Name  [ifNameSize]byte
	Flags uint16
	_     [0x28 - ifNameSize - 2]byte
}

func NewIf(name string, flag uint16) (*If, error) {
	var err error
	const netDev = "/dev/net/tun"

	t := &If{-1}

	if t.fd, err = syscall.Open(netDev, syscall.O_RDWR, 0); err != nil {
		return t, fmt.Errorf("%s: %w", netDev, err)
	}
	ifr := ifReq{
		Name:  [ifNameSize]byte{},
		Flags: flag | syscall.IFF_NO_PI,
	}
	copy(ifr.Name[:ifNameSize-1], name)

	ifrPtr := P(Ptr(&ifr))
	if _, err = Ioctl(P(t.fd), syscall.TUNSETIFF, ifrPtr); err != nil {
		return t, fmt.Errorf("TUN TUNSETIFF: %w", err)
	}
	if _, err = fcntl(P(t.fd), syscall.F_SETSIG, 0); err != nil {
		return t, fmt.Errorf("tun SETSIG: %w", err)
	}

	var flags P

	if flags, err = fcntl(P(t.fd), syscall.F_GETFL, 0); err != nil {
		return t, fmt.Errorf("TUN GETFL: %w", err)
	}
	flags |= syscall.O_NONBLOCK | syscall.O_ASYNC
	if _, err = fcntl(P(t.fd), syscall.F_SETFL, flags); err != nil {
		return t, fmt.Errorf("TUN SETFL NONBLOCK|ASYNC: %w", err)
	}
	return t, nil
}

func (t *If) Close() error {
	return syscall.Close(t.fd)
}

func (t *If) Write(buf []byte) (n int, err error) {
	return syscall.Write(t.fd, buf)
}

func (t *If) Read(buf []byte) (n int, err error) {
	return syscall.Read(t.fd, buf)
}

const (
	LowRAMStart                 = 0x0
	EBDAPointer                 = 0x40e
	BootGDTStart                = 0x500
	BootIDTStart                = 0x520
	PVHInfoStart                = 0x6000
	PVHModListStart             = 0x6040
	PVHMemMapStart              = 0x7000
	KernelCmdLine               = 0x2_0000
	KernelCmdLineSizeMax        = 0x1_0000
	MPTableStart                = 0x9_FC00
	EBDAStart                   = 0xA_0000
	RSDPPointer                 = EBDAStart
	SMBIOSStart                 = 0xF_0000
	HighRAMStart                = 0x10_0000
	Mem32BitReservedStart       = 0xC000_0000
	Mem32BitReservedSize        = PCIMMConfigSize + Mem32BitDeviceSize
	Mem32BitDeviceStart         = Mem32BitReservedStart
	Mem32BitDeviceSize          = 640 << 20
	PCIMMConfigStart            = Mem32BitDeviceStart + Mem32BitDeviceSize
	PCIMMConfigSize             = 256 << 20
	PCIMMIOConfigSizePerSegment = 4096 * 256
	KVMTSSStart                 = PCIMMConfigStart + PCIMMConfigSize
	KVMTSSSize                  = (3 * 4) << 10
	KVMIdentityMapStart         = KVMTSSStart + KVMTSSSize
	KVMIdentityMapSize          = 4 << 10
	IOAPICStart                 = 0xFEC0_0000
	IOAPICSize                  = 0x20
	APICStart                   = 0xFEE0_0000
	RAM64BitStart               = 0x1_0000_0000
)

const (
	PlatformDeviceAreaSize = 1 << 20
)

type Ptr unsafe.Pointer
type P uintptr

type PhysMemory struct {
	mem  []byte
	size int
}

func NewPhysMemory(size int) *PhysMemory {
	mem, err := syscall.Mmap(-1, 0, size,
		syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS|syscall.MAP_NORESERVE)
	if err != nil {
		panic(fmt.Errorf("%v", err))
	}
	if debug {
		log.Printf("Physical memory: %d bytes\n", size)
	}
	return &PhysMemory{mem: mem, size: size}
}

func (p *PhysMemory) Len() uint64 {
	return uint64(len(p.mem))
}

func (p *PhysMemory) GetRamPtr(addr uint64) Ptr {
	return Ptr(&p.mem[addr])
}

func (p *PhysMemory) Get(start, end uint64) []byte {
	return p.mem[start:end]
}

func (p *PhysMemory) GetFromStart(pos uint64) []byte {
	return p.mem[pos:]
}

func (p *PhysMemory) CopyStart(start uint64, data []byte) {
	copy(p.mem[start:], data)
}

func (p *PhysMemory) SetZero(pos int) {
	p.mem[pos] = 0
}

func (p *PhysMemory) ReadAt(b []byte, off int64) (int, error) {
	mem := bytes.NewReader(p.mem)
	return mem.ReadAt(b, off)
}

func (p *PhysMemory) WriteAt(b []byte, off int64) (int, error) {
	if off > int64(len(p.mem)) {
		return 0, syscall.EFBIG
	}
	n := copy(p.mem[off:], b)
	return n, nil
}

func (p *PhysMemory) Free() {
	if p.mem != nil && p.size > 0 {
		syscall.Munmap(p.mem)
	}
}

type UserspaceMemoryRegion struct {
	Slot          uint32
	Flags         uint32
	GuestPhysAddr uint64
	MemorySize    uint64
	UserspaceAddr uint64
}

func (r *UserspaceMemoryRegion) SetMemLogDirtyPages() {
	r.Flags |= 1 << 0
}

func (r *UserspaceMemoryRegion) SetMemReadonly() {
	r.Flags |= 1 << 1
}

func SetUserMemoryRegion(vmFd P, region *UserspaceMemoryRegion) error {
	if debug {
		log.Printf("Memory Region Details:\n")
		log.Printf("  Slot: %d\n", region.Slot)
		log.Printf("  Flags: 0x%x\n", region.Flags)
		log.Printf("  Guest Physical Addr: 0x%x\n", region.GuestPhysAddr)
		log.Printf("  Memory Size: 0x%x (%d bytes)\n", region.MemorySize, region.MemorySize)
		log.Printf("  Userspace Addr: 0x%x\n", region.UserspaceAddr)

		log.Printf("Ioctl Details:\n")
		log.Printf("  VM FD: %d\n", vmFd)
		log.Printf("  Command: 0x%x\n", IIOW(kvmSetUserMemoryRegion, P(unsafe.Sizeof(UserspaceMemoryRegion{}))))

		log.Printf("Memory Alignment:\n")
		log.Printf("  Guest Physical Addr alignment: 0x%x\n", region.GuestPhysAddr&0xFFF)
		log.Printf("  Userspace Addr alignment: 0x%x\n", region.UserspaceAddr&0xFFF)

		cmd := exec.Command("dmesg", "|", "tail", "-n", "20")
		output, _ := cmd.CombinedOutput()
		log.Printf("Recent kernel messages:\n%s\n", string(output))

		log.Printf("Current memory mappings:\n")
		maps, err := ioutil.ReadFile("/proc/self/maps")
		if err == nil {
			log.Println(string(maps))
		}
	}
	_, err := Ioctl(vmFd, IIOW(kvmSetUserMemoryRegion, P(unsafe.Sizeof(UserspaceMemoryRegion{}))),
		P(Ptr(region)))
	return err
}

func ClearUserMemoryRegion(vmFd P, i uint32) error {
	return SetUserMemoryRegion(vmFd,
		&UserspaceMemoryRegion{Slot: i, Flags: 0, GuestPhysAddr: 0, MemorySize: 0, UserspaceAddr: uint64(0)})
}

func SetTSSAddr(vmFd P, addr uint32) error {
	_, err := Ioctl(vmFd, IIO(kvmSetTSSAddr), P(addr))
	return err
}

func SetIdentityMapAddr(vmFd P, addr uint32) error {
	_, err := Ioctl(vmFd, IIOW(kvmSetIdentityMapAddr, 8), P(Ptr(&addr)))
	return err
}

type DirtyLog struct {
	Slot   uint32
	_      uint32
	BitMap uint64
}

func GetDirtyLog(vmFd P, dirtlog *DirtyLog) error {
	_, err := Ioctl(vmFd,
		IIOW(kvmGetDirtyLog, P(unsafe.Sizeof(DirtyLog{}))), P(Ptr(dirtlog)))
	if errors.Is(err, syscall.ENOENT) {
		return nil
	}
	return err
}

func SetNrMMUPages(vmFd P, shadowMem uint64) error {
	_, err := Ioctl(vmFd,
		IIO(kvmSetNrMMUPages),
		P(shadowMem))
	return err
}

func GetNrMMUPages(vmFd P, shadowMem *uint64) error {
	_, err := Ioctl(vmFd,
		IIO(kvmGetNrMMUPages),
		P(Ptr(shadowMem)))
	return err
}

type coalescedMMIOZone struct {
	Addr   uint64
	Size   uint32
	PadPio uint32
}

func RegisterCoalescedMMIO(vmFd P, addr uint64, size uint32) error {
	zone := &coalescedMMIOZone{
		Addr:   addr,
		Size:   size,
		PadPio: 0,
	}
	_, err := Ioctl(vmFd,
		IIOW(kvmResgisterCoalescedMMIO, P(unsafe.Sizeof(coalescedMMIOZone{}))),
		P(Ptr(zone)))
	return err
}

func UnregisterCoalescedMMIO(vmFd P, addr uint64, size uint32) error {
	zone := &coalescedMMIOZone{
		Addr:   addr,
		Size:   size,
		PadPio: 0,
	}
	_, err := Ioctl(vmFd,
		IIOW(kvmUnResgisterCoalescedMMIO, P(unsafe.Sizeof(coalescedMMIOZone{}))),
		P(Ptr(zone)))
	return err
}

const (
	QueueSize = 32
)

type IRQInjector interface {
	VirtualIONetIRQ() error
	VirtualIOBlkIRQ() error
}

type commonHeader struct {
	_        uint32
	_        uint32
	_        uint32
	queueNUM uint16
	queueSEL uint16
	_        uint16
	_        uint8
	isr      uint8
}

type VirtualQueue struct {
	DescTable [QueueSize]struct {
		Addr  uint64
		Len   uint32
		Flags uint16
		Next  uint16
	}

	AvailRing struct {
		Flags     uint16
		Idx       uint16
		Ring      [QueueSize]uint16
		UsedEvent uint16
	}

	_        [4096 - ((16*QueueSize + 6 + 2*QueueSize) % 4096)]uint8
	UsedRing struct {
		Flags uint16
		Idx   uint16
		Ring  [QueueSize]struct {
			Idx uint32
			Len uint32
		}
		availEvent uint16
	}
}

//nolint:dupl
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

//nolint:dupl
type CPUID struct {
	Nent    uint32
	Padding uint32
	Entries []CPUIDEntry2
}

func (c *CPUID) Bytes() ([]byte, error) {
	var buf bytes.Buffer

	if err := binary.Write(&buf, binary.LittleEndian, c.Nent); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.LittleEndian, c.Padding); err != nil {
		return nil, err
	}
	for _, entry := range c.Entries {
		if err := binary.Write(&buf, binary.LittleEndian, entry); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

func NewCPUID(data []byte) (*CPUID, error) {
	c := CPUID{}

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, data); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if err := binary.Read(&buf, binary.LittleEndian, &c.Nent); err != nil {
		return nil, err
	}
	if err := binary.Read(&buf, binary.LittleEndian, &c.Padding); err != nil {
		return nil, err
	}
	c.Entries = make([]CPUIDEntry2, c.Nent)
	if err := binary.Read(&buf, binary.LittleEndian, &c.Entries); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return &c, nil
}

type CPUIDEntry2 struct {
	Function uint32
	Index    uint32
	Flags    uint32
	Eax      uint32
	Ebx      uint32
	Ecx      uint32
	Edx      uint32
	Padding  [3]uint32
}

func GetSupportedCPUID(kvmFd P, kvmCPUID *CPUID) error {
	var c *CPUID

	data, err := kvmCPUID.Bytes()
	if err != nil {
		return err
	}

	if _, err = Ioctl(kvmFd,
		IIOWR(kvmGetSupportedCPUID, P(unsafe.Sizeof(kvmCPUID))),
		P(Ptr(&data[0]))); err != nil {
		return err
	}

	if c, err = NewCPUID(data); err != nil {
		return err
	}

	*kvmCPUID = *c
	return err
}

func SetCPUID2(vCpuFd P, kvmCPUID *CPUID) error {
	data, err := kvmCPUID.Bytes()
	if err != nil {
		return err
	}

	if _, err := Ioctl(vCpuFd,
		IIOW(kvmSetCPUID2, P(unsafe.Sizeof(kvmCPUID))),
		P(Ptr(&data[0]))); err != nil {
		return err
	}
	return err
}

func GetCPUID2(vCpuFd P, kvmCPUID *CPUID) error {
	var c *CPUID

	data, err := kvmCPUID.Bytes()
	if err != nil {
		return err
	}

	if _, err = Ioctl(vCpuFd,
		IIOWR(kvmGetCPUID2, 8),
		P(Ptr(&data[0]))); err != nil {
		return err
	}
	if c, err = NewCPUID(data); err != nil {
		return err
	}

	*kvmCPUID = *c
	return err
}

func GetEmulatedCPUID(kvmFd P, kvmCPUID *CPUID) error {
	var c *CPUID

	data, err := kvmCPUID.Bytes()
	if err != nil {
		return err
	}

	if _, err = Ioctl(kvmFd,
		IIOWR(kvmGetEmulatedCPUID, P(unsafe.Sizeof(kvmCPUID))),
		P(Ptr(&data[0]))); err != nil {
		return err
	}
	if c, err = NewCPUID(data); err != nil {
		return err
	}

	*kvmCPUID = *c
	return nil
}

const (
	kvmGetAPIVersion     = 0x00
	kvmCreateVM          = 0x1
	kvmGetMSRIndexList   = 0x02
	kvmCheckExtension    = 0x03
	kvmGetVCPUMMapSize   = 0x04
	kvmGetSupportedCPUID = 0x05

	kvmGetEmulatedCPUID       = 0x09
	kvmGetMSRFeatureIndexList = 0x0A

	kvmCreateVCPU          = 0x41
	kvmGetDirtyLog         = 0x42
	kvmSetNrMMUPages       = 0x44
	kvmGetNrMMUPages       = 0x45
	kvmSetUserMemoryRegion = 0x46
	kvmSetTSSAddr          = 0x47
	kvmSetIdentityMapAddr  = 0x48

	kvmCreateIRQChip = 0x60
	kvmGetIRQChip    = 0x62
	kvmSetIRQChip    = 0x63
	kvmIRQLineStatus = 0x67

	kvmResgisterCoalescedMMIO   = 0x67
	kvmUnResgisterCoalescedMMIO = 0x68

	kvmSetGSIRouting = 0x6A

	kvmReinjectControl = 0x71
	kvmCreatePIT2      = 0x77
	kvmSetClock        = 0x7B
	kvmGetClock        = 0x7C

	kvmRun       = 0x80
	kvmGetRegs   = 0x81
	kvmSetRegs   = 0x82
	kvmGetSregs  = 0x83
	kvmSetSregs  = 0x84
	kvmTranslate = 0x85
	kvmInterrupt = 0x86

	kvmGetMSRS = 0x88
	kvmSetMSRS = 0x89

	kvmGetLAPIC = 0x8e
	kvmSetLAPIC = 0x8f

	kvmSetCPUID2          = 0x90
	kvmGetCPUID2          = 0x91
	kvmTRPAccessReporting = 0x92

	kvmGetMPState = 0x98
	kvmSetMPState = 0x99

	kvmX86SetupMCE           = 0x9C
	kvmX86GetMCECapSupported = 0x9D

	kvmGetPIT2 = 0x9F
	kvmSetPIT2 = 0xA0

	kvmGetVCPUEvents = 0x9F
	kvmSetVCPUEvents = 0xA0

	kvmGetDebugRegs = 0xA1
	kvmSetDebugRegs = 0xA2

	kvmSetTSCKHz = 0xA2
	kvmGetTSCKHz = 0xA3

	kvmGetXCRS = 0xA6
	kvmSetXCRS = 0xA7

	kvmSMI = 0xB7

	kvmGetSRegs2 = 0xCC
	kvmSetSRegs2 = 0xCD

	kvmCreateDev = 0xE0
)

const (
	numInterrupts   = 0x100
	CPUIDFeatures   = 0x40000001
	CPUIDSignature  = 0x40000000
	CPUIDFuncPerMon = 0x0A
)

const kvmDev = "/dev/kvm"

type KVM struct {
	fd      P
	vmFd    P
	vCpuFds []P
	runs    []*RunData
}

func NewKVM(cpus int) (*KVM, error) {
	var err error

	devKVM, err := os.OpenFile(kvmDev, os.O_RDWR, 0o644)
	if err != nil {
		return nil, fmt.Errorf("kvm dev: %w", err)
	}

	fd := devKVM.Fd()
	vmFd := P(0)
	vCpuFds := make([]P, cpus)
	runs := make([]*RunData, cpus)

	if vmFd, err = CreateVM(P(fd)); err != nil {
		return nil, fmt.Errorf("CreateVM: %w", err)
	}
	if err := SetTSSAddr(vmFd, KVMTSSStart); err != nil {
		return nil, fmt.Errorf("SetTSSAddr: %w", err)
	}
	if err := SetIdentityMapAddr(vmFd, KVMIdentityMapStart); err != nil {
		return nil, fmt.Errorf("SetIdentityMapAddr: %w", err)
	}
	if err := CreateIRQChip(vmFd); err != nil {
		return nil, fmt.Errorf("CreateIRQChip: %w", err)
	}
	if err := CreatePIT2(vmFd); err != nil {
		return nil, fmt.Errorf("CreatePIT2: %w", err)
	}

	mMapSize, err := GetVCPUMMmapSize(P(fd))
	if err != nil {
		return nil, err
	}

	if debug {
		log.Printf("VCPU memory size: %d", mMapSize)
	}

	for cpu := 0; cpu < cpus; cpu++ {
		vCpuFds[cpu], err = CreateVCPU(vmFd, cpu)
		if err != nil {
			return nil, err
		}
		r, err := syscall.Mmap(int(vCpuFds[cpu]), 0, int(mMapSize),
			syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
		if err != nil {
			return nil, err
		}
		runs[cpu] = (*RunData)(Ptr(&r[0]))
	}

	return &KVM{
		fd:      P(fd),
		vmFd:    vmFd,
		vCpuFds: vCpuFds,
		runs:    runs,
	}, nil
}

func (k *KVM) Init(m *PhysMemory) error {
	for cpuNr := range k.runs {
		if err := k.initCPUid(cpuNr); err != nil {
			return fmt.Errorf("initCPUid: %w", err)
		}
	}
	if debug {
		log.Printf("memory size: %d", m.size)
	}
	gpa := m.size
	if gpa <= (2 << 30) {
		gpa = 0
	}
	err := SetUserMemoryRegion(k.vmFd, &UserspaceMemoryRegion{
		Slot: 0, Flags: 0, GuestPhysAddr: uint64(gpa), MemorySize: uint64(m.size),
		UserspaceAddr: uint64(P(m.GetRamPtr(0))),
	})
	if err != nil {
		log.Printf("KVM_SET_USER_MEMORY_REGION failed: %+v\n", err)
		if sysErr, ok := err.(syscall.Errno); ok {
			return fmt.Errorf("System error number: %d\n", sysErr)
		} else {
			return err
		}
	}
	return nil
}

func (k *KVM) initCPUid(cpu int) error {
	cpuid := CPUID{
		Nent:    100,
		Entries: make([]CPUIDEntry2, 100),
	}

	if err := GetSupportedCPUID(k.fd, &cpuid); err != nil {
		return err
	}

	for i := 0; i < int(cpuid.Nent); i++ {
		switch cpuid.Entries[i].Function {
		case CPUIDFuncPerMon:
			cpuid.Entries[i].Eax = 0
		case CPUIDSignature:
			cpuid.Entries[i].Eax = CPUIDFeatures
			cpuid.Entries[i].Ebx = 0x4b4d564b
			cpuid.Entries[i].Ecx = 0x564b4d56
			cpuid.Entries[i].Edx = 0x4d
		case 7:
			cpuid.Entries[i].Edx &= ^(uint32(1) << 4)
		default:
			continue
		}
	}
	if err := SetCPUID2(k.vCpuFds[cpu], &cpuid); err != nil {
		return err
	}
	return nil
}

func (k *KVM) Translate(vaddr uint64) ([]*Translation, error) {
	t := make([]*Translation, 0, len(k.vCpuFds))

	for cpu := range k.vCpuFds {
		tr := &Translation{
			LinearAddress: vaddr,
		}
		if err := Translate(k.vCpuFds[cpu], tr); err != nil {
			return t, err
		}
		t = append(t, tr)
	}
	return t, nil
}

func (k *KVM) CPUToFD(cpu int) (P, error) {
	if cpu > len(k.vCpuFds) {
		return 0, fmt.Errorf("cpu %d out of range 0-%d:%w", cpu, len(k.vCpuFds), ErrBadCPU)
	}
	return k.vCpuFds[cpu], nil
}

func (k *KVM) RunData() []*RunData {
	return k.runs
}

func (k *KVM) RunDataByCpu(cpu int) *RunData {
	return k.runs[cpu]
}

func (k *KVM) vCpuFdList() []P {
	return k.vCpuFds
}

func (k *KVM) vCpuLen() int {
	return len(k.vCpuFds)
}

func (k *KVM) GetExitReasonByCpu(cpu int) Exit {
	return Exit(k.runs[cpu].ExitReason)
}

func (k *KVM) GetIOByCpu(cpu int) (uint64, uint64, uint64, uint64, uint64) {
	return k.runs[cpu].IO()
}

func (k *KVM) GetVmFd() P {
	return k.vmFd
}

type debugControl struct { // nolint:unused
	Control  uint32
	_        uint32
	DebugReg [8]uint64
}

func (k *KVM) SingleStep(cpu int, onOff bool) error {
	const (
		Enable     = 1
		SingleStep = 2
	)

	var (
		debug         [unsafe.Sizeof(debugControl{})]byte
		setGuestDebug = IIOW(0x9b, P(unsafe.Sizeof(debugControl{})))
	)

	if onOff {
		debug[2] = 0x0002
		debug[0] = Enable | SingleStep
	}
	_, err := Ioctl(k.vCpuFds[cpu], setGuestDebug, P(Ptr(&debug[0])))
	return err
}

type RunData struct {
	RequestInterruptWindow     uint8
	ImmediateExit              uint8
	_                          [6]uint8
	ExitReason                 uint32
	ReadyForInterruptInjection uint8
	IfFlag                     uint8
	_                          [2]uint8
	CR8                        uint64
	ApicBase                   uint64
	Data                       [32]uint64
}

func (r *RunData) IO() (uint64, uint64, uint64, uint64, uint64) {
	direction := r.Data[0] & 0xFF
	size := (r.Data[0] >> 8) & 0xFF
	port := (r.Data[0] >> 16) & 0xFFFF
	count := (r.Data[0] >> 32) & 0xFFFFFFFF
	offset := r.Data[1]
	return direction, size, port, count, offset
}

func GetAPIVersion(kvmFd P) (P, error) {
	return Ioctl(kvmFd, IIO(kvmGetAPIVersion), P(0))
}

func CreateVM(kvmFd P) (P, error) {
	return Ioctl(kvmFd, IIO(kvmCreateVM), P(0))
}

func CreateVCPU(vmFd P, vCpuID int) (P, error) {
	return Ioctl(vmFd, IIO(kvmCreateVCPU), P(vCpuID))
}

func Run(vCpuFd P) error {
	_, err := Ioctl(vCpuFd, IIO(kvmRun), P(0))
	if err != nil {
		if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EINTR) {
			return nil
		}
	}
	return err
}

func GetVCPUMMmapSize(kvmFd P) (P, error) {
	return Ioctl(kvmFd, IIO(kvmGetVCPUMMapSize), P(0))
}

func SetTSCKHz(vCpuFd P, freq uint64) error {
	_, err := Ioctl(vCpuFd,
		IIO(kvmSetTSCKHz), P(freq))
	return err
}

func GetTSCKHz(vCpuFd P) (uint64, error) {
	ret, err := Ioctl(vCpuFd,
		IIO(kvmGetTSCKHz), 0)
	if err != nil {
		return 0, err
	}
	return uint64(ret), nil
}

type ClockFlag uint32

const (
	TSCStable ClockFlag = 2
	Realtime  ClockFlag = (1 << 2)
	HostTSC   ClockFlag = (1 << 3)
)

type ClockData struct {
	Clock    uint64
	Flags    uint32
	_        uint32
	Realtime uint64
	HostTSC  uint64
	_        [4]uint32
}

func SetClock(vmFd P, cd *ClockData) error {
	_, err := Ioctl(vmFd,
		IIOW(kvmSetClock, P(unsafe.Sizeof(ClockData{}))),
		P(Ptr(cd)))
	return err
}

func GetClock(vmFd P, cd *ClockData) error {
	_, err := Ioctl(vmFd,
		IIOR(kvmGetClock, P(unsafe.Sizeof(ClockData{}))),
		P(Ptr(cd)))
	return err
}

type DevType uint32

const (
	DevFSLMPIC20 DevType = 1 + iota
	DevFSLMPIC42
	DevXICS
	DevVFIO
	_
	DevFLIC
	_
	_
	DevXIVE
	_
	DevMAX
)

type Dev struct {
	Type  uint32
	Fd    uint32
	Flags uint32
}

func CreateDev(vmFd P, dev *Dev) error {
	_, err := Ioctl(vmFd,
		IIOWR(kvmCreateDev, P(unsafe.Sizeof(Dev{}))), P(Ptr(dev)))
	return err
}

type Translation struct {
	LinearAddress   uint64
	PhysicalAddress uint64
	Valid           uint8
	Writeable       uint8
	Usermode        uint8
	_               [5]uint8
}

func Translate(vCpuFd P, t *Translation) error {
	_, err := Ioctl(vCpuFd,
		IIOWR(kvmTranslate, P(unsafe.Sizeof(Translation{}))), P(Ptr(t)))
	return err
}

type MPState struct {
	State uint32
}

const (
	MPStateRunnable uint32 = 0 + iota
	MPStateUninitialized
	MPStateInitReceived
	MPStateHalted
	MPStateSipiReceived
	MPStateStopped
	MPStateCheckStop
	MPStateOperating
	MPStateLoad
	MPStateApResetHold
	MPStateSuspended
)

func GetMPState(vCpuFd P, mps *MPState) error {
	_, err := Ioctl(vCpuFd,
		IIOR(kvmGetMPState, P(unsafe.Sizeof(MPState{}))), P(Ptr(mps)))
	return err
}

// SetMPState sets the vcpu’s current multiprocessing state.
func SetMPState(vCpuFd P, mps *MPState) error {
	_, err := Ioctl(vCpuFd,
		IIOW(kvmSetMPState, P(unsafe.Sizeof(MPState{}))), P(Ptr(mps)))
	return err
}

type Exception struct {
	Inject       uint8
	Nr           uint8
	HadErrorCode uint8
	Pending      uint8
	ErrorCode    uint32
}

type Interrupt struct {
	Inject uint8
	Nr     uint8
	Soft   uint8
	Shadow uint8
}

type NMI struct {
	Inject  uint8
	Pending uint8
	Masked  uint8
	_       uint8
}

type SMI struct {
	SMM          uint8
	Pening       uint8
	SMMInsideNMI uint8
	LatchedInit  uint8
}

type VCPUEvents struct {
	E                   Exception
	I                   Interrupt
	N                   NMI
	SipiVector          uint32
	Flags               uint32
	S                   SMI
	TripleFault         uint8
	_                   [26]uint8
	ExceptionHasPayload uint8
	ExceptionPayload    uint64
}

func GetVCPUEvents(vCpuFd P, event *VCPUEvents) error {
	_, err := Ioctl(vCpuFd,
		IIOR(kvmGetVCPUEvents, P(unsafe.Sizeof(VCPUEvents{}))), P(Ptr(event)))
	return err
}

func SetVCPUEvents(vCpuFd P, event *VCPUEvents) error {
	_, err := Ioctl(vCpuFd,
		IIOW(kvmSetVCPUEvents, P(unsafe.Sizeof(VCPUEvents{}))), P(Ptr(event)))
	return err
}

func PutSMI(vCpuFd P) error {
	_, err := Ioctl(vCpuFd, IIO(kvmSMI), 0)
	return err
}

type MSR uint32

const (
	MSRIA32TSC            MSR = 0x10
	MSRIA32APICBASE       MSR = 0x1b
	MSRIA32FEATURECONTROL MSR = 0x0000003a
	MSRTSCADJUST          MSR = 0x0000003b
	MSRIA32SPECCTRL       MSR = 0x48
	MSRVIRTSSBD           MSR = 0xc001011f
	MSRIA32PREDCMD        MSR = 0x49
	MSRIA32UCODEREV       MSR = 0x8b
	MSRIA32CORECAPABILITY MSR = 0xcf

	MSRIA32ARCHCAPABILITIES MSR = 0x10a
	MSRIA32PERFCAPABILITIES MSR = 0x345
	MSRIA32TSXCTRL          MSR = 0x122
	MSRIA32TSCDEADLINE      MSR = 0x6e0
	MSRIA32PKRS             MSR = 0x6e1
	MSRARCHLBRCTL           MSR = 0x000014ce
	MSRARCHLBRDEPTH         MSR = 0x000014cf
	MSRARCHLBRFROM0         MSR = 0x00001500
	MSRARCHLBRTO0           MSR = 0x00001600
	MSRARCHLBRINFO0         MSR = 0x00001200
	MSRIA32SGXLEPUBKEYHASH0 MSR = 0x8c
	MSRIA32SGXLEPUBKEYHASH1 MSR = 0x8d
	MSRIA32SGXLEPUBKEYHASH2 MSR = 0x8e
	MSRIA32SGXLEPUBKEYHASH3 MSR = 0x8f

	MSRP6PERFCTR0 MSR = 0xc1

	MSRIA32SMBASE      MSR = 0x9e
	MSRSMICOUNT        MSR = 0x34
	MSRCORETHREADCOUNT MSR = 0x35
	MSRMTRRcap         MSR = 0xfe
	MSRIA32SYSENTERCS  MSR = 0x174
	MSRIA32SYSENTERESP MSR = 0x175
	MSRIA32SYSENTEREIP MSR = 0x176

	MSRMCGCAP    MSR = 0x179
	MSRMCGSTATUS MSR = 0x17a
	MSRMCGCTL    MSR = 0x17b
	MSRMCGEXTCTL MSR = 0x4d0

	MSRP6EVNTSEL0 MSR = 0x186

	MSRIA32PERFSTATUS MSR = 0x198

	MSRIA32MISCENABLE  MSR = 0x1a0
	MSRMTRRfix64K00000 MSR = 0x250
	MSRMTRRfix16K80000 MSR = 0x258
	MSRMTRRfix16KA0000 MSR = 0x259
	MSRMTRRfix4KC0000  MSR = 0x268
	MSRMTRRfix4KC8000  MSR = 0x269
	MSRMTRRfix4KD0000  MSR = 0x26a
	MSRMTRRfix4KD8000  MSR = 0x26b
	MSRMTRRfix4KE0000  MSR = 0x26c
	MSRMTRRfix4KE8000  MSR = 0x26d
	MSRMTRRfix4KF0000  MSR = 0x26e
	MSRMTRRfix4KF8000  MSR = 0x26f

	MSRPAT MSR = 0x277

	MSRMTRRdefType MSR = 0x2ff

	MSRCOREPERFFIXEDCTR0     MSR = 0x309
	MSRCOREPERFFIXEDCTR1     MSR = 0x30a
	MSRCOREPERFFIXEDCTR2     MSR = 0x30b
	MSRCOREPERFFIXEDCTRCTRL  MSR = 0x38d
	MSRCOREPERFGLOBALSTATUS  MSR = 0x38e
	MSRCOREPERFGLOBALCTRL    MSR = 0x38f
	MSRCOREPERFGLOBALOVFCTRL MSR = 0x390

	MSRMC0CTL    MSR = 0x400
	MSRMC0STATUS MSR = 0x401
	MSRMC0ADDR   MSR = 0x402
	MSRMC0MISC   MSR = 0x403

	MSRIA32RTITOUTPUTBASE MSR = 0x560
	MSRIA32RTITOUTPUTMASK MSR = 0x561
	MSRIA32RTITCTL        MSR = 0x570
	MSRIA32RTITSTATUS     MSR = 0x571
	MSRIA32RTITCR3MATCH   MSR = 0x572
	MSRIA32RTITADDR0A     MSR = 0x580
	MSRIA32RTITADDR0B     MSR = 0x581
	MSRIA32RTITADDR1A     MSR = 0x582
	MSRIA32RTITADDR1B     MSR = 0x583
	MSRIA32RTITADDR2A     MSR = 0x584
	MSRIA32RTITADDR2B     MSR = 0x585
	MSRIA32RTITADDR3A     MSR = 0x586
	MSRIA32RTITADDR3B     MSR = 0x587
	MSRSTAR               MSR = 0xc0000081
	MSRLSTAR              MSR = 0xc0000082
	MSRCSTAR              MSR = 0xc0000083
	MSRFMASK              MSR = 0xc0000084
	MSRFSBASE             MSR = 0xc0000100
	MSRGSBASE             MSR = 0xc0000101
	MSRKERNELGSBASE       MSR = 0xc0000102
	MSRTSCAUX             MSR = 0xc0000103
	MSRAMD64TSCRATIO      MSR = 0xc0000104

	MSRVMHSAVEPA MSR = 0xc0010117

	MSRIA32XFD    MSR = 0x000001c4
	MSRIA32XFDERR MSR = 0x000001c5

	MSRIA32BNDCFGS       MSR = 0x00000d90
	MSRIA32XSS           MSR = 0x00000da0
	MSRIA32UMWAITCONTROL MSR = 0xe1

	MSRIA32VMXBASIC             MSR = 0x00000480
	MSRIA32VMXPINBASEDCTLS      MSR = 0x00000481
	MSRIA32VMXPROCBASEDCTLS     MSR = 0x00000482
	MSRIA32VMXEXITCTLS          MSR = 0x00000483
	MSRIA32VMXENTRYCTLS         MSR = 0x00000484
	MSRIA32VMXMISC              MSR = 0x00000485
	MSRIA32VMXCR0FIXED0         MSR = 0x00000486
	MSRIA32VMXCR0FIXED1         MSR = 0x00000487
	MSRIA32VMXCR4FIXED0         MSR = 0x00000488
	MSRIA32VMXCR4FIXED1         MSR = 0x00000489
	MSRIA32VMXVMCSENUM          MSR = 0x0000048a
	MSRIA32VMXPROCBASEDCTLS2    MSR = 0x0000048b
	MSRIA32VMXEPTVPIDCAP        MSR = 0x0000048c
	MSRIA32VMXTRUEPINBASEDCTLS  MSR = 0x0000048d
	MSRIA32VMXTRUEPROCBASEDCTLS MSR = 0x0000048e
	MSRIA32VMXTRUEEXITCTLS      MSR = 0x0000048f
	MSRIA32VMXTRUEENTRYCTLS     MSR = 0x00000490
	MSRIA32VMXVMFUNC            MSR = 0x00000491
)

type MSRList struct {
	NMSRs    uint32
	Indicies [1000]uint32
}

func GetMSRIndexList(kvmFd P, list *MSRList) error {
	_, err := Ioctl(kvmFd,
		IIOWR(kvmGetMSRIndexList, P(unsafe.Sizeof(list.NMSRs))),
		P(Ptr(list)))
	return err
}

func GetMSRFeatureIndexList(kvmFd P, list *MSRList) error {
	_, err := Ioctl(kvmFd,
		IIOWR(kvmGetMSRFeatureIndexList, P(unsafe.Sizeof(list.NMSRs))),
		P(Ptr(list)))
	return err
}

type MSREntry struct {
	Index   uint32
	Padding uint32
	Data    uint64
}

type MSRS struct {
	NMSRs   uint32
	Padding uint32
	Entries []MSREntry
}

func (m *MSRS) Bytes() ([]byte, error) {
	var buf bytes.Buffer

	if err := binary.Write(&buf, binary.LittleEndian, m.NMSRs); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.LittleEndian, m.Padding); err != nil {
		return nil, err
	}

	for _, entry := range m.Entries {
		if err := binary.Write(&buf, binary.LittleEndian, entry.Index); err != nil {
			return nil, err
		}
		if err := binary.Write(&buf, binary.LittleEndian, entry.Padding); err != nil {
			return nil, err
		}
		if err := binary.Write(&buf, binary.LittleEndian, entry.Data); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

func NewMSRS(data []byte) (*MSRS, error) {
	m := MSRS{}

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, data); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if err := binary.Read(&buf, binary.LittleEndian, &m.NMSRs); err != nil {
		return nil, err
	}
	if err := binary.Read(&buf, binary.LittleEndian, &m.Padding); err != nil {
		return nil, err
	}
	m.Entries = make([]MSREntry, m.NMSRs)
	if err := binary.Read(&buf, binary.LittleEndian, &m.Entries); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return &m, nil
}

func SetMSRs(vCpuFd P, msrs *MSRS) error {
	var m *MSRS

	data, err := msrs.Bytes()
	if err != nil {
		return err
	}
	if _, err := Ioctl(vCpuFd,
		IIOW(kvmSetMSRS, 8),
		P(Ptr(&data[0]))); err != nil {
		return err
	}

	if m, err = NewMSRS(data); err != nil {
		return err
	}

	*msrs = *m
	return err
}

func GetMSRs(vCpuFd P, msrs *MSRS) error {
	var m *MSRS

	data, err := msrs.Bytes()
	if err != nil {
		return err
	}
	if _, err := Ioctl(vCpuFd,
		IIOWR(kvmGetMSRS, 8),
		P(Ptr(&data[0]))); err != nil {
		return err
	}
	if m, err = NewMSRS(data); err != nil {
		return err
	}

	*msrs = *m
	return err
}

type PortIONoop struct {
}

func (r *PortIONoop) In(port uint64, data []byte) error  { return nil }
func (r *PortIONoop) Out(port uint64, data []byte) error { return nil }

type DeviceNoop struct {
	Port  uint64
	Psize uint64
}

func (r *DeviceNoop) In(port uint64, data []byte) error  { return nil }
func (r *DeviceNoop) Out(port uint64, data []byte) error { return nil }
func (r *DeviceNoop) IOPort() uint64                     { return r.Port }
func (r *DeviceNoop) Size() uint64                       { return r.Psize }


type PCIDevice interface {
	PortIO
	GetDeviceHeader() DeviceHeader
	IOPort() uint64
	Size() uint64
}

type DeviceHeader struct {
	VendorID      uint16
	DeviceID      uint16
	Command       uint16
	_             uint16
	_             uint8
	_             [3]uint8
	_             uint8
	_             uint8
	HeaderType    uint8
	_             uint8
	BAR           [6]uint32
	_             uint32
	_             uint16
	SubsystemID   uint16
	_             uint32
	_             uint8
	_             [7]uint8
	InterruptLine uint8
	InterruptPin  uint8
	_             uint8
	_             uint8
}

func (h DeviceHeader) Bytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	if err := binary.Write(buf, binary.LittleEndian, h); err != nil {
		return []byte{}, err
	}
	return buf.Bytes(), nil
}

type address uint32

func (a address) getRegisterOffset() uint32 {
	return uint32(a) & 0xfc
}

func (a address) getFunctionNumber() uint32 {
	return (uint32(a) >> 8) & 0x7
}

func (a address) getDeviceNumber() uint32 {
	return (uint32(a) >> 11) & 0x1f
}

func (a address) getBusNumber() uint32 {
	return (uint32(a) >> 16) & 0xff
}

func (a address) isEnable() bool {
	return ((uint32(a) >> 31) | 0x1) == 0x1
}

type PCI struct {
	addr        address
	isBAR0Probe bool
	Devices     []PCIDevice
}

func NewPCI(devices ...PCIDevice) *PCI {
	return &PCI{Devices: devices}
}

func (p *PCI) PciConfDataIn(port uint64, values []byte) error {
	offset := int(p.addr.getRegisterOffset() + uint32(port-0xCFC))

	if !p.addr.isEnable() {
		return nil
	}
	if p.addr.getBusNumber() != 0 {
		return nil
	}
	if p.addr.getFunctionNumber() != 0 {
		return nil
	}

	slot := int(p.addr.getDeviceNumber())
	if slot >= len(p.Devices) {
		return nil
	}

	if bar := offset/4 - 4; bar == 0 && p.isBAR0Probe {
		size := p.Devices[slot].Size()
		copy(values[:4], NumToBytes(SizeToBits(size)))
		p.isBAR0Probe = false
		return nil
	}
	b, err := p.Devices[slot].GetDeviceHeader().Bytes()
	if err != nil {
		return err
	}

	l := len(values)
	copy(values[:l], b[offset:offset+l])
	return nil
}

func (p *PCI) PciConfDataOut(port uint64, values []byte) error {
	offset := int(p.addr.getRegisterOffset() + uint32(port-0xCFC))

	if !p.addr.isEnable() {
		return nil
	}
	if p.addr.getBusNumber() != 0 {
		return nil
	}
	if p.addr.getFunctionNumber() != 0 {
		return nil
	}

	slot := int(p.addr.getDeviceNumber())
	if slot >= len(p.Devices) {
		return nil
	}
	if bar := offset/4 - 4; bar == 0 && BytesToNum(values) == 0xffffffff {
		p.isBAR0Probe = true

		return nil
	}
	return nil
}

func (p *PCI) In(port uint64, values []byte) error {
	if len(values) != 4 {
		return nil
	}
	copy(values[:4], NumToBytes(uint32(p.addr)))
	return nil
}

func (p *PCI) Out(port uint64, values []byte) error {
	if len(values) != 4 {
		return nil
	}
	p.addr = address(BytesToNum(values))
	return nil
}

type PCIConf struct {
	*PCI
}

func (c *PCIConf) In(port uint64, values []byte) error {
	return c.PciConfDataIn(port, values)
}

func (c *PCIConf) Out(port uint64, values []byte) error {
	return c.PciConfDataOut(port, values)
}

func SizeToBits(size uint64) uint32 {
	if size == 0 {
		return 0
	}
	return ^uint32(1) - uint32(size-2)
}

func BytesToNum(bytes []byte) uint64 {
	res := uint64(0)
	for i, x := range bytes {
		res |= uint64(x) << (i * 8)
	}
	return res
}

func NumToBytes(x interface{}) []byte {
	res := []byte{}
	l := 0
	y := uint64(0)

	switch v := x.(type) {
	case uint8:
		l = 1
		y = uint64(v)
	case uint16:
		l = 2
		y = uint64(v)
	case uint32:
		l = 4
		y = uint64(v)
	case uint64:
		l = 8
		y = v
	default:
		return []byte{}
	}

	for i := 0; i < l; i++ {
		res = append(res, uint8(y))
		y >>= 8
	}
	return res
}

const (
	xenHVMstartMagicValue uint32 = 0x336ec578
	xenELFNotePhys32Entry uint32 = 18
	pvhNoteStrSz          uint32 = 4
	elfNoteSize                  = 12
)

type HVMStartInfo struct {
	Magic         uint32
	Version       uint32
	Flags         uint32
	NrModules     uint32
	ModlistPAddr  uint64
	CmdLinePAddr  uint64
	RSDPPAddr     uint64
	MemMapPAddr   uint64
	MemMapEntries uint32
	_             uint32
}

func NewStartInfo(rsdpPAddr, cmdLinePAddr uint64) *HVMStartInfo {
	return &HVMStartInfo{
		Magic:        xenHVMstartMagicValue,
		Version:      1,
		NrModules:    0,
		CmdLinePAddr: cmdLinePAddr,
		RSDPPAddr:    rsdpPAddr,
		MemMapPAddr:  PVHMemMapStart,
	}
}

func (h *HVMStartInfo) Bytes() ([]byte, error) {
	var buf bytes.Buffer

	for _, item := range []interface{}{
		h.Magic,
		h.Version,
		h.Flags,
		h.NrModules,
		h.ModlistPAddr,
		h.CmdLinePAddr,
		h.RSDPPAddr,
		h.MemMapPAddr,
		h.MemMapEntries,
		uint32(0x0),
	} {
		if err := binary.Write(&buf, binary.LittleEndian, item); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

type HVMModListEntry struct {
	Addr        uint64
	Size        uint64
	CmdLineAddr uint64
	_           uint64
}

func NewModListEntry(addr, size, cmdaddr uint64) *HVMModListEntry {
	return &HVMModListEntry{
		Addr:        addr,
		Size:        size,
		CmdLineAddr: cmdaddr,
	}
}

func (h *HVMModListEntry) Bytes() ([]byte, error) {
	var buf bytes.Buffer

	for _, item := range []interface{}{
		h.Addr,
		h.Size,
		h.CmdLineAddr,
		uint64(0x0),
	} {
		if err := binary.Write(&buf, binary.LittleEndian, item); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

type HVMMemMapTableEntry struct {
	Addr uint64
	Size uint64
	Type uint32
	_    uint32
}

func NewMemMapTableEntry(addr, size uint64, t uint32) *HVMMemMapTableEntry {
	return &HVMMemMapTableEntry{
		Addr: addr,
		Size: size,
		Type: t,
	}
}

func (h *HVMMemMapTableEntry) Bytes() ([]byte, error) {
	var buf bytes.Buffer

	for _, item := range []interface{}{
		h.Addr,
		h.Size,
		h.Type,
		uint32(0x0),
	} {
		if err := binary.Write(&buf, binary.LittleEndian, item); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

type GDT [4]uint64

func CreateGDT() GDT {
	var gdtTable GDT

	gdtTable[0] = GdtEntry(0, 0, 0)               // NULL
	gdtTable[1] = GdtEntry(0xc09b, 0, 0xffffffff) // Code
	gdtTable[2] = GdtEntry(0xc093, 0, 0xffffffff) // DATA
	gdtTable[3] = GdtEntry(0x008b, 0, 0x67)       // TSS
	return gdtTable
}

func InitSRegs(vCpuFd P, gdttable GDT) error {
	codeseg := SegmentFromGDT(gdttable[1], 1)
	dataseg := SegmentFromGDT(gdttable[2], 2)
	tssseg := SegmentFromGDT(gdttable[3], 3)

	gdt := Descriptor{
		Base:  BootGDTStart,
		Limit: uint16(len(gdttable)*8) - 1, // 4 entries of 64bit (8byte) per entry
	}

	idt := Descriptor{
		Base:  BootIDTStart,
		Limit: 8,
	}

	sregs, err := GetSregs(vCpuFd)
	if err != nil {
		return err
	}

	sregs.GDT = gdt
	sregs.IDT = idt

	sregs.CS = codeseg
	sregs.DS = dataseg
	sregs.ES = dataseg
	sregs.FS = dataseg
	sregs.GS = dataseg
	sregs.SS = dataseg
	sregs.TR = tssseg

	sregs.EFER |= (0 << 17) | (0 << 9) | (0 << 8) // VM=0, IF=0, TF=0

	sregs.CR0 = 0x1
	sregs.CR4 = 0x0
	return SetSregs(vCpuFd, sregs)
}

func (gdt GDT) Bytes() []byte {
	bytes := make([]byte, binary.Size(gdt))

	for i, entry := range gdt {
		binary.LittleEndian.PutUint64(bytes[i*binary.Size(entry):], entry)
	}
	return bytes
}

func InitRegs(vCpuFd P, bootIP uint64) error {
	regs, err := GetRegs(vCpuFd)
	if err != nil {
		return err
	}

	regs.RFLAGS = 0x2
	regs.RBX = PVHInfoStart
	regs.RIP = bootIP
	return SetRegs(vCpuFd, regs)
}

type elfNote struct {
	NameSize uint32
	DescSize uint32
	Type     uint32
}

func ParsePVHEntry(fwimg io.ReaderAt, phdr *elf.Prog) (uint32, error) {
	node := elfNote{}
	off := int64(phdr.Off)
	readSize := 0

	for readSize < int(phdr.Filesz) {
		nodeByte := make([]byte, 12)

		n, err := fwimg.ReadAt(nodeByte, off)
		if err != nil {
			return 0x0, err
		}

		readSize += n
		off += int64(n)

		nsb := make([]byte, 4)
		dsb := make([]byte, 4)
		tsb := make([]byte, 4)

		copy(nsb, nodeByte[:3])
		copy(dsb, nodeByte[4:7])
		copy(tsb, nodeByte[8:])

		node.NameSize = binary.LittleEndian.Uint32(nsb)
		node.DescSize = binary.LittleEndian.Uint32(dsb)
		node.Type = binary.LittleEndian.Uint32(tsb)

		if node.Type == xenELFNotePhys32Entry && node.NameSize == pvhNoteStrSz {
			buf := make([]byte, pvhNoteStrSz)

			n, err := fwimg.ReadAt(buf, off)
			if err != nil {
				return 0x0, err
			}

			off += int64(n)
			if bytes.Equal(buf, []byte{'X', 'e', 'n', '\000'}) {
				break
			}
		}

		nameAlign, err := alignUp(uint64(node.NameSize))
		if err != nil {
			return 0x0, err
		}

		descAlign, err := alignUp(uint64(node.DescSize))
		if err != nil {
			return 0x0, err
		}

		readSize += int(nameAlign)
		readSize += int(descAlign)
		off = int64(phdr.Off) + int64(readSize)
	}

	if readSize >= int(phdr.Filesz) {
		// No PVH entry found. Return
		return 0x0, ErrPVHEntryNotFound
	}

	nameAlign, err := alignUp(uint64(node.NameSize))
	if err != nil {
		return 0x0, err
	}

	off += (int64(nameAlign) - int64(pvhNoteStrSz))
	pvhAddrByte := make([]byte, 4) // address is 4 byte/32-bit

	if _, err := fwimg.ReadAt(pvhAddrByte, off); err != nil {
		return 0x0, err
	}

	retAddr := binary.LittleEndian.Uint32(pvhAddrByte)
	return retAddr, nil
}

func alignUp(addr uint64) (uint64, error) {
	align := uint64(4)
	if !isPowerOf2(align) {
		return addr, ErrAlign
	}

	alignMask := align - 1
	if addr&alignMask == 0 {
		return addr, nil
	}
	return (addr | alignMask) + 1, nil
}

func isPowerOf2(n uint64) bool {
	if n == 0 {
		return true
	}
	return (n & (n - 1)) == 0
}

func CheckPVH(kern io.ReaderAt) (bool, error) {
	elfKern, err := elf.NewFile(kern)
	if err != nil {
		return false, nil //nolint:nilerr
	}
	defer elfKern.Close()

	for _, prog := range elfKern.Progs {
		note := elfNote{}
		off := int64(prog.Off)
		readSize := 0

		for readSize < int(prog.Filesz) {
			noteByte := make([]byte, elfNoteSize)

			n, err := kern.ReadAt(noteByte, off)
			if err != nil {
				return false, err
			}

			readSize += n
			off += int64(n)

			nsb := make([]byte, 4)
			dsb := make([]byte, 4)
			tsb := make([]byte, 4)

			copy(nsb, noteByte[:3])
			copy(dsb, noteByte[4:7])
			copy(tsb, noteByte[8:])

			note.NameSize = binary.LittleEndian.Uint32(nsb)
			note.DescSize = binary.LittleEndian.Uint32(dsb)
			note.Type = binary.LittleEndian.Uint32(tsb)

			if note.Type == xenELFNotePhys32Entry && note.NameSize == pvhNoteStrSz {
				buf := make([]byte, pvhNoteStrSz)

				_, err := kern.ReadAt(buf, off)
				if err != nil {
					return false, err
				}
				if bytes.Equal(buf, []byte{'X', 'e', 'n', '\000'}) {
					return true, nil
				}
			}

			nameAlign, err := alignUp(uint64(note.NameSize))
			if err != nil {
				return false, err
			}

			descAlign, err := alignUp(uint64(note.DescSize))
			if err != nil {
				return false, err
			}

			readSize += int(nameAlign)
			readSize += int(descAlign)
			off = int64(prog.Off) + int64(readSize)
		}
	}
	return false, nil
}

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

const (
	nrbits   = 8
	typebits = 8
	sizebits = 14
	dirbits  = 2

	nrmask   = (1 << nrbits) - 1
	sizemask = (1 << sizebits) - 1
	dirmask  = (1 << dirbits) - 1

	none      = 0
	write     = 1
	read      = 2
	readwrite = 3

	nrshift   = 0
	typeshift = nrshift + nrbits
	sizeshift = typeshift + typebits
	dirshift  = sizeshift + sizebits
)

const KVMIO = 0xAE

func IIOWR(nr, size P) P {
	return IIOC(readwrite, nr, size)
}

func IIOR(nr, size P) P {
	return IIOC(read, nr, size)
}

func IIOW(nr, size P) P {
	return IIOC(write, nr, size)
}

func IIO(nr P) P {
	return IIOC(none, nr, 0)
}

func IIOC(dir, nr, size P) P {
	return ((dir & dirmask) << dirshift) | (KVMIO << typeshift) |
		((nr & nrmask) << nrshift) | ((size & sizemask) << sizeshift)
}

func Ioctl(fd, op, arg P) (P, error) {
	res, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(op), uintptr(arg))
	if errno != 0 {
		return P(res), errno
	}
	return P(res), nil
}

func fcntl(fd, op, arg P) (P, error) {
	res, _, errno := syscall.Syscall(
		syscall.SYS_FCNTL, uintptr(fd), uintptr(op), uintptr(arg))
	if errno != 0 {
		return P(res), errno
	}
	return P(res), nil
}

func putLe32(d []byte, v uint32) {
	binary.LittleEndian.PutUint32(d, v)
}

type termios struct {
	Iflag  uint32
	Oflag  uint32
	Cflag  uint32
	Lflag  uint32
	Line   uint8
	Cc     [32]uint8
	Pad    [3]byte
	Ispeed uint32
	Ospeed uint32
}

func termRead(fd int) (termios, error) {
	var t termios
	_, errno := Ioctl(P(fd), 0x5401, P(Ptr(&t)))
	if errno != nil {
		return t, errno
	}
	return t, nil
}

func termWrite(fd int, t termios) error {
	_, errno := Ioctl(P(fd), 0x5402, P(Ptr(&t)))
	return errno
}

func IsTerminal() bool {
	_, err := termRead(0)
	return err == nil
}

func SetRawMode() (func(), error) {
	t, err := termRead(0)
	if err != nil {
		return func() {}, err
	}

	oldTermios := t

	t.Iflag &^= syscall.BRKINT | syscall.ICRNL | syscall.INPCK | syscall.ISTRIP | syscall.IXON
	t.Oflag &^= syscall.OPOST
	t.Cflag &^= syscall.CSIZE | syscall.PARENB
	t.Cflag |= syscall.CS8
	t.Lflag &^= syscall.ECHO | syscall.ICANON | syscall.IEXTEN | syscall.ISIG
	t.Cc[syscall.VMIN] = 1
	t.Cc[syscall.VTIME] = 0

	return func() {
		_ = termWrite(0, oldTermios)
	}, termWrite(0, t)
}

const (
	BlkIOPortStart = 0x6300
	BlkIOPortSize  = 0x100

	SectorSize = 512
)

type Blk struct {
	file         *os.File
	Hdr          blkHdr
	Queues       [1]*VirtualQueue
	PhyMem       *PhysMemory
	LastAvailIdx [1]uint16
	kick         chan interface{}
	irq          uint8
	IRQInjector  IRQInjector
}

type blkHdr struct {
	commonHeader commonHeader
	blkHeader    blkHeader
}

type blkHeader struct {
	capacity uint64
}

type BlkReq struct {
	Type   uint32
	_      uint32
	Sector uint64
}

func NewBlk(path string, irq uint8, irqInjector IRQInjector, m *PhysMemory) (*Blk, error) {
	file, err := os.OpenFile(path, os.O_RDWR, 0o644)

	if err != nil {
		return nil, err
	}
	fileInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}

	fileSize := uint64(fileInfo.Size())

	res := &Blk{
		Hdr: blkHdr{
			commonHeader: commonHeader{
				queueNUM: QueueSize,
				isr:      0x0,
			},
			blkHeader: blkHeader{
				capacity: fileSize / SectorSize,
			},
		},
		file:         file,
		irq:          irq,
		IRQInjector:  irqInjector,
		kick:         make(chan interface{}),
		PhyMem:       m,
		Queues:       [1]*VirtualQueue{},
		LastAvailIdx: [1]uint16{0},
	}
	return res, nil
}

func (h blkHdr) Bytes() ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.LittleEndian, h); err != nil {
		return []byte{}, err
	}
	return buf.Bytes(), nil
}

func (v *Blk) GetDeviceHeader() DeviceHeader {
	return DeviceHeader{
		DeviceID:    0x1001,
		VendorID:    0x1AF4,
		HeaderType:  0,
		SubsystemID: 2,
		Command:     1,
		BAR: [6]uint32{
			BlkIOPortStart | 0x1,
		},
		InterruptPin:  1,
		InterruptLine: v.irq,
	}
}

func (v *Blk) IOThreadEntry() {
	for range v.kick {
		for v.IO() == nil {
		}
	}
}

func (v *Blk) IO() error {
	sel := uint16(0)
	if debug {
		//v.dumpDesc(sel)
	}
	availRing := &v.Queues[sel].AvailRing
	usedRing := &v.Queues[sel].UsedRing

	if v.LastAvailIdx[sel] == availRing.Idx {
		return ErrNoTxPacket
	}

	for v.LastAvailIdx[sel] != availRing.Idx {
		descID := availRing.Ring[v.LastAvailIdx[sel]%QueueSize]
		usedRing.Ring[usedRing.Idx%QueueSize].Idx = uint32(descID)
		usedRing.Ring[usedRing.Idx%QueueSize].Len = 0

		var buf [3][]byte

		for i := 0; i < 3; i++ {
			desc := v.Queues[sel].DescTable[descID]
			buf[i] = v.PhyMem.Get(desc.Addr, desc.Addr+uint64(desc.Len))

			usedRing.Ring[usedRing.Idx%QueueSize].Len += desc.Len
			descID = desc.Next
		}

		blkReq := *((*BlkReq)(Ptr(&buf[0][0])))
		data := buf[1]

		var err error
		if blkReq.Type&0x1 == 0x1 {
			_, err = v.file.WriteAt(data, int64(blkReq.Sector*SectorSize))
		} else {
			_, err = v.file.ReadAt(data, int64(blkReq.Sector*SectorSize))
		}

		if err != nil {
			return err
		}
		if err = v.file.Sync(); err != nil {
			return err
		}

		usedRing.Idx++
		v.LastAvailIdx[sel]++
	}

	v.Hdr.commonHeader.isr = 0x1
	if err := v.IRQInjector.VirtualIOBlkIRQ(); err != nil {
		return err
	}
	return nil
}

func (v *Blk) In(port uint64, bytes []byte) error {
	offset := int(port - BlkIOPortStart)

	b, err := v.Hdr.Bytes()
	if err != nil {
		return err
	}

	l := len(bytes)
	copy(bytes[:l], b[offset:offset+l])
	return nil
}

func (v *Blk) Out(port uint64, bytes []byte) error {
	offset := int(port - BlkIOPortStart)

	switch offset {
	case 8:
		physAddr := BytesToNum(bytes) * 4096
		v.Queues[v.Hdr.commonHeader.queueSEL] = (*VirtualQueue)(v.PhyMem.GetRamPtr(physAddr))
	case 14:
		v.Hdr.commonHeader.queueSEL = uint16(BytesToNum(bytes))
	case 16:
		v.Hdr.commonHeader.isr = 0x0
		v.kick <- true
	case 19:
	default:
	}
	return nil
}

func (v *Blk) IOPort() uint64 {
	return BlkIOPortStart
}

func (v *Blk) Size() uint64 {
	return BlkIOPortSize
}

const (
	NetIOPortStart = 0x6200
	NetIOPortSize  = 0x100
)

type netHdr struct {
	commonHeader commonHeader
	_            netHeader
}

type Net struct {
	Hdr          netHdr
	Queues       [2]*VirtualQueue
	PhyMem       *PhysMemory
	LastAvailIdx [2]uint16
	If           io.ReadWriter
	txKick       chan interface{}
	rxKick       chan os.Signal
	irq          uint8
	IRQInjector  IRQInjector
}

func (h netHdr) Bytes() ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.LittleEndian, h); err != nil {
		return []byte{}, err
	}
	return buf.Bytes(), nil
}

type netHeader struct {
	_ [6]uint8
	_ uint16
	_ uint16
}

func NewNet(irq uint8, irqInjector IRQInjector, ioIf io.ReadWriter, m *PhysMemory) *Net {
	res := &Net{
		Hdr: netHdr{
			commonHeader: commonHeader{
				queueNUM: QueueSize,
				isr:      0x0,
			},
		},
		irq:          irq,
		IRQInjector:  irqInjector,
		txKick:       make(chan interface{}),
		rxKick:       make(chan os.Signal),
		If:           ioIf,
		PhyMem:       m,
		Queues:       [2]*VirtualQueue{},
		LastAvailIdx: [2]uint16{0, 0},
	}
	signal.Notify(res.rxKick, syscall.SIGIO)
	return res
}

func (v *Net) GetDeviceHeader() DeviceHeader {
	return DeviceHeader{
		DeviceID:    0x1000,
		VendorID:    0x1AF4,
		HeaderType:  0,
		SubsystemID: 1,
		Command:     1,
		BAR: [6]uint32{
			NetIOPortStart | 0x1,
		},
		InterruptPin:  1,
		InterruptLine: v.irq,
	}
}

func (v *Net) In(port uint64, bytes []byte) error {
	offset := int(port - NetIOPortStart)

	b, err := v.Hdr.Bytes()
	if err != nil {
		return err
	}

	l := len(bytes)
	copy(bytes[:l], b[offset:offset+l])
	return nil
}

func (v *Net) RxThreadEntry() {
	for range v.rxKick {
		for v.Rx() == nil {
		}
	}
}

func (v *Net) Rx() error {
	packet := make([]byte, 4096)

	n, err := v.If.Read(packet)
	if err != nil {
		return ErrNoRxPacket
	}

	packet = packet[:n]

	packet = append(make([]byte, 10), packet...)

	sel := 0

	if v.Queues[sel] == nil {
		return ErrVQNotInit
	}

	availRing := &v.Queues[sel].AvailRing
	usedRing := &v.Queues[sel].UsedRing

	if v.LastAvailIdx[sel] == availRing.Idx {
		return ErrNoRxBuf
	}

	const NONE = uint16(256)
	headDescID := NONE
	prevDescID := NONE

	for len(packet) > 0 {
		descID := availRing.Ring[v.LastAvailIdx[sel]%QueueSize]

		if headDescID == NONE {
			headDescID = descID
			usedRing.Ring[usedRing.Idx%QueueSize].Idx = uint32(headDescID)
			usedRing.Ring[usedRing.Idx%QueueSize].Len = 0
		}

		desc := &v.Queues[sel].DescTable[descID]
		l := uint32(len(packet))

		if l > desc.Len {
			l = desc.Len
		}

		copy(v.PhyMem.mem[desc.Addr:desc.Addr+uint64(l)], packet[:l])
		packet = packet[l:]
		desc.Len = l

		usedRing.Ring[usedRing.Idx%QueueSize].Len += l

		if prevDescID != NONE {
			v.Queues[sel].DescTable[prevDescID].Flags |= 0x1
			v.Queues[sel].DescTable[prevDescID].Next = descID
		}

		prevDescID = descID
		v.LastAvailIdx[sel]++
	}

	usedRing.Idx++
	v.Hdr.commonHeader.isr = 0x1
	return v.IRQInjector.VirtualIONetIRQ()
}

func (v *Net) TxThreadEntry() {
	for range v.txKick {
		for v.Tx() == nil {
		}
	}
}

func (v *Net) Tx() error {
	sel := v.Hdr.commonHeader.queueSEL
	if sel == 0 {
		return ErrInvalidSel
	}

	availRing := &v.Queues[sel].AvailRing
	usedRing := &v.Queues[sel].UsedRing

	if v.LastAvailIdx[sel] == availRing.Idx {
		return ErrNoTxPacket
	}

	for v.LastAvailIdx[sel] != availRing.Idx {
		buf := []byte{}
		descID := availRing.Ring[v.LastAvailIdx[sel]%QueueSize]

		usedRing.Ring[usedRing.Idx%QueueSize].Idx = uint32(descID)
		usedRing.Ring[usedRing.Idx%QueueSize].Len = 0

		for {
			desc := v.Queues[sel].DescTable[descID]

			b := make([]byte, desc.Len)
			copy(b, v.PhyMem.mem[desc.Addr:desc.Addr+uint64(desc.Len)])
			buf = append(buf, b...)
			usedRing.Ring[usedRing.Idx%QueueSize].Len += desc.Len

			if desc.Flags&0x1 != 0 {
				descID = desc.Next
			} else {
				break
			}
		}

		buf = buf[10:]

		if _, err := v.If.Write(buf); err != nil {
			return err
		}
		usedRing.Idx++
		v.LastAvailIdx[sel]++
	}

	v.Hdr.commonHeader.isr = 0x1
	return v.IRQInjector.VirtualIONetIRQ()
}

func (v *Net) Out(port uint64, bytes []byte) error {
	offset := int(port - NetIOPortStart)

	switch offset {
	case 8:
		physAddr := uint32(BytesToNum(bytes) * 4096)
		v.Queues[v.Hdr.commonHeader.queueSEL] = (*VirtualQueue)(Ptr(&v.PhyMem.mem[physAddr]))
	case 14:
		v.Hdr.commonHeader.queueSEL = uint16(BytesToNum(bytes))
	case 16:
		v.Hdr.commonHeader.isr = 0x0
		v.txKick <- true
	case 19:
		fmt.Printf("ISR was written!\r\n")
	default:
	}
	return nil
}

func (v *Net) IOPort() uint64 {
	return NetIOPortStart
}

func (v *Net) Size() uint64 {
	return NetIOPortSize
}
