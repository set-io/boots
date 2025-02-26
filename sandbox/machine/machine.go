package machine

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/arch/x86/x86asm"
	"io"
	"log"
	"os"
	"reflect"
	"runtime"
	"syscall"
	"unsafe"
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

var debug bool

type Machine struct {
	phyMem  *PhysMemory
	kvm     *KVM
	pci     *PCI
	serial  *Serial
	devices []Device
	ports   [portRange]PortIO
}

func New(cpus int, memSize int) (*Machine, error) {
	if memSize < MinMemSize {
		return nil, fmt.Errorf("memory size %d:%w", memSize, ErrMemTooSmall)
	}

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

func (m *Machine) AddDevice(dev Device) {
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
