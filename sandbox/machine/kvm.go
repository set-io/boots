package machine

import (
	"errors"
	"fmt"
	"log"
	"os"
	"syscall"
	"unsafe"
)

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
	err := SetUserMemoryRegion(k.vmFd, &UserspaceMemoryRegion{
		Slot: 1, Flags: 0, GuestPhysAddr: 0, MemorySize: uint64(m.size),
		UserspaceAddr: uint64(P(m.GetRamPtr(0))),
	})
	if err != nil {
		return fmt.Errorf("SetUserMemoryRegion: %w", err)
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

func CreateDev(vmFd P, dev *Device) error {
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
