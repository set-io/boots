package machine

import (
	"bytes"
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

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
		syscall.MAP_SHARED|syscall.MAP_ANONYMOUS)
	if err != nil {
		panic(fmt.Errorf("%v", err))
	}
	return &PhysMemory{mem: mem, size: size}
}

func (p *PhysMemory) Len() uint64 {
	return uint64(len(p.mem))
}

func (p *PhysMemory) GetRamPtr(addr uint32) Ptr {
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
