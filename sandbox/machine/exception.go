package machine

import (
	"fmt"
	"unsafe"
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
