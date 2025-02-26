package machine

import (
	"unsafe"
)

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
