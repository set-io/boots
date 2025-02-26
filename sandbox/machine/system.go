package machine

import (
	"encoding/binary"
	"syscall"
)

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
