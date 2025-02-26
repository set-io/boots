package machine

import (
	"fmt"
	"syscall"
)

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
