package machine

import (
	"syscall"
)

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
