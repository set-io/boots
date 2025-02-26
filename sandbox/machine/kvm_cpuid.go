//nolint:dupl
package machine

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"unsafe"
)

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
