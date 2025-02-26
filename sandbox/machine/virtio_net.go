package machine

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
)

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
