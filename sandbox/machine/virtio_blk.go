package machine

import (
	"bytes"
	"encoding/binary"
	"os"
)

const (
	BlkIOPortStart = 0x6300
	BlkIOPortSize  = 0x100

	SectorSize = 512
)

type Blk struct {
	file         *os.File
	Hdr          blkHdr
	Queues       [1]*VirtualQueue
	PhyMem       *PhysMemory
	LastAvailIdx [1]uint16
	kick         chan interface{}
	irq          uint8
	IRQInjector  IRQInjector
}

type blkHdr struct {
	commonHeader commonHeader
	blkHeader    blkHeader
}

type blkHeader struct {
	capacity uint64
}

type BlkReq struct {
	Type   uint32
	_      uint32
	Sector uint64
}

func NewBlk(path string, irq uint8, irqInjector IRQInjector, m *PhysMemory) (*Blk, error) {
	file, err := os.OpenFile(path, os.O_RDWR, 0o644)

	if err != nil {
		return nil, err
	}
	fileInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}

	fileSize := uint64(fileInfo.Size())

	res := &Blk{
		Hdr: blkHdr{
			commonHeader: commonHeader{
				queueNUM: QueueSize,
				isr:      0x0,
			},
			blkHeader: blkHeader{
				capacity: fileSize / SectorSize,
			},
		},
		file:         file,
		irq:          irq,
		IRQInjector:  irqInjector,
		kick:         make(chan interface{}),
		PhyMem:       m,
		Queues:       [1]*VirtualQueue{},
		LastAvailIdx: [1]uint16{0},
	}
	return res, nil
}

func (h blkHdr) Bytes() ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.LittleEndian, h); err != nil {
		return []byte{}, err
	}
	return buf.Bytes(), nil
}

func (v *Blk) GetDeviceHeader() DeviceHeader {
	return DeviceHeader{
		DeviceID:    0x1001,
		VendorID:    0x1AF4,
		HeaderType:  0,
		SubsystemID: 2,
		Command:     1,
		BAR: [6]uint32{
			BlkIOPortStart | 0x1,
		},
		InterruptPin:  1,
		InterruptLine: v.irq,
	}
}

func (v *Blk) IOThreadEntry() {
	for range v.kick {
		for v.IO() == nil {
		}
	}
}

func (v *Blk) IO() error {
	sel := uint16(0)
	if debug {
		//v.dumpDesc(sel)
	}
	availRing := &v.Queues[sel].AvailRing
	usedRing := &v.Queues[sel].UsedRing

	if v.LastAvailIdx[sel] == availRing.Idx {
		return ErrNoTxPacket
	}

	for v.LastAvailIdx[sel] != availRing.Idx {
		descID := availRing.Ring[v.LastAvailIdx[sel]%QueueSize]
		usedRing.Ring[usedRing.Idx%QueueSize].Idx = uint32(descID)
		usedRing.Ring[usedRing.Idx%QueueSize].Len = 0

		var buf [3][]byte

		for i := 0; i < 3; i++ {
			desc := v.Queues[sel].DescTable[descID]
			buf[i] = v.PhyMem.Get(desc.Addr, desc.Addr+uint64(desc.Len))

			usedRing.Ring[usedRing.Idx%QueueSize].Len += desc.Len
			descID = desc.Next
		}

		blkReq := *((*BlkReq)(Ptr(&buf[0][0])))
		data := buf[1]

		var err error
		if blkReq.Type&0x1 == 0x1 {
			_, err = v.file.WriteAt(data, int64(blkReq.Sector*SectorSize))
		} else {
			_, err = v.file.ReadAt(data, int64(blkReq.Sector*SectorSize))
		}

		if err != nil {
			return err
		}
		if err = v.file.Sync(); err != nil {
			return err
		}

		usedRing.Idx++
		v.LastAvailIdx[sel]++
	}

	v.Hdr.commonHeader.isr = 0x1
	if err := v.IRQInjector.VirtualIOBlkIRQ(); err != nil {
		return err
	}
	return nil
}

func (v *Blk) In(port uint64, bytes []byte) error {
	offset := int(port - BlkIOPortStart)

	b, err := v.Hdr.Bytes()
	if err != nil {
		return err
	}

	l := len(bytes)
	copy(bytes[:l], b[offset:offset+l])
	return nil
}

func (v *Blk) Out(port uint64, bytes []byte) error {
	offset := int(port - BlkIOPortStart)

	switch offset {
	case 8:
		physAddr := uint32(BytesToNum(bytes) * 4096)
		v.Queues[v.Hdr.commonHeader.queueSEL] = (*VirtualQueue)(v.PhyMem.GetRamPtr(physAddr))
	case 14:
		v.Hdr.commonHeader.queueSEL = uint16(BytesToNum(bytes))
	case 16:
		v.Hdr.commonHeader.isr = 0x0
		v.kick <- true
	case 19:
	default:
	}
	return nil
}

func (v *Blk) IOPort() uint64 {
	return BlkIOPortStart
}

func (v *Blk) Size() uint64 {
	return BlkIOPortSize
}
