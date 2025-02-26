package machine

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"unsafe"
)

const (
	maxVCPUs             = 64
	apicDefaultPhysBase  = 0xfee00000
	apicBaseAddrStep     = 0x00400000
	mpfIntelSignature    = (('_' << 24) | ('P' << 16) | ('M' << 8) | '_')
	mpcTableSignature    = (('P' << 24) | ('M' << 16) | ('C' << 8) | 'P')
	mpEntryTypeProcessor = 0
	cpuFlagEnabled       = 1
	cpuFlagBP            = 2
	cpuStepping          = uint32(0x600)
	cpuFeatureAPIC       = uint32(0x200)
	cpuFeatureFPU        = uint32(0x001)
	mpAPICVersion        = uint8(0x14)
)

type (
	EBDA struct {
		_        [16 * 3]uint8
		mpfIntel mpfIntel
		mpcTable mpcTable
	}

	mpfIntel struct {
		signature     uint32
		physPtr       uint32
		length        uint8
		specification uint8
		checkSum      uint8
		_             uint8 // padding feature1
		_             uint8
		_             uint8
		_             uint8
		_             uint8
	}

	mpcTable struct {
		signature uint32
		length    uint16
		spec      uint8
		checkSum  uint8
		OEMId     [8]uint8
		ProdID    [12]uint8
		_         uint32
		_         uint16
		oemCount  uint16
		lapic     uint32
		_         uint32
		mpcCPU    [maxVCPUs]mpcCPU
	}
)

func (e *EBDA) Bytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	if err := binary.Write(buf, binary.LittleEndian, e); err != nil {
		return []byte{}, err
	}

	return buf.Bytes(), nil
}

func NewEBDA(nCPUs int) (*EBDA, error) {
	e := &EBDA{}

	mpfIntel, err := newMPFIntel()
	if err != nil {
		return e, err
	}
	e.mpfIntel = *mpfIntel
	mpcTable, err := newMPCTable(nCPUs)
	if err != nil {
		return e, err
	}
	e.mpcTable = *mpcTable
	return e, nil
}

func newMPFIntel() (*mpfIntel, error) {
	m := &mpfIntel{}
	m.signature = mpfIntelSignature
	m.length = 1
	m.specification = 4
	m.physPtr = EBDAStarted + 0x40

	var err error

	m.checkSum, err = m.calcCheckSum()
	if err != nil {
		return m, err
	}

	m.checkSum ^= uint8(0xff)
	m.checkSum++
	return m, nil
}

func (m *mpfIntel) calcCheckSum() (uint8, error) {
	bytes, err := m.bytes()
	if err != nil {
		return 0, err
	}

	tmp := uint32(0)
	for _, b := range bytes {
		tmp += uint32(b)
	}
	return uint8(tmp & 0xff), nil
}

func (m *mpfIntel) bytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	if err := binary.Write(buf, binary.LittleEndian, m); err != nil {
		return []byte{}, err
	}
	return buf.Bytes(), nil
}

func apicAddr(apic uint32) uint32 {
	return apicDefaultPhysBase + apic*apicBaseAddrStep
}

func newMPCTable(nCPUs int) (*mpcTable, error) {
	m := &mpcTable{}
	m.signature = mpcTableSignature
	m.length = uint16(unsafe.Sizeof(mpcTable{}))
	m.spec = 4
	m.lapic = apicAddr(0)
	m.OEMId = [8]byte{0x42, 0x4F, 0x4F, 0x54, 0x53, 0x00, 0x00, 0x00} // "BOOTS   "
	m.oemCount = maxVCPUs

	if nCPUs > maxVCPUs {
		return nil, fmt.Errorf("the number of vCPUs must be less than or equal to %d", maxVCPUs)
	}

	var err error

	for i := 0; i < nCPUs; i++ {
		m.mpcCPU[i] = *newMPCCpu(i)
	}

	m.checkSum, err = m.calcCheckSum()
	if err != nil {
		return m, err
	}

	m.checkSum ^= uint8(0xff)
	m.checkSum++
	return m, nil
}

func (m *mpcTable) calcCheckSum() (uint8, error) {
	bytes, err := m.bytes()
	if err != nil {
		return 0, err
	}

	tmp := uint32(0)
	for _, b := range bytes {
		tmp += uint32(b)
	}
	return uint8(tmp & 0xff), nil
}

func (m *mpcTable) bytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	if err := binary.Write(buf, binary.LittleEndian, m); err != nil {
		return []byte{}, err
	}
	return buf.Bytes(), nil
}

type mpcCPU struct {
	typ         uint8
	apicID      uint8
	apicVer     uint8
	cpuFlag     uint8
	sig         uint32
	featureFlag uint32
	_           [2]uint32
}

func newMPCCpu(i int) *mpcCPU {
	m := &mpcCPU{}

	f := uint8(cpuFlagEnabled)

	if i == 0 {
		f |= cpuFlagBP
	}

	m.typ = mpEntryTypeProcessor
	m.apicID = uint8(i)
	m.apicVer = mpAPICVersion
	m.cpuFlag = f
	m.sig = (cpuStepping << 16)
	m.featureFlag = cpuFeatureAPIC | cpuFeatureFPU
	return m
}
