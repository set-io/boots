package machine

import (
	"log"
	"time"
)

type ACPIPMTimer struct {
	Start time.Time
}

const (
	pmTimerFreqHz  uint64 = 3_579_545
	nanosPerSecond uint64 = 1_000_000_000
)

func NewACPIPMTimer() *ACPIPMTimer {
	return &ACPIPMTimer{
		Start: time.Now(),
	}
}

func (a *ACPIPMTimer) In(base uint64, data []byte) error {
	if len(data) != 4 {
		return ErrDataLenInvalid
	}

	since := time.Since(a.Start)
	nanos := since.Nanoseconds()
	counter := (nanos * int64(pmTimerFreqHz)) / int64(nanosPerSecond)
	counter32 := uint32(counter & 0xFFFF_FFFF)

	counterBytes := make([]byte, 4)
	putLe32(counterBytes, counter32)
	copy(data[0:], counterBytes)
	return nil
}

func (a *ACPIPMTimer) Out(base uint64, data []byte) error {
	return nil
}

func (a *ACPIPMTimer) IOPort() uint64 {
	return 0x608
}

func (a *ACPIPMTimer) Size() uint64 {
	return 0x4
}

type ACPIShutDown struct {
	Port       uint64
	ExitEvent  chan int
	ResetEvent chan int
}

func NewACPIShutDownEvent() *ACPIShutDown {
	return &ACPIShutDown{}
}

func (a *ACPIShutDown) Read(base uint64, data []byte) error {
	data[0] = 0
	return nil
}

func (a *ACPIShutDown) Write(base uint64, data []byte) error {
	if data[0] == 1 {
		log.Println("ACPI Reboot signaled")
	}
	S5SleepVal := uint8(5)
	SleepStatusENBit := uint8(5)
	SleepValBit := uint8(2)

	if data[0] == (S5SleepVal<<SleepValBit)|(1<<SleepStatusENBit) {
		a.ExitEvent <- 1
		log.Println("ACPI Shutdown signalled")
	}
	return nil
}

func (a *ACPIShutDown) IOPort() uint64 {
	return 0x600
}

func (a *ACPIShutDown) Size() uint64 {
	return 0x8
}
