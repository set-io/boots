package machine

import (
	"errors"
)

var (
	ErrInvalidSel           = errors.New("queue sel is invalid")
	ErrIONotPermit          = errors.New("IO is not permitted for virtio device")
	ErrNoTxPacket           = errors.New("no packet for tx")
	ErrNoRxPacket           = errors.New("no packet for rx")
	ErrVQNotInit            = errors.New("vq not initialized")
	ErrNoRxBuf              = errors.New("no buffer found for rx")
	ErrZeroSizeKernel       = errors.New("kernel is 0 bytes")
	ErrBadVA                = errors.New("bad virtual address")
	ErrBadCPU               = errors.New("bad cpu number")
	ErrUnsupported          = errors.New("unsupported")
	ErrMemTooSmall          = errors.New("mem request must be at least 1<<20")
	ErrNotELF64File         = errors.New("file is not ELF64")
	ErrPTNoteHasNoFSize     = errors.New("elf program PT_NOTE has file size equal zero")
	ErrBridgeNotPermit      = errors.New("IO is not permitted for PCI bridge")
	ErrSignatureNotMatch    = errors.New("signature not match in bzImage")
	ErrOldProtocolVersion   = errors.New("old protocol version")
	ErrAlign                = errors.New("alignment is not a power of 2")
	ErrPVHEntryNotFound     = errors.New("no pvh entry found")
	ErrDataLenInvalid       = errors.New("invalid data size on port")
	ErrWriteToCF9           = errors.New("power cycle via 0xcf9")
	ErrUnexpectedExitReason = errors.New("unexpected kvm exit reason")
	ErrDebug                = errors.New("debug exit")
	ErrBadRegister          = errors.New("bad register")
	ErrBadArg               = errors.New("arg count must be in range 1..6")
	ErrBadArgType           = errors.New("bad arg type")
)
