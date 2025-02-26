package sandbox

import "errors"

var (
	ErrExist      = errors.New("sandbox with given ID already exists")
	ErrInvalidID  = errors.New("invalid sandbox ID format")
	ErrNotExist   = errors.New("sandbox does not exist")
	ErrRunning    = errors.New("sandbox still running")
	ErrNotRunning = errors.New("sandbox not running")
)
