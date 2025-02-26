package sandbox

import (
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"
)

type openResult struct {
	file *os.File
	err  error
}

func readFromFifo(r io.Reader) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	if len(data) <= 0 {
		return errors.New("cannot start an already running sandbox")
	}
	return nil
}

func awaitFifoOpen(path string) <-chan openResult {
	fifoOpened := make(chan openResult)
	go func() {
		result := fifoOpen(path, true)
		fifoOpened <- result
	}()
	return fifoOpened
}

func fifoOpen(path string, block bool) openResult {
	flags := os.O_RDONLY
	if !block {
		flags |= unix.O_NONBLOCK
	}
	f, err := os.OpenFile(path, flags, 0)
	if err != nil {
		return openResult{err: fmt.Errorf("fifo: %w", err)}
	}
	return openResult{file: f}
}

func handleFifoResult(result openResult) error {
	if result.err != nil {
		return result.err
	}
	f := result.file
	defer f.Close()
	if err := readFromFifo(f); err != nil {
		return err
	}
	return os.Remove(f.Name())
}
