package sandbox

import (
	"encoding/json"
	"fmt"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/set-io/boots/utils"
	"golang.org/x/sys/unix"
	"os"
	"time"
)

type state interface {
	transition(state) error
	destroy() error
	status() Status
}

type Status int

const (
	Created Status = iota
	Running
	Stopped
)

func (s Status) String() string {
	switch s {
	case Created:
		return "created"
	case Running:
		return "running"
	case Stopped:
		return "stopped"
	default:
		return "unknown"
	}
}

type BaseState struct {
	ID                   string    `json:"id"`
	InitProcessPid       int       `json:"init_process_pid"`
	InitProcessStartTime uint64    `json:"init_process_start"`
	Created              time.Time `json:"created"`
	Config               Config    `json:"config"`
}

type State struct {
	BaseState
	ExternalDescriptors []string `json:"external_descriptors,omitempty"`
}

func LoadState(root string) (*State, error) {
	stateFilePath := utils.StateFile(root)
	f, err := os.Open(stateFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotExist
		}
		return nil, err
	}
	defer f.Close()
	var state *State
	if err := json.NewDecoder(f).Decode(&state); err != nil {
		return nil, err
	}
	return state, nil
}

type stopped struct {
	s *Sandbox
}

func (b *stopped) status() Status {
	return Stopped
}

func (b *stopped) transition(s state) error {
	switch s.(type) {
	case *running:
		b.s.state = s
		return nil
	case *stopped:
		return nil
	}
	return newTransitionError(b, s)
}

func (b *stopped) destroy() error {
	return destroy(b.s)
}

type running struct {
	s *Sandbox
}

func (r *running) status() Status {
	return Running
}

func (r *running) transition(s state) error {
	switch s.(type) {
	case *stopped:
		if r.s.hasInit() {
			return ErrRunning
		}
		r.s.state = s
		return nil
	case *running:
		return nil
	}
	return newTransitionError(r, s)
}

func (r *running) destroy() error {
	if r.s.hasInit() {
		return ErrRunning
	}
	return destroy(r.s)
}

type created struct {
	s *Sandbox
}

func (i *created) status() Status {
	return Created
}

func (i *created) transition(s state) error {
	switch s.(type) {
	case *running, *stopped:
		i.s.state = s
		return nil
	case *created:
		return nil
	}
	return newTransitionError(i, s)
}

func (i *created) destroy() error {
	_ = i.s.initProcess.signal(unix.SIGKILL)
	return destroy(i.s)
}

func newTransitionError(from, to state) error {
	return &stateTransitionError{
		From: from.status().String(),
		To:   to.status().String(),
	}
}

type stateTransitionError struct {
	From string
	To   string
}

func (s *stateTransitionError) Error() string {
	return fmt.Sprintf("invalid state transition from %s to %s", s.From, s.To)
}

func destroy(s *Sandbox) error {
	if err := os.RemoveAll(s.stateDir); err != nil {
		return fmt.Errorf("unable to remove sandbox state dir: %w", err)
	}
	s.initProcess = nil
	err := runPostStopHooks(s)
	s.state = &stopped{s: s}
	return err
}

func runPostStopHooks(c *Sandbox) error {
	hooks := c.config.Hooks
	if hooks == nil {
		return nil
	}
	s, err := c.currentOCIState()
	if err != nil {
		return err
	}
	s.Status = specs.StateStopped
	return hooks.Run(PostStop, s)
}

type loadedState struct {
	s  *Sandbox
	st Status
}

func (n *loadedState) status() Status {
	return n.st
}

func (n *loadedState) transition(s state) error {
	n.s.state = s
	return nil
}

func (n *loadedState) destroy() error {
	if err := n.s.refreshState(); err != nil {
		return err
	}
	return n.s.state.destroy()
}
