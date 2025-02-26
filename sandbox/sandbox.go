package sandbox

import (
	"errors"
	"fmt"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/set-io/boots/utils"
	"github.com/set-io/boots/utils/process"
	"golang.org/x/sys/unix"
	"log"
	"os"
	"sync"
	"time"
)

type parentProcess interface {
	pid() int
	start() error
	terminate() error
	wait() (*os.ProcessState, error)
	startTime() (uint64, error)
	signal(os.Signal) error
}

type Sandbox struct {
	id                   string
	stateDir             string
	config               *Config
	initProcess          parentProcess
	initProcessStartTime uint64
	mu                   sync.Mutex
	state                state
	created              time.Time
}

func (s *Sandbox) ID() string {
	return s.id
}

func (s *Sandbox) Config() Config {
	return *s.config
}

func (s *Sandbox) SetProbe(probe bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.config.Probe = probe
}

func (s *Sandbox) SetStable(stable bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.config.Stable = stable
}

func (s *Sandbox) PipeName() string {
	return utils.PipePath(s.stateDir)
}

func (s *Sandbox) currentStatus() (Status, error) {
	if err := s.refreshState(); err != nil {
		return -1, err
	}
	return s.state.status(), nil
}

func (s *Sandbox) hasInit() bool {
	if s.initProcess == nil {
		return false
	}
	pid := s.initProcess.pid()
	stat, err := process.Stat(pid)
	if err != nil {
		return false
	}
	if stat.StartTime != s.initProcessStartTime || stat.State == process.Zombie || stat.State == process.Dead {
		return false
	}
	return true
}

func (s *Sandbox) Status() (Status, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.currentStatus()
}

func (s *Sandbox) State() (*State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.currentState(), nil
}

func (s *Sandbox) updateState() (*State, error) {
	state := s.currentState()
	if err := s.saveState(state); err != nil {
		return nil, err
	}
	return state, nil
}

func (s *Sandbox) saveState(r *State) (retErr error) {
	tmpFile, err := os.CreateTemp(s.stateDir, "state-")
	if err != nil {
		return err
	}

	defer func() {
		if retErr != nil {
			tmpFile.Close()
			os.Remove(tmpFile.Name())
		}
	}()

	err = utils.WriteJSON(tmpFile, r)
	if err != nil {
		return err
	}
	err = tmpFile.Close()
	if err != nil {
		return err
	}
	stateFilePath := utils.StateFile(s.stateDir)
	return os.Rename(tmpFile.Name(), stateFilePath)
}

func (s *Sandbox) currentState() *State {
	var (
		startTime           uint64
		externalDescriptors []string
		pid                 = -1
	)
	if s.initProcess != nil {
		pid = s.initProcess.pid()
		startTime, _ = s.initProcess.startTime()
	}
	state := &State{
		BaseState: BaseState{
			ID:                   s.ID(),
			Config:               *s.config,
			InitProcessPid:       pid,
			InitProcessStartTime: startTime,
			Created:              s.created,
		},
		ExternalDescriptors: externalDescriptors,
	}
	return state
}

func (s *Sandbox) refreshState() error {
	if !s.hasInit() {
		return s.state.transition(&stopped{s: s})
	}
	if _, err := os.Stat(utils.FifoFile(s.stateDir)); err == nil {
		return s.state.transition(&created{s: s})
	}
	return s.state.transition(&running{s: s})
}

func (s *Sandbox) Signal(sig os.Signal) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.signal(sig)
}

func (s *Sandbox) signal(sig os.Signal) error {
	if !s.hasInit() {
		return ErrNotRunning
	}
	if err := s.initProcess.signal(sig); err != nil {
		return fmt.Errorf("unable to signal init: %w", err)
	}
	return nil
}

func (s *Sandbox) Destroy() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.state.destroy(); err != nil {
		return fmt.Errorf("unable to destroy sandbox: %w", err)
	}
	return nil
}

func (s *Sandbox) currentOCIState() (*specs.State, error) {
	bundle, annotations := utils.Annotations(s.config.Labels)
	state := &specs.State{
		Version:     specs.Version,
		ID:          s.ID(),
		Bundle:      bundle,
		Annotations: annotations,
	}
	status, err := s.currentStatus()
	if err != nil {
		return nil, err
	}
	state.Status = specs.ContainerState(status.String())
	if status != Stopped {
		if s.initProcess != nil {
			state.Pid = s.initProcess.pid()
		}
	}
	return state, nil
}

func (s *Sandbox) NewInitProcess(config *specs.Process) (*InitProcess, error) {
	name, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("failed to get executable path: %v", err)
	}
	b, ok := utils.SearchArrays(s.config.Labels, "bundle")
	if !ok {
		return nil, fmt.Errorf("missing bundle label in sandbox config")
	}
	return &InitProcess{
		&ExecProcess{
			Args:     []string{name, "boot", "--bundle", b, "--probe"},
			Env:      config.Env,
			UID:      int(config.User.UID),
			GID:      int(config.User.GID),
			Cwd:      config.Cwd,
			Stdout:   os.Stdout,
			Stderr:   os.Stderr,
			Init:     true,
			Terminal: config.Terminal,
		},
		false,
	}, nil
}

func (s *Sandbox) NewExecProcess(config *specs.Process) (*InitProcess, error) {
	config.Env = append(config.Env, s.config.Labels...)
	return &InitProcess{
		&ExecProcess{
			Args:     config.Args,
			Env:      config.Env,
			UID:      int(config.User.UID),
			GID:      int(config.User.GID),
			Cwd:      config.Cwd,
			Stdout:   os.Stdout,
			Stderr:   os.Stderr,
			Terminal: config.Terminal,
		},
		true,
	}, nil
}

func (s *Sandbox) Start(process *InitProcess) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.start(process)
}

func (s *Sandbox) createFifo() (errs error) {
	fifoName := utils.FifoFile(s.stateDir)
	if err := unix.Mkfifo(fifoName, 0o666); err != nil {
		return &os.PathError{Op: "mkfifo", Path: fifoName, Err: err}
	}
	defer func() {
		if errs != nil {
			os.Remove(fifoName)
		}
	}()
	return os.Chmod(fifoName, 0o666)
}

func (s *Sandbox) deleteFifo() {
	_ = os.Remove(utils.FifoFile(s.stateDir))
}

func (s *Sandbox) writeFifo(state string) error {
	fifoName := utils.FifoFile(s.stateDir)
	f, err := os.OpenFile(fifoName, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	n, err := f.WriteString(state)
	if n != len(state) {
		return fmt.Errorf("partial write: %d/%d bytes", n, len(state))
	}
	return err
}

func (s *Sandbox) start(process *InitProcess) (errs error) {
	pipeFile, err := utils.OpenPipeFile(s.PipeName())
	if err != nil {
		return fmt.Errorf("error opening output file: %v", err)
	}
	process.Stdout = pipeFile
	process.Stderr = pipeFile

	if process.Init {
		if s.initProcessStartTime != 0 {
			return errors.New("sandbox already has init process")
		}
		if err := s.createFifo(); err != nil {
			return err
		}
		defer func() {
			if errs != nil {
				s.deleteFifo()
			}
		}()
		if err := process.start(); err != nil {
			return fmt.Errorf("error starting init process: %v", err)
		}
		s.initProcess = process
		s.created = time.Now().UTC()
		s.state = &created{s: s}
		state, err := s.updateState()
		if err != nil {
			return err
		}
		s.initProcessStartTime = state.InitProcessStartTime
		return nil
	}
	return process.start()
}

func (s *Sandbox) Run(process *InitProcess) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.start(process); err != nil {
		return fmt.Errorf("failed to start init process: %w", err)
	}
	if process.Init {
		return s.step()
	}
	return nil
}

func (s *Sandbox) RegisterInitHooks() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.config.Hooks.Register(CreateSandbox, &ready{s})
	if err != nil {
		return fmt.Errorf("failed to register hook: %w", err)
	}
	err = s.config.Hooks.Register(StartSandbox, &status{s})
	if err != nil {
		return fmt.Errorf("failed to register hook: %w", err)
	}
	return nil
}

func (s *Sandbox) Boot(config *specs.Process) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e := entrypoint{
		c: s.config,
	}

	var err error
	s.initProcess, err = newRuntimeProcess()
	if err != nil {
		return -1, fmt.Errorf("failed to create runtime process: %w", err)
	}

	if debug {
		log.Printf("daemon process id: %d", s.initProcess.pid())
	}

	e.id = s.initProcess.pid()
	if err := e.boot(config); err != nil {
		return -1, err
	}
	return 0, nil
}

func (s *Sandbox) Step() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.step()
}

func (s *Sandbox) step() error {
	path := utils.FifoFile(s.stateDir)
	pid := s.initProcess.pid()
	blockingFifoOpenCh := awaitFifoOpen(path)
	for {
		select {
		case result := <-blockingFifoOpenCh:
			return handleFifoResult(result)
		case <-time.After(time.Millisecond * 100):
			stat, err := process.Stat(pid)
			if err != nil || stat.State == process.Zombie {
				if err := handleFifoResult(fifoOpen(path, false)); err != nil {
					return errors.New("sandbox process is already dead")
				}
				return nil
			}
		}
	}
}
