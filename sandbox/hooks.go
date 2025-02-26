package sandbox

import (
	"fmt"
	"github.com/opencontainers/runtime-spec/specs-go"
	"log"
	"time"
)

type (
	HookName string
	HookList []Hook
	Hooks    map[HookName]HookList
)

type Hook interface {
	Run(*specs.State) error
}

const (
	PreStart      HookName = "preStart"
	CreateRuntime HookName = "createRuntime"
	CreateSandbox HookName = "createSandbox"
	StartSandbox  HookName = "startSandbox"
	PostStart     HookName = "postStart"
	PostStop      HookName = "postStop"
)

func KnownHookNames() []string {
	return []string{
		string(PreStart),
		string(CreateRuntime),
		string(CreateSandbox),
		string(StartSandbox),
		string(PostStart),
		string(PostStop),
	}
}

func (hooks Hooks) Register(name HookName, hook Hook) error {
	if _, exists := hooks[name]; exists {
		return fmt.Errorf("hook %q already registered", name)
	}
	hooks[name] = append(hooks[name], hook)
	return nil
}

func (hooks Hooks) Run(name HookName, state *specs.State) error {
	list := hooks[name]
	for i, hook := range list {
		if err := hook.Run(state); err != nil {
			return fmt.Errorf("error running %s hook #%d: %w", name, i, err)
		}
	}
	return nil
}

type ready struct {
	s *Sandbox
}

func (r *ready) Run(st *specs.State) error {
	if debug {
		log.Println("flow ready")
	}
	return r.s.writeFifo("READY")
}

type status struct {
	s *Sandbox
}

func (s *status) Run(st *specs.State) error {
	s.s.created = time.Now().UTC()
	s.s.state = &running{s: s.s}
	state, err := s.s.updateState()
	if err != nil {
		return err
	}
	s.s.initProcessStartTime = state.InitProcessStartTime
	if debug {
		log.Println("status content ", state)
	}
	return nil
}
