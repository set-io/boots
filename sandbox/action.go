package sandbox

import (
	"errors"
	"log"
	"os"
	"path/filepath"
)

var debug bool

func Load(root, id string, debugOpts bool) (*Sandbox, error) {
	debug = debugOpts
	if root == "" {
		return nil, errors.New("root not set")
	}
	if err := ValidateID(id); err != nil {
		return nil, err
	}
	stateDir := filepath.Join(root, id)
	st, err := LoadState(stateDir)
	if err != nil {
		return nil, err
	}
	r := &nonChildProcess{
		processPid:       st.InitProcessPid,
		processStartTime: st.InitProcessStartTime,
	}
	st.Config.Debug = debug
	if err = st.Config.Validate(); err != nil {
		return nil, err
	}
	s := &Sandbox{
		id:                   id,
		stateDir:             stateDir,
		config:               &st.Config,
		initProcess:          r,
		initProcessStartTime: st.InitProcessStartTime,
		created:              st.Created,
	}
	s.state = &loadedState{s: s}
	if err := s.refreshState(); err != nil {
		return nil, err
	}
	return s, nil
}

func Create(root, id string, config *Config) (*Sandbox, error) {
	debug = config.Debug
	if root == "" {
		return nil, errors.New("root not set")
	}
	if err := ValidateID(id); err != nil {
		return nil, err
	}
	if config.Hostname == "" {
		config.Hostname = id
	}
	if debug {
		log.Printf("create sandbox config: %+v", config)
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	stateDir := filepath.Join(root, id)
	if _, err := os.Stat(stateDir); err == nil {
		return nil, ErrExist
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if err := os.Mkdir(stateDir, 0o711); err != nil {
		return nil, err
	}
	s := &Sandbox{
		id:       id,
		stateDir: stateDir,
		config:   config,
	}
	s.state = &stopped{
		s: s,
	}
	return s, nil
}
