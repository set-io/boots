package boots

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"io"
	"os/exec"
	"sync"
	"golang.org/x/sys/unix"
	"net"
	"encoding/json"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"


	"github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sync/errgroup"
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

const (
	User   = "org.set-io.boots.user"
	Cipher = "org.set-io.boots.cipher"
	Address   = "org.set-io.boots.addr"
)

type Config struct {
	Debug                bool
	RootDir              string
	Labels               []string `json:"labels"`
	Version              string   `json:"version"`
	Rootfs               string   `json:"rootfs"`
	Hostname             string   `json:"hostname"`
	HypervisorPath       string   `json:"hypervisor_path"`
	HypervisorParameters []string `json:"hypervisor_parameters,omitempty"`
	KernelPath           string   `json:"kernel_path"`
	KernelParameters     []string `json:"kernel_parameters,omitempty"`
	InitRD               string   `json:"initrd,omitempty"`
	Probe                bool     `json:"probe,omitempty"`
	Stable               bool     `json:"stable,omitempty"`
	Net                  NetConfig`json:"net"`
	Bridge               string   `json:"bridge"`
	Hooks                Hooks    `json:"-"`
}

func (c *Config) Validate() error {
	if len(c.Hostname) > 64 {
		return fmt.Errorf("hostname length exceeds maximum of 64 characters")
	}
	if c.Hooks == nil {
		c.Hooks = make(Hooks)
	}
	if err := c.Net.Validate(); err != nil {
		return fmt.Errorf("invalid net configuration: %w", err)
	}
	return nil
}

func (c *Config) GetHypervisorParameters(key string) string {
	return GetParams(c.HypervisorParameters, key)
}

type entrypoint struct {
	id         string
	Net        string
	Kernel     string
	Initrd     string
	Params     string
	Interface  string
	Disk       string
	NCPUs      int
	MemSize    int
	TraceCount int
	c          *Config
}

func (e *entrypoint) init() error {
	sc := e.c
	hpm := map[string]string{}
	for _, hp := range sc.HypervisorParameters {
		kv := strings.Split(hp, "=")
		hpm[kv[0]] = strings.TrimSpace(kv[1])
	}

	if e.c.Stable {
		for _, label := range sc.Labels {
			if strings.Contains(label, "bundle") || strings.Contains(label, Address) {
				continue
			}
			sc.KernelParameters = append(sc.KernelParameters, label)
		}
	}
	if !e.c.Stable {
		sc.Hostname = "localhost"
	}
	sc.KernelParameters = append(sc.KernelParameters, fmt.Sprintf("%s=%s", "hostname", sc.Hostname))

	if e.c.Debug {
		DebugEnabled()
	}

	for k, v := range hpm {
		switch k {
		case "cpus":
			n, err := strconv.Atoi(v)
			if err != nil {
				return err
			}
			e.NCPUs = n
		case "memory":
			l := len(v)
			size, err := ParseSize(v[0:l-1], v[l-1:])
			if err != nil {
				return err
			}
			e.MemSize = size
		case "disk":
			e.Disk = v
		case "net":
			e.Net = v
		case "interface":
			e.Interface = v
		default:
			return fmt.Errorf("unknown hypervisor parameter: %s", k)
		}
	}
	e.Kernel = sc.KernelPath
	e.Initrd = sc.InitRD
	e.Params = strings.Join(sc.KernelParameters, " ")
	if debug {
		log.Printf("hypervisor setup: %+v\n", e)
	}
	return nil
}

func (e *entrypoint) setup(process *specs.Process) (*Machine, error) {
	if debug {
		log.Printf("vm init, net: %s, kernel: %s, initrd: %s, params: %s, interface: %s, disk: %s, ncpus: %d, memsize: %d, tracecount: %d\n",
			e.Net, e.Kernel, e.Initrd, e.Params, e.Interface, e.Disk, e.NCPUs, e.MemSize, e.TraceCount)
	}
	if debug {
		log.Println("start new machine")
	}
	m, err := New(e.NCPUs, e.MemSize)
	if err != nil {
		return nil, err
	}
	if debug {
		log.Println("start setup interface")
	}
	if len(e.Interface) > 0 {
		if err := m.AddIf(e.Interface, e.Net); err != nil {
			return nil, err
		}
	}

	if len(e.c.Bridge) > 0 {
		if err := e.c.Net.Add(e.c.Bridge, e.Interface); err != nil {
			return nil, err
		}
	}

	if debug {
		log.Println("setup disk")
	}
	if len(e.Disk) > 0 {
		if err := m.AddDisk(e.Disk); err != nil {
			return nil, err
		}
	}
	if debug {
		log.Println("setup kernel and initrd")
	}
	var initrd *os.File
	kern, err := os.Open(e.Kernel)
	if err != nil {
		return nil, err
	}
	isPVH, err := CheckPVH(kern)
	if err != nil {
		return nil, err
	}
	if e.Initrd != "" {
		initrd, err = os.Open(e.Initrd)
		if err != nil {
			return nil, err
		}
	}
	if debug {
		log.Println("setup process")
	}
	if e.c.Stable {
		SetParams(&e.Params, process.Args, "args")
		SetParams(&e.Params, process.Env, "envs")
		SetParams(&e.Params, []string{process.Cwd}, "cwd")
	}

	if isPVH {
		if err := m.LoadPVH(kern, initrd, e.Params); err != nil {
			return nil, err
		}
	} else {
		if err := m.LoadLinux(kern, initrd, e.Params); err != nil {
			return nil, err
		}
	}
	return m, nil
}

func (e *entrypoint) run(m *Machine) error {
	trace := e.TraceCount > 0
	if err := m.SingleStep(trace); err != nil {
		return fmt.Errorf("setting trace to %v:%w", trace, err)
	}

	g := new(errgroup.Group)

	for cpu := 0; cpu < e.NCPUs; cpu++ {
		if debug {
			log.Printf("start CPU %d of %d\r\n", cpu, e.NCPUs)
		}
		i := cpu
		f := func() error {
			return m.VCPU(i, e.TraceCount)
		}
		g.Go(f)
	}

	if !e.c.Stable {
		if debug {
			log.Printf("waiting for CPUs to exit\n")
		}
		err := e.c.Hooks.Run(StartSandbox, &specs.State{})
		if err != nil {
			return err
		}
	}

	if IsTerminal() {
		restoreMode, err := SetRawMode()
		if err != nil {
			return err
		}

		defer restoreMode()

		if err := m.SingleStep(trace); err != nil {
			log.Printf("singleStep(%v): %v", trace, err)
			return err
		}

		in := bufio.NewReader(os.Stdin)

		g.Go(func() error {
			err := m.GetSerial().Start(*in, restoreMode, m.InjectSerialIRQ)
			log.Printf("serial exits: %v\n", err)
			return err
		})
		return g.Wait()
	}
	return e.wait()
}

func (e *entrypoint) wait() error {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	if debug {
		log.Printf("this is not terminal and does not accept input\n")
	}
	err := e.c.Hooks.Run(PostStart,
		&specs.State{Version: e.c.Version, ID: e.id, Status: specs.StateRunning})
	if err != nil {
		return err
	}
	select {
	case sig := <-sigChan:
		return fmt.Errorf("received signal: %v", sig)
	}
}

func (e *entrypoint) boot(process *specs.Process) error {
	err := e.init()
	if err != nil {
		return err
	}
	m, err := e.setup(process)
	if err != nil {
		return err
	}

	if e.c.Stable {
		if debug {
			log.Printf("ready booting\n")
		}
		err = e.c.Hooks.Run(CreateSandbox,
			&specs.State{ID: e.id, Version: e.c.Version, Status: specs.StateCreated})
		if err != nil {
			return err
		}
	}

	if err := e.run(m); err != nil {
		return err
	}

	if e.c.Probe {
		if err := KVMCapabilities(); err != nil {
			return err
		}
		if err := ProbeCPUID(); err != nil {
			return err
		}
	}
	defer func() {
		e.shutdown()
	}()
	return nil
}

func (e *entrypoint) shutdown() {
}

var (
	ErrExist      = errors.New("sandbox with given ID already exists")
	ErrInvalidID  = errors.New("invalid sandbox ID format")
	ErrNotExist   = errors.New("sandbox does not exist")
	ErrRunning    = errors.New("sandbox still running")
	ErrNotRunning = errors.New("sandbox not running")
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

func (r *ready) Run(s *specs.State) error {
	if debug {
		log.Println("flow ready")
	}
	return r.s.writeFifo(string(s.Status))
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

type bridge1 struct {
	brName string
	ifa    string
	net    NetConfig
}

func (b *bridge1) Run(s *specs.State) error {
	return nil
}

type NetConfig struct {
	IPAddress string `json:"ip_address"`
	Subnet    Subnet `json:"subnet"`
	Eth       string `json:"eth"`
}

type Subnet struct {
	Gateway string `json:"gateway"`
	Mask    string `json:"mask"`
}

func (s Subnet) String() string {
	n, err := s.MaskToPrefix()
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("%s/%d", s.Gateway, n)
}

func (s Subnet) MaskToPrefix() (int, error) {
	ip := net.ParseIP(s.Mask)
	if ip == nil {
		return 0, fmt.Errorf("invalid mask")
	}
	mask := net.IPMask(ip.To4())
	ones, bits := mask.Size()
	if bits == 0 {
		return 0, fmt.Errorf("invalid mask")
	}
	return ones, nil
}

func (n *NetConfig) Validate() error {
	if n.IPAddress == "" || n.Subnet.Gateway == "" || n.Subnet.Mask == "" {
		// TODO: ip validate
		return errors.New("ip_address and gateway must be provided")
	}
	return nil
}

func (n *NetConfig) String() string {
	if n.Eth == "" {
		n.Eth = "eth0"
	}
	// 192.168.100.18::192.168.100.1:255.255.255.0::eth0:off
	// https://www.kernel.org/doc/Documentation/filesystems/nfs/nfsroot.txt
	return fmt.Sprintf("%s::%s:%s::%s:off", n.IPAddress, n.Subnet.Gateway, n.Subnet.Mask, n.Eth)
}

func (n *NetConfig) Add(br, ifa string) error {
	subnet := n.Subnet.String()
	bridge, err := LinkByName(br)
	if err != nil {
		bridge = &Bridge{
			LinkAttrs: LinkAttrs{
				Name: br,
			},
		}
		if err := LinkAdd(bridge); err != nil {
			return fmt.Errorf("failed to create bridge: %v", err)
		}
		if debug {
			log.Printf("created new bridge: %s\n", br)
		}
	}

	if debug {
		log.Printf("using existing bridge: %s\n", br)
	}

	if debug {
		log.Printf("subnet is: %s\n", subnet)
	}

	addr, err := ParseAddr(subnet)
	if err != nil {
		return fmt.Errorf("failed to parse address: %v", err)
	}

	if err := AddrAdd(bridge, addr); err != nil {
		if os.IsExist(err) {
			if debug {
				log.Printf("ip address %s already exists, skipping...\n", addr.IPNet.String())
			}
		} else {
			return fmt.Errorf("failed to add address: %v", err)
		}
	}

	if err := LinkSetUp(bridge); err != nil {
		return fmt.Errorf("failed to set bridge up: %v", err)
	}

	ifac, err := LinkByName(ifa)
	if err != nil {
		return fmt.Errorf("failed to get interface(%s): %v\n", ifac, err)
	}

	if err := LinkSetMaster(ifac, bridge); err != nil {
		return fmt.Errorf("failed to add interface(%s) to bridge: %v", ifac, err)
	}

	if err := LinkSetUp(ifac); err != nil {
		return fmt.Errorf("failed to set interface(%s) up: %v", ifac, err)
	}

	if debug {
		log.Println("bridge and IF devices configured successfully")
	}
	return nil
}

type InitProcess struct {
	*ExecProcess
	exec bool
}

type ExecProcess struct {
	id       int
	Args     []string
	Env      []string
	UID, GID int
	Cwd      string
	Stdout   io.Writer
	Stderr   io.Writer
	Init     bool
	Terminal bool
}

func (e *ExecProcess) start() error {
	if debug {
		log.Printf("start exec process: %s\n", strings.Join(e.Args, " "))
	}
	user, _ := SearchArrays(e.Env, User)
	config := &ssh.ClientConfig{User: user}
	pwd, _ := SearchArrays(e.Env, Cipher)
	config.Auth = []ssh.AuthMethod{ssh.Password(pwd)}
	config.HostKeyCallback = ssh.InsecureIgnoreHostKey()
	config.Timeout = 10 * time.Second
	addr, _ := SearchArrays(e.Env, Address)
	if debug {
		log.Printf("start ssh session: %s, %s, %s\n", user, pwd, addr)
	}
	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:22", addr), config)
	if err != nil {
		return fmt.Errorf("failed to dial: %s", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session: %s", err)
	}
	defer session.Close()

	if e.Terminal {
		if debug {
			log.Println("start terminal session")
		}
		modes := ssh.TerminalModes{
			ssh.ECHO:          1,
			ssh.TTY_OP_ISPEED: 14400,
			ssh.TTY_OP_OSPEED: 14400,
		}

		fd := int(os.Stdin.Fd())
		state, err := term.MakeRaw(fd)
		if err != nil {
			return fmt.Errorf("failed to set terminal to raw mode: %s", err)
		}
		defer term.Restore(fd, state)

		width, height, err := term.GetSize(fd)
		if err != nil {
			return fmt.Errorf("failed to get terminal size: %s", err)
		}

		if err := session.RequestPty("xterm", height, width, modes); err != nil {
			return fmt.Errorf("failed to request PTY: %s", err)
		}

		session.Stdout = os.Stdout
		session.Stderr = os.Stderr
		session.Stdin = os.Stdin

		if err := session.Shell(); err != nil {
			return fmt.Errorf("failed to start shell: %s", err)
		}
		return session.Wait()
	}
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr
	session.Stdin = os.Stdin
	return session.Run(strings.Join(e.Args, " "))
}

func (p *InitProcess) pid() int {
	return p.id
}

func (p *InitProcess) start() error {
	if p.exec {
		if debug {
			log.Println("start exec process")
		}
		return p.ExecProcess.start()
	}
	cmd := exec.Command(p.Args[0], p.Args[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}
	cmd.Stdout = p.Stdout
	cmd.Stderr = p.Stderr
	if debug {
		log.Printf("start init process: %v\n", cmd.String())
	}
	err := cmd.Start()
	if err != nil {
		return fmt.Errorf("error starting command: %v", err)
	}
	p.id = cmd.Process.Pid
	if debug {
		log.Printf("start process: %d\n", cmd.Process.Pid)
	}
	return nil
}

func (p *InitProcess) terminate() error {
	return errors.New("init process cannot be terminated")
}

func (p *InitProcess) wait() (*os.ProcessState, error) {
	return nil, errors.New("init process cannot be waited on")
}

func (p *InitProcess) startTime() (uint64, error) {
	stat, err := Stat(p.pid())
	return stat.StartTime, err
}

func (p *InitProcess) signal(_ os.Signal) error {
	return errors.New("init process cannot receive signals")
}

func (p *InitProcess) forwardChildLogs() chan error {
	return make(chan error)
}

type nonChildProcess struct {
	processPid       int
	processStartTime uint64
}

func (p *nonChildProcess) start() error {
	return errors.New("restored process cannot be started")
}

func (p *nonChildProcess) pid() int {
	return p.processPid
}

func (p *nonChildProcess) terminate() error {
	return errors.New("restored process cannot be terminated")
}

func (p *nonChildProcess) wait() (*os.ProcessState, error) {
	return nil, errors.New("restored process cannot be waited on")
}

func (p *nonChildProcess) startTime() (uint64, error) {
	return p.processStartTime, nil
}

func (p *nonChildProcess) signal(s os.Signal) error {
	proc, err := os.FindProcess(p.processPid)
	if err != nil {
		return err
	}
	return proc.Signal(s)
}

func (p *nonChildProcess) forwardChildLogs() chan error {
	return nil
}

type runtimeProcess struct {
	*os.Process
}

func newRuntimeProcess() (parentProcess, error) {
	pid := os.Getpid()
	p, err := os.FindProcess(pid)
	if err != nil {
		return nil, fmt.Errorf("error finding process: %v", err)
	}
	return &runtimeProcess{
		Process: p,
	}, nil
}

func (p *runtimeProcess) pid() int {
	return p.Pid
}

func (p *runtimeProcess) start() error {
	return errors.New("runtime process cannot be started")
}

func (p *runtimeProcess) terminate() error {
	err := p.Kill()
	if _, wErr := p.wait(); err == nil {
		err = wErr
	}
	return err
}

func (p *runtimeProcess) wait() (*os.ProcessState, error) {
	return p.Wait()
}

func (p *runtimeProcess) startTime() (uint64, error) {
	stat, err := Stat(p.pid())
	return stat.StartTime, err
}

func (p *runtimeProcess) signal(sig os.Signal) error {
	s, ok := sig.(unix.Signal)
	if !ok {
		return errors.New("os: unsupported signal type")
	}
	return unix.Kill(p.pid(), s)
}

func (p *runtimeProcess) forwardChildLogs() chan error {
	return make(chan error)
}

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

func (s *Sandbox) SetBridge(br string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.config.Bridge = br
}

func (s *Sandbox) SetStable(stable bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.config.Stable = stable
}

func (s *Sandbox) PipeName() string {
	return PipePath(s.stateDir)
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
	stat, err := Stat(pid)
	if err != nil {
		return false
	}
	if stat.StartTime != s.initProcessStartTime || stat.State == Zombie || stat.State == Dead {
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

	err = WriteJSON(tmpFile, r)
	if err != nil {
		return err
	}
	err = tmpFile.Close()
	if err != nil {
		return err
	}
	stateFilePath := StateFile(s.stateDir)
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
	if _, err := os.Stat(FifoFile(s.stateDir)); err == nil {
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
	bundle, annotations := Annotations(s.config.Labels)
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
	if status != SandboxStopped {
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
	b, ok := SearchArrays(s.config.Labels, "bundle")
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
	fifoName := FifoFile(s.stateDir)
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
	_ = os.Remove(FifoFile(s.stateDir))
}

func (s *Sandbox) writeFifo(state string) error {
	fifoName := FifoFile(s.stateDir)
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
	pipeFile, err := OpenPipeFile(s.PipeName())
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
		return fmt.Errorf("failed to register ready hook: %w", err)
	}
	err = s.config.Hooks.Register(StartSandbox, &status{s})
	if err != nil {
		return fmt.Errorf("failed to register status hook: %w", err)
	}

	ifa, ok := SearchArrays(s.config.HypervisorParameters, "interface")
	if !ok {
		return fmt.Errorf("missing interface label in hypervisor parameters")
	}

	err = s.config.Hooks.Register(PostStart, &bridge1{brName: s.config.Bridge, net: s.config.Net, ifa: ifa})
	if err != nil {
		return fmt.Errorf("failed to register bridge hook: %w", err)
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

	e.id = s.id
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
	path := FifoFile(s.stateDir)
	pid := s.initProcess.pid()
	blockingFifoOpenCh := awaitFifoOpen(path)
	for {
		select {
		case result := <-blockingFifoOpenCh:
			return handleFifoResult(result)
		case <-time.After(time.Millisecond * 100):
			stat, err := Stat(pid)
			if err != nil || stat.State == Zombie {
				if err := handleFifoResult(fifoOpen(path, false)); err != nil {
					return errors.New("sandbox process is already dead")
				}
				return nil
			}
		}
	}
}

type state interface {
	transition(state) error
	destroy() error
	status() Status
}

type Status int

const (
	Created Status = iota
	SandboxRunning
	SandboxStopped
)

func (s Status) String() string {
	switch s {
	case Created:
		return "created"
	case SandboxRunning:
		return "running"
	case SandboxStopped:
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
	stateFilePath := StateFile(root)
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
	return SandboxStopped
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
	return SandboxRunning
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

func CleanPath(path string) string {
	if path == "" {
		return ""
	}
	path = filepath.Clean(path)
	if !filepath.IsAbs(path) {
		path = filepath.Clean(string(os.PathSeparator) + path)
		path, _ = filepath.Rel(string(os.PathSeparator), path)
	}
	return filepath.Clean(path)
}

func ValidateID(id string) error {
	if len(id) < 1 {
		return ErrInvalidID
	}

	// Allowed characters: 0-9 A-Z a-z _ + - .
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '_':
		case c == '+':
		case c == '-':
		case c == '.':
		default:
			return ErrInvalidID
		}
	}
	if string(os.PathSeparator)+id != CleanPath(string(os.PathSeparator)+id) {
		return ErrInvalidID
	}
	return nil
}

func SetParams(params *string, args []string, name string) {
	if args != nil {
		if len(args) > 1 {
			*params = fmt.Sprintf("%s %s", *params, fmt.Sprintf("%s=%s", name, strings.Join(args, " ")))
		} else {
			*params = fmt.Sprintf("%s %s", *params, fmt.Sprintf("%s=%s", name, args[0]))
		}
	}
}
