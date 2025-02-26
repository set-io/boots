package sandbox

import (
	"bufio"
	"fmt"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/set-io/boots/sandbox/machine"
	"github.com/set-io/boots/utils"
	"golang.org/x/sync/errgroup"
	"log"
	"os"
	"strconv"
	"strings"
)

type entrypoint struct {
	id         int
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
			if strings.Contains(label, "bundle") || strings.Contains(label, Addr) {
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
		machine.DebugEnabled()
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
			size, err := utils.ParseSize(v[0:l-1], v[l-1:])
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

func (e *entrypoint) setup(process *specs.Process) (*machine.Machine, error) {
	if debug {
		log.Printf("vm init, net: %s, kernel: %s, initrd: %s, params: %s, interface: %s, disk: %s, ncpus: %d, memsize: %d, tracecount: %d\n",
			e.Net, e.Kernel, e.Initrd, e.Params, e.Interface, e.Disk, e.NCPUs, e.MemSize, e.TraceCount)
	}
	if debug {
		log.Println("start new machine")
	}
	m, err := machine.New(e.NCPUs, e.MemSize)
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
	isPVH, err := machine.CheckPVH(kern)
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

func (e *entrypoint) run(m *machine.Machine) error {
	var err error

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

	if !machine.IsTerminal() {
		log.Printf("this is not terminal and does not accept input\n")
		select {}
	}

	restoreMode, err := machine.SetRawMode()
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

	if err := g.Wait(); err != nil {
		log.Printf("%s\n", err)
		return err
	}
	if debug {
		log.Printf("all CPUs done\r\n")
	}
	return nil
}

func (e *entrypoint) shutdown() {
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
		err = e.c.Hooks.Run(CreateSandbox, &specs.State{})
		if err != nil {
			return err
		}
	}

	if err := e.run(m); err != nil {
		return err
	}
	if e.c.Probe {
		if err := machine.KVMCapabilities(); err != nil {
			return err
		}
		if err := machine.ProbeCPUID(); err != nil {
			return err
		}
	}
	defer func() {
		e.shutdown()
	}()
	return nil
}
