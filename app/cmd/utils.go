package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/set-io/boots/app/cmd/cli"
	bts "github.com/set-io/boots"
	"golang.org/x/sys/unix"
	"log"
	"os"
	"path/filepath"
	"time"
)

type Action uint8

const (
	CREATE Action = iota + 1
	RUN
)

const (
	exactArgs = iota
	minArgs
	maxArgs
)

var (
	errEmptyID = errors.New("sandbox id cannot be empty")
)

func checkArgs(context *cli.Context, expected, checkType int) error {
	var err error
	cmdName := context.Command.Name
	switch checkType {
	case exactArgs:
		if context.Args().Len() != expected {
			err = fmt.Errorf("%s: %q requires exactly %d argument(s)", os.Args[0], cmdName, expected)
		}
	case minArgs:
		if context.Args().Len() < expected {
			err = fmt.Errorf("%s: %q requires a minimum of %d argument(s)", os.Args[0], cmdName, expected)
		}
	case maxArgs:
		if context.Args().Len() > expected {
			err = fmt.Errorf("%s: %q requires a maximum of %d argument(s)", os.Args[0], cmdName, expected)
		}
	}
	if err != nil {
		fmt.Printf("Incorrect Usage.\n\n")
		cli.ShowCommandHelp(context, cmdName)
		return err
	}
	return nil
}

func getSandbox(context *cli.Context) (*bts.Sandbox, error) {
	id := context.Args().First()
	if id == "" {
		return nil, errEmptyID
	}
	root := context.GlobalString("root")
	debug := context.GlobalBool("debug")
	return bts.Load(root, id, debug)
}

func setupSpec(context *cli.Context) (*specs.Spec, error) {
	bundle := context.String("bundle")
	if bundle != "" {
		if err := os.Chdir(bundle); err != nil {
			return nil, err
		}
	}
	spec, err := loadSpec(SpecConfig)
	if err != nil {
		return nil, err
	}
	return spec, nil
}

func loadSpec(path string) (spec *specs.Spec, err error) {
	cf, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("JSON specification file %s not found", path)
		}
		return nil, err
	}
	defer cf.Close()

	if err = json.NewDecoder(cf).Decode(&spec); err != nil {
		return nil, err
	}
	if spec == nil {
		return nil, errors.New("config cannot be null")
	}
	return spec, validateProcessSpec(spec.Process)
}

func validateProcessSpec(spec *specs.Process) error {
	if spec == nil {
		return errors.New("process property must not be empty")
	}
	if spec.Cwd == "" {
		return errors.New("cwd property must not be empty")
	}
	if !filepath.IsAbs(spec.Cwd) {
		return errors.New("cwd must be an absolute path")
	}
	if len(spec.Args) == 0 {
		return errors.New("args must not be empty")
	}
	return nil
}

func loadSandbox(ctx *cli.Context, id string, spec *specs.Spec) (*bts.Sandbox, error) {
	root := ctx.GlobalString("root")
	debug := ctx.GlobalBool("debug")
	if debug {
		log.Printf("enabeld debug param")
	}
	s, err := bts.Load(root, id, debug)
	if err != nil {
		config, err := sandboxSpec(spec, ctx.GlobalString("cipher"))
		if err != nil {
			return nil, err
		}
		config.Debug = debug
		if debug {
			log.Printf("sandbox config: %+v", config)
		}
		return bts.Create(root, id, config)
	}
	if !ctx.Bool("silent") {
		log.SetOutput(bts.MustOpenPipeFile(s.PipeName()))
	}
	return s, nil
}

func startSandbox(ctx *cli.Context, act Action) (int, error) {
	spec, err := setupSpec(ctx)
	if err != nil {
		return -1, err
	}
	id := ctx.Args().First()
	if id == "" {
		return -1, errEmptyID
	}
	s, err := loadSandbox(ctx, id, spec)
	if err != nil {
		return -1, err
	}
	r := runner{
		s:    s,
		act:  act,
		init: true,
	}
	return r.run(spec.Process)
}

func bootSandbox(ctx *cli.Context) (int, error) {
	spec, err := setupSpec(ctx)
	if err != nil {
		return -1, err
	}
	id := ctx.Args().First()
	if id == "" {
		return -1, errEmptyID
	}
	s, err := loadSandbox(ctx, id, spec)
	if err != nil {
		return -1, err
	}
	s.SetProbe(ctx.Bool("probe"))
	s.SetStable(ctx.Bool("stable"))
	s.SetBridge(ctx.GlobalString("bridge"))
	if err = s.RegisterInitHooks(); err != nil {
		return -1, err
	}
	return s.Boot(spec.Process)
}

func killSandbox(c *bts.Sandbox) error {
	_ = c.Signal(unix.SIGKILL)
	for i := 0; i < 100; i++ {
		time.Sleep(100 * time.Millisecond)
		if err := c.Signal(unix.Signal(0)); err != nil {
			return c.Destroy()
		}
	}
	return errors.New("sandbox init still running")
}

func sandboxSpec(spec *specs.Spec, cipher string) (*bts.Config, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	img := specs.VMImage{}
	if spec.VM.Image != img {
		switch spec.VM.Image.Format {
		case "qcow2":
			return nil, errors.New("qcow2 image format not supported")
		case "raw":
			spec.VM.Hypervisor.Parameters = append(spec.VM.Hypervisor.Parameters,
				fmt.Sprintf("disk=%s", spec.VM.Image.Path))
		case "vhd":
			return nil, errors.New("vhd image format not supported")
		}
	}
	if spec.Root != nil {
		access := "rw"
		if spec.Root.Readonly {
			access = "ro"
		}
		spec.VM.Kernel.Parameters = append(spec.VM.Kernel.Parameters,
			fmt.Sprintf("root=%s %s", spec.Root.Path, access))
	}
	if _, ok := spec.Annotations[bts.User]; !ok {
		spec.Annotations[bts.User] = "root"
	}
	if _, ok := spec.Annotations[bts.Cipher]; !ok {
		spec.Annotations[bts.Cipher] = cipher
	}
	labels := []string{}
	net := bts.NetConfig{}
	for k, v := range spec.Annotations {
		switch k {
		case "ip":
			net.IPAddress = v
		case "gateway":
			net.Subnet.Gateway = v
		case "subnet":
			net.Subnet.Mask = v
		case "eth":
			net.Eth = v
		default:
			labels = append(labels, k+"="+v)
		}
	}
	return &bts.Config{
		Version:              spec.Version,
		Hostname:             spec.Hostname,
		Labels:               append(labels, "bundle="+cwd, "ip="+net.String(), bts.Address+"="+net.IPAddress),
		HypervisorPath:       spec.VM.Hypervisor.Path,
		HypervisorParameters: spec.VM.Hypervisor.Parameters,
		KernelPath:           spec.VM.Kernel.Path,
		KernelParameters:     spec.VM.Kernel.Parameters,
		InitRD:               spec.VM.Kernel.InitRD,
		Net:                  net,
		Hooks:                make(bts.Hooks),
	}, nil
}

type runner struct {
	s    *bts.Sandbox
	act  Action
	init bool
}

func (r *runner) run(config *specs.Process) (int, error) {
	process, err := r.s.NewInitProcess(config)
	if err != nil {
		return -1, err
	}
	if process.Init {
		process.Args = append(process.Args, "--stable")
	}
	process.Args = append(process.Args, r.s.ID())

	if !r.init {
		process, err = r.s.NewExecProcess(config)
		if err != nil {
			return -1, err
		}
		process.Init = r.init
		if r.s.Config().Debug {
			log.Printf("create exec process: %+v", process)
		}
	}

	switch r.act {
	case CREATE:
		err = r.s.Start(process)
	case RUN:
		err = r.s.Run(process)
	default:
		panic("Unknown action")
	}
	if err != nil {
		return -1, err
	}
	return 0, nil
}
