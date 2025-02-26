package cmd

import (
	"errors"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/set-io/boots/cmd/cli"
	"github.com/set-io/boots/sandbox"
	"github.com/set-io/boots/utils"
	"os"
)

var execCommand = cli.Command{
	Name:  "exec",
	Usage: "execute new processt inside the sandbox",
	ArgsUsage: `<sandbox-id> <command> [command options]

Where "<sandbox-id>" is the name for the instance of the sandbox and
"<command>" is the command to be executed in the sandbox.

EXAMPLE:
For example, if the sandbox is configured to run the linux ps command the
following will output a list of processes running in the sandbox:

       # boots exec <sandbox-id> ps`,
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:  "tty, t",
			Usage: "allocate a pseudo-TTY",
		},
	},
	Action: func(ctx *cli.Context) error {
		if err := checkArgs(ctx, 1, minArgs); err != nil {
			return err
		}
		status, err := execProcess(ctx)
		if err == nil {
			os.Exit(status)
		}
		return err
	},
}

func execProcess(ctx *cli.Context) (int, error) {
	s, err := getSandbox(ctx)
	if err != nil {
		return -1, err
	}
	status, err := s.Status()
	if err != nil {
		return -1, err
	}
	if status == sandbox.Stopped {
		return -1, errors.New("cannot exec in a stopped sandbox")
	}
	p, err := getProcess(ctx, s)
	if err != nil {
		return -1, err
	}
	r := runner{
		s:    s,
		act:  RUN,
		init: false,
	}
	return r.run(p)
}

func getProcess(ctx *cli.Context, s *sandbox.Sandbox) (*specs.Process, error) {
	bundle, ok := utils.SearchArrays(s.Config().Labels, "bundle")
	if !ok {
		return nil, errors.New("bundle not found in labels")
	}
	if err := os.Chdir(bundle); err != nil {
		return nil, err
	}
	spec, err := loadSpec(SpecConfig)
	if err != nil {
		return nil, err
	}
	p := spec.Process
	p.Terminal = ctx.Bool("tty")
	if !p.Terminal {
		args := ctx.Args()
		if len(args) < 2 {
			return nil, errors.New("exec args cannot be empty")
		}
		p.Args = args[1:]
	}
	return p, validateProcessSpec(p)
}
