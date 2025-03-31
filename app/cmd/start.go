package cmd

import (
	"errors"
	"fmt"
	"github.com/set-io/boots/app/cmd/cli"
	bts "github.com/set-io/boots"
)

var startCommand = cli.Command{
	Name:  "start",
	Usage: "activate a  environment and user defined process in a created sandbox",
	ArgsUsage: `<sandbox-id>

Where "<sandbox-id>" is your name for the instance of the sandbox that you
are starting. The name you provide for the sandbox instance must be unique on
your host.`,
	Description: `The start command activate a  environment and user defined process in a created sandbox.`,
	Action: func(context *cli.Context) error {
		if err := checkArgs(context, 1, exactArgs); err != nil {
			return err
		}
		s, err := getSandbox(context)
		if err != nil {
			return err
		}
		status, err := s.Status()
		if err != nil {
			return err
		}
		switch status {
		case bts.Created:
			if err := s.Step(); err != nil {
				return err
			}
			return nil
		case bts.SandboxStopped:
			return errors.New("cannot start a sandbox that has stopped")
		case bts.SandboxRunning:
			return errors.New("cannot start an already running sandbox")
		default:
			return fmt.Errorf("cannot start a sandbox in the %s state", status)
		}
	},
}
