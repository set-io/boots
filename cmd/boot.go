package cmd

import (
	"fmt"
	"github.com/set-io/boots/cmd/cli"
	"os"
)

var bootCommand = cli.Command{
	Name:  "boot",
	Usage: "boot new sandbox",
	ArgsUsage: `<sandbox-id>

Where "<sandbox-id>" is the name for the instance of the sandbox and
"<command>" is the command to be boot in the sandbox.

EXAMPLE:
For example, if the sandbox is configured to run the linux ps command the
following will output a list of processes running in the sandbox:

       # boots boot <sandbox-id>`,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "bundle, b",
			Value: "",
			Usage: `path to the root of the bundle directory, defaults to the current directory`,
		},
		cli.BoolFlag{
			Name:  "probe",
			Usage: "Open kernel monitor",
		},
		cli.BoolFlag{
			Name:  "stable",
			Usage: "Install and initialize a production environment",
		},
		cli.BoolFlag{
			Name:  "silent",
			Usage: "Run silently without output",
		},
	},
	Action: func(context *cli.Context) error {
		if err := checkArgs(context, 1, exactArgs); err != nil {
			return err
		}
		status, err := bootSandbox(context)
		if err == nil {
			os.Exit(status)
		}
		return fmt.Errorf("boots boot failed: %w", err)
	},
}
