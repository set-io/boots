package cmd

import (
	"fmt"
	"github.com/set-io/boots/cmd/cli"
	"os"
)

var createCommand = cli.Command{
	Name:  "create",
	Usage: "create a sandbox",
	ArgsUsage: `<sandbox-id>

Where "<sandbox-id>" is your name for the instance of the sandbox that you
are starting. The name you provide for the sandbox instance must be unique on
your host.`,
	Description: `The create command creates an instance of a sandbox for a bundle. The bundle
is a directory with a specification file named "` + SpecConfig + `" and a root
filesystem.

The specification file includes an args parameter. The args parameter is used
to specify command(s) that get run when the sandbox is started. To change the
command(s) that get executed on start, edit the args parameter of the spec. See
"boots spec --help" for more explanation.`,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "bundle, b",
			Value: "",
			Usage: `path to the root of the bundle directory, defaults to the current directory`,
		},
	},
	Action: func(context *cli.Context) error {
		if err := checkArgs(context, 1, exactArgs); err != nil {
			return err
		}
		status, err := startSandbox(context, CREATE)
		if err == nil {
			os.Exit(status)
		}
		return fmt.Errorf("boots create failed: %w", err)
	},
}
