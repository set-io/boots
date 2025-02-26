package cmd

import (
	"errors"
	"fmt"
	"github.com/set-io/boots/cmd/cli"
	"github.com/set-io/boots/sandbox"
	"os"
	"path/filepath"
)

var deleteCommand = cli.Command{
	Name:  "delete",
	Usage: "delete any resources held by the sandbox often used with detached sandbox(",
	ArgsUsage: `<sandbox-id>

Where "<sandbox-id>" is the name for the instance of the sandbox.

EXAMPLE:
For example, if the sandbox id is "sandbox01" and boots list currently shows the
status of "sandbox01" as "stopped" the following will delete resources held for
"sandbox01" removing "sandbox01" from the boots list of sandboxes:

       # boots delete sandbox01`,
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:  "force, f",
			Usage: "Forcibly deletes the sandbox if it is still running (uses SIGKILL)",
		},
	},
	Action: func(context *cli.Context) error {
		if err := checkArgs(context, 1, exactArgs); err != nil {
			return err
		}
		id := context.Args().First()
		force := context.Bool("force")
		c, err := getSandbox(context)
		if err != nil {
			if errors.Is(err, sandbox.ErrNotExist) {
				path := filepath.Join(context.GlobalString("root"), id)
				if e := os.RemoveAll(path); e != nil {
					fmt.Fprintf(os.Stderr, "remove %s: %v\n", path, e)
				}
				if force {
					return nil
				}
			}
			return err
		}
		if force {
			return killSandbox(c)
		}
		s, err := c.Status()
		if err != nil {
			return err
		}
		switch s {
		case sandbox.Stopped:
			return c.Destroy()
		case sandbox.Created:
			return killSandbox(c)
		default:
			return fmt.Errorf("cannot delete sandbox %s that is not stopped: %s", id, s)
		}
	},
}
