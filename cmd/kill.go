package cmd

import (
	"errors"
	"fmt"
	"github.com/set-io/boots/cmd/cli"
	"github.com/set-io/boots/sandbox"
	"golang.org/x/sys/unix"
	"strconv"
	"strings"
)

var killCommand = cli.Command{
	Name:  "kill",
	Usage: "kill sends the specified signal (default: SIGTERM) to the sandbox's init process",
	ArgsUsage: `<sandbox-id> [signal]

Where "<sandbox-id>" is the name for the instance of the sandbox and
"[signal]" is the signal to be sent to the init process.

EXAMPLE:
For example, if the sandbox id is "sandbox01" the following will send a "KILL"
signal to the init process of the "sandbox01" sandbox:

       # boots kill sandbox01 KILL`,
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:  "all, a",
			Usage: "(obsoleted, do not use)",
		},
	},
	Action: func(context *cli.Context) error {
		if err := checkArgs(context, 1, minArgs); err != nil {
			return err
		}
		if err := checkArgs(context, 2, maxArgs); err != nil {
			return err
		}
		c, err := getSandbox(context)
		if err != nil {
			return err
		}
		sigStr := context.Args().Get(1)
		if sigStr == "" {
			sigStr = "SIGTERM"
		}
		signal, err := parseSignal(sigStr)
		if err != nil {
			return err
		}
		err = c.Signal(signal)
		if errors.Is(err, sandbox.ErrNotRunning) && context.Bool("all") {
			err = nil
		}
		return err
	},
}

func parseSignal(rawSignal string) (unix.Signal, error) {
	s, err := strconv.Atoi(rawSignal)
	if err == nil {
		return unix.Signal(s), nil
	}
	sig := strings.ToUpper(rawSignal)
	if !strings.HasPrefix(sig, "SIG") {
		sig = "SIG" + sig
	}
	signal := unix.SignalNum(sig)
	if signal == 0 {
		return -1, fmt.Errorf("unknown signal %q", rawSignal)
	}
	return signal, nil
}
