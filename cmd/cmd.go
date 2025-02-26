package cmd

import (
	"fmt"
	"github.com/set-io/boots/cmd/cli"
	"github.com/set-io/boots/utils"
	"log"
	"os"
	"runtime"
	"strings"
)

const (
	SpecConfig       = "config.json"
	minKernelVersion = "5.0.0"
)

func Execute(name, usage, version, cipher, commit string) {
	app := cli.NewApp()
	app.Name = name
	app.Usage = usage

	v := []string{version}

	if commit != "" {
		v = append(v, "commit: "+commit)
	}
	v = append(v, "go: "+runtime.Version())
	app.Version = strings.Join(v, "\n")

	root := "/run/boots"
	xdgDirUsed := false
	xdgRuntimeDir := os.Getenv("XDG_RUNTIME_DIR")
	if xdgRuntimeDir != "" {
		root = xdgRuntimeDir + "/boots"
		xdgDirUsed = true
	}
	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "debug",
			Usage: "enable debug logging",
		},
		cli.StringFlag{
			Name:  "log",
			Value: "",
			Usage: "set the log file to write boots logs to (default is '/dev/stderr')",
		},
		cli.StringFlag{
			Name:  "log-format",
			Value: "text",
			Usage: "set the log format ('text' (default), or 'json')",
		},
		cli.StringFlag{
			Name:  "root",
			Value: root,
			Usage: "root directory for storage of sandbox state (this should be located in tmpfs)",
		},
		cli.StringFlag{
			Name:  "cipher",
			Value: cipher,
			Usage: "cipher for encrypting sandbox data (default is 'md5')",
		},
	}
	app.Commands = []cli.Command{
		createCommand,
		startCommand,
		runCommand,
		execCommand,
		killCommand,
		deleteCommand,
		listCommand,
		stateCommand,
		bootCommand,
		specCommand,
	}

	app.Before = func(ctx *cli.Context) error {
		if err := utils.CheckKernelVersion(minKernelVersion); err != nil {
			return err
		}
		if !ctx.IsSet("root") && xdgDirUsed {
			if err := os.MkdirAll(root, 0o700); err != nil {
				_, err = fmt.Fprintln(os.Stderr, "the path in $XDG_RUNTIME_DIR must be writable by the user")
				panic(err)
			}
			if err := os.Chmod(root, os.FileMode(0o700)|os.ModeSticky); err != nil {
				_, err = fmt.Fprintln(os.Stderr, "you should check permission of the path in $XDG_RUNTIME_DIR")
				panic(err)
			}
		}
		if ctx.IsSet("log") {
			logFile, err := os.OpenFile(ctx.String("log"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
			if err != nil {
				panic(err)
			}
			defer logFile.Close()
			log.SetOutput(logFile)
		}
		return nil
	}
	if err := app.Run(os.Args); err != nil {
		panic(err)
	}
}
