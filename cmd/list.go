package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/set-io/boots/cmd/cli"
	"github.com/set-io/boots/sandbox"
	"github.com/set-io/boots/utils"
	"os"
	"os/user"
	"strconv"
	"syscall"
	"text/tabwriter"
	"time"
)

const formatOptions = `table or json`

type sandboxState struct {
	Version        string            `json:"ociVersion"`
	ID             string            `json:"id"`
	InitProcessPid int               `json:"pid"`
	Status         string            `json:"status"`
	Bundle         string            `json:"bundle"`
	Rootfs         string            `json:"rootfs"`
	Interface      string            `json:"interface"`
	Created        time.Time         `json:"created"`
	Annotations    map[string]string `json:"annotations,omitempty"`
	Owner          string            `json:"owner"`
}

var listCommand = cli.Command{
	Name:  "list",
	Usage: "lists sandboxes started by boots with the given root",
	ArgsUsage: `

Where the given root is specified via the global option "--root"
(default: "/run/boots").

EXAMPLE 1:
To list sandboxes created via the default "--root":
       # boots list

EXAMPLE 2:
To list sandboxes created using a non-default value for "--root":
       # boots --root value list`,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "format, f",
			Value: "table",
			Usage: `select one of: ` + formatOptions,
		},
		cli.BoolFlag{
			Name:  "quiet, q",
			Usage: "display only sandbox IDs",
		},
	},
	Action: func(ctx *cli.Context) error {
		if err := checkArgs(ctx, 0, exactArgs); err != nil {
			return err
		}
		s, err := getSandboxList(ctx)
		if err != nil {
			return err
		}
		if ctx.Bool("quiet") {
			for _, item := range s {
				fmt.Println(item.ID)
			}
			return nil
		}

		switch ctx.String("format") {
		case "table":
			w := tabwriter.NewWriter(os.Stdout, 12, 1, 3, ' ', 0)
			_, _ = fmt.Fprint(w, "ID\tPID\tSTATUS\tBUNDLE\tCREATED\tOWNER\n")
			for _, item := range s {
				_, _ = fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\t%s\n",
					item.ID,
					item.InitProcessPid,
					item.Status,
					item.Bundle,
					item.Created.Format(time.RFC3339Nano),
					item.Owner)
			}
			if err := w.Flush(); err != nil {
				return err
			}
		case "json":
			if err := json.NewEncoder(os.Stdout).Encode(s); err != nil {
				return err
			}
		default:
			return errors.New("invalid format option")
		}
		return nil
	},
}

func getSandboxList(ctx *cli.Context) ([]sandboxState, error) {
	root := ctx.GlobalString("root")
	list, err := os.ReadDir(root)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && ctx.IsSet("root") {
			return nil, nil
		}
		return nil, err
	}
	debug := ctx.GlobalBool("debug")
	var s []sandboxState
	for _, item := range list {
		if !item.IsDir() {
			continue
		}
		st, err := item.Info()
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, err
		}
		uid := st.Sys().(*syscall.Stat_t).Uid
		owner, err := user.LookupId(strconv.Itoa(int(uid)))
		if err != nil {
			owner.Name = fmt.Sprintf("#%d", uid)
		}

		c, err := sandbox.Load(root, item.Name(), debug)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "load sandbox %s: %v\n", item.Name(), err)
			continue
		}
		sandboxStatus, err := c.Status()
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "status for %s: %v\n", item.Name(), err)
			continue
		}
		if debug {
			fmt.Println("sandbox status", c.ID(), sandboxStatus)
		}
		state, err := c.State()
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "state for %s: %v\n", item.Name(), err)
			continue
		}
		pid := state.BaseState.InitProcessPid
		if sandboxStatus == sandbox.Stopped {
			pid = 0
		}
		bundle, annotations := utils.Annotations(state.Config.Labels)
		s = append(s, sandboxState{
			Version:        state.BaseState.Config.Version,
			ID:             state.BaseState.ID,
			InitProcessPid: pid,
			Status:         sandboxStatus.String(),
			Bundle:         bundle,
			Rootfs:         state.BaseState.Config.Rootfs,
			Created:        state.BaseState.Created,
			Annotations:    annotations,
			Owner:          owner.Name,
		})
	}
	return s, nil
}
