package cmd

import (
	"encoding/json"
	"github.com/set-io/boots/cmd/cli"
	"github.com/set-io/boots/sandbox"
	"github.com/set-io/boots/utils"
	"os"
)

var stateCommand = cli.Command{
	Name:  "state",
	Usage: "output the state of a sandbox",
	ArgsUsage: `<sandbox-id>

Where "<sandbox-id>" is your name for the instance of the sandbox.`,
	Description: `The state command outputs current state information for the
instance of a sandbox.`,
	Action: func(context *cli.Context) error {
		if err := checkArgs(context, 1, exactArgs); err != nil {
			return err
		}
		s, err := getSandbox(context)
		if err != nil {
			return err
		}
		sandboxStatus, err := s.Status()
		if err != nil {
			return err
		}
		state, err := s.State()
		if err != nil {
			return err
		}
		pid := state.BaseState.InitProcessPid
		if sandboxStatus == sandbox.Stopped {
			pid = 0
		}
		bundle, annotations := utils.Annotations(state.Config.Labels)
		cs := sandboxState{
			Version:        state.BaseState.Config.Version,
			ID:             state.BaseState.ID,
			InitProcessPid: pid,
			Status:         sandboxStatus.String(),
			Bundle:         bundle,
			Rootfs:         state.BaseState.Config.Rootfs,
			Interface:      state.BaseState.Config.GetHypervisorParameters("interface"),
			Created:        state.BaseState.Created,
			Annotations:    annotations,
		}
		data, err := json.MarshalIndent(cs, "", "  ")
		if err != nil {
			return err
		}
		os.Stdout.Write(data)
		return nil
	},
}
