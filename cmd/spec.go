package cmd

import (
	"encoding/json"
	"fmt"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/set-io/boots/cmd/cli"
	"os"
)

var specCommand = cli.Command{
	Name:      "spec",
	Usage:     "create a new specification file",
	ArgsUsage: "",
	Description: `The spec command creates the new specification file named "` + SpecConfig + `" for
the bundle.

The spec generated is just a starter file. Editing of the spec is required to
achieve desired results. For example, the newly generated spec includes an args.

An alternative for generating a customized spec config is to use "oci-runtime-tool", the
sub-command "oci-runtime-tool generate" has lots of options that can be used to do any
customizations as you want, see runtime-tools (https://github.com/opencontainers/runtime-tools)
to get more information.

When starting a sandbox through boots, boots needs root privilege. If not
already running as root, you can use sudo to give boots root privilege. For
example: "sudo boots start sandbox1" will give boots root privilege to start the
sandbox on your host.
`,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "bundle, b",
			Value: "",
			Usage: "path to the root of the bundle directory",
		},
		cli.BoolFlag{
			Name:  "debug",
			Usage: "run the sandbox in debug mode",
		},
	},
	Action: func(context *cli.Context) error {
		spec := specStable()
		if context.Bool("debug") {
			spec = specDebug()
		}
		checkNoFile := func(name string) error {
			_, err := os.Stat(name)
			if err == nil {
				return fmt.Errorf("file %s exists. remove it first", name)
			}
			if !os.IsNotExist(err) {
				return err
			}
			return nil
		}
		bundle := context.String("bundle")
		if bundle != "" {
			if err := os.Chdir(bundle); err != nil {
				return err
			}
		}
		if err := checkNoFile(SpecConfig); err != nil {
			return err
		}
		data, err := json.MarshalIndent(spec, "", "\t")
		if err != nil {
			return err
		}
		return os.WriteFile(SpecConfig, data, 0o666)
	},
}

func specStable() *specs.Spec {
	return &specs.Spec{
		Version: specs.Version,
		Root: &specs.Root{
			Path:     "/dev/vda",
			Readonly: false,
		},
		Process: &specs.Process{
			Terminal: true,
			User:     specs.User{Username: "root"},
			Args: []string{
				"/bin/bash",
				"helloworld.sh",
				"--greeting",
				"Hello",
			},
			Env: []string{
				"USER_NAME=Alice",
				"LANGUAGE=en",
				"GREETING_COLOR=blue",
				"SHOW_TIME=true",
				"TIME_FORMAT=%H:%M:%S",
			},
			Cwd: "/home/app",
			Rlimits: []specs.POSIXRlimit{
				{
					Type: "RLIMIT_NOFILE",
					Hard: uint64(1024),
					Soft: uint64(1024),
				},
			},
		},
		Hostname: "",
		Annotations: map[string]string{
			"rootfstype": "ext4",
			"ip":         "",
			"gateway":    "",
			"mask":       "",
			"eth":        "",
		},
		VM: &specs.VM{
			Hypervisor: specs.VMHypervisor{
				Path: "./boots",
				Parameters: []string{
					"cpus=1",
					"memory=2G",
					"interface=tap0",
					"net=tap",
				},
			},
			Kernel: specs.VMKernel{
				Path: "bzImage",
				Parameters: []string{
					"console=ttyS0",
					"quiet",
					"loglevel=0",
					"rd.udev.log_level=0",
					"rd.systemd.show_status=0",
					"systemd.show_status=0",
					"vt.global_cursor_default=0",
					"plymouth.enable=0",
					"nosplash",
					"noapic noacpi",
					"notsc nowatchdog",
					"nmi_watchdog=0",
					"mitigations=off",
					"lapic",
					"rw",
					"tsc_early_khz=2000",
					"pci=realloc=off",
					"virtio_pci.force_legacy=1",
				},
				InitRD: "initrd",
			},
			Image: specs.VMImage{
				Path:   "rootfs.img",
				Format: "raw",
			},
		},
	}
}

func specDebug() *specs.Spec {
	return &specs.Spec{
		Version: specs.Version,
		Root: &specs.Root{
			Path:     "/dev/vda",
			Readonly: false,
		},
		Process: &specs.Process{
			Terminal: true,
			User:     specs.User{Username: "root"},
			Args: []string{
				"/bin/bash",
				"helloworld.sh",
				"--greeting",
				"Hello",
			},
			Env: []string{
				"USER_NAME=Alice",
				"LANGUAGE=en",
				"GREETING_COLOR=blue",
				"SHOW_TIME=true",
				"TIME_FORMAT=%H:%M:%S",
			},
			Cwd: "/home/app",
			Rlimits: []specs.POSIXRlimit{
				{
					Type: "RLIMIT_NOFILE",
					Hard: uint64(1024),
					Soft: uint64(1024),
				},
			},
		},
		Hostname: "",
		Annotations: map[string]string{
			"rootfstype": "ext4",
			"ip":         "",
			"gateway":    "",
			"mask":       "",
			"eth":        "",
		},
		VM: &specs.VM{
			Hypervisor: specs.VMHypervisor{
				Path: "./boots",
				Parameters: []string{
					"cpus=1",
					"memory=2G",
					"interface=tap0",
					"net=tap",
				},
			},
			Kernel: specs.VMKernel{
				Path: "bzImage",
				Parameters: []string{
					"console=ttyS0",
					"debug",
					"earlyprintk=serial",
					"noapic noacpi ",
					"notsc nowatchdog",
					"nmi_watchdog=0 ",
					"debug apic=debug show_lapic=all",
					"mitigations=off",
					"lapic",
					"tsc_early_khz=2000",
					"dyndbg=\"file arch/x86/kernel/smpboot.c +plf ; file drivers/net/virtio_net.c +plf\"",
					"pci=realloc=off",
					"rw",
					"virtio_pci.force_legacy=1",
				},
				InitRD: "initrd",
			},
			Image: specs.VMImage{
				Path:   "rootfs.img",
				Format: "raw",
			},
		},
	}
}
