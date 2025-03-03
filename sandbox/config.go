package sandbox

import (
	"fmt"
	"github.com/set-io/boots/utils"
)

const (
	User   = "org.set-io.boots.user"
	Cipher = "org.set-io.boots.cipher"
	Addr   = "org.set-io.boots.addr"
)

type Config struct {
	Debug                bool
	RootDir              string
	Labels               []string `json:"labels"`
	Version              string   `json:"version"`
	Rootfs               string   `json:"rootfs"`
	Hostname             string   `json:"hostname"`
	HypervisorPath       string   `json:"hypervisor_path"`
	HypervisorParameters []string `json:"hypervisor_parameters,omitempty"`
	KernelPath           string   `json:"kernel_path"`
	KernelParameters     []string `json:"kernel_parameters,omitempty"`
	InitRD               string   `json:"initrd,omitempty"`
	Probe                bool     `json:"probe,omitempty"`
	Stable               bool     `json:"stable,omitempty"`
	Net                  Net      `json:"net"`
	Bridge               string   `json:"bridge"`
	Hooks                Hooks    `json:"-"`
}

func (c *Config) Validate() error {
	if len(c.Hostname) > 64 {
		return fmt.Errorf("hostname length exceeds maximum of 64 characters")
	}
	if c.Hooks == nil {
		c.Hooks = make(Hooks)
	}
	if err := c.Net.Validate(); err != nil {
		return fmt.Errorf("invalid net configuration: %w", err)
	}
	return nil
}

func (c *Config) GetHypervisorParameters(key string) string {
	return utils.GetParams(c.HypervisorParameters, key)
}
