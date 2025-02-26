package sandbox

import (
	"errors"
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
	Hooks                Hooks    `json:"-"`
}

type Net struct {
	IPAddress string `json:"ip_address"`
	Gateway   string `json:"gateway"`
	Subnet    string `json:"subnet"`
	Eth       string `json:"eth"`
}

func (n *Net) Validate() error {
	if n.IPAddress == "" || n.Gateway == "" || n.Subnet == "" {
		// TODO: ip validate
		return errors.New("ip_address and gateway must be provided")
	}
	return nil
}

func (n *Net) String() string {
	if n.Eth == "" {
		n.Eth = "eth0"
	}
	// 192.168.100.18::192.168.100.1:255.255.255.0::eth0:off
	// https://www.kernel.org/doc/Documentation/filesystems/nfs/nfsroot.txt
	return fmt.Sprintf("%s::%s:%s::%s:off", n.IPAddress, n.Gateway, n.Subnet, n.Eth)
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
