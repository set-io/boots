package sandbox

import (
	"errors"
	"fmt"
	"github.com/set-io/boots/utils"
	"net"
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

type Subnet struct {
	Gateway string `json:"gateway"`
	Mask    string `json:"mask"`
}

func (s Subnet) String() string {
	n, err := s.MaskToPrefix()
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("%s/%d", s.Gateway, n)
}

func (s Subnet) MaskToPrefix() (int, error) {
	ip := net.ParseIP(s.Mask)
	if ip == nil {
		return 0, fmt.Errorf("invalid mask")
	}
	mask := net.IPMask(ip.To4())
	ones, bits := mask.Size()
	if bits == 0 {
		return 0, fmt.Errorf("invalid mask")
	}
	return ones, nil
}

type Net struct {
	IPAddress string `json:"ip_address"`
	Subnet    Subnet `json:"subnet"`
	Eth       string `json:"eth"`
}

func (n *Net) Validate() error {
	if n.IPAddress == "" || n.Subnet.Gateway == "" || n.Subnet.Mask == "" {
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
	return fmt.Sprintf("%s::%s:%s::%s:off", n.IPAddress, n.Subnet.Gateway, n.Subnet.Mask, n.Eth)
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
