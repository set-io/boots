package sandbox

import (
	"errors"
	"fmt"
	"github.com/set-io/boots/utils/iface"
	"log"
	"net"
	"os"
)

type Net struct {
	IPAddress string `json:"ip_address"`
	Subnet    Subnet `json:"subnet"`
	Eth       string `json:"eth"`
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

func (n *Net) Add(br, ifa string) error {
	subnet := n.Subnet.String()
	bridge, err := iface.LinkByName(br)
	if err != nil {
		bridge = &iface.Bridge{
			LinkAttrs: iface.LinkAttrs{
				Name: br,
			},
		}
		if err := iface.LinkAdd(bridge); err != nil {
			return fmt.Errorf("failed to create bridge: %v", err)
		}
		if debug {
			log.Printf("created new bridge: %s\n", br)
		}
	}

	if debug {
		log.Printf("using existing bridge: %s\n", br)
	}

	if debug {
		log.Printf("subnet is: %s\n", subnet)
	}

	addr, err := iface.ParseAddr(subnet)
	if err != nil {
		return fmt.Errorf("failed to parse address: %v", err)
	}

	if err := iface.AddrAdd(bridge, addr); err != nil {
		if os.IsExist(err) {
			if debug {
				log.Printf("ip address %s already exists, skipping...\n", addr.IPNet.String())
			}
		} else {
			return fmt.Errorf("failed to add address: %v", err)
		}
	}

	if err := iface.LinkSetUp(bridge); err != nil {
		return fmt.Errorf("failed to set bridge up: %v", err)
	}

	ifac, err := iface.LinkByName(ifa)
	if err != nil {
		return fmt.Errorf("failed to get interface(%s): %v\n", ifac, err)
	}

	if err := iface.LinkSetMaster(ifac, bridge); err != nil {
		return fmt.Errorf("failed to add interface(%s) to bridge: %v", ifac, err)
	}

	if err := iface.LinkSetUp(ifac); err != nil {
		return fmt.Errorf("failed to set interface(%s) up: %v", ifac, err)
	}

	if debug {
		log.Println("bridge and IF devices configured successfully")
	}
	return nil
}
