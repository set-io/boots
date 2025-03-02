package sandbox

import (
	"fmt"
	"github.com/set-io/boots/utils/iface"
	"log"
	"os"
)

func AddNetwork(br, subnet, ifa string) error {
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
