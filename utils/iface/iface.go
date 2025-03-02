package iface

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"golang.org/x/sys/unix"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"
)

var pkgHandle = &Handle{}

type Handle struct {
	sockets      map[int]*SocketHandle
	lookupByDump bool
}

type SocketHandle struct {
	Seq    uint32
	Socket *NetlinkSocket
}

type NetlinkSocket struct {
	fd   int32
	file *os.File
	lsa  unix.SockaddrNetlink
	sync.Mutex
}

func (s *NetlinkSocket) Close() {
	s.file.Close()
}

type Link interface {
	Attrs() *LinkAttrs
	Type() string
}

type (
	NsPid int
	NsFd  int
)

type LinkAttrs struct {
	Index          int
	MTU            int
	TxQLen         int // Transmit Queue Length
	Name           string
	HardwareAddr   net.HardwareAddr
	Flags          net.Flags
	RawFlags       uint32
	ParentIndex    int         // index of the parent link device
	MasterIndex    int         // must be the index of a bridge
	Namespace      interface{} // nil | NsPid | NsFd
	Alias          string
	AltNames       []string
	Promisc        int
	Allmulti       int
	Multi          int
	EncapType      string
	Protinfo       *Protinfo
	OperState      LinkOperState
	PhysSwitchID   int
	NetNsID        int
	NumTxQueues    int
	NumRxQueues    int
	TSOMaxSegs     uint32
	TSOMaxSize     uint32
	GSOMaxSegs     uint32
	GSOMaxSize     uint32
	GROMaxSize     uint32
	GSOIPv4MaxSize uint32
	GROIPv4MaxSize uint32
	Vfs            []VfInfo // virtual functions available on link
	Group          uint32
	PermHWAddr     net.HardwareAddr
}

type VfInfo struct {
	ID        int
	Mac       net.HardwareAddr
	Vlan      int
	Qos       int
	VlanProto int
	TxRate    int // IFLA_VF_TX_RATE  Max TxRate
	Spoofchk  bool
	LinkState uint32
	MaxTxRate uint32 // IFLA_VF_RATE Max TxRate
	MinTxRate uint32 // IFLA_VF_RATE Min TxRate
	RxPackets uint64
	TxPackets uint64
	RxBytes   uint64
	TxBytes   uint64
	Multicast uint64
	Broadcast uint64
	RxDropped uint64
	TxDropped uint64

	RssQuery uint32
	Trust    uint32
}

type LinkOperState uint8

const (
	OperUnknown        = iota // Status can't be determined.
	OperNotPresent            // Some component is missing.
	OperDown                  // Down.
	OperLowerLayerDown        // Down due to state of lower layer.
	OperTesting               // In some test mode.
	OperDormant               // Not up but pending an external event.
	OperUp                    // Up, ready to send packets.
)

func (s LinkOperState) String() string {
	switch s {
	case OperNotPresent:
		return "not-present"
	case OperDown:
		return "down"
	case OperLowerLayerDown:
		return "lower-layer-down"
	case OperTesting:
		return "testing"
	case OperDormant:
		return "dormant"
	case OperUp:
		return "up"
	default:
		return "unknown"
	}
}

type Protinfo struct {
	Hairpin       bool
	Guard         bool
	FastLeave     bool
	RootBlock     bool
	Learning      bool
	Flood         bool
	ProxyArp      bool
	ProxyArpWiFi  bool
	Isolated      bool
	NeighSuppress bool
}

func byteToBool(x byte) bool {
	return uint8(x) != 0
}

const (
	IFLA_BRPORT_UNSPEC = iota
	IFLA_BRPORT_STATE
	IFLA_BRPORT_PRIORITY
	IFLA_BRPORT_COST
	IFLA_BRPORT_MODE
	IFLA_BRPORT_GUARD
	IFLA_BRPORT_PROTECT
	IFLA_BRPORT_FAST_LEAVE
	IFLA_BRPORT_LEARNING
	IFLA_BRPORT_UNICAST_FLOOD
	IFLA_BRPORT_PROXYARP
	IFLA_BRPORT_LEARNING_SYNC
	IFLA_BRPORT_PROXYARP_WIFI
	IFLA_BRPORT_ROOT_ID
	IFLA_BRPORT_BRIDGE_ID
	IFLA_BRPORT_DESIGNATED_PORT
	IFLA_BRPORT_DESIGNATED_COST
	IFLA_BRPORT_ID
	IFLA_BRPORT_NO
	IFLA_BRPORT_TOPOLOGY_CHANGE_ACK
	IFLA_BRPORT_CONFIG_PENDING
	IFLA_BRPORT_MESSAGE_AGE_TIMER
	IFLA_BRPORT_FORWARD_DELAY_TIMER
	IFLA_BRPORT_HOLD_TIMER
	IFLA_BRPORT_FLUSH
	IFLA_BRPORT_MULTICAST_ROUTER
	IFLA_BRPORT_PAD
	IFLA_BRPORT_MCAST_FLOOD
	IFLA_BRPORT_MCAST_TO_UCAST
	IFLA_BRPORT_VLAN_TUNNEL
	IFLA_BRPORT_BCAST_FLOOD
	IFLA_BRPORT_GROUP_FWD_MASK
	IFLA_BRPORT_NEIGH_SUPPRESS
	IFLA_BRPORT_ISOLATED
	IFLA_BRPORT_BACKUP_PORT
	IFLA_BRPORT_MRP_RING_OPEN
	IFLA_BRPORT_MRP_IN_OPEN
	IFLA_BRPORT_MCAST_EHT_HOSTS_LIMIT
	IFLA_BRPORT_MCAST_EHT_HOSTS_CNT
	IFLA_BRPORT_LOCKED
	IFLA_BRPORT_MAB
	IFLA_BRPORT_MCAST_N_GROUPS
	IFLA_BRPORT_MCAST_MAX_GROUPS
	IFLA_BRPORT_MAX = IFLA_BRPORT_MCAST_MAX_GROUPS
)

func parseProtinfo(infos []syscall.NetlinkRouteAttr) (pi Protinfo) {
	for _, info := range infos {
		switch info.Attr.Type {
		case IFLA_BRPORT_MODE:
			pi.Hairpin = byteToBool(info.Value[0])
		case IFLA_BRPORT_GUARD:
			pi.Guard = byteToBool(info.Value[0])
		case IFLA_BRPORT_FAST_LEAVE:
			pi.FastLeave = byteToBool(info.Value[0])
		case IFLA_BRPORT_PROTECT:
			pi.RootBlock = byteToBool(info.Value[0])
		case IFLA_BRPORT_LEARNING:
			pi.Learning = byteToBool(info.Value[0])
		case IFLA_BRPORT_UNICAST_FLOOD:
			pi.Flood = byteToBool(info.Value[0])
		case IFLA_BRPORT_PROXYARP:
			pi.ProxyArp = byteToBool(info.Value[0])
		case IFLA_BRPORT_PROXYARP_WIFI:
			pi.ProxyArpWiFi = byteToBool(info.Value[0])
		case IFLA_BRPORT_ISOLATED:
			pi.Isolated = byteToBool(info.Value[0])
		case IFLA_BRPORT_NEIGH_SUPPRESS:
			pi.NeighSuppress = byteToBool(info.Value[0])
		}
	}
	return
}

// String returns a list of enabled flags
func (prot *Protinfo) String() string {
	if prot == nil {
		return "<nil>"
	}

	var boolStrings []string
	if prot.Hairpin {
		boolStrings = append(boolStrings, "Hairpin")
	}
	if prot.Guard {
		boolStrings = append(boolStrings, "Guard")
	}
	if prot.FastLeave {
		boolStrings = append(boolStrings, "FastLeave")
	}
	if prot.RootBlock {
		boolStrings = append(boolStrings, "RootBlock")
	}
	if prot.Learning {
		boolStrings = append(boolStrings, "Learning")
	}
	if prot.Flood {
		boolStrings = append(boolStrings, "Flood")
	}
	if prot.ProxyArp {
		boolStrings = append(boolStrings, "ProxyArp")
	}
	if prot.ProxyArpWiFi {
		boolStrings = append(boolStrings, "ProxyArpWiFi")
	}
	if prot.Isolated {
		boolStrings = append(boolStrings, "Isolated")
	}
	if prot.NeighSuppress {
		boolStrings = append(boolStrings, "NeighSuppress")
	}
	return strings.Join(boolStrings, " ")
}

func LinkAdd(link Link) error {
	return pkgHandle.LinkAdd(link)
}

func LinkByName(name string) (Link, error) {
	return pkgHandle.LinkByName(name)
}

type NetlinkRequest struct {
	unix.NlMsghdr
	Data    []NetlinkRequestData
	RawData []byte
	Sockets map[int]*SocketHandle
}

type NetlinkRequestData interface {
	Len() int
	Serialize() []byte
}

var nextSeqNr uint32

func NewNetlinkRequest(proto, flags int) *NetlinkRequest {
	return &NetlinkRequest{
		NlMsghdr: unix.NlMsghdr{
			Len:   uint32(unix.SizeofNlMsghdr),
			Type:  uint16(proto),
			Flags: unix.NLM_F_REQUEST | uint16(flags),
			Seq:   atomic.AddUint32(&nextSeqNr, 1),
		},
	}
}

func (h *Handle) newNetlinkRequest(proto, flags int) *NetlinkRequest {
	if h.sockets == nil {
		return NewNetlinkRequest(proto, flags)
	}
	return &NetlinkRequest{
		NlMsghdr: unix.NlMsghdr{
			Len:   uint32(unix.SizeofNlMsghdr),
			Type:  uint16(proto),
			Flags: unix.NLM_F_REQUEST | uint16(flags),
		},
		Sockets: h.sockets,
	}
}

type LinkNotFoundError struct {
	error
}

func (h *Handle) linkByNameDump(name string) (Link, error) {
	links, err := h.LinkList()
	if err != nil {
		return nil, err
	}

	for _, link := range links {
		if link.Attrs().Name == name {
			return link, nil
		}
		for _, altName := range link.Attrs().AltNames {
			if altName == name {
				return link, nil
			}
		}
	}
	return nil, LinkNotFoundError{fmt.Errorf("Link %s not found", name)}
}

type IfInfomsg struct {
	unix.IfInfomsg
}

func (msg *IfInfomsg) Len() int {
	return unix.SizeofIfInfomsg
}

func NewIfInfomsg(family int) *IfInfomsg {
	return &IfInfomsg{
		IfInfomsg: unix.IfInfomsg{
			Family: uint8(family),
		},
	}
}

func (req *NetlinkRequest) AddData(data NetlinkRequestData) {
	req.Data = append(req.Data, data)
}

func (msg *IfInfomsg) Serialize() []byte {
	return (*(*[unix.SizeofIfInfomsg]byte)(unsafe.Pointer(msg)))[:]
}

type RtAttr struct {
	unix.RtAttr
	Data     []byte
	children []NetlinkRequestData
}

func NewRtAttr(attrType int, data []byte) *RtAttr {
	return &RtAttr{
		RtAttr: unix.RtAttr{
			Type: uint16(attrType),
		},
		children: []NetlinkRequestData{},
		Data:     data,
	}
}

func (a *RtAttr) Len() int {
	if len(a.children) == 0 {
		return (unix.SizeofRtAttr + len(a.Data))
	}

	l := 0
	for _, child := range a.children {
		l += rtaAlignOf(child.Len())
	}
	l += unix.SizeofRtAttr
	return rtaAlignOf(l + len(a.Data))
}

func (a *RtAttr) Serialize() []byte {
	native := NativeEndian()

	length := a.Len()
	buf := make([]byte, rtaAlignOf(length))

	next := 4
	if a.Data != nil {
		copy(buf[next:], a.Data)
		next += rtaAlignOf(len(a.Data))
	}
	if len(a.children) > 0 {
		for _, child := range a.children {
			childBuf := child.Serialize()
			copy(buf[next:], childBuf)
			next += rtaAlignOf(len(childBuf))
		}
	}

	if l := uint16(length); l != 0 {
		native.PutUint16(buf[0:2], l)
	}
	native.PutUint16(buf[2:4], a.Type)
	return buf
}

func Uint32Attr(v uint32) []byte {
	native := NativeEndian()
	bytes := make([]byte, 4)
	native.PutUint32(bytes, v)
	return bytes
}

var nativeEndian binary.ByteOrder

func NativeEndian() binary.ByteOrder {
	if nativeEndian == nil {
		var x uint32 = 0x01020304
		if *(*byte)(unsafe.Pointer(&x)) == 0x01 {
			nativeEndian = binary.BigEndian
		} else {
			nativeEndian = binary.LittleEndian
		}
	}
	return nativeEndian
}

const (
	RTEXT_FILTER_VF = 1 << iota
	RTEXT_FILTER_BRVLAN
	RTEXT_FILTER_BRVLAN_COMPRESSED
)

func (req *NetlinkRequest) Execute(sockType int, resType uint16) ([][]byte, error) {
	var res [][]byte
	err := req.ExecuteIter(sockType, resType, func(msg []byte) bool {
		res = append(res, msg)
		return true
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

func getNetlinkSocket(protocol int) (*NetlinkSocket, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, protocol)
	if err != nil {
		return nil, err
	}
	err = unix.SetNonblock(fd, true)
	if err != nil {
		return nil, err
	}
	s := &NetlinkSocket{
		fd:   int32(fd),
		file: os.NewFile(uintptr(fd), "netlink"),
	}
	s.lsa.Family = unix.AF_NETLINK
	if err := unix.Bind(fd, &s.lsa); err != nil {
		unix.Close(fd)
		return nil, err
	}

	return s, nil
}

func (s *NetlinkSocket) SetSendTimeout(timeout *unix.Timeval) error {
	return unix.SetsockoptTimeval(int(s.fd), unix.SOL_SOCKET, unix.SO_SNDTIMEO, timeout)
}

func (s *NetlinkSocket) SetReceiveTimeout(timeout *unix.Timeval) error {
	return unix.SetsockoptTimeval(int(s.fd), unix.SOL_SOCKET, unix.SO_RCVTIMEO, timeout)
}

var SocketTimeoutTv = unix.Timeval{Sec: 60, Usec: 0}
var EnableErrorMessageReporting bool = false

func (s *NetlinkSocket) SetExtAck(enable bool) error {
	var enableN int
	if enable {
		enableN = 1
	}
	return unix.SetsockoptInt(int(s.fd), unix.SOL_NETLINK, unix.NETLINK_EXT_ACK, enableN)
}

func (sh *SocketHandle) Close() {
	if sh.Socket != nil {
		sh.Socket.Close()
	}
}

func (s *NetlinkSocket) Send(request *NetlinkRequest) error {
	return unix.Sendto(int(s.fd), request.Serialize(), 0, &s.lsa)
}

func (req *NetlinkRequest) Serialize() []byte {
	length := unix.SizeofNlMsghdr
	dataBytes := make([][]byte, len(req.Data))
	for i, data := range req.Data {
		dataBytes[i] = data.Serialize()
		length = length + len(dataBytes[i])
	}
	length += len(req.RawData)

	req.Len = uint32(length)
	b := make([]byte, length)
	hdr := (*(*[unix.SizeofNlMsghdr]byte)(unsafe.Pointer(req)))[:]
	next := unix.SizeofNlMsghdr
	copy(b[0:next], hdr)
	for _, data := range dataBytes {
		for _, dataByte := range data {
			b[next] = dataByte
			next = next + 1
		}
	}
	// Add the raw data if any
	if len(req.RawData) > 0 {
		copy(b[next:length], req.RawData)
	}
	return b
}

func (s *NetlinkSocket) GetPid() (uint32, error) {
	lsa, err := unix.Getsockname(int(s.fd))
	if err != nil {
		return 0, err
	}
	switch v := lsa.(type) {
	case *unix.SockaddrNetlink:
		return v.Pid, nil
	}
	return 0, fmt.Errorf("Wrong socket type")
}

const (
	// Family type definitions
	FAMILY_ALL  = unix.AF_UNSPEC
	FAMILY_V4   = unix.AF_INET
	FAMILY_V6   = unix.AF_INET6
	FAMILY_MPLS = unix.AF_MPLS
	// Arbitrary set value (greater than default 4k) to allow receiving
	// from kernel more verbose messages e.g. for statistics,
	// tc rules or filters, or other more memory requiring data.
	RECEIVE_BUFFER_SIZE = 65536
	// Kernel netlink pid
	PidKernel     uint32 = 0
	SizeofCnMsgOp        = 0x18
)

func nlmAlignOf(msglen int) int {
	return (msglen + syscall.NLMSG_ALIGNTO - 1) & ^(syscall.NLMSG_ALIGNTO - 1)
}

func (s *NetlinkSocket) Receive() ([]syscall.NetlinkMessage, *unix.SockaddrNetlink, error) {
	rawConn, err := s.file.SyscallConn()
	if err != nil {
		return nil, nil, err
	}
	var (
		fromAddr *unix.SockaddrNetlink
		rb       [RECEIVE_BUFFER_SIZE]byte
		nr       int
		from     unix.Sockaddr
		innerErr error
	)
	err = rawConn.Read(func(fd uintptr) (done bool) {
		nr, from, innerErr = unix.Recvfrom(int(fd), rb[:], 0)
		return innerErr != unix.EWOULDBLOCK
	})
	if innerErr != nil {
		err = innerErr
	}
	if err != nil {
		return nil, nil, err
	}
	fromAddr, ok := from.(*unix.SockaddrNetlink)
	if !ok {
		return nil, nil, fmt.Errorf("Error converting to netlink sockaddr")
	}
	if nr < unix.NLMSG_HDRLEN {
		return nil, nil, fmt.Errorf("Got short response from netlink")
	}
	msgLen := nlmAlignOf(nr)
	rb2 := make([]byte, msgLen)
	copy(rb2, rb[:msgLen])
	nl, err := syscall.ParseNetlinkMessage(rb2)
	if err != nil {
		return nil, nil, err
	}
	return nl, fromAddr, nil
}

const (
	NLMSGERR_ATTR_UNUSED = 0
	NLMSGERR_ATTR_MSG    = 1
	NLMSGERR_ATTR_OFFS   = 2
	NLMSGERR_ATTR_COOKIE = 3
	NLMSGERR_ATTR_POLICY = 4
)

func rtaAlignOf(attrlen int) int {
	return (attrlen + unix.RTA_ALIGNTO - 1) & ^(unix.RTA_ALIGNTO - 1)
}

func (req *NetlinkRequest) ExecuteIter(sockType int, resType uint16, f func(msg []byte) bool) error {
	var (
		s   *NetlinkSocket
		err error
	)

	if req.Sockets != nil {
		if sh, ok := req.Sockets[sockType]; ok {
			s = sh.Socket
			req.Seq = atomic.AddUint32(&sh.Seq, 1)
		}
	}
	sharedSocket := s != nil

	if s == nil {
		s, err = getNetlinkSocket(sockType)
		if err != nil {
			return err
		}

		if err := s.SetSendTimeout(&SocketTimeoutTv); err != nil {
			return err
		}
		if err := s.SetReceiveTimeout(&SocketTimeoutTv); err != nil {
			return err
		}
		if EnableErrorMessageReporting {
			if err := s.SetExtAck(true); err != nil {
				return err
			}
		}

		defer s.Close()
	} else {
		s.Lock()
		defer s.Unlock()
	}

	if err := s.Send(req); err != nil {
		return err
	}

	pid, err := s.GetPid()
	if err != nil {
		return err
	}

done:
	for {
		msgs, from, err := s.Receive()
		if err != nil {
			return err
		}
		if from.Pid != PidKernel {
			return fmt.Errorf("Wrong sender portid %d, expected %d", from.Pid, PidKernel)
		}
		for _, m := range msgs {
			if m.Header.Seq != req.Seq {
				if sharedSocket {
					continue
				}
				return fmt.Errorf("Wrong Seq nr %d, expected %d", m.Header.Seq, req.Seq)
			}
			if m.Header.Pid != pid {
				continue
			}

			if m.Header.Flags&unix.NLM_F_DUMP_INTR != 0 {
				return syscall.Errno(unix.EINTR)
			}

			if m.Header.Type == unix.NLMSG_DONE || m.Header.Type == unix.NLMSG_ERROR {
				if m.Header.Type == unix.NLMSG_DONE && len(m.Data) == 0 {
					break done
				}

				native := NativeEndian()
				errno := int32(native.Uint32(m.Data[0:4]))
				if errno == 0 {
					break done
				}
				var err error
				err = syscall.Errno(-errno)

				unreadData := m.Data[4:]
				if m.Header.Flags&unix.NLM_F_ACK_TLVS != 0 && len(unreadData) > syscall.SizeofNlMsghdr {
					echoReqH := (*syscall.NlMsghdr)(unsafe.Pointer(&unreadData[0]))
					unreadData = unreadData[nlmAlignOf(int(echoReqH.Len)):]

					for len(unreadData) >= syscall.SizeofRtAttr {
						attr := (*syscall.RtAttr)(unsafe.Pointer(&unreadData[0]))
						attrData := unreadData[syscall.SizeofRtAttr:attr.Len]

						switch attr.Type {
						case NLMSGERR_ATTR_MSG:
							err = fmt.Errorf("%w: %s", err, unix.ByteSliceToString(attrData))
						default:
							// TODO: handle other NLMSGERR_ATTR types
						}
						unreadData = unreadData[rtaAlignOf(int(attr.Len)):]
					}
				}
				return err
			}
			if resType != 0 && m.Header.Type != resType {
				continue
			}
			if cont := f(m.Data); !cont {
				f = dummyMsgIterFunc
			}
			if m.Header.Flags&unix.NLM_F_MULTI == 0 {
				break done
			}
		}
	}
	return nil
}

func dummyMsgIterFunc(msg []byte) bool {
	return true
}

func (h *Handle) LinkList() ([]Link, error) {
	req := h.newNetlinkRequest(unix.RTM_GETLINK, unix.NLM_F_DUMP)

	msg := NewIfInfomsg(unix.AF_UNSPEC)
	req.AddData(msg)
	attr := NewRtAttr(unix.IFLA_EXT_MASK, Uint32Attr(RTEXT_FILTER_VF))
	req.AddData(attr)

	msgs, err := req.Execute(unix.NETLINK_ROUTE, unix.RTM_NEWLINK)
	if err != nil {
		return nil, err
	}

	var res []Link
	for _, m := range msgs {
		link, err := LinkDeserialize(nil, m)
		if err != nil {
			return nil, err
		}
		res = append(res, link)
	}

	return res, nil
}

func DeserializeIfInfomsg(b []byte) *IfInfomsg {
	return (*IfInfomsg)(unsafe.Pointer(&b[0:unix.SizeofIfInfomsg][0]))
}

func netlinkRouteAttrAndValue(b []byte) (*unix.RtAttr, []byte, int, error) {
	a := (*unix.RtAttr)(unsafe.Pointer(&b[0]))
	if int(a.Len) < unix.SizeofRtAttr || int(a.Len) > len(b) {
		return nil, nil, 0, unix.EINVAL
	}
	return a, b[unix.SizeofRtAttr:], rtaAlignOf(int(a.Len)), nil
}

func ParseRouteAttr(b []byte) ([]syscall.NetlinkRouteAttr, error) {
	var attrs []syscall.NetlinkRouteAttr
	for len(b) >= unix.SizeofRtAttr {
		a, vbuf, alen, err := netlinkRouteAttrAndValue(b)
		if err != nil {
			return nil, err
		}
		ra := syscall.NetlinkRouteAttr{Attr: syscall.RtAttr(*a), Value: vbuf[:int(a.Len)-unix.SizeofRtAttr]}
		attrs = append(attrs, ra)
		b = b[alen:]
	}
	return attrs, nil
}

func NewLinkAttrs() LinkAttrs {
	return LinkAttrs{
		NetNsID: -1,
		TxQLen:  -1,
	}
}

func linkFlags(rawFlags uint32) net.Flags {
	var f net.Flags
	if rawFlags&unix.IFF_UP != 0 {
		f |= net.FlagUp
	}
	if rawFlags&unix.IFF_BROADCAST != 0 {
		f |= net.FlagBroadcast
	}
	if rawFlags&unix.IFF_LOOPBACK != 0 {
		f |= net.FlagLoopback
	}
	if rawFlags&unix.IFF_POINTOPOINT != 0 {
		f |= net.FlagPointToPoint
	}
	if rawFlags&unix.IFF_MULTICAST != 0 {
		f |= net.FlagMulticast
	}
	return f
}

func (msg *IfInfomsg) EncapType() string {
	switch msg.Type {
	case 0:
		return "generic"
	case unix.ARPHRD_ETHER:
		return "ether"
	case unix.ARPHRD_EETHER:
		return "eether"
	case unix.ARPHRD_AX25:
		return "ax25"
	case unix.ARPHRD_PRONET:
		return "pronet"
	case unix.ARPHRD_CHAOS:
		return "chaos"
	case unix.ARPHRD_IEEE802:
		return "ieee802"
	case unix.ARPHRD_ARCNET:
		return "arcnet"
	case unix.ARPHRD_APPLETLK:
		return "atalk"
	case unix.ARPHRD_DLCI:
		return "dlci"
	case unix.ARPHRD_ATM:
		return "atm"
	case unix.ARPHRD_METRICOM:
		return "metricom"
	case unix.ARPHRD_IEEE1394:
		return "ieee1394"
	case unix.ARPHRD_INFINIBAND:
		return "infiniband"
	case unix.ARPHRD_SLIP:
		return "slip"
	case unix.ARPHRD_CSLIP:
		return "cslip"
	case unix.ARPHRD_SLIP6:
		return "slip6"
	case unix.ARPHRD_CSLIP6:
		return "cslip6"
	case unix.ARPHRD_RSRVD:
		return "rsrvd"
	case unix.ARPHRD_ADAPT:
		return "adapt"
	case unix.ARPHRD_ROSE:
		return "rose"
	case unix.ARPHRD_X25:
		return "x25"
	case unix.ARPHRD_HWX25:
		return "hwx25"
	case unix.ARPHRD_PPP:
		return "ppp"
	case unix.ARPHRD_HDLC:
		return "hdlc"
	case unix.ARPHRD_LAPB:
		return "lapb"
	case unix.ARPHRD_DDCMP:
		return "ddcmp"
	case unix.ARPHRD_RAWHDLC:
		return "rawhdlc"
	case unix.ARPHRD_TUNNEL:
		return "ipip"
	case unix.ARPHRD_TUNNEL6:
		return "tunnel6"
	case unix.ARPHRD_FRAD:
		return "frad"
	case unix.ARPHRD_SKIP:
		return "skip"
	case unix.ARPHRD_LOOPBACK:
		return "loopback"
	case unix.ARPHRD_LOCALTLK:
		return "ltalk"
	case unix.ARPHRD_FDDI:
		return "fddi"
	case unix.ARPHRD_BIF:
		return "bif"
	case unix.ARPHRD_SIT:
		return "sit"
	case unix.ARPHRD_IPDDP:
		return "ip/ddp"
	case unix.ARPHRD_IPGRE:
		return "gre"
	case unix.ARPHRD_PIMREG:
		return "pimreg"
	case unix.ARPHRD_HIPPI:
		return "hippi"
	case unix.ARPHRD_ASH:
		return "ash"
	case unix.ARPHRD_ECONET:
		return "econet"
	case unix.ARPHRD_IRDA:
		return "irda"
	case unix.ARPHRD_FCPP:
		return "fcpp"
	case unix.ARPHRD_FCAL:
		return "fcal"
	case unix.ARPHRD_FCPL:
		return "fcpl"
	case unix.ARPHRD_FCFABRIC:
		return "fcfb0"
	case unix.ARPHRD_FCFABRIC + 1:
		return "fcfb1"
	case unix.ARPHRD_FCFABRIC + 2:
		return "fcfb2"
	case unix.ARPHRD_FCFABRIC + 3:
		return "fcfb3"
	case unix.ARPHRD_FCFABRIC + 4:
		return "fcfb4"
	case unix.ARPHRD_FCFABRIC + 5:
		return "fcfb5"
	case unix.ARPHRD_FCFABRIC + 6:
		return "fcfb6"
	case unix.ARPHRD_FCFABRIC + 7:
		return "fcfb7"
	case unix.ARPHRD_FCFABRIC + 8:
		return "fcfb8"
	case unix.ARPHRD_FCFABRIC + 9:
		return "fcfb9"
	case unix.ARPHRD_FCFABRIC + 10:
		return "fcfb10"
	case unix.ARPHRD_FCFABRIC + 11:
		return "fcfb11"
	case unix.ARPHRD_FCFABRIC + 12:
		return "fcfb12"
	case unix.ARPHRD_IEEE802_TR:
		return "tr"
	case unix.ARPHRD_IEEE80211:
		return "ieee802.11"
	case unix.ARPHRD_IEEE80211_PRISM:
		return "ieee802.11/prism"
	case unix.ARPHRD_IEEE80211_RADIOTAP:
		return "ieee802.11/radiotap"
	case unix.ARPHRD_IEEE802154:
		return "ieee802.15.4"

	case 65534:
		return "none"
	case 65535:
		return "void"
	}
	return fmt.Sprintf("unknown%d", msg.Type)
}

const (
	IFLA_INFO_UNSPEC = iota
	IFLA_INFO_KIND
	IFLA_INFO_DATA
	IFLA_INFO_XSTATS
	IFLA_INFO_SLAVE_KIND
	IFLA_INFO_SLAVE_DATA
	IFLA_INFO_MAX = IFLA_INFO_SLAVE_DATA
)

type Device struct {
	LinkAttrs
}

func (device *Device) Attrs() *LinkAttrs {
	return &device.LinkAttrs
}

func (device *Device) Type() string {
	return "device"
}

func readSysPropAsInt64(ifname, prop string) (int64, error) {
	fname := fmt.Sprintf("/sys/class/net/%s/%s", ifname, prop)
	contents, err := ioutil.ReadFile(fname)
	if err != nil {
		return 0, err
	}

	num, err := strconv.ParseInt(strings.TrimSpace(string(contents)), 0, 64)
	if err == nil {
		return num, nil
	}

	return 0, err
}

func BytesToString(b []byte) string {
	n := bytes.Index(b, []byte{0})
	return string(b[:n])
}

type Dummy struct {
	LinkAttrs
}

func (dummy *Dummy) Attrs() *LinkAttrs {
	return &dummy.LinkAttrs
}

func (dummy *Dummy) Type() string {
	return "dummy"
}

type Bridge struct {
	LinkAttrs
	MulticastSnooping *bool
	AgeingTime        *uint32
	HelloTime         *uint32
	VlanFiltering     *bool
	VlanDefaultPVID   *uint16
	GroupFwdMask      *uint16
}

func (bridge *Bridge) Attrs() *LinkAttrs {
	return &bridge.LinkAttrs
}

func (bridge *Bridge) Type() string {
	return "bridge"
}

type Iptun struct {
	LinkAttrs
	Ttl        uint8
	Tos        uint8
	PMtuDisc   uint8
	Link       uint32
	Local      net.IP
	Remote     net.IP
	EncapSport uint16
	EncapDport uint16
	EncapType  uint16
	EncapFlags uint16
	FlowBased  bool
	Proto      uint8
}

func (iptun *Iptun) Attrs() *LinkAttrs {
	return &iptun.LinkAttrs
}

func (iptun *Iptun) Type() string {
	return "ipip"
}

type GenericLink struct {
	LinkAttrs
	LinkType string
}

func (generic *GenericLink) Attrs() *LinkAttrs {
	return &generic.LinkAttrs
}

func (generic *GenericLink) Type() string {
	return generic.LinkType
}

func LinkDeserialize(hdr *unix.NlMsghdr, m []byte) (Link, error) {
	msg := DeserializeIfInfomsg(m)

	attrs, err := ParseRouteAttr(m[msg.Len():])
	if err != nil {
		return nil, err
	}

	base := NewLinkAttrs()
	base.Index = int(msg.Index)
	base.RawFlags = msg.Flags
	base.Flags = linkFlags(msg.Flags)
	base.EncapType = msg.EncapType()
	base.NetNsID = -1
	if msg.Flags&unix.IFF_ALLMULTI != 0 {
		base.Allmulti = 1
	}
	if msg.Flags&unix.IFF_MULTICAST != 0 {
		base.Multi = 1
	}

	var (
		link     Link
		linkType string
	)
	for _, attr := range attrs {
		switch attr.Attr.Type {
		case unix.IFLA_LINKINFO:
			infos, err := ParseRouteAttr(attr.Value)
			if err != nil {
				return nil, err
			}
			for _, info := range infos {
				switch info.Attr.Type {
				case IFLA_INFO_KIND:
					linkType = string(info.Value[:len(info.Value)-1])
					switch linkType {
					case "dummy":
						link = &Dummy{}
					case "bridge":
						link = &Bridge{}
					case "ipip":
						link = &Iptun{}
					case "tun":
						link = &Tuntap{}
					default:
						link = &GenericLink{LinkType: linkType}
					}
				case IFLA_INFO_DATA:
					data, err := ParseRouteAttr(info.Value)
					if err != nil {
						return nil, err
					}
					switch linkType {
					case "bridge":
						parseBridgeData(link, data)
					case "tun":
						parseTuntapData(link, data)
					case "ipip":
						parseIptunData(link, data)
					}
				}
			}
		case unix.IFLA_ADDRESS:
			var nonzero bool
			for _, b := range attr.Value {
				if b != 0 {
					nonzero = true
				}
			}
			if nonzero {
				base.HardwareAddr = attr.Value[:]
			}
		case unix.IFLA_IFNAME:
			base.Name = string(attr.Value[:len(attr.Value)-1])
		case unix.IFLA_MTU:
			base.MTU = int(native.Uint32(attr.Value[0:4]))
		case unix.IFLA_PROMISCUITY:
			base.Promisc = int(native.Uint32(attr.Value[0:4]))
		case unix.IFLA_LINK:
			base.ParentIndex = int(native.Uint32(attr.Value[0:4]))
		case unix.IFLA_MASTER:
			base.MasterIndex = int(native.Uint32(attr.Value[0:4]))
		case unix.IFLA_TXQLEN:
			base.TxQLen = int(native.Uint32(attr.Value[0:4]))
		case unix.IFLA_IFALIAS:
			base.Alias = string(attr.Value[:len(attr.Value)-1])
		case unix.IFLA_PROTINFO | unix.NLA_F_NESTED:
			if hdr != nil && hdr.Type == unix.RTM_NEWLINK &&
				msg.Family == unix.AF_BRIDGE {
				attrs, err := ParseRouteAttr(attr.Value[:])
				if err != nil {
					return nil, err
				}
				protinfo := parseProtinfo(attrs)
				base.Protinfo = &protinfo
			}
		case unix.IFLA_PROP_LIST | unix.NLA_F_NESTED:
			attrs, err := ParseRouteAttr(attr.Value[:])
			if err != nil {
				return nil, err
			}

			base.AltNames = []string{}
			for _, attr := range attrs {
				if attr.Attr.Type == unix.IFLA_ALT_IFNAME {
					base.AltNames = append(base.AltNames, BytesToString(attr.Value))
				}
			}
		case unix.IFLA_OPERSTATE:
			base.OperState = LinkOperState(uint8(attr.Value[0]))
		case unix.IFLA_PHYS_SWITCH_ID:
			base.PhysSwitchID = int(native.Uint32(attr.Value[0:4]))
		case unix.IFLA_LINK_NETNSID:
			base.NetNsID = int(native.Uint32(attr.Value[0:4]))
		case unix.IFLA_TSO_MAX_SEGS:
			base.TSOMaxSegs = native.Uint32(attr.Value[0:4])
		case unix.IFLA_TSO_MAX_SIZE:
			base.TSOMaxSize = native.Uint32(attr.Value[0:4])
		case unix.IFLA_GSO_MAX_SEGS:
			base.GSOMaxSegs = native.Uint32(attr.Value[0:4])
		case unix.IFLA_GSO_MAX_SIZE:
			base.GSOMaxSize = native.Uint32(attr.Value[0:4])
		case unix.IFLA_GRO_MAX_SIZE:
			base.GROMaxSize = native.Uint32(attr.Value[0:4])
		case unix.IFLA_GSO_IPV4_MAX_SIZE:
			base.GSOIPv4MaxSize = native.Uint32(attr.Value[0:4])
		case unix.IFLA_GRO_IPV4_MAX_SIZE:
			base.GROIPv4MaxSize = native.Uint32(attr.Value[0:4])
		case unix.IFLA_NUM_TX_QUEUES:
			base.NumTxQueues = int(native.Uint32(attr.Value[0:4]))
		case unix.IFLA_NUM_RX_QUEUES:
			base.NumRxQueues = int(native.Uint32(attr.Value[0:4]))
		case unix.IFLA_GROUP:
			base.Group = native.Uint32(attr.Value[0:4])
		case unix.IFLA_PERM_ADDRESS:
			for _, b := range attr.Value {
				if b != 0 {
					base.PermHWAddr = attr.Value[:]
					break
				}
			}
		}
	}

	if link == nil {
		link = &Device{}
	}
	*link.Attrs() = base

	if link != nil && linkType == "tun" {
		tuntap := link.(*Tuntap)

		if tuntap.Mode == 0 {
			ifname := tuntap.Attrs().Name
			if flags, err := readSysPropAsInt64(ifname, "tun_flags"); err == nil {

				if flags&unix.IFF_TUN != 0 {
					tuntap.Mode = unix.IFF_TUN
				} else if flags&unix.IFF_TAP != 0 {
					tuntap.Mode = unix.IFF_TAP
				}

				tuntap.NonPersist = false
				if flags&unix.IFF_PERSIST == 0 {
					tuntap.NonPersist = true
				}
			}

			if owner, err := readSysPropAsInt64(ifname, "owner"); err == nil && owner > 0 {
				tuntap.Owner = uint32(owner)
			}
			if group, err := readSysPropAsInt64(ifname, "group"); err == nil && group > 0 {
				tuntap.Group = uint32(group)
			}
		}
	}

	return link, nil
}

const (
	IFLA_TUN_UNSPEC = iota
	IFLA_TUN_OWNER
	IFLA_TUN_GROUP
	IFLA_TUN_TYPE
	IFLA_TUN_PI
	IFLA_TUN_VNET_HDR
	IFLA_TUN_PERSIST
	IFLA_TUN_MULTI_QUEUE
	IFLA_TUN_NUM_QUEUES
	IFLA_TUN_NUM_DISABLED_QUEUES
	IFLA_TUN_MAX = IFLA_TUN_NUM_DISABLED_QUEUES
)

func parseTuntapData(link Link, data []syscall.NetlinkRouteAttr) {
	tuntap := link.(*Tuntap)
	for _, datum := range data {
		switch datum.Attr.Type {
		case IFLA_TUN_OWNER:
			tuntap.Owner = native.Uint32(datum.Value)
		case IFLA_TUN_GROUP:
			tuntap.Group = native.Uint32(datum.Value)
		case IFLA_TUN_TYPE:
			tuntap.Mode = TuntapMode(uint8(datum.Value[0]))
		case IFLA_TUN_PERSIST:
			tuntap.NonPersist = false
			if uint8(datum.Value[0]) == 0 {
				tuntap.NonPersist = true
			}
		}
	}
}

const (
	IFLA_IPTUN_UNSPEC = iota
	IFLA_IPTUN_LINK
	IFLA_IPTUN_LOCAL
	IFLA_IPTUN_REMOTE
	IFLA_IPTUN_TTL
	IFLA_IPTUN_TOS
	IFLA_IPTUN_ENCAP_LIMIT
	IFLA_IPTUN_FLOWINFO
	IFLA_IPTUN_FLAGS
	IFLA_IPTUN_PROTO
	IFLA_IPTUN_PMTUDISC
	IFLA_IPTUN_6RD_PREFIX
	IFLA_IPTUN_6RD_RELAY_PREFIX
	IFLA_IPTUN_6RD_PREFIXLEN
	IFLA_IPTUN_6RD_RELAY_PREFIXLEN
	IFLA_IPTUN_ENCAP_TYPE
	IFLA_IPTUN_ENCAP_FLAGS
	IFLA_IPTUN_ENCAP_SPORT
	IFLA_IPTUN_ENCAP_DPORT
	IFLA_IPTUN_COLLECT_METADATA
	IFLA_IPTUN_MAX = IFLA_IPTUN_COLLECT_METADATA
)

func ntohs(buf []byte) uint16 {
	return binary.BigEndian.Uint16(buf)
}

func parseIptunData(link Link, data []syscall.NetlinkRouteAttr) {
	iptun := link.(*Iptun)
	for _, datum := range data {
		switch datum.Attr.Type {
		case IFLA_IPTUN_LOCAL:
			iptun.Local = net.IP(datum.Value[0:4])
		case IFLA_IPTUN_REMOTE:
			iptun.Remote = net.IP(datum.Value[0:4])
		case IFLA_IPTUN_TTL:
			iptun.Ttl = uint8(datum.Value[0])
		case IFLA_IPTUN_TOS:
			iptun.Tos = uint8(datum.Value[0])
		case IFLA_IPTUN_PMTUDISC:
			iptun.PMtuDisc = uint8(datum.Value[0])
		case IFLA_IPTUN_ENCAP_SPORT:
			iptun.EncapSport = ntohs(datum.Value[0:2])
		case IFLA_IPTUN_ENCAP_DPORT:
			iptun.EncapDport = ntohs(datum.Value[0:2])
		case IFLA_IPTUN_ENCAP_TYPE:
			iptun.EncapType = native.Uint16(datum.Value[0:2])
		case IFLA_IPTUN_ENCAP_FLAGS:
			iptun.EncapFlags = native.Uint16(datum.Value[0:2])
		case IFLA_IPTUN_COLLECT_METADATA:
			iptun.FlowBased = true
		case IFLA_IPTUN_PROTO:
			iptun.Proto = datum.Value[0]
		}
	}
}

const (
	IFLA_BR_UNSPEC = iota
	IFLA_BR_FORWARD_DELAY
	IFLA_BR_HELLO_TIME
	IFLA_BR_MAX_AGE
	IFLA_BR_AGEING_TIME
	IFLA_BR_STP_STATE
	IFLA_BR_PRIORITY
	IFLA_BR_VLAN_FILTERING
	IFLA_BR_VLAN_PROTOCOL
	IFLA_BR_GROUP_FWD_MASK
	IFLA_BR_ROOT_ID
	IFLA_BR_BRIDGE_ID
	IFLA_BR_ROOT_PORT
	IFLA_BR_ROOT_PATH_COST
	IFLA_BR_TOPOLOGY_CHANGE
	IFLA_BR_TOPOLOGY_CHANGE_DETECTED
	IFLA_BR_HELLO_TIMER
	IFLA_BR_TCN_TIMER
	IFLA_BR_TOPOLOGY_CHANGE_TIMER
	IFLA_BR_GC_TIMER
	IFLA_BR_GROUP_ADDR
	IFLA_BR_FDB_FLUSH
	IFLA_BR_MCAST_ROUTER
	IFLA_BR_MCAST_SNOOPING
	IFLA_BR_MCAST_QUERY_USE_IFADDR
	IFLA_BR_MCAST_QUERIER
	IFLA_BR_MCAST_HASH_ELASTICITY
	IFLA_BR_MCAST_HASH_MAX
	IFLA_BR_MCAST_LAST_MEMBER_CNT
	IFLA_BR_MCAST_STARTUP_QUERY_CNT
	IFLA_BR_MCAST_LAST_MEMBER_INTVL
	IFLA_BR_MCAST_MEMBERSHIP_INTVL
	IFLA_BR_MCAST_QUERIER_INTVL
	IFLA_BR_MCAST_QUERY_INTVL
	IFLA_BR_MCAST_QUERY_RESPONSE_INTVL
	IFLA_BR_MCAST_STARTUP_QUERY_INTVL
	IFLA_BR_NF_CALL_IPTABLES
	IFLA_BR_NF_CALL_IP6TABLES
	IFLA_BR_NF_CALL_ARPTABLES
	IFLA_BR_VLAN_DEFAULT_PVID
	IFLA_BR_PAD
	IFLA_BR_VLAN_STATS_ENABLED
	IFLA_BR_MCAST_STATS_ENABLED
	IFLA_BR_MCAST_IGMP_VERSION
	IFLA_BR_MCAST_MLD_VERSION
	IFLA_BR_MAX = IFLA_BR_MCAST_MLD_VERSION
)

func parseBridgeData(bridge Link, data []syscall.NetlinkRouteAttr) {
	br := bridge.(*Bridge)
	for _, datum := range data {
		switch datum.Attr.Type {
		case IFLA_BR_AGEING_TIME:
			ageingTime := native.Uint32(datum.Value[0:4])
			br.AgeingTime = &ageingTime
		case IFLA_BR_HELLO_TIME:
			helloTime := native.Uint32(datum.Value[0:4])
			br.HelloTime = &helloTime
		case IFLA_BR_MCAST_SNOOPING:
			mcastSnooping := datum.Value[0] == 1
			br.MulticastSnooping = &mcastSnooping
		case IFLA_BR_VLAN_FILTERING:
			vlanFiltering := datum.Value[0] == 1
			br.VlanFiltering = &vlanFiltering
		case IFLA_BR_VLAN_DEFAULT_PVID:
			vlanDefaultPVID := native.Uint16(datum.Value[0:2])
			br.VlanDefaultPVID = &vlanDefaultPVID
		case IFLA_BR_GROUP_FWD_MASK:
			mask := native.Uint16(datum.Value[0:2])
			br.GroupFwdMask = &mask
		}
	}
}

func ZeroTerminated(s string) []byte {
	bytes := make([]byte, len(s)+1)
	for i := 0; i < len(s); i++ {
		bytes[i] = s[i]
	}
	bytes[len(s)] = 0
	return bytes
}

func (h *Handle) LinkByName(name string) (Link, error) {
	if h.lookupByDump {
		return h.linkByNameDump(name)
	}

	req := h.newNetlinkRequest(unix.RTM_GETLINK, unix.NLM_F_ACK)

	msg := NewIfInfomsg(unix.AF_UNSPEC)
	req.AddData(msg)

	attr := NewRtAttr(unix.IFLA_EXT_MASK, Uint32Attr(RTEXT_FILTER_VF))
	req.AddData(attr)

	nameData := NewRtAttr(unix.IFLA_IFNAME, ZeroTerminated(name))
	if len(name) > 15 {
		nameData = NewRtAttr(unix.IFLA_ALT_IFNAME, ZeroTerminated(name))
	}
	req.AddData(nameData)

	link, err := execGetLink(req)
	if err == unix.EINVAL {
		h.lookupByDump = true
		return h.linkByNameDump(name)
	}

	return link, err
}

func execGetLink(req *NetlinkRequest) (Link, error) {
	msgs, err := req.Execute(unix.NETLINK_ROUTE, 0)
	if err != nil {
		if errno, ok := err.(syscall.Errno); ok {
			if errno == unix.ENODEV {
				return nil, LinkNotFoundError{fmt.Errorf("Link not found")}
			}
		}
		return nil, err
	}

	switch {
	case len(msgs) == 0:
		return nil, LinkNotFoundError{fmt.Errorf("Link not found")}

	case len(msgs) == 1:
		return LinkDeserialize(nil, msgs[0])

	default:
		return nil, fmt.Errorf("More than one link found")
	}
}

func (h *Handle) LinkAdd(link Link) error {
	return h.linkModify(link, unix.NLM_F_CREATE|unix.NLM_F_EXCL|unix.NLM_F_ACK)
}

type TuntapMode uint16
type TuntapFlag uint16

type Tuntap struct {
	LinkAttrs
	Mode       TuntapMode
	Flags      TuntapFlag
	NonPersist bool
	Queues     int
	Fds        []*os.File
	Owner      uint32
	Group      uint32
}

func (tuntap *Tuntap) Attrs() *LinkAttrs {
	return &tuntap.LinkAttrs
}

func (tuntap *Tuntap) Type() string {
	return "tuntap"
}

const (
	SizeOfIfReq = 40
	IFNAMSIZ    = 16
)

type ifReq struct {
	Name  [IFNAMSIZ]byte
	Flags uint16
	pad   [SizeOfIfReq - IFNAMSIZ - 2]byte
}

const (
	TUNTAP_MODE_TUN             TuntapMode = unix.IFF_TUN
	TUNTAP_MODE_TAP             TuntapMode = unix.IFF_TAP
	TUNTAP_DEFAULTS             TuntapFlag = unix.IFF_TUN_EXCL | unix.IFF_ONE_QUEUE
	TUNTAP_VNET_HDR             TuntapFlag = unix.IFF_VNET_HDR
	TUNTAP_TUN_EXCL             TuntapFlag = unix.IFF_TUN_EXCL
	TUNTAP_NO_PI                TuntapFlag = unix.IFF_NO_PI
	TUNTAP_ONE_QUEUE            TuntapFlag = unix.IFF_ONE_QUEUE
	TUNTAP_MULTI_QUEUE          TuntapFlag = unix.IFF_MULTI_QUEUE
	TUNTAP_MULTI_QUEUE_DEFAULTS TuntapFlag = TUNTAP_MULTI_QUEUE | TUNTAP_NO_PI
)

func (h *Handle) linkModify(link Link, flags int) error {
	base := link.Attrs()
	tuntap, isTuntap := link.(*Tuntap)

	if base.Name == "" && !isTuntap {
		return fmt.Errorf("LinkAttrs.Name cannot be empty")
	}

	if isTuntap {
		if tuntap.Mode < unix.IFF_TUN || tuntap.Mode > unix.IFF_TAP {
			return fmt.Errorf("Tuntap.Mode %v unknown", tuntap.Mode)
		}

		queues := tuntap.Queues

		var fds []*os.File
		var req ifReq
		copy(req.Name[:15], base.Name)

		req.Flags = uint16(tuntap.Flags)

		if queues == 0 { //Legacy compatibility
			queues = 1
			if tuntap.Flags == 0 {
				req.Flags = uint16(TUNTAP_DEFAULTS)
			}
		} else {
			if tuntap.Flags == 0 {
				req.Flags = uint16(TUNTAP_MULTI_QUEUE_DEFAULTS)
			}
		}

		req.Flags |= uint16(tuntap.Mode)
		const TUN = "/dev/net/tun"
		for i := 0; i < queues; i++ {
			localReq := req
			fd, err := unix.Open(TUN, os.O_RDWR|syscall.O_CLOEXEC, 0)
			if err != nil {
				cleanupFds(fds)
				return err
			}

			_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&localReq)))
			if errno != 0 {
				unix.Close(fd)
				cleanupFds(fds)
				return fmt.Errorf("Tuntap IOCTL TUNSETIFF failed [%d], errno %v", i, errno)
			}

			_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.TUNSETOWNER, uintptr(tuntap.Owner))
			if errno != 0 {
				cleanupFds(fds)
				return fmt.Errorf("Tuntap IOCTL TUNSETOWNER failed [%d], errno %v", i, errno)
			}

			_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.TUNSETGROUP, uintptr(tuntap.Group))
			if errno != 0 {
				cleanupFds(fds)
				return fmt.Errorf("Tuntap IOCTL TUNSETGROUP failed [%d], errno %v", i, errno)
			}

			err = unix.SetNonblock(fd, true)
			if err != nil {
				cleanupFds(fds)
				return fmt.Errorf("Tuntap set to non-blocking failed [%d], err %v", i, err)
			}

			file := os.NewFile(uintptr(fd), TUN)
			fds = append(fds, file)

			if i == 0 {
				link.Attrs().Name = strings.Trim(string(localReq.Name[:]), "\x00")
			}
		}

		control := func(file *os.File, f func(fd uintptr)) error {
			name := file.Name()
			conn, err := file.SyscallConn()
			if err != nil {
				return fmt.Errorf("SyscallConn() failed on %s: %v", name, err)
			}
			if err := conn.Control(f); err != nil {
				return fmt.Errorf("Failed to get file descriptor for %s: %v", name, err)
			}
			return nil
		}

		if !tuntap.NonPersist {
			var errno syscall.Errno
			if err := control(fds[0], func(fd uintptr) {
				_, _, errno = unix.Syscall(unix.SYS_IOCTL, fd, uintptr(unix.TUNSETPERSIST), 1)
			}); err != nil {
				return err
			}
			if errno != 0 {
				cleanupFds(fds)
				return fmt.Errorf("Tuntap IOCTL TUNSETPERSIST failed, errno %v", errno)
			}
		}

		h.ensureIndex(base)

		if base.MasterIndex != 0 {
			// TODO: verify MasterIndex is actually a bridge?
			err := h.LinkSetMasterByIndex(link, base.MasterIndex)
			if err != nil {
				if !tuntap.NonPersist {
					_ = control(fds[0], func(fd uintptr) {
						_, _, _ = unix.Syscall(unix.SYS_IOCTL, fd, uintptr(unix.TUNSETPERSIST), 0)
					})
				}
				cleanupFds(fds)
				return err
			}
		}

		if tuntap.Queues == 0 {
			cleanupFds(fds)
		} else {
			tuntap.Fds = fds
		}

		return nil
	}

	req := h.newNetlinkRequest(unix.RTM_NEWLINK, flags)

	msg := NewIfInfomsg(unix.AF_UNSPEC)
	// TODO: make it shorter
	if base.Flags&net.FlagUp != 0 {
		msg.Change = unix.IFF_UP
		msg.Flags = unix.IFF_UP
	}
	if base.Flags&net.FlagBroadcast != 0 {
		msg.Change |= unix.IFF_BROADCAST
		msg.Flags |= unix.IFF_BROADCAST
	}
	if base.Flags&net.FlagLoopback != 0 {
		msg.Change |= unix.IFF_LOOPBACK
		msg.Flags |= unix.IFF_LOOPBACK
	}
	if base.Flags&net.FlagPointToPoint != 0 {
		msg.Change |= unix.IFF_POINTOPOINT
		msg.Flags |= unix.IFF_POINTOPOINT
	}
	if base.Flags&net.FlagMulticast != 0 {
		msg.Change |= unix.IFF_MULTICAST
		msg.Flags |= unix.IFF_MULTICAST
	}
	if base.Index != 0 {
		msg.Index = int32(base.Index)
	}

	req.AddData(msg)

	if base.ParentIndex != 0 {
		b := make([]byte, 4)
		native.PutUint32(b, uint32(base.ParentIndex))
		data := NewRtAttr(unix.IFLA_LINK, b)
		req.AddData(data)
	} else if link.Type() == "ipvlan" || link.Type() == "ipoib" {
		return fmt.Errorf("Can't create %s link without ParentIndex", link.Type())
	}

	nameData := NewRtAttr(unix.IFLA_IFNAME, ZeroTerminated(base.Name))
	req.AddData(nameData)

	if base.Alias != "" {
		alias := NewRtAttr(unix.IFLA_IFALIAS, []byte(base.Alias))
		req.AddData(alias)
	}

	if base.MTU > 0 {
		mtu := NewRtAttr(unix.IFLA_MTU, Uint32Attr(uint32(base.MTU)))
		req.AddData(mtu)
	}

	if base.TxQLen >= 0 {
		qlen := NewRtAttr(unix.IFLA_TXQLEN, Uint32Attr(uint32(base.TxQLen)))
		req.AddData(qlen)
	}

	if base.HardwareAddr != nil {
		hwaddr := NewRtAttr(unix.IFLA_ADDRESS, []byte(base.HardwareAddr))
		req.AddData(hwaddr)
	}

	if base.NumTxQueues > 0 {
		txqueues := NewRtAttr(unix.IFLA_NUM_TX_QUEUES, Uint32Attr(uint32(base.NumTxQueues)))
		req.AddData(txqueues)
	}

	if base.NumRxQueues > 0 {
		rxqueues := NewRtAttr(unix.IFLA_NUM_RX_QUEUES, Uint32Attr(uint32(base.NumRxQueues)))
		req.AddData(rxqueues)
	}

	if base.GSOMaxSegs > 0 {
		gsoAttr := NewRtAttr(unix.IFLA_GSO_MAX_SEGS, Uint32Attr(base.GSOMaxSegs))
		req.AddData(gsoAttr)
	}

	if base.GSOMaxSize > 0 {
		gsoAttr := NewRtAttr(unix.IFLA_GSO_MAX_SIZE, Uint32Attr(base.GSOMaxSize))
		req.AddData(gsoAttr)
	}

	if base.GROMaxSize > 0 {
		groAttr := NewRtAttr(unix.IFLA_GRO_MAX_SIZE, Uint32Attr(base.GROMaxSize))
		req.AddData(groAttr)
	}

	if base.GSOIPv4MaxSize > 0 {
		gsoAttr := NewRtAttr(unix.IFLA_GSO_IPV4_MAX_SIZE, Uint32Attr(base.GSOIPv4MaxSize))
		req.AddData(gsoAttr)
	}

	if base.GROIPv4MaxSize > 0 {
		groAttr := NewRtAttr(unix.IFLA_GRO_IPV4_MAX_SIZE, Uint32Attr(base.GROIPv4MaxSize))
		req.AddData(groAttr)
	}

	if base.Group > 0 {
		groupAttr := NewRtAttr(unix.IFLA_GROUP, Uint32Attr(base.Group))
		req.AddData(groupAttr)
	}

	if base.Namespace != nil {
		var attr *RtAttr
		switch ns := base.Namespace.(type) {
		case NsPid:
			val := Uint32Attr(uint32(ns))
			attr = NewRtAttr(unix.IFLA_NET_NS_PID, val)
		case NsFd:
			val := Uint32Attr(uint32(ns))
			attr = NewRtAttr(unix.IFLA_NET_NS_FD, val)
		}

		req.AddData(attr)
	}

	linkInfo := NewRtAttr(unix.IFLA_LINKINFO, nil)
	linkInfo.AddRtAttr(IFLA_INFO_KIND, NonZeroTerminated(link.Type()))

	switch link := link.(type) {
	case *Iptun:
		addIptunAttrs(link, linkInfo)
	case *Bridge:
		addBridgeAttrs(link, linkInfo)
	}

	req.AddData(linkInfo)

	_, err := req.Execute(unix.NETLINK_ROUTE, 0)
	if err != nil {
		return err
	}

	h.ensureIndex(base)

	if base.MasterIndex != 0 {
		return h.LinkSetMasterByIndex(link, base.MasterIndex)
	}
	return nil
}

func boolToByte(x bool) []byte {
	if x {
		return []byte{1}
	}
	return []byte{0}
}

func addBridgeAttrs(bridge *Bridge, linkInfo *RtAttr) {
	data := linkInfo.AddRtAttr(IFLA_INFO_DATA, nil)
	if bridge.MulticastSnooping != nil {
		data.AddRtAttr(IFLA_BR_MCAST_SNOOPING, boolToByte(*bridge.MulticastSnooping))
	}
	if bridge.AgeingTime != nil {
		data.AddRtAttr(IFLA_BR_AGEING_TIME, Uint32Attr(*bridge.AgeingTime))
	}
	if bridge.HelloTime != nil {
		data.AddRtAttr(IFLA_BR_HELLO_TIME, Uint32Attr(*bridge.HelloTime))
	}
	if bridge.VlanFiltering != nil {
		data.AddRtAttr(IFLA_BR_VLAN_FILTERING, boolToByte(*bridge.VlanFiltering))
	}
	if bridge.VlanDefaultPVID != nil {
		data.AddRtAttr(IFLA_BR_VLAN_DEFAULT_PVID, Uint16Attr(*bridge.VlanDefaultPVID))
	}
	if bridge.GroupFwdMask != nil {
		data.AddRtAttr(IFLA_BR_GROUP_FWD_MASK, Uint16Attr(*bridge.GroupFwdMask))
	}
}

func addIptunAttrs(iptun *Iptun, linkInfo *RtAttr) {
	data := linkInfo.AddRtAttr(IFLA_INFO_DATA, nil)

	if iptun.FlowBased {
		data.AddRtAttr(IFLA_IPTUN_COLLECT_METADATA, []byte{})
		return
	}

	ip := iptun.Local.To4()
	if ip != nil {
		data.AddRtAttr(IFLA_IPTUN_LOCAL, []byte(ip))
	}

	ip = iptun.Remote.To4()
	if ip != nil {
		data.AddRtAttr(IFLA_IPTUN_REMOTE, []byte(ip))
	}

	if iptun.Link != 0 {
		data.AddRtAttr(IFLA_IPTUN_LINK, Uint32Attr(iptun.Link))
	}
	data.AddRtAttr(IFLA_IPTUN_PMTUDISC, Uint8Attr(iptun.PMtuDisc))
	data.AddRtAttr(IFLA_IPTUN_TTL, Uint8Attr(iptun.Ttl))
	data.AddRtAttr(IFLA_IPTUN_TOS, Uint8Attr(iptun.Tos))
	data.AddRtAttr(IFLA_IPTUN_ENCAP_TYPE, Uint16Attr(iptun.EncapType))
	data.AddRtAttr(IFLA_IPTUN_ENCAP_FLAGS, Uint16Attr(iptun.EncapFlags))
	data.AddRtAttr(IFLA_IPTUN_ENCAP_SPORT, htons(iptun.EncapSport))
	data.AddRtAttr(IFLA_IPTUN_ENCAP_DPORT, htons(iptun.EncapDport))
	data.AddRtAttr(IFLA_IPTUN_PROTO, Uint8Attr(iptun.Proto))
}

func Uint8Attr(v uint8) []byte {
	return []byte{byte(v)}
}

func htons(val uint16) []byte {
	bytes := make([]byte, 2)
	binary.BigEndian.PutUint16(bytes, val)
	return bytes
}

func Uint16Attr(v uint16) []byte {
	native := NativeEndian()
	bytes := make([]byte, 2)
	native.PutUint16(bytes, v)
	return bytes
}

func cleanupFds(fds []*os.File) {
	for _, f := range fds {
		f.Close()
	}
}

func NonZeroTerminated(s string) []byte {
	bytes := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		bytes[i] = s[i]
	}
	return bytes
}

func ParseAddr(s string) (*Addr, error) {
	label := ""
	parts := strings.Split(s, " ")
	if len(parts) > 1 {
		s = parts[0]
		label = parts[1]
	}
	m, err := ParseIPNet(s)
	if err != nil {
		return nil, err
	}
	return &Addr{IPNet: m, Label: label}, nil
}

type Addr struct {
	*net.IPNet
	Label       string
	Flags       int
	Scope       int
	Peer        *net.IPNet
	Broadcast   net.IP
	PreferedLft int
	ValidLft    int
	LinkIndex   int
}

func (a Addr) String() string {
	return strings.TrimSpace(fmt.Sprintf("%s %s", a.IPNet, a.Label))
}

func (a Addr) Equal(x Addr) bool {
	sizea, _ := a.Mask.Size()
	sizeb, _ := x.Mask.Size()
	return a.IP.Equal(x.IP) && sizea == sizeb
}

func (a Addr) PeerEqual(x Addr) bool {
	sizea, _ := a.Peer.Mask.Size()
	sizeb, _ := x.Peer.Mask.Size()
	return a.Peer.IP.Equal(x.Peer.IP) && sizea == sizeb
}

func ParseIPNet(s string) (*net.IPNet, error) {
	ip, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		return nil, err
	}
	ipNet.IP = ip
	return ipNet, nil
}

func AddrAdd(link Link, addr *Addr) error {
	return pkgHandle.AddrAdd(link, addr)
}

func (h *Handle) AddrAdd(link Link, addr *Addr) error {
	req := h.newNetlinkRequest(unix.RTM_NEWADDR, unix.NLM_F_CREATE|unix.NLM_F_EXCL|unix.NLM_F_ACK)
	return h.addrHandle(link, addr, req)
}

func GetIPFamily(ip net.IP) int {
	if len(ip) <= net.IPv4len {
		return FAMILY_V4
	}
	if ip.To4() != nil {
		return FAMILY_V4
	}
	return FAMILY_V6
}

type IfAddrmsg struct {
	unix.IfAddrmsg
}

func NewIfAddrmsg(family int) *IfAddrmsg {
	return &IfAddrmsg{
		IfAddrmsg: unix.IfAddrmsg{
			Family: uint8(family),
		},
	}
}

func (msg *IfAddrmsg) Serialize() []byte {
	return (*(*[unix.SizeofIfAddrmsg]byte)(unsafe.Pointer(msg)))[:]
}

func (msg *IfAddrmsg) Len() int {
	return unix.SizeofIfAddrmsg
}

func (a *RtAttr) AddRtAttr(attrType int, data []byte) *RtAttr {
	attr := NewRtAttr(attrType, data)
	a.children = append(a.children, attr)
	return attr
}

type IfaCacheInfo struct {
	unix.IfaCacheinfo
}

func (msg *IfaCacheInfo) Len() int {
	return unix.SizeofIfaCacheinfo
}

func DeserializeIfaCacheInfo(b []byte) *IfaCacheInfo {
	return (*IfaCacheInfo)(unsafe.Pointer(&b[0:unix.SizeofIfaCacheinfo][0]))
}

func (msg *IfaCacheInfo) Serialize() []byte {
	return (*(*[unix.SizeofIfaCacheinfo]byte)(unsafe.Pointer(msg)))[:]
}

func (h *Handle) addrHandle(link Link, addr *Addr, req *NetlinkRequest) error {
	family := GetIPFamily(addr.IP)
	msg := NewIfAddrmsg(family)
	msg.Scope = uint8(addr.Scope)
	if link == nil {
		msg.Index = uint32(addr.LinkIndex)
	} else {
		base := link.Attrs()
		if addr.Label != "" && !strings.HasPrefix(addr.Label, base.Name) {
			return fmt.Errorf("label must begin with interface name")
		}
		h.ensureIndex(base)
		msg.Index = uint32(base.Index)
	}
	mask := addr.Mask
	if addr.Peer != nil {
		mask = addr.Peer.Mask
	}
	prefixlen, masklen := mask.Size()
	msg.Prefixlen = uint8(prefixlen)
	req.AddData(msg)

	var localAddrData []byte
	if family == FAMILY_V4 {
		localAddrData = addr.IP.To4()
	} else {
		localAddrData = addr.IP.To16()
	}

	localData := NewRtAttr(unix.IFA_LOCAL, localAddrData)
	req.AddData(localData)
	var peerAddrData []byte
	if addr.Peer != nil {
		if family == FAMILY_V4 {
			peerAddrData = addr.Peer.IP.To4()
		} else {
			peerAddrData = addr.Peer.IP.To16()
		}
	} else {
		peerAddrData = localAddrData
	}

	addressData := NewRtAttr(unix.IFA_ADDRESS, peerAddrData)
	req.AddData(addressData)

	if addr.Flags != 0 {
		if addr.Flags <= 0xff {
			msg.IfAddrmsg.Flags = uint8(addr.Flags)
		} else {
			b := make([]byte, 4)
			native.PutUint32(b, uint32(addr.Flags))
			flagsData := NewRtAttr(unix.IFA_FLAGS, b)
			req.AddData(flagsData)
		}
	}

	if family == FAMILY_V4 {
		if addr.Broadcast == nil && prefixlen < 31 {
			calcBroadcast := make(net.IP, masklen/8)
			for i := range localAddrData {
				calcBroadcast[i] = localAddrData[i] | ^mask[i]
			}
			addr.Broadcast = calcBroadcast
		}

		if addr.Broadcast != nil {
			req.AddData(NewRtAttr(unix.IFA_BROADCAST, addr.Broadcast))
		}

		if addr.Label != "" {
			labelData := NewRtAttr(unix.IFA_LABEL, ZeroTerminated(addr.Label))
			req.AddData(labelData)
		}
	}

	if addr.ValidLft > 0 || addr.PreferedLft > 0 {
		cachedata := IfaCacheInfo{unix.IfaCacheinfo{
			Valid:    uint32(addr.ValidLft),
			Prefered: uint32(addr.PreferedLft),
		}}
		req.AddData(NewRtAttr(unix.IFA_CACHEINFO, cachedata.Serialize()))
	}

	_, err := req.Execute(unix.NETLINK_ROUTE, 0)
	return err
}

func LinkSetUp(link Link) error {
	return pkgHandle.LinkSetUp(link)
}

func (h *Handle) LinkSetUp(link Link) error {
	base := link.Attrs()
	h.ensureIndex(base)
	req := h.newNetlinkRequest(unix.RTM_NEWLINK, unix.NLM_F_ACK)

	msg := NewIfInfomsg(unix.AF_UNSPEC)
	msg.Change = unix.IFF_UP
	msg.Flags = unix.IFF_UP
	msg.Index = int32(base.Index)
	req.AddData(msg)

	_, err := req.Execute(unix.NETLINK_ROUTE, 0)
	return err
}

func LinkSetMaster(link Link, master Link) error {
	return pkgHandle.LinkSetMaster(link, master)
}

func (h *Handle) LinkSetMaster(link Link, master Link) error {
	index := 0
	if master != nil {
		masterBase := master.Attrs()
		h.ensureIndex(masterBase)
		index = masterBase.Index
	}
	if index <= 0 {
		return fmt.Errorf("Device does not exist")
	}
	return h.LinkSetMasterByIndex(link, index)
}

var native = NativeEndian()

func (h *Handle) LinkSetMasterByIndex(link Link, masterIndex int) error {
	base := link.Attrs()
	h.ensureIndex(base)
	req := h.newNetlinkRequest(unix.RTM_SETLINK, unix.NLM_F_ACK)

	msg := NewIfInfomsg(unix.AF_UNSPEC)
	msg.Index = int32(base.Index)
	req.AddData(msg)

	b := make([]byte, 4)
	native.PutUint32(b, uint32(masterIndex))

	data := NewRtAttr(unix.IFLA_MASTER, b)
	req.AddData(data)
	_, err := req.Execute(unix.NETLINK_ROUTE, 0)
	return err
}

func (h *Handle) ensureIndex(link *LinkAttrs) {
	if link != nil && link.Index == 0 {
		newlink, _ := h.LinkByName(link.Name)
		if newlink != nil {
			link.Index = newlink.Attrs().Index
		}
	}
}
