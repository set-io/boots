package machine

type PortIONoop struct {
}

func (r *PortIONoop) In(port uint64, data []byte) error  { return nil }
func (r *PortIONoop) Out(port uint64, data []byte) error { return nil }

type DeviceNoop struct {
	Port  uint64
	Psize uint64
}

func (r *DeviceNoop) In(port uint64, data []byte) error  { return nil }
func (r *DeviceNoop) Out(port uint64, data []byte) error { return nil }
func (r *DeviceNoop) IOPort() uint64                     { return r.Port }
func (r *DeviceNoop) Size() uint64                       { return r.Psize }
