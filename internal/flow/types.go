package flow

type Key struct {
	Source, Destination         [16]byte
	SourcePort, DestinationPort uint16
	Protocol, Family            uint8
	TOS, Padding                uint8
}

type Counters struct {
	Packets, Octets, First, Last uint64
	FlagCounts                   [8]uint64
}

func (c Counters) TCPFlags() uint8 {
	var flags uint8
	for bit, count := range c.FlagCounts {
		if count != 0 {
			flags |= 1 << bit
		}
	}
	return flags
}

type Value struct {
	Counters
}

type Packet struct {
	Key
	Octets  uint32
	Flags   uint8
	Padding [3]byte
	Time    uint64
}

func (c *Counters) add(p Packet) {
	if c.Packets == 0 || p.Time < c.First {
		c.First = p.Time
	}
	if p.Time > c.Last {
		c.Last = p.Time
	}
	c.Packets++
	c.Octets += uint64(p.Octets)
	for bit := range c.FlagCounts {
		if p.Flags&(1<<bit) != 0 {
			c.FlagCounts[bit]++
		}
	}
}

type Interface struct {
	Index          int
	Name, Identity string
	IPv4, IPv6     string
}

type Record struct {
	Key
	Interface Interface
	Counters
	Reason uint8
}
