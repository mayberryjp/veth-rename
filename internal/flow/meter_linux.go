//go:build linux

package flow

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"veth-manager/internal/firewall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

//go:generate clang-14 -O2 -g -fdebug-compilation-dir=. -target bpfel -I/usr/include/x86_64-linux-gnu -c bpf/meter.c -o meter_bpfel.o

//go:embed meter_bpfel.o
var meterObject []byte

type kernelMeter struct {
	collection *ebpf.Collection
	links      []link.Link
	reader     *ringbuf.Reader
	dropReader *ringbuf.Reader
	dropLoss   uint64
	ruleSpec   *ebpf.MapSpec
	generation uint32
}

type meterOptions struct {
	samplingRate, filter uint32
	collector            Key
	ringBytes            uint32
	stateEntries         uint32
	fragmentEntries      uint32
	firewall             *firewall.Policy
}

func platformReady() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("eBPF memlock limit: %w", err)
	}
	// Load before changing any interfaces so verifier/capability failures are fatal.
	m, err := loadConfiguredMeter(meterOptions{samplingRate: 1})
	if err != nil {
		return err
	}
	return m.Close()
}

func validateFirewall(p *firewall.Policy) error {
	m, err := loadConfiguredMeter(meterOptions{samplingRate: 1, firewall: &firewall.Policy{Config: p.Config}})
	if err != nil {
		return err
	}
	return m.Close()
}

func monotonic() (uint64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0, err
	}
	return uint64(ts.Nano()), nil
}

func loadConfiguredMeter(options meterOptions) (*kernelMeter, error) {
	samplingRate := options.samplingRate
	if samplingRate < 1 || samplingRate > 1000000 {
		return nil, fmt.Errorf("invalid eBPF sampling rate %d", samplingRate)
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(meterObject))
	if err != nil {
		return nil, fmt.Errorf("read eBPF meter: %w", err)
	}
	if options.ringBytes != 0 {
		spec.Maps["packets"].MaxEntries = options.ringBytes
	}
	enabled, permitICMP, auditMode := uint32(0), uint32(1), uint32(0)
	enforcementHooks := uint32(3)
	if options.firewall != nil && options.firewall.Config.Enabled {
		enabled = 1
		enforcementHooks = 0
		for _, hook := range []uint8{1, 2} {
			if options.firewall.Config.Enforces(hook) {
				enforcementHooks |= uint32(hook)
			}
		}
		if options.firewall.Config.AuditMode {
			auditMode = 1
		}
		if !options.firewall.Config.PermitAllICMP {
			permitICMP = 0
		}
	}
	if enabled == 0 {
		spec.Maps["connections"].MaxEntries = 1
		spec.Maps["fragments"].MaxEntries = 1
		spec.Maps["rules"].InnerMap.MaxEntries = 1
		spec.Maps["rule_template"].MaxEntries = 1
		spec.Maps["drops"].MaxEntries = 4096
	} else if options.stateEntries != 0 {
		spec.Maps["connections"].MaxEntries = options.stateEntries
	}
	if enabled != 0 && options.fragmentEntries != 0 {
		spec.Maps["fragments"].MaxEntries = options.fragmentEntries
	}
	if err := spec.RewriteConstants(map[string]interface{}{
		"sampling_rate": samplingRate, "capture_filter": options.filter, "collector": options.collector,
		"firewall_enabled": enabled, "permit_all_icmp": permitICMP, "audit_mode": auditMode,
		"enforcement_hooks": enforcementHooks,
	}); err != nil {
		return nil, fmt.Errorf("configure eBPF sampling: %w", err)
	}
	c, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load eBPF meter (Linux 6.6+ and BPF/NET_ADMIN capabilities required): %w", err)
	}
	reader, err := ringbuf.NewReader(c.Maps["packets"])
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("open eBPF packet handoff: %w", err)
	}
	m := &kernelMeter{collection: c, reader: reader}
	if enabled != 0 {
		m.ruleSpec = spec.Maps["rules"].InnerMap
		if err := m.UpdateFirewall(options.firewall); err != nil {
			return nil, errors.Join(err, m.Close())
		}
		m.dropReader, err = ringbuf.NewReader(c.Maps["drops"])
		if err != nil {
			return nil, errors.Join(fmt.Errorf("open firewall drops: %w", err), m.Close())
		}
	}
	return m, nil
}

func (m *kernelMeter) UpdateFirewall(p *firewall.Policy) (updateErr error) {
	if m.ruleSpec == nil {
		return fmt.Errorf("firewall is not enabled on this meter")
	}
	if len(p.Kernel) > firewall.MaxRulesPerVeth {
		return fmt.Errorf("at most %d rules per veth are supported", firewall.MaxRulesPerVeth)
	}
	table, err := ebpf.NewMap(m.ruleSpec)
	if err != nil {
		return fmt.Errorf("create veth firewall table: %w", err)
	}
	defer func() { updateErr = errors.Join(updateErr, table.Close()) }()
	for i, rule := range p.Kernel {
		if err := table.Update(uint32(i), rule, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("load veth firewall rule %d: %w", i, err)
		}
	}
	generation := p.Generation
	if generation == 0 {
		generation = max(m.generation, 1)
	}
	if err := table.Update(uint32(firewall.MaxRulesPerVeth), firewall.KernelRule{ID: generation}, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("load firewall generation: %w", err)
	}
	if err := m.collection.Maps["rules"].Update(uint32(0), table, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("replace veth firewall table: %w", err)
	}
	m.generation = generation
	return nil
}

func attachMeter(iface Interface, options meterOptions) (meter, error) {
	current, err := net.InterfaceByIndex(iface.Index)
	if err != nil {
		return nil, err
	}
	if current.Name != iface.Name {
		return nil, fmt.Errorf("veth identity changed before eBPF attachment")
	}
	m, err := loadConfiguredMeter(options)
	if err != nil {
		return nil, err
	}
	for _, direction := range []ebpf.AttachType{ebpf.AttachTCXIngress, ebpf.AttachTCXEgress} {
		program := "meter"
		if direction == ebpf.AttachTCXEgress {
			program = "meter_egress"
		}
		hook, err := link.AttachTCX(link.TCXOptions{
			Interface: iface.Index, Program: m.collection.Programs[program], Attach: direction,
		})
		if err != nil {
			return nil, errors.Join(fmt.Errorf("attach eBPF to %s: %w", iface.Name, err), m.Close())
		}
		m.links = append(m.links, hook)
	}
	after, err := net.InterfaceByIndex(iface.Index)
	if err != nil || after.Name != iface.Name {
		return nil, errors.Join(fmt.Errorf("veth changed during eBPF attachment: %v", err), m.Close())
	}
	return m, nil
}

func (m *kernelMeter) Read() ([]Packet, error) {
	var result []Packet
	// Snapshot the available byte budget so sustained traffic cannot monopolize a poll.
	budget := m.reader.AvailableBytes()
	until := time.Now().Add(100 * time.Millisecond)
	m.reader.SetDeadline(time.Now().Add(time.Millisecond))
	var record ringbuf.Record
	for budget > 0 {
		if len(result)%256 == 0 && !time.Now().Before(until) {
			break
		}
		if err := m.reader.ReadInto(&record); err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}
			return result, fmt.Errorf("read eBPF packet handoff: %w", err)
		}
		budget -= (len(record.RawSample) + 8 + 7) &^ 7
		if len(record.RawSample) != 56 {
			return result, fmt.Errorf("unexpected eBPF packet size %d", len(record.RawSample))
		}
		var packet Packet
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &packet); err != nil {
			return result, fmt.Errorf("decode eBPF packet: %w", err)
		}
		result = append(result, packet)
	}
	return result, nil
}

func (m *kernelMeter) Losses() ([2]uint64, error) {
	var result [2]uint64
	for index := uint32(0); index < 2; index++ {
		var values []uint64
		if err := m.collection.Maps["losses"].Lookup(index, &values); err != nil {
			return result, err
		}

		for _, value := range values {
			result[index] += value
		}
	}
	return result, nil
}

func (m *kernelMeter) ReadDrops() ([]Drop, error) {
	if m.dropReader == nil {
		return nil, nil
	}
	var result []Drop
	budget := m.dropReader.AvailableBytes()
	m.dropReader.SetDeadline(time.Now().Add(time.Millisecond))
	until := time.Now().Add(100 * time.Millisecond)
	var record ringbuf.Record
	for budget > 0 && time.Now().Before(until) {
		if err := m.dropReader.ReadInto(&record); err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}
			return result, fmt.Errorf("read firewall drops: %w", err)
		}
		budget -= (len(record.RawSample) + 8 + 7) &^ 7
		if len(record.RawSample) != 64 {
			return result, fmt.Errorf("unexpected firewall drop size %d", len(record.RawSample))
		}
		var drop Drop
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &drop); err != nil {
			return result, err
		}
		result = append(result, drop)
	}
	var counts []uint64
	if err := m.collection.Maps["drop_losses"].Lookup(uint32(0), &counts); err != nil {
		return result, err
	}
	var count uint64
	for _, n := range counts {
		count += n
	}
	var lossErr error
	if count != m.dropLoss {
		m.dropLoss = count
		lossErr = fmt.Errorf("firewall drop log incomplete: ring_buffer_drops_lost=%d", count)
	}
	_, _, gcErr := m.collection.Programs["expire_states"].Test(make([]byte, 14))
	return result, errors.Join(lossErr, gcErr)
}

func (m *kernelMeter) Buffered() bool {
	return m.reader.AvailableBytes() > 0 || (m.dropReader != nil && m.dropReader.AvailableBytes() > 0)
}

func (m *kernelMeter) Detach() error {
	var errs []error
	for _, hook := range m.links {
		errs = append(errs, hook.Close())
	}
	m.links = nil
	return errors.Join(errs...)
}

func (m *kernelMeter) Close() error {
	err := m.Detach()
	err = errors.Join(err, m.reader.Close())
	if m.dropReader != nil {
		err = errors.Join(err, m.dropReader.Close())
	}
	m.collection.Close()
	return err
}
