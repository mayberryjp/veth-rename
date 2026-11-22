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
}

type meterOptions struct {
	samplingRate, filter uint32
	collector            Key
	ringBytes            uint32
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
	if err := spec.RewriteConstants(map[string]interface{}{
		"sampling_rate": samplingRate, "capture_filter": options.filter, "collector": options.collector,
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
	return &kernelMeter{collection: c, reader: reader}, nil
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
		hook, err := link.AttachTCX(link.TCXOptions{
			Interface: iface.Index, Program: m.collection.Programs["meter"], Attach: direction,
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

func (m *kernelMeter) Buffered() bool { return m.reader.AvailableBytes() > 0 }

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
	m.collection.Close()
	return err
}
