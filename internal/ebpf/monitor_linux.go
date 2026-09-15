//go:build linux

package ebpf

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// The compiled CO-RE object, built from bpf/monitor.bpf.c. Committed rather
// than compiled at build time so `go install` and `go build` need no clang or
// llvm — the single-binary, no-toolchain install story holds. Rebuild it with
// `make -C internal/ebpf` after changing the .c, and CI verifies it is current.
//
//go:embed monitor.bpf.o
var monitorObj []byte

// rawEvent mirrors struct event in monitor.bpf.c exactly, padding included, so
// binary.Read decodes it without surprises. 288 bytes.
type rawEvent struct {
	Kind  uint8
	_     [3]byte
	PID   uint32
	DPort uint16 // network byte order
	_     [2]byte
	DAddr [4]byte // IPv4 wire order
	Comm  [16]byte
	Path  [256]byte
}

type linuxMonitor struct {
	coll   *ebpf.Collection
	links  []link.Link
	reader *ringbuf.Reader
	events chan Event
	done   chan struct{}
}

// New attaches the monitor, scoped to cgroupID, and starts streaming events.
//
// Best-effort: any failure to load or attach (no privilege, no BTF, an older
// kernel) returns an unavailable no-op monitor and a nil error, so a scan is
// never broken by eBPF being out of reach. cgroupID is the target container's
// cgroup id; 0 leaves the in-kernel filter matching nothing.
func New(cgroupID uint64) (Monitor, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return noopMonitor{}, nil
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(monitorObj))
	if err != nil {
		return noopMonitor{}, nil
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		// Most commonly: not privileged enough to load a program. Additive, so
		// this is a silent downgrade, not a scan failure.
		return noopMonitor{}, nil
	}

	m := &linuxMonitor{
		coll:   coll,
		events: make(chan Event, 128),
		done:   make(chan struct{}),
	}

	if err := coll.Maps["target_cgid"].Update(uint32(0), cgroupID, ebpf.UpdateAny); err != nil {
		m.closeResources()
		return noopMonitor{}, nil
	}

	for _, tp := range []struct{ group, name, prog string }{
		{"syscalls", "sys_enter_connect", "handle_connect"},
		{"syscalls", "sys_enter_openat", "handle_openat"},
	} {
		prog := coll.Programs[tp.prog]
		if prog == nil {
			m.closeResources()
			return noopMonitor{}, nil
		}
		l, err := link.Tracepoint(tp.group, tp.name, prog, nil)
		if err != nil {
			m.closeResources()
			return noopMonitor{}, nil
		}
		m.links = append(m.links, l)
	}

	rd, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		m.closeResources()
		return noopMonitor{}, nil
	}
	m.reader = rd

	go m.loop()
	return m, nil
}

func (m *linuxMonitor) loop() {
	defer close(m.events)
	for {
		rec, err := m.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}
		var e rawEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &e); err != nil {
			continue
		}
		ev := Event{
			Kind: EventKind(e.Kind),
			PID:  e.PID,
			Comm: cstr(e.Comm[:]),
		}
		switch ev.Kind {
		case KindConnect:
			ip := net.IPv4(e.DAddr[0], e.DAddr[1], e.DAddr[2], e.DAddr[3])
			port := (e.DPort >> 8) | (e.DPort << 8) // ntohs
			ev.Dest = fmt.Sprintf("%s:%d", ip, port)
		case KindOpenWrite:
			ev.Path = cstr(e.Path[:])
		}
		select {
		case m.events <- ev:
		case <-m.done:
			return
		}
	}
}

func (m *linuxMonitor) Events() <-chan Event { return m.events }
func (m *linuxMonitor) Available() bool      { return true }

func (m *linuxMonitor) Close() error {
	close(m.done)
	if m.reader != nil {
		m.reader.Close() // unblocks loop's Read
	}
	m.closeResources()
	return nil
}

func (m *linuxMonitor) closeResources() {
	for _, l := range m.links {
		l.Close()
	}
	if m.coll != nil {
		m.coll.Close()
	}
}

func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}
