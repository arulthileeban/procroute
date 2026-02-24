package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

// DenyLogEntry is what we write to stdout as JSONL.
type DenyLogEntry struct {
	Timestamp string `json:"timestamp"`
	Action    string `json:"action"`
	PID       uint32 `json:"pid"`
	UID       uint32 `json:"uid"`
	Comm      string `json:"comm"`
	CgroupID  uint64 `json:"cgroup_id"`
	AppIndex  uint32 `json:"app_index"`
	AF        string `json:"af"`
	Protocol  string `json:"protocol"`
	DstIP     string `json:"dst_ip"`
	DstPort   uint16 `json:"dst_port"`
}

// StreamDenyEvents reads from the deny ring buffer and writes JSONL to stdout.
func StreamDenyEvents(ctx context.Context, eventsMap *ebpf.Map) error {
	rd, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		return fmt.Errorf("creating ring buffer reader: %w", err)
	}
	defer rd.Close()

	enc := json.NewEncoder(os.Stdout)

	go func() {
		<-ctx.Done()
		rd.Close()
	}()

	for {
		record, err := rd.Read()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				fmt.Fprintf(os.Stderr, "warning: ring buffer read error (continuing): %v\n", err)
				time.Sleep(10 * time.Millisecond)
				continue
			}
		}

		if len(record.RawSample) < 64 { // minimum deny_event size
			continue
		}

		evt, err := parseDenyEvent(record.RawSample)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: parsing deny event: %v\n", err)
			continue
		}

		af := "inet"
		if evt.AF == 10 {
			af = "inet6"
		}

		entry := DenyLogEntry{
			Timestamp: time.Unix(0, int64(evt.TimestampNS)).UTC().Format(time.RFC3339Nano),
			Action:    "deny",
			PID:       evt.PID,
			UID:       evt.UID,
			Comm:      evt.CommString(),
			CgroupID:  evt.CgroupID,
			AppIndex:  evt.AppIndex,
			AF:        af,
			Protocol:  evt.ProtoString(),
			DstIP:     evt.DstIP().String(),
			DstPort:   evt.DstPort,
		}

		if err := enc.Encode(entry); err != nil {
			fmt.Fprintf(os.Stderr, "warning: encoding deny log: %v\n", err)
		}
	}
}


type GwDenyLogEntry struct {
	Timestamp string `json:"timestamp"`
	Action    string `json:"action"`
	AppIndex  uint32 `json:"app_index"`
	Protocol  string `json:"protocol"`
	SrcIP     string `json:"src_ip"`
	SrcPort   uint16 `json:"src_port"`
	DstIP     string `json:"dst_ip"`
	DstPort   uint16 `json:"dst_port"`
}

// StreamGwDenyEvents is the gateway equivalent of StreamDenyEvents.
func StreamGwDenyEvents(ctx context.Context, eventsMap *ebpf.Map) error {
	rd, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		return fmt.Errorf("creating ring buffer reader: %w", err)
	}
	defer rd.Close()

	enc := json.NewEncoder(os.Stdout)

	go func() {
		<-ctx.Done()
		rd.Close()
	}()

	for {
		record, err := rd.Read()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				fmt.Fprintf(os.Stderr, "warning: gw ring buffer read error (continuing): %v\n", err)
				time.Sleep(10 * time.Millisecond)
				continue
			}
		}

		if len(record.RawSample) < 32 {
			continue
		}

		evt := parseGwDenyEvent(record.RawSample)

		entry := GwDenyLogEntry{
			Timestamp: time.Unix(0, int64(evt.TimestampNS)).UTC().Format(time.RFC3339Nano),
			Action:    "gw-deny",
			AppIndex:  evt.AppIndex,
			Protocol:  evt.ProtoString(),
			SrcIP:     evt.SrcAddr().String(),
			SrcPort:   evt.SrcPort,
			DstIP:     evt.DstAddr().String(),
			DstPort:   evt.DstPort,
		}

		if err := enc.Encode(entry); err != nil {
			fmt.Fprintf(os.Stderr, "warning: encoding gw deny log: %v\n", err)
		}
	}
}

// StreamGwDenyEventsV6 -- same as above but for IPv6.
func StreamGwDenyEventsV6(ctx context.Context, eventsMap *ebpf.Map) error {
	rd, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		return fmt.Errorf("creating ring buffer reader: %w", err)
	}
	defer rd.Close()

	enc := json.NewEncoder(os.Stdout)

	go func() {
		<-ctx.Done()
		rd.Close()
	}()

	for {
		record, err := rd.Read()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				fmt.Fprintf(os.Stderr, "warning: gw v6 ring buffer read error (continuing): %v\n", err)
				time.Sleep(10 * time.Millisecond)
				continue
			}
		}

		if len(record.RawSample) < 56 {
			continue
		}

		evt := parseGwDenyEventV6(record.RawSample)

		entry := GwDenyLogEntry{
			Timestamp: time.Unix(0, int64(evt.TimestampNS)).UTC().Format(time.RFC3339Nano),
			Action:    "gw-deny",
			AppIndex:  evt.AppIndex,
			Protocol:  evt.ProtoString(),
			SrcIP:     evt.SrcAddr().String(),
			SrcPort:   evt.SrcPort,
			DstIP:     evt.DstAddr().String(),
			DstPort:   evt.DstPort,
		}

		if err := enc.Encode(entry); err != nil {
			fmt.Fprintf(os.Stderr, "warning: encoding gw deny v6 log: %v\n", err)
		}
	}
}

func parseGwDenyEventV6(raw []byte) *GatewayDenyEventV6 {
	evt := &GatewayDenyEventV6{}
	evt.TimestampNS = nativeEndianUint64(raw[0:8])
	copy(evt.SrcIP[:], raw[8:24])
	copy(evt.DstIP[:], raw[24:40])
	evt.SrcPort = nativeEndianUint16(raw[40:42])
	evt.DstPort = nativeEndianUint16(raw[42:44])
	evt.AppIndex = nativeEndianUint32(raw[44:48])
	evt.Proto = raw[48]
	return evt
}

func parseGwDenyEvent(raw []byte) *GatewayDenyEvent {
	evt := &GatewayDenyEvent{}
	evt.TimestampNS = nativeEndianUint64(raw[0:8])
	evt.SrcIP = nativeEndianUint32(raw[8:12])
	evt.DstIP = nativeEndianUint32(raw[12:16])
	evt.SrcPort = nativeEndianUint16(raw[16:18])
	evt.DstPort = nativeEndianUint16(raw[18:20])
	evt.AppIndex = nativeEndianUint32(raw[20:24])
	evt.Proto = raw[24]
	return evt
}

func parseDenyEvent(raw []byte) (*DenyEvent, error) {
	if len(raw) < 64 {
		return nil, fmt.Errorf("short event: %d bytes", len(raw))
	}

	evt := &DenyEvent{}

	evt.TimestampNS = nativeEndianUint64(raw[0:8])
	evt.CgroupID = nativeEndianUint64(raw[8:16])
	evt.PID = nativeEndianUint32(raw[16:20])
	evt.UID = nativeEndianUint32(raw[20:24])
	copy(evt.Comm[:], raw[24:40])
	evt.AF = raw[40]
	evt.Proto = raw[41]
	evt.DstPort = nativeEndianUint16(raw[42:44])
	copy(evt.DstAddr[:], raw[44:60])
	evt.AppIndex = nativeEndianUint32(raw[60:64])

	return evt, nil
}

func nativeEndianUint16(b []byte) uint16 {
	return uint16(b[0]) | uint16(b[1])<<8
}

func nativeEndianUint32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func nativeEndianUint64(b []byte) uint64 {
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
}
