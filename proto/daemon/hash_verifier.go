package daemon

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

// HashVerifier listens on the exec ring buffer and verifies binary hashes.
type HashVerifier struct {
	taskVerifiedMap *ebpf.Map
	appExecHashMap  *ebpf.Map
}

func NewHashVerifier(taskVerifiedMap, appExecHashMap *ebpf.Map) *HashVerifier {
	return &HashVerifier{
		taskVerifiedMap: taskVerifiedMap,
		appExecHashMap:  appExecHashMap,
	}
}

// StreamExecEvents loops on the ring buffer until ctx is done.
func (hv *HashVerifier) StreamExecEvents(ctx context.Context, execEventsMap *ebpf.Map) error {
	rd, err := ringbuf.NewReader(execEventsMap)
	if err != nil {
		return fmt.Errorf("creating exec events ring buffer reader: %w", err)
	}
	defer rd.Close()

	// Close reader when context is done
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
				return fmt.Errorf("reading exec events ring buffer: %w", err)
			}
		}

		if len(record.RawSample) < 40 { // sizeof(exec_event) = 40
			continue
		}

		evt := parseExecEvent(record.RawSample)
		hv.handleExecEvent(evt)
	}
}

func parseExecEvent(raw []byte) *ExecEvent {
	evt := &ExecEvent{}
	evt.TimestampNS = nativeEndianUint64(raw[0:8])
	evt.CgroupID = nativeEndianUint64(raw[8:16])
	evt.TGID = nativeEndianUint32(raw[16:20])
	evt.AppIndex = nativeEndianUint32(raw[20:24])
	copy(evt.Comm[:], raw[24:40])
	return evt
}

func (hv *HashVerifier) handleExecEvent(evt *ExecEvent) {
	exePath := fmt.Sprintf("/proc/%d/exe", evt.TGID)
	binPath, err := os.Readlink(exePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "hash_verifier: readlink %s: %v\n", exePath, err)
		return
	}

	actual, err := hashFile(binPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "hash_verifier: hashing %s (pid %d): %v\n",
			binPath, evt.TGID, err)
		return
	}

	var expected ExecHashValue
	if err := hv.appExecHashMap.Lookup(&evt.AppIndex, &expected); err != nil {
		fmt.Fprintf(os.Stderr, "hash_verifier: lookup expected hash for app_index %d: %v\n",
			evt.AppIndex, err)
		return
	}

	if actual != expected.Hash {
		fmt.Fprintf(os.Stderr, "hash_verifier: MISMATCH pid=%d comm=%s app_index=%d binary=%s\n",
			evt.TGID, evt.CommString(), evt.AppIndex, binPath)
		return
	}

	if err := hv.taskVerifiedMap.Put(&evt.TGID, &evt.AppIndex); err != nil {
		fmt.Fprintf(os.Stderr, "hash_verifier: setting verified for pid %d: %v\n",
			evt.TGID, err)
		return
	}

	fmt.Fprintf(os.Stderr, "hash_verifier: verified pid=%d comm=%s app_index=%d binary=%s\n",
		evt.TGID, evt.CommString(), evt.AppIndex, binPath)
}

func hashFile(path string) ([32]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return [32]byte{}, err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return [32]byte{}, err
	}

	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest, nil
}
