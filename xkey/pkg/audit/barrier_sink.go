package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// ErrNilBarrierBackend is returned by OpenBarrierSink without a backend.
var ErrNilBarrierBackend = errors.New("audit: nil barrier backend")

// ErrChainUnsupported is returned by QRDBStore.VerifyChain while its sink
// keeps no hash chain (the start-up ring buffer, or no barrier).
var ErrChainUnsupported = errors.New("audit: the current sink keeps no hash chain")

// ChainBrokenError reports the first persisted record whose link to its
// predecessor does not hold.
type ChainBrokenError struct {
	Key    string
	Reason string
}

func (e *ChainBrokenError) Error() string {
	return fmt.Sprintf("audit: hash chain broken at record %s: %s", e.Key, e.Reason)
}

// BarrierSink is xkey's go-qrdb audit sink while the barrier is unsealed.
// Every record is persisted through the barrier-encrypted storage backend,
// so no audit field reaches the disk in plaintext, and an in-process go-qrdb
// ring buffer answers queries. Each persisted record carries in PrevHash the
// SHA-256 digest of the previous record's plaintext encoding: the stored set
// is a hash chain over the plaintext records, which VerifyChain walks.
//
// The backend is not owned: the barrier service closes it.
type BarrierSink struct {
	mu      sync.Mutex
	backend xkms.StorageBackend
	ring    xkms.QRDBNodeAuditLogger
	seq     uint64
	head    string
}

// OpenBarrierSink opens the sink over backend (a prefix of the barrier
// backend), verifies the records already stored there and loads them into
// a ring buffer of ringCapacity events.
func OpenBarrierSink(ctx context.Context, backend xkms.StorageBackend, ringCapacity int) (*BarrierSink, error) {
	if backend == nil {
		return nil, ErrNilBarrierBackend
	}
	s := &BarrierSink{backend: backend, ring: xkms.NewQRDBAuditRingBuffer(ringCapacity)}
	seq, head, err := s.walk(ctx, func(ev xkms.QRDBNodeAuditEvent) error {
		return s.ring.Emit(ctx, ev)
	})
	if err != nil {
		_ = s.ring.Close()
		return nil, err
	}
	s.seq, s.head = seq, head
	return s, nil
}

// Emit links ev to the chain, persists it through the barrier and holds it
// in the ring. A nil return means the sealed record is stored.
func (s *BarrierSink) Emit(ctx context.Context, ev xkms.QRDBNodeAuditEvent) error {
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ev.PrevHash = s.head
	raw, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("audit: encode event: %w", err)
	}
	if err := s.backend.Put(ctx, recordKey(s.seq+1), raw); err != nil {
		return fmt.Errorf("audit: persist event through the barrier: %w", err)
	}
	s.seq++
	s.head = digest(raw)
	return s.ring.Emit(ctx, ev)
}

// Query answers from the ring buffer.
func (s *BarrierSink) Query(ctx context.Context, f xkms.QRDBNodeAuditFilter) (*xkms.QRDBNodeAuditPage, error) {
	return s.ring.Query(ctx, f)
}

// Close releases the ring buffer; the barrier backend stays open.
func (s *BarrierSink) Close() error {
	return s.ring.Close()
}

// VerifyChain re-reads every persisted record and checks that each one
// links to its predecessor and that the stored chain ends where this sink
// last wrote.
func (s *BarrierSink) VerifyChain(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	seq, head, err := s.walk(ctx, nil)
	if err != nil {
		return err
	}
	if seq != s.seq || head != s.head {
		return &ChainBrokenError{Key: recordKey(seq), Reason: "stored chain does not end at the last record written"}
	}
	return nil
}

// walk reads the persisted records in sequence order, checks each link and
// hands each event to fn (when set). It returns the last sequence number
// and digest.
func (s *BarrierSink) walk(ctx context.Context, fn func(xkms.QRDBNodeAuditEvent) error) (uint64, string, error) {
	keys, err := s.backend.List(ctx, "")
	if err != nil {
		return 0, "", fmt.Errorf("audit: list sealed records: %w", err)
	}
	sort.Strings(keys)
	var (
		seq  uint64
		head string
	)
	for _, key := range keys {
		n, err := strconv.ParseUint(key[strings.LastIndex(key, "/")+1:], 10, 64)
		if err != nil {
			return 0, "", &ChainBrokenError{Key: key, Reason: "not a record key"}
		}
		if n != seq+1 {
			return 0, "", &ChainBrokenError{Key: key, Reason: fmt.Sprintf("expected record %d", seq+1)}
		}
		raw, err := s.backend.Get(ctx, key)
		if err != nil {
			return 0, "", fmt.Errorf("audit: read sealed record %s: %w", key, err)
		}
		var ev xkms.QRDBNodeAuditEvent
		if err := json.Unmarshal(raw, &ev); err != nil {
			return 0, "", &ChainBrokenError{Key: key, Reason: "record does not decode"}
		}
		if ev.PrevHash != head {
			return 0, "", &ChainBrokenError{Key: key, Reason: "previous-record digest does not match"}
		}
		if fn != nil {
			if err := fn(ev); err != nil {
				return 0, "", fmt.Errorf("audit: load sealed record %s: %w", key, err)
			}
		}
		seq, head = n, digest(raw)
	}
	return seq, head, nil
}

func recordKey(seq uint64) string { return fmt.Sprintf("%020d", seq) }

func digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
