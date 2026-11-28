package continuous

import (
	"context"
	"errors"
	"fmt"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
	"github.com/jeremyhahn/go-xkms/pkg/dao"
	"github.com/jeremyhahn/go-xkms/pkg/scope"
)

const (
	// verdictFeature scopes verdict keys per tenant.
	verdictFeature = "attestation-verdicts"

	// verdictEntityType is the verdict DAO's entity type in
	// appraisal.DatabaseName.
	verdictEntityType = "attestation_verdicts"

	// maxDeviceIDLen bounds a device ID.
	maxDeviceIDLen = 253
)

// StoreConfig configures a Store.
type StoreConfig struct {
	// DAOs is the qrdb DAO factory the store persists through;
	// appraisal.DatabaseName must already be ensured on it. Required.
	DAOs *qrdbsdk.DAOFactory
}

// Store persists verdicts per tenant and device.
type Store struct {
	// records holds every verdict and each device's head. SaveVerdict
	// claims a sequence with SaveIfAbsent and advances the head by
	// CompareAndSwap, so stores in any number of processes over one
	// datastore keep every verdict without a lock of their own.
	records verdictRecords
}

// verdictRecords is the narrow DAO seam the store reads and writes
// through: every read is one record by its natural key, so a read's cost
// is bounded by the number of keys it names, never by a device's history.
type verdictRecords interface {
	SaveIfAbsent(ctx context.Context, e *verdictEntity) (bool, error)
	CompareAndSwap(ctx context.Context, expected, next *verdictEntity) (bool, error)
	GetByNaturalKey(ctx context.Context, key string) (*verdictEntity, error)
}

type verdictEntity struct {
	ID  uint64 `json:"id"`
	Key string `json:"key"`
	// Device is the tenant-scoped device prefix; indexed so a read
	// selects one device's verdicts without a collection scan.
	Device  string  `json:"device" index:"true"`
	Verdict Verdict `json:"verdict"`
	// Seq is the verdict's 1-based position in the device's history; on
	// the device's head record it is the latest verdict's sequence.
	Seq uint64 `json:"seq"`
	// Count is the number of verdicts stored for the device; set on the
	// head record only.
	Count uint64 `json:"count,omitempty"`
}

// headKey is the natural key of a device's head record, which carries the
// device's verdict count and latest sequence.
func headKey(prefix string) string { return prefix + "head" }

// verdictKey is the natural key of a device's seq-th verdict.
func verdictKey(prefix string, seq uint64) string { return fmt.Sprintf("%sv%020d", prefix, seq) }

// isNotFound reports whether err is the DAO's "no entity under this key".
func isNotFound(err error) bool {
	var byValue qrdbsdk.DAONotFoundError
	var byPointer *qrdbsdk.DAONotFoundError
	return errors.As(err, &byValue) || errors.As(err, &byPointer) || qrdbsdk.IsNotFound(err)
}

// EntityID returns the entity ID.
func (e *verdictEntity) EntityID() uint64 { return e.ID }

// SetEntityID sets the entity ID.
func (e *verdictEntity) SetEntityID(id uint64) { e.ID = id }

// NewStore opens the verdict collection on cfg.DAOs.
func NewStore(cfg StoreConfig) (*Store, error) {
	if cfg.DAOs == nil {
		return nil, &ConfigError{Field: "DAOs", Reason: "is required"}
	}
	newEntity := func() *verdictEntity { return &verdictEntity{} }
	records, err := dao.New(cfg.DAOs, appraisal.DatabaseName, verdictEntityType, newEntity,
		qrdbsdk.WithIDGenerator(qrdbsdk.NewCryptoFieldHashGenerator("Key")))
	if err != nil {
		return nil, &ConfigError{Field: "DAOs", Reason: "cannot open the verdict DAO", Cause: err}
	}
	return &Store{records: records}, nil
}

// SaveVerdict stores v under its tenant and device. Every verdict is kept;
// none replaces an earlier one.
func (s *Store) SaveVerdict(ctx context.Context, v Verdict) error {
	if v.At.IsZero() {
		return &InputError{Field: "verdict time", Cause: errors.New("is zero")}
	}
	prefix, err := devicePrefix(v.Tenant, v.DeviceID)
	if err != nil {
		return err
	}
	head, err := s.head(ctx, prefix)
	if err != nil {
		return err
	}
	seq, err := s.claimSequence(ctx, prefix, head.Count+1, v)
	if err != nil {
		return err
	}
	return s.advanceHead(ctx, prefix, seq)
}

// maxSequenceAttempts bounds the probe for a free verdict sequence and the
// retries of the head's compare-and-swap; each lost attempt means another
// writer stored a verdict or moved the head, so only that many concurrent
// writers on one device can exhaust it.
const maxSequenceAttempts = 64

// claimSequence stores v under a free sequence from seq on and returns
// it, re-reading the head after each lost claim. The verdict write
// is the claim: SaveIfAbsent stores it only
// when no verdict holds the sequence, so two stores over one datastore
// never overwrite each other's verdict. The verdict is written before the
// head that names it, so a reader never follows the head to a missing
// verdict; a claim whose head write was lost is skipped by the next probe.
func (s *Store) claimSequence(ctx context.Context, prefix string, seq uint64, v Verdict) (uint64, error) {
	for range maxSequenceAttempts {
		key := verdictKey(prefix, seq)
		stored, err := s.records.SaveIfAbsent(ctx, &verdictEntity{Key: key, Device: prefix, Verdict: v, Seq: seq})
		if err != nil {
			return 0, &StoreError{Op: "save", Key: key, Err: err}
		}
		if stored {
			return seq, nil
		}
		// Another writer holds seq; the head may have moved past it since
		// it was read, so probe from the head again rather than one by one.
		head, err := s.head(ctx, prefix)
		if err != nil {
			return 0, err
		}
		seq = max(seq+1, head.Count+1)
	}
	return 0, &StoreError{Op: "save", Key: verdictKey(prefix, seq),
		Err: fmt.Errorf("no free verdict sequence in %d attempts", maxSequenceAttempts)}
}

// advanceHead moves the device's head to seq unless it is already at or
// past it, by compare-and-swap, so the head never goes backwards and every
// sequence at or below it names a stored verdict.
func (s *Store) advanceHead(ctx context.Context, prefix string, seq uint64) error {
	key := headKey(prefix)
	for range maxSequenceAttempts {
		old, found, err := s.readHead(ctx, prefix)
		if err != nil {
			return err
		}
		if old.Count >= seq {
			return nil
		}
		next := *old
		next.Count, next.Seq = seq, seq
		var swapped bool
		if found {
			swapped, err = s.records.CompareAndSwap(ctx, old, &next)
		} else {
			swapped, err = s.records.SaveIfAbsent(ctx, &next)
		}
		if err != nil {
			return &StoreError{Op: "save", Key: key, Err: err}
		}
		if swapped {
			return nil
		}
	}
	return &StoreError{Op: "save", Key: key,
		Err: fmt.Errorf("head not advanced in %d attempts", maxSequenceAttempts)}
}

// head reads the device's head record; a device with no verdicts yields a
// new head with a zero count.
func (s *Store) head(ctx context.Context, prefix string) (*verdictEntity, error) {
	head, _, err := s.readHead(ctx, prefix)
	return head, err
}

// readHead returns the device's head record and whether it is stored; an
// absent head is a zero-count record under the head key.
func (s *Store) readHead(ctx context.Context, prefix string) (*verdictEntity, bool, error) {
	key := headKey(prefix)
	head, err := s.records.GetByNaturalKey(ctx, key)
	if err != nil {
		if isNotFound(err) {
			return &verdictEntity{Key: key}, false, nil
		}
		return nil, false, &StoreError{Op: "read", Key: key, Err: err}
	}
	return head, true, nil
}

// readRange reads the verdicts with sequences first..last inclusive, one
// record per sequence, in sequence (save) order.
func (s *Store) readRange(ctx context.Context, prefix string, first, last uint64) ([]Verdict, error) {
	verdicts := make([]Verdict, 0, last-first+1)
	for seq := first; seq <= last; seq++ {
		key := verdictKey(prefix, seq)
		e, err := s.records.GetByNaturalKey(ctx, key)
		if err != nil {
			return nil, &StoreError{Op: "read", Key: key, Err: err}
		}
		verdicts = append(verdicts, e.Verdict)
	}
	return verdicts, nil
}

// ListVerdicts returns the device's whole history in save order, which is
// oldest first: each verdict is saved as it is made. It reads one record per
// verdict; a caller serving a request pages with ListVerdictsPage instead.
func (s *Store) ListVerdicts(ctx context.Context, tenant, deviceID string) ([]Verdict, error) {
	prefix, err := devicePrefix(tenant, deviceID)
	if err != nil {
		return nil, err
	}
	// Every key read is under this tenant's device prefix; no other
	// tenant's or device's history is read.
	head, err := s.head(ctx, prefix)
	if err != nil {
		return nil, err
	}
	if head.Count == 0 {
		return []Verdict{}, nil
	}
	return s.readRange(ctx, prefix, 1, head.Count)
}

// DefaultVerdictPageSize is the page size of a history request that names
// none; MaxVerdictPageSize caps the page a request may ask for, so one
// response stays well inside a transport's default 4 MiB message limit
// however long a device's history grows.
const (
	DefaultVerdictPageSize = 100
	MaxVerdictPageSize     = 500
)

// VerdictPage is one page of a device's verdicts, oldest first, with the
// number of verdicts in the whole history.
type VerdictPage struct {
	Verdicts []Verdict
	Total    int
}

// ListVerdictsPage returns at most limit of the device's verdicts, oldest
// first, starting at offset. A zero limit means DefaultVerdictPageSize and
// a limit above MaxVerdictPageSize is capped to it; a negative offset or
// limit is an *InputError. An offset past the end returns an empty page.
func (s *Store) ListVerdictsPage(ctx context.Context, tenant, deviceID string, offset, limit int) (VerdictPage, error) {
	if offset < 0 {
		return VerdictPage{}, &InputError{Field: "offset", Cause: errors.New("is negative")}
	}
	if limit < 0 {
		return VerdictPage{}, &InputError{Field: "limit", Cause: errors.New("is negative")}
	}
	if limit == 0 {
		limit = DefaultVerdictPageSize
	}
	limit = min(limit, MaxVerdictPageSize)
	prefix, err := devicePrefix(tenant, deviceID)
	if err != nil {
		return VerdictPage{}, err
	}
	head, err := s.head(ctx, prefix)
	if err != nil {
		return VerdictPage{}, err
	}
	page := VerdictPage{Verdicts: []Verdict{}, Total: int(head.Count)}
	if uint64(offset) >= head.Count {
		return page, nil
	}
	first := uint64(offset) + 1
	last := min(uint64(offset)+uint64(limit), head.Count)
	page.Verdicts, err = s.readRange(ctx, prefix, first, last)
	if err != nil {
		return VerdictPage{}, err
	}
	return page, nil
}

// LatestVerdict returns the device's newest verdict, or a
// *VerdictNotFoundError when it has none.
func (s *Store) LatestVerdict(ctx context.Context, tenant, deviceID string) (*Verdict, error) {
	prefix, err := devicePrefix(tenant, deviceID)
	if err != nil {
		return nil, err
	}
	head, err := s.head(ctx, prefix)
	if err != nil {
		return nil, err
	}
	if head.Count == 0 {
		return nil, &VerdictNotFoundError{Tenant: tenant, DeviceID: deviceID}
	}
	verdicts, err := s.readRange(ctx, prefix, head.Seq, head.Seq)
	if err != nil {
		return nil, err
	}
	return &verdicts[0], nil
}

// devicePrefix returns the key prefix of one device's verdicts.
func devicePrefix(tenant, deviceID string) (string, error) {
	if err := validateDeviceID(deviceID); err != nil {
		return "", err
	}
	if tenant == "" {
		return "", &InputError{Field: "tenant", Cause: errors.New("is empty")}
	}
	prefix, err := scope.SharedPrefix(tenant, verdictFeature)
	if err != nil {
		return "", &InputError{Field: "tenant", Cause: err}
	}
	return prefix + deviceID + "/", nil
}

// validateDeviceID accepts a non-empty printable ID without a slash.
func validateDeviceID(deviceID string) error {
	if deviceID == "" || len(deviceID) > maxDeviceIDLen {
		return &InputError{Field: "device ID", Cause: fmt.Errorf("length must be 1 to %d", maxDeviceIDLen)}
	}
	for _, r := range deviceID {
		if r == '/' || r < 0x21 || r == 0x7f {
			return &InputError{Field: "device ID", Cause: fmt.Errorf("character %q is not allowed", r)}
		}
	}
	return nil
}
