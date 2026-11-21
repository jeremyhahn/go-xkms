package continuous

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"sort"

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
	records qrdbsdk.GenericDAO[*verdictEntity]
}

type verdictEntity struct {
	ID  uint64 `json:"id"`
	Key string `json:"key"`
	// Device is the tenant-scoped device prefix; indexed so a read
	// selects one device's verdicts without a collection scan.
	Device  string  `json:"device" index:"true"`
	Verdict Verdict `json:"verdict"`
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
	key := fmt.Sprintf("%s%020d-%s", prefix, v.At.UnixNano(), rand.Text())
	if err := s.records.Save(ctx, &verdictEntity{Key: key, Device: prefix, Verdict: v}); err != nil {
		return &StoreError{Op: "save", Key: key, Err: err}
	}
	return nil
}

// ListVerdicts returns the device's verdicts, oldest first.
func (s *Store) ListVerdicts(ctx context.Context, tenant, deviceID string) ([]Verdict, error) {
	prefix, err := devicePrefix(tenant, deviceID)
	if err != nil {
		return nil, err
	}
	// The indexed Device field selects one device's verdicts; no other
	// tenant's or device's history is read.
	entities, err := s.records.Find(ctx).Where("Device = ?", prefix).Execute()
	if err != nil {
		return nil, &StoreError{Op: "list", Key: prefix, Err: err}
	}
	sort.Slice(entities, func(i, j int) bool {
		if !entities[i].Verdict.At.Equal(entities[j].Verdict.At) {
			return entities[i].Verdict.At.Before(entities[j].Verdict.At)
		}
		return entities[i].Key < entities[j].Key
	})
	verdicts := make([]Verdict, 0, len(entities))
	for _, e := range entities {
		verdicts = append(verdicts, e.Verdict)
	}
	return verdicts, nil
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
	all, err := s.ListVerdicts(ctx, tenant, deviceID)
	if err != nil {
		return VerdictPage{}, err
	}
	page := VerdictPage{Verdicts: []Verdict{}, Total: len(all)}
	if offset < len(all) {
		page.Verdicts = all[offset:min(offset+limit, len(all))]
	}
	return page, nil
}

// LatestVerdict returns the device's newest verdict, or a
// *VerdictNotFoundError when it has none.
func (s *Store) LatestVerdict(ctx context.Context, tenant, deviceID string) (*Verdict, error) {
	verdicts, err := s.ListVerdicts(ctx, tenant, deviceID)
	if err != nil {
		return nil, err
	}
	if len(verdicts) == 0 {
		return nil, &VerdictNotFoundError{Tenant: tenant, DeviceID: deviceID}
	}
	return &verdicts[len(verdicts)-1], nil
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
