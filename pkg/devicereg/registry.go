// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package devicereg

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/dao"
	"github.com/jeremyhahn/go-xkms/pkg/scope"
)

const (
	// DatabaseName is the go-qrdb database the registry's records live in.
	DatabaseName = "devices"

	// feature is the scope feature the records' keys are prefixed with.
	feature = "paired-devices"

	// entityType is the qrdb entity type of a stored record.
	entityType = "paired_devices"

	// maxIDLen is the longest device ID ValidateID accepts.
	maxIDLen = 128

	// listPageSize is the page size List reads records in.
	listPageSize = 1000
)

// Device is one paired device of a tenant. Its field names follow the
// local-mode record, xkey's pairing.PairedDevice, where the two overlap.
type Device struct {
	// ID is the device's key in the tenant: one path-safe name (ValidateID).
	ID string `json:"id"`
	// Name is the human-readable device name.
	Name string `json:"name"`
	// IdentityKey is the device identity public key, SPKI DER.
	IdentityKey []byte `json:"identity_key"`
	// AttestationProtocolVersion is the attestation model the device was
	// paired under; a later attestation under a lower version is a downgrade.
	AttestationProtocolVersion int `json:"attestation_protocol_version,omitempty"`
	// PairedAt is when the device was paired.
	PairedAt time.Time `json:"paired_at"`
	// RevokedAt is when the device was revoked; nil while it is active.
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	// PairedBy is the principal that paired the device.
	PairedBy string `json:"paired_by,omitempty"`
}

// Active reports whether the device is not revoked.
func (d *Device) Active() bool { return d.RevokedAt == nil }

// ValidateID reports whether id is one path-safe name: 1 to 128 ASCII
// letters, digits, '.', '_' or '-', and not "." or "..".
func ValidateID(id string) error {
	if id == "" || len(id) > maxIDLen || id == "." || id == ".." {
		return fmt.Errorf("%w: %q", ErrInvalidID, id)
	}
	for i := 0; i < len(id); i++ {
		if !idChar(id[i]) {
			return fmt.Errorf("%w: %q", ErrInvalidID, id)
		}
	}
	return nil
}

// idChar reports whether c may appear in a device ID.
func idChar(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	default:
		return c == '.' || c == '_' || c == '-'
	}
}

// entity is a Device as the qrdb DAO stores it, keyed by the tenant-scoped
// natural key.
type entity struct {
	ID     uint64 `json:"id"`
	Key    string `json:"key"`
	Device Device `json:"device"`
}

// EntityID implements the qrdb entity interface.
func (e *entity) EntityID() uint64 { return e.ID }

// SetEntityID implements the qrdb entity interface.
func (e *entity) SetEntityID(id uint64) { e.ID = id }

// Registry is the tenant-scoped paired-device registry. It is safe for
// concurrent use, also across processes on one store: Pair creates a record
// with the store's atomic conditional put, so of two concurrent pairs of one
// ID exactly one wins. Revoke is serialised within one registry.
type Registry struct {
	mu      sync.Mutex
	records qrdbsdk.GenericDAO[*entity]
}

// NewRegistry opens the registry on daos.
func NewRegistry(daos *qrdbsdk.DAOFactory) (*Registry, error) {
	if daos == nil {
		return nil, fmt.Errorf("%w: no DAO factory", ErrInvalidConfig)
	}
	records, err := dao.New(daos, DatabaseName, entityType, func() *entity { return &entity{} },
		qrdbsdk.WithIDGenerator(qrdbsdk.NewCryptoFieldHashGenerator("Key")))
	if err != nil {
		return nil, fmt.Errorf("%w: cannot open the %s DAO: %v", ErrInvalidConfig, entityType, err)
	}
	return &Registry{records: records}, nil
}

// Pair records device in tenant. It refuses a nil device, a device with no
// identity key or already revoked, and an ID the tenant already holds
// (ErrDeviceExists), active or revoked. The create is atomic in the store
// (SaveIfAbsent); a store without atomic writes is refused with a
// StoreError matching qrdbsdk.ErrKVAtomicWriteUnsupported.
func (r *Registry) Pair(ctx context.Context, tenant string, device *Device) error {
	if device == nil || len(device.IdentityKey) == 0 || device.RevokedAt != nil {
		return fmt.Errorf("%w: a pair needs an unrevoked device with an identity key", ErrInvalidDevice)
	}
	key, err := recordKey(tenant, device.ID)
	if err != nil {
		return err
	}
	record := *device
	record.IdentityKey = bytes.Clone(device.IdentityKey)
	stored, err := r.records.SaveIfAbsent(ctx, &entity{Key: key, Device: record})
	if err != nil {
		return &StoreError{Op: "pair", ID: device.ID, Err: err}
	}
	if !stored {
		return fmt.Errorf("%w: %q", ErrDeviceExists, device.ID)
	}
	return nil
}

// Get returns tenant's device id, or ErrDeviceNotFound.
func (r *Registry) Get(ctx context.Context, tenant, id string) (*Device, error) {
	key, err := recordKey(tenant, id)
	if err != nil {
		return nil, err
	}
	stored, err := r.load(ctx, "get", key, id)
	if err != nil {
		return nil, err
	}
	return &stored.Device, nil
}

// List returns tenant's devices, active and revoked, ordered by ID.
func (r *Registry) List(ctx context.Context, tenant string) ([]*Device, error) {
	prefix, err := tenantPrefix(tenant)
	if err != nil {
		return nil, err
	}
	var entities []*entity
	query := qrdbsdk.PageQuery{Page: 1, PageSize: listPageSize}
	err = r.records.ForEachPage(ctx, query, func(page qrdbsdk.PageResult[*entity]) error {
		for _, e := range page.Entities {
			if strings.HasPrefix(e.Key, prefix) {
				entities = append(entities, e)
			}
		}
		return nil
	})
	if err != nil {
		return nil, &StoreError{Op: "list", Err: err}
	}
	sort.Slice(entities, func(i, j int) bool { return entities[i].Device.ID < entities[j].Device.ID })
	devices := make([]*Device, 0, len(entities))
	for _, e := range entities {
		devices = append(devices, &e.Device)
	}
	return devices, nil
}

// Revoke marks tenant's device id revoked at at and keeps the record. A
// device already revoked keeps its first revocation time; the call succeeds.
func (r *Registry) Revoke(ctx context.Context, tenant, id string, at time.Time) error {
	if at.IsZero() {
		return fmt.Errorf("%w: a revoke needs a time", ErrInvalidDevice)
	}
	key, err := recordKey(tenant, id)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	stored, err := r.load(ctx, "revoke", key, id)
	if err != nil {
		return err
	}
	if !stored.Device.Active() {
		return nil
	}
	stored.Device.RevokedAt = &at
	if err := r.records.Save(ctx, stored); err != nil {
		return &StoreError{Op: "revoke", ID: id, Err: err}
	}
	return nil
}

// IsActive reports whether tenant's device id is paired and not revoked. An
// ID the tenant does not hold is ErrDeviceNotFound.
func (r *Registry) IsActive(ctx context.Context, tenant, id string) (bool, error) {
	device, err := r.Get(ctx, tenant, id)
	if err != nil {
		return false, err
	}
	return device.Active(), nil
}

// load reads the record at key; ErrDeviceNotFound when it is absent.
func (r *Registry) load(ctx context.Context, op, key, id string) (*entity, error) {
	stored, err := r.records.GetByNaturalKey(ctx, key)
	if qrdbsdk.IsDAONotFound(err) {
		return nil, ErrDeviceNotFound
	}
	if err != nil {
		return nil, &StoreError{Op: op, ID: id, Err: err}
	}
	return stored, nil
}

// tenantPrefix is the key prefix of tenant's records.
func tenantPrefix(tenant string) (string, error) {
	if tenant == "" {
		return "", fmt.Errorf("%w: empty tenant", ErrInvalidTenant)
	}
	prefix, err := scope.SharedPrefix(tenant, feature)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidTenant, err)
	}
	return prefix, nil
}

// recordKey is the natural key of tenant's device id.
func recordKey(tenant, id string) (string, error) {
	if err := ValidateID(id); err != nil {
		return "", err
	}
	prefix, err := tenantPrefix(tenant)
	if err != nil {
		return "", err
	}
	return prefix + id, nil
}
