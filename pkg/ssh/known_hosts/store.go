// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package known_hosts

import (
	"context"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/records"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
)

// Store is the pluggable persistence interface for host-key pins. All
// methods take a context.Context so storage backends can propagate
// deadlines / cancellation. Implementations MUST be safe for
// concurrent use.
type Store interface {
	// Add persists pin. If a pin already exists for
	// (pin.Scope, pin.Owner, pin.Host) — or, for a tenant-scoped pin,
	// for the host under any owner — returns *DuplicateError: Add does
	// NOT overwrite. Callers that intend to rotate must Remove first.
	Add(ctx context.Context, pin *Pin) error

	// Get loads the pin for (sc, owner, host). Returns *NotFoundError
	// when absent or held by another owner.
	Get(ctx context.Context, sc scope.Scope, owner, host string) (*Pin, error)

	// List returns all pins under the requested filter. When sc is
	// empty every scope is returned; when owner is empty every owner
	// under sc is returned. Pins are returned in record-path order.
	List(ctx context.Context, sc scope.Scope, owner string) ([]*Pin, error)

	// Remove deletes the pin. Returns *NotFoundError if it is already
	// absent or held by another owner.
	Remove(ctx context.Context, sc scope.Scope, owner, host string) error
}

// envelope is the stored body of a pin. Pins carry no secret material and
// no structured algorithm parameters; the host is the record's name.
type envelope struct {
	Fingerprint string    `json:"fp"`
	Algorithm   string    `json:"algo,omitempty"`
	AddedAt     time.Time `json:"added"`
	Source      string    `json:"source,omitempty"`

	// PublicKey is the SSH wire-format host key.
	PublicKey []byte `json:"pub"`
}

// DAOStore is the production Store. Each pin is a records.Entity of kind
// scope.KindKnownHosts in the records.DatabaseName database, named by its
// host.
//
// A tenant-scoped pin's path carries no owner, so the stored Owner is
// authoritative: a pin held by another owner answers as missing.
type DAOStore struct {
	table *records.Table[envelope]
}

var _ Store = (*DAOStore)(nil)

// NewDAOStore constructs the DAOStore over the DAOs daos builds, viewed
// through the platform partition. Returns *NilInputError if daos is nil.
func NewDAOStore(daos *qrdbsdk.DAOFactory) (*DAOStore, error) {
	if daos == nil {
		return nil, &NilInputError{Field: "daos"}
	}
	table, err := records.New[envelope](daos, scope.KindKnownHosts)
	if err != nil {
		return nil, &StorageError{Op: "open", Err: err}
	}
	return &DAOStore{table: table}, nil
}

// Partition returns the view of s through tenantID's partition ("" is the
// platform partition). The view shares s's DAO.
func (s *DAOStore) Partition(tenantID string) (*DAOStore, error) {
	table, err := s.table.Partition(tenantID)
	if err != nil {
		return nil, err
	}
	return &DAOStore{table: table}, nil
}

// Add implements Store.Add.
func (s *DAOStore) Add(ctx context.Context, pin *Pin) error {
	if pin == nil {
		return &NilInputError{Field: "pin"}
	}
	if err := validate(pin.Scope, pin.Owner, pin.Host); err != nil {
		return err
	}
	if err := ValidateFingerprint(pin.Fingerprint); err != nil {
		return err
	}
	if len(pin.PublicKey) == 0 {
		return &PublicKeyRequiredError{Host: pin.Host}
	}

	env := envelope{
		Fingerprint: pin.Fingerprint,
		Algorithm:   pin.Algorithm,
		AddedAt:     pin.AddedAt,
		Source:      pin.Source,
		PublicKey:   pin.PublicKey,
	}
	if env.AddedAt.IsZero() {
		env.AddedAt = time.Now().UTC()
	}
	stored, err := s.table.Create(ctx, pin.Scope, pin.Owner, pin.Host, env)
	if err != nil {
		return &StorageError{Op: "put", Err: err}
	}
	if !stored {
		return &DuplicateError{Scope: string(pin.Scope), Owner: pin.Owner, Host: pin.Host}
	}
	return nil
}

// Get implements Store.Get.
func (s *DAOStore) Get(ctx context.Context, sc scope.Scope, owner, host string) (*Pin, error) {
	if err := validate(sc, owner, host); err != nil {
		return nil, err
	}
	e, found, err := s.table.Get(ctx, sc, owner, host)
	if err != nil {
		return nil, &StorageError{Op: "get", Err: err}
	}
	if !found {
		return nil, &NotFoundError{Scope: string(sc), Owner: owner, Host: host}
	}
	return pin(e), nil
}

// List implements Store.List.
func (s *DAOStore) List(ctx context.Context, sc scope.Scope, owner string) ([]*Pin, error) {
	if err := scope.ValidateFilter(sc, owner); err != nil {
		return nil, err
	}
	entities, err := s.table.List(ctx, sc, owner)
	if err != nil {
		return nil, &StorageError{Op: "list", Err: err}
	}
	out := make([]*Pin, 0, len(entities))
	for _, e := range entities {
		out = append(out, pin(e))
	}
	return out, nil
}

// Remove implements Store.Remove. A pin held by another owner answers as
// missing and survives.
func (s *DAOStore) Remove(ctx context.Context, sc scope.Scope, owner, host string) error {
	if err := validate(sc, owner, host); err != nil {
		return err
	}
	deleted, err := s.table.Delete(ctx, sc, owner, host)
	if err != nil {
		return &StorageError{Op: "delete", Err: err}
	}
	if !deleted {
		return &NotFoundError{Scope: string(sc), Owner: owner, Host: host}
	}
	return nil
}

// validate checks the coordinates of a pin. The host is validated first so
// a malformed host reports *InvalidHostError; the rest is validated as
// scope.KindKnownHosts.RecordPath validates it.
func validate(sc scope.Scope, owner, host string) error {
	if !sc.Valid() {
		return &scope.ScopeInvalidError{Value: string(sc)}
	}
	if err := ValidateHost(host); err != nil {
		return err
	}
	_, err := scope.KindKnownHosts.RecordPath(sc, owner, host)
	return err
}

// pin reconstructs the *Pin e stores.
func pin(e *records.Entity[envelope]) *Pin {
	return &Pin{
		Host:        e.Name,
		Fingerprint: e.Body.Fingerprint,
		Algorithm:   e.Body.Algorithm,
		Scope:       e.Scope,
		Owner:       e.Owner,
		AddedAt:     e.Body.AddedAt,
		Source:      e.Body.Source,
		PublicKey:   e.Body.PublicKey,
	}
}
