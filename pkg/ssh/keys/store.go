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

package keys

import (
	"context"
	"errors"
	"strings"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/records"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// Store is the pluggable persistence interface for SSH keys. All
// methods take a context.Context so storage backends can propagate
// deadlines / cancellation. Store implementations MUST be safe for
// concurrent use.
type Store interface {
	// Put persists key (overwriting any prior entry at the same
	// Scope/Owner/Name). The key's Material must be non-nil. A
	// tenant-scoped key held by another owner is never overwritten: Put
	// returns *OwnerConflictError.
	Put(ctx context.Context, key *Key) error

	// Get loads the key identified by (sc, owner, name). Returns a
	// *KeyNotFoundError when the key does not exist or is held by
	// another owner.
	Get(ctx context.Context, sc scope.Scope, owner, name string) (*Key, error)

	// Delete removes the key. Returns *KeyNotFoundError if it is
	// already absent or held by another owner.
	Delete(ctx context.Context, sc scope.Scope, owner, name string) error

	// List returns stored key records scoped to (sc, owner) when both
	// are non-empty, to sc alone when owner is empty, or to everything
	// when sc is empty. The returned Keys have nil Material — the
	// stored envelope is not opened during a list. Callers that need
	// the material must Get each one.
	List(ctx context.Context, sc scope.Scope, owner string) ([]*Key, error)
}

// envelope is the stored body of a Key. The private key material is the
// PEM-encoded bytes exactly as ssh.MarshalPrivateKey produced them — the
// wrap ceremony lives one layer up in the backend, not here.
type envelope struct {
	Algorithm   string            `json:"algo"`
	Fingerprint string            `json:"fp"`
	CreatedAt   time.Time         `json:"created"`
	Comment     string            `json:"comment,omitempty"`
	PublicKey   string            `json:"pub"`               // authorized_keys line (no newline)
	MaterialPEM types.SecretBytes `json:"pem_b64,omitempty"` // empty for backend-backed keys

	// BackendID / BackendKeyID identify the crypto backend holding the
	// private half of a backend-backed key. When BackendID is set,
	// MaterialPEM is empty and signing is delegated to the backend.
	BackendID    string `json:"backend_id,omitempty"`
	BackendKeyID string `json:"backend_key_id,omitempty"`
}

// Wipe zeroes the envelope's private material. It implements
// records.Wiper, so the record table wipes every envelope it reads and
// withholds.
func (e *envelope) Wipe() {
	e.MaterialPEM.Wipe()
}

// DAOStore is the production Store. Each key is a records.Entity of kind
// scope.KindKeys in the records.DatabaseName database.
//
// A tenant-scoped key's path carries no owner, so the stored Owner is
// authoritative: a key held by another owner answers as missing and is
// never overwritten.
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
	table, err := records.New[envelope](daos, scope.KindKeys)
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

// Put writes key. A software key's Material enclave is opened to read the
// PEM, which is wiped before Put returns.
func (s *DAOStore) Put(ctx context.Context, key *Key) error {
	if key == nil {
		return &NilInputError{Field: "key"}
	}
	if key.PublicKey == nil {
		return &NilInputError{Field: "key.PublicKey"}
	}
	// A key is either software (Material holds the sealed PEM) or
	// backend-backed (BackendID set, no PEM). At least one must hold.
	if key.Material == nil && !key.IsBackendBacked() {
		return &NilInputError{Field: "key.Material"}
	}
	if _, err := scope.KindKeys.RecordPath(key.Scope, key.Owner, key.Name); err != nil {
		return err
	}

	env := envelope{
		Algorithm:    string(key.Algorithm),
		Fingerprint:  key.Fingerprint,
		CreatedAt:    key.CreatedAt,
		Comment:      key.Comment,
		PublicKey:    strings.TrimRight(string(ssh.MarshalAuthorizedKey(key.PublicKey)), "\n"),
		BackendID:    key.BackendID,
		BackendKeyID: key.BackendKeyID,
	}
	if !key.IsBackendBacked() {
		buf, err := key.Material.Open(ctx)
		if err != nil {
			return &KeyMaterialError{Op: "open secret for put", Err: err}
		}
		defer buf.Destroy()
		pem, err := secure.CopyOut(buf)
		if err != nil {
			return &KeyMaterialError{Op: "copy secret for put", Err: err}
		}
		defer secure.Wipe(pem)
		env.MaterialPEM = pem
	}

	stored, err := s.table.Put(ctx, key.Scope, key.Owner, key.Name, env)
	if err != nil {
		return &StorageError{Op: "put", Err: err}
	}
	if !stored {
		return &OwnerConflictError{ID: string(key.Scope) + "/" + key.Owner + "/" + key.Name}
	}
	return nil
}

// Get loads the key and rehydrates a fully-populated *Key.
func (s *DAOStore) Get(ctx context.Context, sc scope.Scope, owner, name string) (*Key, error) {
	if _, err := scope.KindKeys.RecordPath(sc, owner, name); err != nil {
		return nil, err
	}
	e, found, err := s.table.Get(ctx, sc, owner, name)
	if err != nil {
		return nil, &StorageError{Op: "get", Err: err}
	}
	if !found {
		return nil, notFound(sc, owner, name)
	}
	return entityToKey(ctx, e)
}

// Delete removes the key. A key held by another owner answers as missing
// and survives.
func (s *DAOStore) Delete(ctx context.Context, sc scope.Scope, owner, name string) error {
	if _, err := scope.KindKeys.RecordPath(sc, owner, name); err != nil {
		return err
	}
	deleted, err := s.table.Delete(ctx, sc, owner, name)
	if err != nil {
		return &StorageError{Op: "delete", Err: err}
	}
	if !deleted {
		return notFound(sc, owner, name)
	}
	return nil
}

// List enumerates keys under the requested filter (see Store.List), in
// path order. The returned Keys have Material=nil — the caller Gets each
// one to receive material.
func (s *DAOStore) List(ctx context.Context, sc scope.Scope, owner string) ([]*Key, error) {
	if err := scope.ValidateFilter(sc, owner); err != nil {
		return nil, err
	}
	entities, err := s.table.List(ctx, sc, owner)
	if err != nil {
		return nil, &StorageError{Op: "list", Err: err}
	}
	// Every envelope is wiped, including those after a failing one.
	defer func() {
		for _, e := range entities {
			e.Body.Wipe()
		}
	}()
	out := make([]*Key, 0, len(entities))
	for _, e := range entities {
		k, err := entityToKeyMetaOnly(e)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, nil
}

// ImportLegacy upserts a key the pre-DAO sealed-KV store wrote: rel is its
// old key below the tenant root and data its JSON. It is the per-record step
// of the SSH store migrator (pkg/ssh/migrate) and returns the
// records.Table.Import errors.
func (s *DAOStore) ImportLegacy(ctx context.Context, rel string, data []byte) error {
	return s.table.Import(ctx, rel, data, checkLegacy)
}

// checkLegacy refuses a pre-DAO key whose public key does not parse or that
// holds neither material nor a backend reference, as Put does.
func checkLegacy(e *records.Entity[envelope]) error {
	k, err := entityToKeyMetaOnly(e)
	if err != nil {
		return err
	}
	if len(e.Body.MaterialPEM) == 0 && !k.IsBackendBacked() {
		return &NilInputError{Field: "key.Material"}
	}
	return nil
}

// notFound returns the *KeyNotFoundError of (sc, owner, name), identified
// by the key's "<scope>/<owner>/<name>" ID. The components were validated by
// RecordPath, so the ID is well-formed.
func notFound(sc scope.Scope, owner, name string) error {
	return &KeyNotFoundError{ID: string(sc) + "/" + owner + "/" + name}
}

// entityToKey reconstructs the full *Key e stores, sealing the PEM into a
// new Secret. e's envelope holds no plaintext afterwards.
func entityToKey(ctx context.Context, e *records.Entity[envelope]) (*Key, error) {
	defer e.Body.Wipe()
	k, err := entityToKeyMetaOnly(e)
	if err != nil {
		return nil, err
	}
	// Backend-backed key: no PEM to seal — the private half lives in the
	// crypto backend; signing is delegated via (*Key).BackendSigner.
	if k.IsBackendBacked() {
		return k, nil
	}
	if len(e.Body.MaterialPEM) == 0 {
		return nil, &KeyMaterialError{Op: "envelope has no material", Err: errors.New("empty pem")}
	}
	// NewSecret takes ownership of the envelope's PEM bytes and wipes them
	// on every path.
	material, err := secure.NewSecret(ctx, e.Body.MaterialPEM)
	e.Body.MaterialPEM = nil
	if err != nil {
		return nil, &KeyMaterialError{Op: "seal envelope pem", Err: err}
	}
	k.Material = material
	return k, nil
}

// entityToKeyMetaOnly builds the *Key e stores with Material=nil — used for
// List results, which deliberately open no enclave.
func entityToKeyMetaOnly(e *records.Entity[envelope]) (*Key, error) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(e.Body.PublicKey))
	if err != nil {
		return nil, &PEMParseError{Err: err}
	}
	return &Key{
		PublicKey:    pub,
		Algorithm:    Algorithm(e.Body.Algorithm),
		Fingerprint:  e.Body.Fingerprint,
		Scope:        e.Scope,
		Owner:        e.Owner,
		Name:         e.Name,
		CreatedAt:    e.Body.CreatedAt,
		Comment:      e.Body.Comment,
		BackendID:    e.Body.BackendID,
		BackendKeyID: e.Body.BackendKeyID,
	}, nil
}
