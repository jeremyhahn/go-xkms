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
	"encoding/json"
	"errors"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// storagePrefix is the top-level namespace under which all SSH key
// envelopes are stored. Changing this string is a disk-layout break
// that requires a migration.
const storagePrefix = "ssh/keys/"

// Store is the pluggable persistence interface for SSH keys. All
// methods take a context.Context so storage backends can propagate
// deadlines / cancellation. Store implementations MUST be safe for
// concurrent use.
type Store interface {
	// Put persists key (overwriting any prior entry at the same
	// Scope/Owner/Name). The key's Material must be non-nil.
	Put(ctx context.Context, key *Key) error

	// Get loads the key identified by (sc, owner, name). Returns a
	// *KeyNotFoundError when the key does not exist.
	Get(ctx context.Context, sc scope.Scope, owner, name string) (*Key, error)

	// Delete removes the key. Returns *KeyNotFoundError if it is
	// already absent.
	Delete(ctx context.Context, sc scope.Scope, owner, name string) error

	// List returns stored key records scoped to (sc, owner) when both
	// are non-empty, to sc alone when owner is empty, or to everything
	// when both are empty. The returned Keys have nil Material — the
	// on-disk envelope is not opened during a list. Callers that need
	// the material must Get each one.
	List(ctx context.Context, sc scope.Scope, owner string) ([]*Key, error)
}

// storedEnvelope is the on-disk representation of a Key. It is a small
// JSON document so we don't need a schema / migration framework for
// trivial metadata changes. The private key material is the
// PEM-encoded bytes exactly as ssh.MarshalPrivateKey produced them —
// the wrap ceremony lives one layer up in the backend, not here.
type storedEnvelope struct {
	Version     int       `json:"v"`
	Scope       string    `json:"scope"`
	Owner       string    `json:"owner"`
	Name        string    `json:"name"`
	Algorithm   string    `json:"algo"`
	Fingerprint string    `json:"fp"`
	CreatedAt   time.Time `json:"created"`
	Comment     string    `json:"comment,omitempty"`
	PublicKey   string    `json:"pub"`     // authorized_keys line (no newline)
	MaterialPEM string    `json:"pem_b64"` // base64 JSON-string-encoded PEM
}

const envelopeVersion = 1

// BackendStore is the production Store. It serializes Keys into JSON
// envelopes and persists them under "ssh/keys/<scope>/<owner>/<name>"
// in the supplied storage.Backend.
type BackendStore struct {
	backend storage.Backend
}

// NewBackendStore constructs a BackendStore. Returns *NilInputError if
// backend is nil.
func NewBackendStore(backend storage.Backend) (*BackendStore, error) {
	if backend == nil {
		return nil, &NilInputError{Field: "backend"}
	}
	return &BackendStore{backend: backend}, nil
}

// Put writes key to the backend. Opens the Material enclave to read
// the PEM, encodes it, writes the envelope, and destroys the Buffer
// before returning.
func (s *BackendStore) Put(ctx context.Context, key *Key) error {
	if key == nil {
		return &NilInputError{Field: "key"}
	}
	if key.Material == nil {
		return &NilInputError{Field: "key.Material"}
	}
	id, err := scope.BuildKeyID(key.Scope, key.Owner, key.Name)
	if err != nil {
		return err
	}

	// Open the Secret into a Buffer, serialize the envelope, then
	// destroy the Buffer. The JSON bytes we hand to the backend are
	// the encrypted-at-rest form the backend chooses (plain on-disk
	// JSON if backed by memory; wrapped if backed by an envelope-
	// encrypting store). We do not wrap here — that lives one level
	// up in the service wiring.
	buf, err := key.Material.Open()
	if err != nil {
		return &KeyMaterialError{Op: "open secret for put", Err: err}
	}
	defer buf.Destroy()

	env := storedEnvelope{
		Version:     envelopeVersion,
		Scope:       string(key.Scope),
		Owner:       key.Owner,
		Name:        key.Name,
		Algorithm:   string(key.Algorithm),
		Fingerprint: key.Fingerprint,
		CreatedAt:   key.CreatedAt,
		Comment:     key.Comment,
		PublicKey:   strings.TrimRight(string(ssh.MarshalAuthorizedKey(key.PublicKey)), "\n"),
		MaterialPEM: string(buf.Bytes()),
	}

	data, jerr := json.Marshal(&env)
	if jerr != nil {
		return &SerializationError{Op: "marshal envelope", Err: jerr}
	}
	if perr := s.backend.Put(ctx, storagePrefix+id, data); perr != nil {
		return &StorageError{Op: "put", Err: perr}
	}
	return nil
}

// Get loads the key and rehydrates a fully-populated *Key.
func (s *BackendStore) Get(ctx context.Context, sc scope.Scope, owner, name string) (*Key, error) {
	id, err := scope.BuildKeyID(sc, owner, name)
	if err != nil {
		return nil, err
	}
	data, err := s.backend.Get(ctx, storagePrefix+id)
	if err != nil {
		if isStorageNotFound(err) {
			return nil, &KeyNotFoundError{ID: id}
		}
		return nil, &StorageError{Op: "get", Err: err}
	}
	var env storedEnvelope
	if jerr := json.Unmarshal(data, &env); jerr != nil {
		return nil, &SerializationError{Op: "unmarshal envelope", Err: jerr}
	}
	return envelopeToKey(&env)
}

// Delete removes the key from the backend.
func (s *BackendStore) Delete(ctx context.Context, sc scope.Scope, owner, name string) error {
	id, err := scope.BuildKeyID(sc, owner, name)
	if err != nil {
		return err
	}
	if derr := s.backend.Delete(ctx, storagePrefix+id); derr != nil {
		if isStorageNotFound(derr) {
			return &KeyNotFoundError{ID: id}
		}
		return &StorageError{Op: "delete", Err: derr}
	}
	return nil
}

// List enumerates keys under the requested prefix (see Store.List).
// The returned Keys have Material=nil — the caller Gets each one to
// receive material.
func (s *BackendStore) List(ctx context.Context, sc scope.Scope, owner string) ([]*Key, error) {
	prefix := storagePrefix
	if sc != "" {
		if !sc.Valid() {
			return nil, &scope.ScopeInvalidError{Value: string(sc)}
		}
		prefix += string(sc) + "/"
		if owner != "" {
			if strings.ContainsRune(owner, '/') {
				return nil, &scope.KeyIDMalformedError{Field: "owner", Reason: "contains separator"}
			}
			prefix += owner + "/"
		}
	}

	var out []*Key
	err := s.backend.Scan(ctx, prefix, func(_ string, value []byte) error {
		var env storedEnvelope
		if jerr := json.Unmarshal(value, &env); jerr != nil {
			return &SerializationError{Op: "unmarshal envelope", Err: jerr}
		}
		k, kerr := envelopeToKeyMetaOnly(&env)
		if kerr != nil {
			return kerr
		}
		out = append(out, k)
		return nil
	})
	if err != nil {
		return nil, &StorageError{Op: "scan", Err: err}
	}
	return out, nil
}

// envelopeToKey decodes an envelope and reconstructs the full *Key,
// including sealing the PEM into a new Secret.
func envelopeToKey(env *storedEnvelope) (*Key, error) {
	sc, err := scope.Parse(env.Scope)
	if err != nil {
		return nil, err
	}

	pub, _, _, _, pubErr := ssh.ParseAuthorizedKey([]byte(env.PublicKey))
	if pubErr != nil {
		return nil, &PEMParseError{Err: pubErr}
	}

	if env.MaterialPEM == "" {
		return nil, &KeyMaterialError{Op: "envelope has no material", Err: errors.New("empty pem")}
	}
	pemCopy := []byte(env.MaterialPEM)
	// Wipe the envelope's in-memory field so the JSON-unmarshal-allocated
	// string no longer holds the plaintext. json.Unmarshal strings are
	// immutable; we drop our reference by zeroing pemCopy after Secret
	// construction below. The original string in env.MaterialPEM is
	// unreachable after this function returns.
	material, merr := secure.NewSecret(pemCopy)
	if merr != nil {
		return nil, &KeyMaterialError{Op: "seal envelope pem", Err: merr}
	}
	secure.Wipe(pemCopy)

	return &Key{
		Material:    material,
		PublicKey:   pub,
		Algorithm:   Algorithm(env.Algorithm),
		Fingerprint: env.Fingerprint,
		Scope:       sc,
		Owner:       env.Owner,
		Name:        env.Name,
		CreatedAt:   env.CreatedAt,
		Comment:     env.Comment,
	}, nil
}

// envelopeToKeyMetaOnly builds a *Key with Material=nil — used for
// List results where we deliberately don't open every enclave.
func envelopeToKeyMetaOnly(env *storedEnvelope) (*Key, error) {
	sc, err := scope.Parse(env.Scope)
	if err != nil {
		return nil, err
	}
	pub, _, _, _, pubErr := ssh.ParseAuthorizedKey([]byte(env.PublicKey))
	if pubErr != nil {
		return nil, &PEMParseError{Err: pubErr}
	}
	return &Key{
		PublicKey:   pub,
		Algorithm:   Algorithm(env.Algorithm),
		Fingerprint: env.Fingerprint,
		Scope:       sc,
		Owner:       env.Owner,
		Name:        env.Name,
		CreatedAt:   env.CreatedAt,
		Comment:     env.Comment,
	}, nil
}

// isStorageNotFound checks whether a storage error indicates a missing
// key. We compare against the storage package's sentinel ErrNotFound;
// the backend implementations wrap it with fmt.Errorf, so
// errors.Is is the correct predicate.
func isStorageNotFound(err error) bool {
	return errors.Is(err, storage.ErrNotFound)
}
