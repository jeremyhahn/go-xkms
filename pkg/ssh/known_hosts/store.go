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
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// storagePrefix is the top-level namespace for pin envelopes. Changing
// this string is a disk-layout break that requires a migration.
const storagePrefix = "ssh/known_hosts/"

// envelopeVersion is the current on-disk envelope format. Incremented
// on incompatible schema changes.
const envelopeVersion = 2

// Store is the pluggable persistence interface for host-key pins. All
// methods take a context.Context so storage backends can propagate
// deadlines / cancellation. Implementations MUST be safe for
// concurrent use.
type Store interface {
	// Add persists pin. If a pin already exists for
	// (pin.Scope, pin.Owner, pin.Host), returns *DuplicateError — Add
	// does NOT overwrite. Callers that intend to rotate must Remove
	// first.
	Add(ctx context.Context, pin *Pin) error

	// Get loads the pin for (sc, owner, host). Returns *NotFoundError
	// when absent.
	Get(ctx context.Context, sc scope.Scope, owner, host string) (*Pin, error)

	// List returns all pins under the requested prefix. When sc is
	// empty every scope is returned; when owner is empty every owner
	// under sc is returned. Returned order is stable (backend-
	// determined prefix scan).
	List(ctx context.Context, sc scope.Scope, owner string) ([]*Pin, error)

	// Remove deletes the pin. Returns *NotFoundError if it is already
	// absent.
	Remove(ctx context.Context, sc scope.Scope, owner, host string) error
}

// storedEnvelope is the on-disk JSON shape for a pin. It is a small
// document because pins carry no secret material and no structured
// algorithm parameters.
type storedEnvelope struct {
	Version     int       `json:"v"`
	Scope       string    `json:"scope"`
	Owner       string    `json:"owner"`
	Host        string    `json:"host"`
	Fingerprint string    `json:"fp"`
	Algorithm   string    `json:"algo,omitempty"`
	AddedAt     time.Time `json:"added"`
	Source      string    `json:"source,omitempty"`

	// PublicKey is the base64 (std) SSH wire-format host key. Required from
	// envelope v2 onward; decodeEnvelope rejects a pre-v2 envelope that
	// lacks it with *LegacyPinError rather than reconstructing a
	// fingerprint-only Pin.
	PublicKey string `json:"pub,omitempty"`
}

// BackendStore is the production Store. It serializes Pins into JSON
// envelopes and persists them under
// "ssh/known_hosts/<scope>/<owner>/<host>" in the supplied
// storage.Backend.
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

// Add implements Store.Add.
func (s *BackendStore) Add(ctx context.Context, pin *Pin) error {
	if pin == nil {
		return &NilInputError{Field: "pin"}
	}
	path, err := buildPath(pin.Scope, pin.Owner, pin.Host)
	if err != nil {
		return err
	}
	if err := ValidateFingerprint(pin.Fingerprint); err != nil {
		return err
	}
	if len(pin.PublicKey) == 0 {
		return &PublicKeyRequiredError{Host: pin.Host}
	}

	// Duplicate check. The backend's Exists is advisory (TOCTOU
	// window) but Store contract says Add is the explicit-pin path;
	// callers racing rotation should serialize through higher layers.
	present, existsErr := s.backend.Exists(ctx, path)
	if existsErr != nil {
		return &StorageError{Op: "exists", Err: existsErr}
	}
	if present {
		return &DuplicateError{Scope: string(pin.Scope), Owner: pin.Owner, Host: pin.Host}
	}

	env := storedEnvelope{
		Version:     envelopeVersion,
		Scope:       string(pin.Scope),
		Owner:       pin.Owner,
		Host:        pin.Host,
		Fingerprint: pin.Fingerprint,
		Algorithm:   pin.Algorithm,
		AddedAt:     pin.AddedAt,
		Source:      pin.Source,
		PublicKey:   base64.StdEncoding.EncodeToString(pin.PublicKey),
	}
	if env.AddedAt.IsZero() {
		env.AddedAt = time.Now().UTC()
	}

	data, jerr := json.Marshal(&env)
	if jerr != nil {
		return &SerializationError{Op: "marshal envelope", Err: jerr}
	}
	if perr := s.backend.Put(ctx, path, data); perr != nil {
		return &StorageError{Op: "put", Err: perr}
	}
	return nil
}

// Get implements Store.Get.
func (s *BackendStore) Get(ctx context.Context, sc scope.Scope, owner, host string) (*Pin, error) {
	path, err := buildPath(sc, owner, host)
	if err != nil {
		return nil, err
	}
	data, gerr := s.backend.Get(ctx, path)
	if gerr != nil {
		if errors.Is(gerr, storage.ErrNotFound) {
			return nil, &NotFoundError{Scope: string(sc), Owner: owner, Host: host}
		}
		return nil, &StorageError{Op: "get", Err: gerr}
	}
	return decodeEnvelope(data)
}

// List implements Store.List.
func (s *BackendStore) List(ctx context.Context, sc scope.Scope, owner string) ([]*Pin, error) {
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

	var out []*Pin
	scanErr := s.backend.Scan(ctx, prefix, func(_ string, value []byte) error {
		pin, perr := decodeEnvelope(value)
		if perr != nil {
			// A single unmatchable legacy (pre-v2) pin must not block
			// listing every other pin in scope — List is the discovery
			// path an operator uses to find which hosts still need
			// re-pinning, so it skips rather than aborts. Get and Verify
			// (single-host lookups) still fail closed on the same pin.
			var legacy *LegacyPinError
			if errors.As(perr, &legacy) {
				return nil
			}
			return perr
		}
		out = append(out, pin)
		return nil
	})
	if scanErr != nil {
		return nil, &StorageError{Op: "scan", Err: scanErr}
	}
	return out, nil
}

// Remove implements Store.Remove.
func (s *BackendStore) Remove(ctx context.Context, sc scope.Scope, owner, host string) error {
	path, err := buildPath(sc, owner, host)
	if err != nil {
		return err
	}
	if derr := s.backend.Delete(ctx, path); derr != nil {
		if errors.Is(derr, storage.ErrNotFound) {
			return &NotFoundError{Scope: string(sc), Owner: owner, Host: host}
		}
		return &StorageError{Op: "delete", Err: derr}
	}
	return nil
}

// buildPath validates the components and returns the full storage key.
// The path layout is "ssh/known_hosts/<scope>/<owner>/<host>".
func buildPath(sc scope.Scope, owner, host string) (string, error) {
	if !sc.Valid() {
		return "", &scope.ScopeInvalidError{Value: string(sc)}
	}
	if owner == "" {
		return "", &scope.KeyIDMalformedError{Field: "owner", Reason: "empty"}
	}
	if strings.ContainsRune(owner, '/') {
		return "", &scope.KeyIDMalformedError{Field: "owner", Reason: "contains separator"}
	}
	if err := ValidateHost(host); err != nil {
		return "", err
	}
	var b strings.Builder
	b.Grow(len(storagePrefix) + len(sc) + len(owner) + len(host) + 2)
	b.WriteString(storagePrefix)
	b.WriteString(string(sc))
	b.WriteByte('/')
	b.WriteString(owner)
	b.WriteByte('/')
	b.WriteString(host)
	return b.String(), nil
}

// decodeEnvelope reads a JSON envelope and reconstructs a *Pin. Returns
// *LegacyPinError for a pre-v2 envelope that carries no PublicKey: such a
// pin can no longer be trusted for matching and must be re-pinned.
func decodeEnvelope(data []byte) (*Pin, error) {
	var env storedEnvelope
	if jerr := json.Unmarshal(data, &env); jerr != nil {
		return nil, &SerializationError{Op: "unmarshal envelope", Err: jerr}
	}
	sc, err := scope.Parse(env.Scope)
	if err != nil {
		return nil, err
	}
	if env.PublicKey == "" {
		return nil, &LegacyPinError{Host: env.Host}
	}
	raw, derr := base64.StdEncoding.DecodeString(env.PublicKey)
	if derr != nil {
		return nil, &SerializationError{Op: "decode public key", Err: derr}
	}
	pin := &Pin{
		Host:        env.Host,
		Fingerprint: env.Fingerprint,
		Algorithm:   env.Algorithm,
		Scope:       sc,
		Owner:       env.Owner,
		AddedAt:     env.AddedAt,
		Source:      env.Source,
		PublicKey:   raw,
	}
	return pin, nil
}
