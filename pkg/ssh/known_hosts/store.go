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
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// envelopeVersion is the current on-disk envelope format. Incremented
// on incompatible schema changes.
const envelopeVersion = 2

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

	// List returns all pins under the requested prefix. When sc is
	// empty every scope is returned; when owner is empty every owner
	// under sc is returned. Returned order is stable (backend-
	// determined prefix scan).
	List(ctx context.Context, sc scope.Scope, owner string) ([]*Pin, error)

	// Remove deletes the pin. Returns *NotFoundError if it is already
	// absent or held by another owner.
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
	// envelope v2 onward; storedEnvelope.pin rejects a pre-v2 envelope that
	// lacks it with *LegacyPinError rather than reconstructing a
	// fingerprint-only Pin.
	PublicKey string `json:"pub,omitempty"`
}

// BackendStore is the production Store. It serializes Pins into JSON
// envelopes and persists them at scope.KindKnownHosts.RecordPath -- e.g.
// "ssh/users/<owner>/known_hosts/<host>" -- in the supplied
// storage.Backend.
//
// A tenant-scoped path carries no owner, so the envelope's Owner is
// authoritative: a pin held by another owner answers as missing.
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
	env, err := s.load(ctx, path, sc, owner, host)
	if err != nil {
		return nil, err
	}
	return env.pin()
}

// List implements Store.List.
func (s *BackendStore) List(ctx context.Context, sc scope.Scope, owner string) ([]*Pin, error) {
	prefix, err := scope.ListPrefix(sc, owner)
	if err != nil {
		return nil, err
	}

	var out []*Pin
	scanErr := s.backend.Scan(ctx, prefix, func(key string, value []byte) error {
		if !scope.KindKnownHosts.Match(key) {
			return nil
		}
		env, derr := decodeEnvelope(value)
		if derr != nil {
			return derr
		}
		if sc != "" && owner != "" && env.Owner != owner {
			return nil
		}
		pin, perr := env.pin()
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

// Remove implements Store.Remove. A tenant-scoped pin is read first so a
// pin held by another owner answers as missing and survives.
func (s *BackendStore) Remove(ctx context.Context, sc scope.Scope, owner, host string) error {
	path, err := buildPath(sc, owner, host)
	if err != nil {
		return err
	}
	if sc == scope.Tenant {
		if _, lerr := s.load(ctx, path, sc, owner, host); lerr != nil {
			return lerr
		}
	}
	if derr := s.backend.Delete(ctx, path); derr != nil {
		if errors.Is(derr, storage.ErrNotFound) {
			return &NotFoundError{Scope: string(sc), Owner: owner, Host: host}
		}
		return &StorageError{Op: "delete", Err: derr}
	}
	return nil
}

// load returns the envelope at path, the pin of (sc, owner, host). A
// missing pin, or one held by another owner, is *NotFoundError.
func (s *BackendStore) load(ctx context.Context, path string, sc scope.Scope, owner, host string) (*storedEnvelope, error) {
	data, err := s.backend.Get(ctx, path)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, &NotFoundError{Scope: string(sc), Owner: owner, Host: host}
		}
		return nil, &StorageError{Op: "get", Err: err}
	}
	env, err := decodeEnvelope(data)
	if err != nil {
		return nil, err
	}
	if env.Owner != owner {
		return nil, &NotFoundError{Scope: string(sc), Owner: owner, Host: host}
	}
	return env, nil
}

// buildPath validates the components and returns the pin's storage path
// (scope.KindKnownHosts.RecordPath). The host is validated first so a
// malformed host reports *InvalidHostError.
func buildPath(sc scope.Scope, owner, host string) (string, error) {
	if !sc.Valid() {
		return "", &scope.ScopeInvalidError{Value: string(sc)}
	}
	if err := ValidateHost(host); err != nil {
		return "", err
	}
	return scope.KindKnownHosts.RecordPath(sc, owner, host)
}

// decodeEnvelope unmarshals a JSON envelope.
func decodeEnvelope(data []byte) (*storedEnvelope, error) {
	var env storedEnvelope
	if jerr := json.Unmarshal(data, &env); jerr != nil {
		return nil, &SerializationError{Op: "unmarshal envelope", Err: jerr}
	}
	return &env, nil
}

// pin reconstructs the *Pin env stores. Returns *LegacyPinError for a
// pre-v2 envelope that carries no PublicKey: such a pin can no longer be
// trusted for matching and must be re-pinned.
func (env *storedEnvelope) pin() (*Pin, error) {
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
	return &Pin{
		Host:        env.Host,
		Fingerprint: env.Fingerprint,
		Algorithm:   env.Algorithm,
		Scope:       sc,
		Owner:       env.Owner,
		AddedAt:     env.AddedAt,
		Source:      env.Source,
		PublicKey:   raw,
	}, nil
}
