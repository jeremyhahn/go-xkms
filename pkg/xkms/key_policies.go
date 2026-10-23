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

package xkms

import (
	"context"
	"fmt"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/keypolicy"
)

// ErrKeyPoliciesNotConfigured is returned by the key management operations
// that change a key's record when no key-policy store is wired
// (SetKeyPolicyStore). It matches ErrNotConfigured.
var ErrKeyPoliciesNotConfigured = fmt.Errorf("%w: key policy store", ErrNotConfigured)

// InvalidKeyPolicyError reports a key management request field the service
// cannot store: an unknown operation or status, a limit out of range.
type InvalidKeyPolicyError struct {
	Field  string
	Reason string
}

// Error implements the error interface.
func (e *InvalidKeyPolicyError) Error() string {
	return fmt.Sprintf("keystore: invalid %s: %s", e.Field, e.Reason)
}

// UnenforceablePolicyError reports a policy field the service cannot
// enforce: per-operation MFA, automatic rotation, automatic version
// retirement. The service refuses the policy rather than store one it would
// ignore.
type UnenforceablePolicyError struct {
	KeyID  string
	Field  string
	Reason string
}

// Error implements the error interface.
func (e *UnenforceablePolicyError) Error() string {
	return fmt.Sprintf("keystore: key %q: %s cannot be enforced: %s", e.KeyID, e.Field, e.Reason)
}

// KeyStatusTransitionError reports a status change the key's current status
// forbids: a revoked key stays revoked.
type KeyStatusTransitionError struct {
	KeyID string
	From  string
	To    string
}

// Error implements the error interface.
func (e *KeyStatusTransitionError) Error() string {
	return fmt.Sprintf("keystore: key %q cannot change from %s to %s", e.KeyID, e.From, e.To)
}

// KeyKindError reports a key management operation the key's kind does not
// support: the public key of a symmetric key, usage limits on a key that is
// not an AEAD key.
type KeyKindError struct {
	KeyID     string
	Operation string
	Reason    string
}

// Error implements the error interface.
func (e *KeyKindError) Error() string {
	return fmt.Sprintf("keystore: key %q does not support %s: %s", e.KeyID, e.Operation, e.Reason)
}

// BackendTestUnsupportedError reports a backend BackendTest cannot run a
// non-destructive round trip on.
type BackendTestUnsupportedError struct {
	Backend string
	Reason  string
}

// Error implements the error interface.
func (e *BackendTestUnsupportedError) Error() string {
	return fmt.Sprintf("keystore: backend %q cannot be tested: %s", e.Backend, e.Reason)
}

// SetKeyPolicyStore wires the store of key-policy records. Without one,
// every key is enabled with no policy and no usage limits, and the
// operations that change a record return ErrKeyPoliciesNotConfigured.
func (s *XKMSService) SetKeyPolicyStore(store *keypolicy.Store) { s.keyPolicies.store(store) }

// KeyPolicyStore returns the wired key-policy store, or nil.
func (s *XKMSService) KeyPolicyStore() *keypolicy.Store { return s.keyPolicies.load() }

// requirePolicyStore returns the key-policy store, or
// ErrKeyPoliciesNotConfigured.
func (s *XKMSService) requirePolicyStore() (*keypolicy.Store, error) {
	store := s.keyPolicies.load()
	if store == nil {
		return nil, ErrKeyPoliciesNotConfigured
	}
	return store, nil
}

// loadPolicyRecord returns the record of k: the stored one, or the implicit
// one when the key has none or no store is wired.
func (s *XKMSService) loadPolicyRecord(ctx context.Context, k *versionedKey) (*keypolicy.Record, error) {
	store := s.keyPolicies.load()
	if store == nil {
		return keypolicy.Implicit(k.keyID, k.backendName), nil
	}
	rec, _, err := store.Load(ctx, k.tenant, k.backendName, k.keyID)
	return rec, err
}

// admitKey applies k's record to a use of the key for op, after RBAC has
// authorized the request: a disabled or revoked key, a use the key's policy
// refuses, or an authenticated encryption past its AEAD usage limits is
// refused. Each size is one use over that many bytes; none is one use of
// no bytes.
//
// A key whose record counts its uses (keypolicy.Record.Tracks) has them
// counted here, under the record's lock, before the operation runs: an
// invocation that is attempted counts toward the limit whether or not it
// succeeds, which is the side NIST SP 800-38D §8.3 errs on. Counting may
// resolve k again to its newest version, so a caller reads k's version
// (k.current) only after admitKey returns.
func (s *XKMSService) admitKey(ctx context.Context, k *versionedKey, op keypolicy.Operation, sizes ...uint64) error {
	store := s.keyPolicies.load()
	if store == nil {
		return nil
	}
	if len(sizes) == 0 {
		sizes = []uint64{0}
	}
	principal := callerSubject(ctx)
	now := time.Now()

	rec, _, err := store.Load(ctx, k.tenant, k.backendName, k.keyID)
	if err != nil {
		return err
	}
	if !rec.Tracks() {
		return rec.Check(principal, op, sizes[0], now)
	}

	// Counting is one step under the record's lock: the counters are pointed
	// at the version k will use, checked and charged. A rotation moves them
	// to its new version under the same lock (keyRotated), and Material never
	// zeroes the counters of the version they count, so a use charged here is
	// never erased by a rotation publishing a newer version.
	unlock := store.Lock(k.tenant, k.backendName, k.keyID)
	defer unlock()
	if rec, _, err = store.Load(ctx, k.tenant, k.backendName, k.keyID); err != nil {
		return err
	}
	if !rec.Material(k.record.Current) {
		// k was resolved before a rotation the counters have already moved
		// past (keyRotated runs after the new version is recorded), so the
		// key is resolved again and the operation uses, and is charged to,
		// the new version.
		fresh, err := s.resolveKeyOf(ctx, k.backend, k.backendName, k.keyID, &k.tenant)
		if err != nil {
			return err
		}
		*k = *fresh
		if !rec.Material(k.record.Current) {
			return &KeyVersionMissingError{KeyID: k.keyID, Version: rec.Usage.Version}
		}
	}
	for _, n := range sizes {
		if err := rec.Check(principal, op, n, now); err != nil {
			return err
		}
		rec.Use(op, n, now)
	}
	return store.Put(ctx, k.tenant, rec)
}

// updatePolicyRecord applies change to k's record under its lock and stores
// the result: a record left with nothing to store is deleted, so the key
// falls back to the implicit record. A record created here is owned by the
// caller.
func (s *XKMSService) updatePolicyRecord(ctx context.Context, k *versionedKey, change func(rec *keypolicy.Record, now time.Time) error) (*keypolicy.Record, error) {
	store, err := s.requirePolicyStore()
	if err != nil {
		return nil, err
	}
	unlock := store.Lock(k.tenant, k.backendName, k.keyID)
	defer unlock()

	rec, found, err := store.Load(ctx, k.tenant, k.backendName, k.keyID)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	if !found {
		rec.CreatedAt = now.Unix()
		rec.Owner = callerSubject(ctx)
	}
	if err := change(rec, now); err != nil {
		return nil, err
	}
	rec.UpdatedAt = now.Unix()

	if rec.Empty() {
		if err := store.Delete(ctx, k.tenant, k.backendName, k.keyID); err != nil {
			return nil, err
		}
		return rec, nil
	}
	if err := store.Put(ctx, k.tenant, rec); err != nil {
		return nil, err
	}
	return rec, nil
}

// deletePolicyRecord removes k's record once its backend keys are deleted,
// so a key created again under the same tenant, backend and ID starts with
// no metadata, restrictions, counters or status of its own predecessor. It
// runs after the keys are gone: a failure before it leaves the key with its
// restrictions (a revoked key stays revoked while its material exists),
// never key material without them.
func (s *XKMSService) deletePolicyRecord(ctx context.Context, k *versionedKey) error {
	store := s.keyPolicies.load()
	if store == nil {
		return nil
	}
	unlock := store.Lock(k.tenant, k.backendName, k.keyID)
	defer unlock()
	return store.Delete(ctx, k.tenant, k.backendName, k.keyID)
}
