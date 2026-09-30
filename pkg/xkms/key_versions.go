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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/keyversion"
	"github.com/jeremyhahn/go-xkms/pkg/tpmpolicy"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// The key-version model (docs/tpm-policies/architecture.md, "Key versions").
//
// A version is its own backend key: version 1 is the key as generated, under
// its own name K, and version n > 1 is the backend key "K--v<n>". The version
// record (pkg/keyversion) lists a key's versions and marks the current one.
// A key without a record is version 1, alone and enabled; GenerateKey writes
// no record, so a key that is never rotated costs nothing, and the first
// rotation writes the record.
//
// Every key operation resolves the key it names through resolveKey, which
// finds all the key's versions in one listing of the backend, and then picks
// the version the operation uses: the current one to sign, encrypt, derive,
// export or wrap; the caller's version, or a safe choice among the enabled
// ones, to verify, decrypt, unseal or unwrap (see trialVersions and
// singleVersion).

// ErrKeyVersionsNotConfigured is returned by the operations that change a
// key's versions when no version store is wired (SetKeyVersionStore). It
// matches ErrNotConfigured.
var ErrKeyVersionsNotConfigured = fmt.Errorf("%w: key version store", ErrNotConfigured)

// KeyVersionMissingError reports a version the key's record holds whose
// backend key is gone -- deleted outside xkms. It matches ErrKeyNotFound.
type KeyVersionMissingError struct {
	KeyID   string
	Version uint32
}

// Error implements the error interface.
func (e *KeyVersionMissingError) Error() string {
	return fmt.Sprintf("keystore: version %d of key %q has no backend key %q", e.Version, e.KeyID, keyversion.Name(e.KeyID, e.Version))
}

// Unwrap returns ErrKeyNotFound.
func (e *KeyVersionMissingError) Unwrap() error { return ErrKeyNotFound }

// KeyExistsError reports a key ID that is already taken by a rotated key,
// whose version 1 may have been retired while later versions remain.
type KeyExistsError struct {
	KeyID string
}

// Error implements the error interface.
func (e *KeyExistsError) Error() string {
	return fmt.Sprintf("keystore: key %q already exists with rotated versions", e.KeyID)
}

// KeyRotationUnsupportedError reports a key whose algorithm the service
// cannot generate a new version of.
type KeyRotationUnsupportedError struct {
	KeyID  string
	Reason string
}

// Error implements the error interface.
func (e *KeyRotationUnsupportedError) Error() string {
	return fmt.Sprintf("keystore: key %q cannot be rotated: %s", e.KeyID, e.Reason)
}

// SetKeyVersionStore wires the store of key-version records. Without one,
// every key is its own version 1 and the operations that change versions
// return ErrKeyVersionsNotConfigured.
func (s *XKMSService) SetKeyVersionStore(store *keyversion.Store) { s.keyVersions.store(store) }

// KeyVersionStore returns the wired key-version store, or nil.
func (s *XKMSService) KeyVersionStore() *keyversion.Store { return s.keyVersions.load() }

// keyVersion is one version of a key and the attributes of its backend key.
type keyVersion struct {
	number uint32
	attrs  *types.KeyAttributes
}

// versionedKey is a key resolved within one backend view, with its record
// and the backend keys of its versions.
type versionedKey struct {
	// backend is the (tenant-scoped) backend view the key was resolved in.
	backend Backend

	// backendName is the registered name of the backend.
	backendName string

	// keyID is the key's ID, the backend name of version 1.
	keyID string

	// tenant is the key's tenant, "" for the system tenant.
	tenant string

	// record is the key's version record; the implicit one when stored is
	// false.
	record *keyversion.Record
	stored bool

	// present maps each version number to the attributes of the backend key
	// found for it, including any not in the record (see rotateKey).
	present map[uint32]*types.KeyAttributes
}

// recordTenant normalizes a key's tenant ID for its version record: the
// system tenant, however spelled, is "".
func recordTenant(tenantID string) string {
	if qrdbsdk.IsSystemTenant(tenantID) {
		return ""
	}
	return tenantID
}

// versionsIn collects the backend keys in keys that are versions of keyID.
// On an unscoped view the same key ID can belong to more than one tenant;
// the tenant of the first match is the one resolved, exactly as findKeyAttrs
// resolves a common name. A non-nil only restricts the match to that tenant
// ("" is the system tenant).
func versionsIn(keys []*types.KeyAttributes, keyID string, only *string) (tenant string, present map[uint32]*types.KeyAttributes) {
	present = make(map[uint32]*types.KeyAttributes)
	matched := false
	if only != nil {
		tenant, matched = *only, true
	}
	for _, attrs := range keys {
		if attrs == nil {
			continue
		}
		n := uint32(1)
		if attrs.CN != keyID {
			base, version, ok := keyversion.Parse(attrs.CN)
			if !ok || base != keyID {
				continue
			}
			n = version
		}
		t := recordTenant(attrs.TenantID)
		if !matched {
			tenant, matched = t, true
		}
		if t == tenant {
			present[n] = attrs
		}
	}
	return tenant, present
}

// FindKeyAttributes returns the attributes of a backend key of keyID in b,
// or ErrKeyNotFound when the key has no version there: keyID's own backend
// key when it exists, else the highest version found. Every version of a key
// has the same algorithm and purpose, so a transport that only needs to know
// whether the key exists and what kind it is reads it from here. A version
// name ("K--v2") is refused with *keyversion.ReservedKeyIDError: versions are
// reached through their key.
func FindKeyAttributes(ctx context.Context, b Backend, keyID string) (*types.KeyAttributes, error) {
	if _, _, ok := keyversion.Parse(keyID); ok {
		return nil, &keyversion.ReservedKeyIDError{KeyID: keyID}
	}
	keys, err := b.ListKeys(ctx)
	if err != nil {
		return nil, err
	}
	_, present := versionsIn(keys, keyID, nil)
	var highest uint32
	for n := range present {
		highest = max(highest, n)
	}
	if highest == 0 {
		return nil, ErrKeyNotFound
	}
	if attrs, ok := present[1]; ok {
		return attrs, nil
	}
	return present[highest], nil
}

// resolveKey resolves keyID in b, the view of the backend registered as
// backendName, to its versions. The key is found when any of its versions
// has a backend key; its record is read from the version store, or is the
// implicit one when the key has none or no store is wired.
func (s *XKMSService) resolveKey(ctx context.Context, b Backend, backendName, keyID string) (*versionedKey, error) {
	return s.resolveKeyOf(ctx, b, backendName, keyID, nil)
}

// resolveKeyOf is resolveKey restricted, when only is non-nil, to the keys
// of that tenant ("" is the system tenant). A key a caller owns by
// convention rather than by name -- its default sealing key -- is resolved
// this way, so an unscoped view never answers with another tenant's.
func (s *XKMSService) resolveKeyOf(ctx context.Context, b Backend, backendName, keyID string, only *string) (*versionedKey, error) {
	if _, _, ok := keyversion.Parse(keyID); ok {
		return nil, &keyversion.ReservedKeyIDError{KeyID: keyID}
	}
	keys, err := b.ListKeys(ctx)
	if err != nil {
		return nil, err
	}
	tenant, present := versionsIn(keys, keyID, only)
	if len(present) == 0 {
		return nil, ErrKeyNotFound
	}
	k := &versionedKey{
		backend:     b,
		backendName: backendName,
		keyID:       keyID,
		tenant:      tenant,
		present:     present,
		record:      keyversion.Implicit(keyID, backendName),
	}
	if store := s.keyVersions.load(); store != nil {
		rec, found, err := store.Load(ctx, tenant, backendName, keyID)
		if err != nil {
			return nil, err
		}
		k.record, k.stored = rec, found
	}
	return k, nil
}

// resolveKeyIn resolves keyID in the view of backendName for tenantID. An
// empty backendName is the default backend.
func (s *XKMSService) resolveKeyIn(ctx context.Context, backendName, tenantID, keyID string) (*versionedKey, error) {
	b, resolvedName, err := s.resolveTenantBackendWithName(backendName, tenantID)
	if err != nil {
		return nil, err
	}
	return s.resolveKey(ctx, b, resolvedName, keyID)
}

// attrsOf returns the backend key of version n, which the record holds.
func (k *versionedKey) attrsOf(n uint32) (keyVersion, error) {
	attrs, ok := k.present[n]
	if !ok {
		return keyVersion{}, &KeyVersionMissingError{KeyID: k.keyID, Version: n}
	}
	return keyVersion{number: n, attrs: attrs}, nil
}

// current returns the current version, the one sign and encrypt use.
func (k *versionedKey) current() (keyVersion, error) {
	return k.attrsOf(k.record.Current)
}

// use returns version n when it is enabled, or the current version when n is
// zero.
func (k *versionedKey) use(n uint32) (keyVersion, error) {
	if n == 0 {
		return k.current()
	}
	if _, err := k.record.Usable(n); err != nil {
		return keyVersion{}, err
	}
	return k.attrsOf(n)
}

// trialVersions returns the versions to try, in order, for an input whose
// construction makes a wrong key fail: a signature, an AEAD ciphertext, an
// RSA-OAEP ciphertext. A requested version is the only one, and must be
// enabled; without one every enabled version is tried, newest first.
func (k *versionedKey) trialVersions(requested uint32) ([]keyVersion, error) {
	if requested != 0 {
		v, err := k.use(requested)
		if err != nil {
			return nil, err
		}
		return []keyVersion{v}, nil
	}
	enabled := k.record.Enabled()
	versions := make([]keyVersion, 0, len(enabled))
	for _, n := range enabled {
		v, err := k.attrsOf(n)
		if err != nil {
			return nil, err
		}
		versions = append(versions, v)
	}
	if len(versions) == 0 {
		return nil, &keyversion.VersionUnavailableError{KeyID: k.keyID, Version: k.record.Current, State: keyversion.StateDisabled}
	}
	return versions, nil
}

// singleVersion returns the one version to use for an input a wrong key does
// not reliably fail on -- AES-CBC and RSA PKCS#1 v1.5 ciphertext, where
// trying keys one after another decrypts to garbage or is a padding oracle.
// A requested version is used when enabled; without one the key must have
// exactly one enabled version, else *keyversion.KeyVersionRequiredError.
func (k *versionedKey) singleVersion(requested uint32) (keyVersion, error) {
	if requested != 0 {
		return k.use(requested)
	}
	enabled := k.record.Enabled()
	if len(enabled) != 1 {
		return keyVersion{}, &keyversion.KeyVersionRequiredError{KeyID: k.keyID, Enabled: enabled}
	}
	return k.attrsOf(enabled[0])
}

// selectVersions returns the versions to try for an input: all enabled ones
// (trialVersions) when trial is true, else the single safe one.
func (k *versionedKey) selectVersions(requested uint32, trial bool) ([]keyVersion, error) {
	if trial {
		return k.trialVersions(requested)
	}
	v, err := k.singleVersion(requested)
	if err != nil {
		return nil, err
	}
	return []keyVersion{v}, nil
}

// representative returns the attributes of any present version, for the
// properties every version shares (algorithm, purpose, symmetry).
func (k *versionedKey) representative() *types.KeyAttributes {
	if v, err := k.current(); err == nil {
		return v.attrs
	}
	var highest uint32
	for n := range k.present {
		highest = max(highest, n)
	}
	return k.present[highest]
}

// firstSuccess runs op on each version in order and returns the first
// success and its version. When every version fails it returns the first
// version's error, so the error a caller sees is the one the newest (or
// requested) version produced.
func firstSuccess[R any](versions []keyVersion, op func(keyVersion) (R, error)) (R, uint32, error) {
	var firstErr error
	for _, v := range versions {
		r, err := op(v)
		if err == nil {
			return r, v.number, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	var zero R
	return zero, 0, firstErr
}

// callerSubject returns the subject of ctx's identity, recorded as a new
// version's creator, or "" without one.
func callerSubject(ctx context.Context) string {
	if identity := auth.GetIdentity(ctx); identity != nil {
		return identity.Subject
	}
	return ""
}

// requireVersionStore returns the version store, or
// ErrKeyVersionsNotConfigured.
func (s *XKMSService) requireVersionStore() (*keyversion.Store, error) {
	store := s.keyVersions.load()
	if store == nil {
		return nil, ErrKeyVersionsNotConfigured
	}
	return store, nil
}

// refuseRotatedKeyID refuses to create keyID in the backend registered as
// backendName for tenant when the key was rotated: its version record exists,
// and a new key would take over the rotated key's name -- its version 1 may
// have been retired, leaving the name free in the backend. A key that was
// never rotated needs no check here; the backend refuses a name it holds.
func (s *XKMSService) refuseRotatedKeyID(ctx context.Context, tenant, backendName, keyID string) error {
	store := s.keyVersions.load()
	if store == nil {
		return nil
	}
	_, found, err := store.Load(ctx, recordTenant(tenant), backendName, keyID)
	if err != nil {
		return err
	}
	if found {
		return &KeyExistsError{KeyID: keyID}
	}
	return nil
}

// rotation is the outcome of creating a key's next version.
type rotation struct {
	version uint32
	attrs   *types.KeyAttributes
	key     crypto.PrivateKey
}

// rotateKey creates the next version of keyID in b, the view of the backend
// registered as backendName, and makes it current. The new version is a new
// backend key "K--v<n>" with the current version's algorithm and attributes
// -- for TPM2, the same tenant scope and TPM policy -- so a rotation never
// touches an existing version's key material.
func (s *XKMSService) rotateKey(ctx context.Context, b Backend, backendName, keyID string) (*rotation, error) {
	k, err := s.resolveKey(ctx, b, backendName, keyID)
	if err != nil {
		return nil, err
	}
	store, err := s.requireVersionStore()
	if err != nil {
		return nil, err
	}

	// The record is read again under the key's lock, so two rotations of
	// one key never create the same version.
	unlock := store.Lock(k.tenant, backendName, keyID)
	defer unlock()
	if k, err = s.resolveKey(ctx, b, backendName, keyID); err != nil {
		return nil, err
	}

	cur, err := k.current()
	if err != nil {
		return nil, err
	}
	next := k.record.Next()
	name := keyversion.Name(keyID, next)

	// A backend key under the next version's name that the record does not
	// hold was left by a rotation interrupted between creating the key and
	// recording it. It was never current, so nothing was ever signed or
	// encrypted with it; it is removed so the name can be created again.
	if orphan, ok := k.present[next]; ok {
		if err := b.DeleteKey(ctx, orphan); err != nil {
			return nil, &ErrKeyOperation{Operation: "remove interrupted rotation", KeyID: name, Err: err}
		}
	}

	attrs, err := s.nextVersionAttributes(ctx, b, backendName, cur.attrs, name)
	if err != nil {
		return nil, err
	}
	priv, err := generateKeyWithAttributes(ctx, b, backendName, attrs)
	if err != nil {
		return nil, err
	}

	k.record.AddCurrent(next, time.Now().UTC(), callerSubject(ctx))
	if err := store.Put(ctx, k.tenant, k.record); err != nil {
		// Unrecorded, the new key would be an orphan; it is removed so the
		// key stays exactly as it was.
		return nil, errors.Join(err, b.DeleteKey(ctx, attrs))
	}
	return &rotation{version: next, attrs: attrs, key: priv}, nil
}

// nextVersionAttributes returns the attributes of a new version named name
// of the key whose current version is cur. The algorithm parameters are read
// from cur's public key rather than from the listing, which on several
// backends reports a default size or curve rather than the key's own. On a
// TPM2 backend the new version keeps cur's tenant scope and is bound to the
// TPM policy the policy registry records for cur.
func (s *XKMSService) nextVersionAttributes(ctx context.Context, b Backend, backendName string, cur *types.KeyAttributes, name string) (*types.KeyAttributes, error) {
	attrs := &types.KeyAttributes{
		CN:         name,
		Backend:    backendName,
		StoreType:  b.Type(),
		TenantID:   cur.TenantID,
		Partition:  cur.Partition,
		KeyType:    cur.KeyType,
		Hash:       cur.Hash,
		Exportable: cur.Exportable,
		Sensitive:  cur.Sensitive,
	}

	switch {
	case cur.QuantumAttributes != nil, cur.X25519Attributes != nil:
		return nil, &KeyRotationUnsupportedError{KeyID: keyversion.BaseKeyID(cur.CN), Reason: "only RSA, ECDSA, Ed25519 and symmetric keys can be rotated"}
	case cur.IsSymmetric():
		attrs.SymmetricAlgorithm = cur.SymmetricAlgorithm
		attrs.KeyType = types.KeyTypeSecret
	default:
		if err := applyPublicKeyAlgorithm(ctx, b, cur, attrs); err != nil {
			return nil, err
		}
	}

	if attrs.StoreType == types.StoreTPM2 {
		policy, err := s.tpmPolicyOf(ctx, cur)
		if err != nil {
			return nil, err
		}
		attrs.TPMPolicy = policy
	}
	return attrs, nil
}

// applyPublicKeyAlgorithm sets attrs' algorithm and its parameters from the
// public key of cur.
func applyPublicKeyAlgorithm(ctx context.Context, b Backend, cur, attrs *types.KeyAttributes) error {
	priv, err := b.GetKey(ctx, cur)
	if err != nil {
		return &ErrKeyOperation{Operation: "read current version", KeyID: cur.CN, Err: err}
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return &KeyRotationUnsupportedError{KeyID: keyversion.BaseKeyID(cur.CN), Reason: fmt.Sprintf("its key (%T) exposes no public key", priv)}
	}
	switch pub := signer.Public().(type) {
	case *rsa.PublicKey:
		attrs.KeyAlgorithm = x509.RSA
		attrs.RSAAttributes = &types.RSAAttributes{KeySize: pub.N.BitLen()}
	case *ecdsa.PublicKey:
		attrs.KeyAlgorithm = x509.ECDSA
		attrs.ECCAttributes = &types.ECCAttributes{Curve: pub.Curve}
	case ed25519.PublicKey:
		attrs.KeyAlgorithm = x509.Ed25519
	default:
		return &KeyRotationUnsupportedError{KeyID: keyversion.BaseKeyID(cur.CN), Reason: fmt.Sprintf("unsupported public key type %T", pub)}
	}
	return nil
}

// tpmPolicyOf returns the TPM policy the policy registry records for the
// TPM2 key cur, in cur's tenant scope, or "" when no TPM policy service is
// wired: the backend then has no scopes and binds every key the same way.
func (s *XKMSService) tpmPolicyOf(ctx context.Context, cur *types.KeyAttributes) (string, error) {
	svc := s.tpmPolicies.load()
	if svc == nil {
		return "", nil
	}
	assignment, err := svc.PolicyOf(ctx, recordTenant(cur.TenantID), tpmpolicy.ObjectKey, cur.CN)
	if err != nil {
		return "", &ErrKeyOperation{Operation: "read the TPM policy of the current version", KeyID: cur.CN, Err: err}
	}
	return assignment.Policy, nil
}

// deleteAllVersions deletes k's record and then every backend key of k --
// each version, and any key an interrupted rotation left -- newest first.
//
// The record goes first. A failure part-way through the keys then leaves
// versions with no record, which resolve as an unrotated key and are all
// deleted again by a retry; the other order could leave a record naming keys
// that no longer exist, which a new key of the same ID would inherit.
func (s *XKMSService) deleteAllVersions(ctx context.Context, k *versionedKey) error {
	if store := s.keyVersions.load(); store != nil {
		unlock := store.Lock(k.tenant, k.backendName, k.keyID)
		defer unlock()
		if err := store.Delete(ctx, k.tenant, k.backendName, k.keyID); err != nil {
			return err
		}
	}
	numbers := slices.Sorted(maps.Keys(k.present))
	slices.Reverse(numbers)
	for _, n := range numbers {
		if err := k.backend.DeleteKey(ctx, k.present[n]); err != nil {
			return err
		}
	}
	return nil
}
