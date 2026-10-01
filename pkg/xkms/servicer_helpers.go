// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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
	"encoding/pem"
	"fmt"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"strings"
)

// resolveBackend returns the backend for the given name, or the default backend
// if the name is empty. This is the canonical backend resolution method shared
// across all servicer files.
func (s *XKMSService) resolveBackend(name string) (Backend, error) {
	if name == "" {
		return s.lookupDefaultBackend()
	}
	return s.lookupBackend(name)
}

// resolveBackendWithName returns the Backend and its resolved name.
// If backendName is empty, the default backend name is used.
func (s *XKMSService) resolveBackendWithName(backendName string) (Backend, string, error) {
	if backendName == "" {
		backendName = s.defaultBackendName()
	}
	b, err := s.resolveBackend(backendName)
	if err != nil {
		return nil, "", err
	}
	return b, backendName, nil
}

// tenantScopes reports whether tenantID names a real tenant, one whose keys a
// backend view must be narrowed to, and validates it when it does.
//
// The system tenant is NOT a scope: qrdb's canonical predicate treats "" and
// the system tenant as the same platform scope (tenant-scope unification), so
// a system-scoped caller — the first-boot administrator among them — operates
// on the unscoped backend, the same view internal pipelines use.
//
// This is the single place the predicate and its validation live, so every
// caller that turns a tenant into a backend view agrees on what a tenant is.
func tenantScopes(tenantID string) (bool, error) {
	if qrdbsdk.IsSystemTenant(tenantID) {
		return false, nil
	}
	if err := storage.ValidateTenantID(tenantID); err != nil {
		return false, &ErrValidation{Sentinel: ErrTenantIDRequired, Detail: err.Error()}
	}
	return true, nil
}

// ScopeBackendToTenant returns base viewed through tenantID, so every key
// lookup made against it — a listing, or a resolution by common name — sees
// only that tenant's keys. A common name is unique only within a tenant, so an
// unscoped lookup by common name resolves whichever tenant's key is listed
// first.
//
// Callers that hold a Backend already, rather than a name to resolve, use this
// instead of resolveTenantBackend. The system tenant returns base unchanged,
// exactly as resolveTenantBackend does.
func ScopeBackendToTenant(base Backend, tenantID string) (Backend, error) {
	scoped, err := tenantScopes(tenantID)
	if err != nil {
		return nil, err
	}
	if !scoped {
		return base, nil
	}
	return NewTenantScopedBackend(base, tenantID), nil
}

// resolveTenantBackend returns a Backend scoped to tenantID when tenantID
// names a real tenant, and the unscoped backend for the system tenant. See
// tenantScopes for why the system tenant is not a scope.
func (s *XKMSService) resolveTenantBackend(name, tenantID string) (Backend, error) {
	scoped, err := tenantScopes(tenantID)
	if err != nil {
		return nil, err
	}
	base, err := s.resolveBackend(name)
	if err != nil {
		return nil, err
	}
	if !scoped {
		return base, nil
	}
	return NewTenantScopedBackend(base, tenantID), nil
}

// resolveTenantBackendWithName returns the Backend, its resolved name, and an
// error. When tenantID names a real tenant the returned Backend is
// tenant-scoped; the system tenant resolves unscoped, exactly as in
// resolveTenantBackend.
func (s *XKMSService) resolveTenantBackendWithName(name, tenantID string) (Backend, string, error) {
	scoped, err := tenantScopes(tenantID)
	if err != nil {
		return nil, "", err
	}
	base, resolvedName, err := s.resolveBackendWithName(name)
	if err != nil {
		return nil, "", err
	}
	if !scoped {
		return base, resolvedName, nil
	}
	return NewTenantScopedBackend(base, tenantID), resolvedName, nil
}

// defaultBackendName returns the name of the default backend.
func (s *XKMSService) defaultBackendName() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.defaultBackend
}

// findKeyAttrs searches a backend's key list for a key matching the given ID.
func findKeyAttrs(ctx context.Context, b Backend, keyID string) (*types.KeyAttributes, error) {
	attrs, err := b.ListKeys(ctx)
	if err != nil {
		return nil, err
	}
	for _, attr := range attrs {
		if attr.CN == keyID {
			return attr, nil
		}
	}
	return nil, ErrKeyNotFound
}

// algorithmString returns a human-readable algorithm string from key attributes.
func algorithmString(attrs *types.KeyAttributes) string {
	if attrs.SymmetricAlgorithm != "" {
		return string(attrs.SymmetricAlgorithm)
	}
	if attrs.KeyAlgorithm != x509.UnknownPublicKeyAlgorithm {
		return attrs.KeyAlgorithm.String()
	}
	return ""
}

// ResolveHash converts a caller-supplied hash algorithm name to a crypto.Hash.
//
// An empty name selects the SHA-256 default, which is the documented behaviour
// for a request that does not specify one. A name that is present but does not
// resolve — misspelled, not linked into this binary, or one of the
// collision-broken digests the weak-hash policy refuses — is an error.
//
// The sentinel name "NONE" (case-insensitive) resolves to crypto.Hash(0) and
// means "do not hash; the caller has already produced the exact bytes to
// pad and sign/verify". This is distinct from the empty string, which means
// "the caller expressed no preference, apply the SHA-256 default": PKCS#11's
// raw CKM_RSA_PKCS mechanism hands the server a complete DigestInfo that the
// caller built itself, and the server's job is to apply PKCS#1 v1.5 padding
// only. Treating an unspecified hash and an explicitly-none hash as the same
// case previously caused that DigestInfo to be re-hashed with SHA-256 and
// signed, producing a signature over the wrong bytes with no error raised.
// Callers that receive crypto.Hash(0) back from this function must not hash
// with it — passing it to Hash.New() panics — they must use the input bytes
// directly, which is exactly what rsa.SignPKCS1v15 and rsa.VerifyPKCS1v15 do
// when given a zero crypto.Hash.
//
// It must not substitute a default for a name the caller did supply. Doing so
// signs, verifies, or encrypts under a digest the caller did not choose and
// reports success, which is indistinguishable to the caller from having got
// what it asked for.
//
// It is exported because the transports need the same answer the service layer
// gives. REST, gRPC, QUIC and MCP each used to carry their own hash table, and
// two of them answered an unresolvable name with SHA-256 and HTTP 200 / OK.
// Every transport now resolves here, so there is one hash vocabulary, one
// default, and one refusal in the process. The returned error is an
// *ErrValidation, which both transports' keyop error maps already render as a
// client error (HTTP 400 / codes.InvalidArgument).
func ResolveHash(hash string) (crypto.Hash, error) {
	if hash == "" {
		return crypto.SHA256, nil
	}
	if strings.EqualFold(hash, "NONE") {
		return crypto.Hash(0), nil
	}
	h := types.ParseHash(hash)
	if h == 0 {
		return 0, &ErrValidation{Sentinel: ErrInvalidHashFunction, Detail: "unsupported hash algorithm: " + hash}
	}
	return h, nil
}

// oaepBareDigestSizes are the bare digest-size spellings the transports have
// always accepted for an OAEP hash ("256" meaning SHA-256). They are normalized
// to canonical names so there is still exactly one hash table in the process.
var oaepBareDigestSizes = map[string]string{
	"1":   "SHA-1",
	"256": "SHA-256",
	"384": "SHA-384",
	"512": "SHA-512",
}

// ResolveOAEPHash resolves the hash for an RSA-OAEP operation.
//
// It is ResolveHash plus an unconditional refusal of the collision-broken
// digests. OAEP has no legacy ciphertexts in this codebase to read back, so the
// weak-hash escape hatch that exists for signing (crypto.allow_weak_hashes,
// reported by Config.ComplianceGaps) deliberately does not apply here: a
// SHA-1 OAEP request is refused even in a deployment that has opted into weak
// hashes elsewhere.
//
// It is exported for the same reason ResolveHash is. The REST transport used to
// carry its own OAEP hash switch that accepted SHA-1 while gRPC and the service
// layer refused it, so the same request was encrypted under a broken digest or
// rejected depending only on which port it arrived on.
func ResolveOAEPHash(hash string) (crypto.Hash, error) {
	name := strings.TrimSpace(hash)
	if canonical, ok := oaepBareDigestSizes[name]; ok {
		name = canonical
	}

	if types.IsWeakHashName(name) {
		return 0, &ErrOperationWrap{
			Sentinel: ErrWeakOAEPHash,
			Detail:   "RSA-OAEP hash must be SHA-256 or stronger; " + name + " is rejected",
		}
	}

	return ResolveHash(name)
}

// pubKeyPEM extracts the public key from a private key and encodes it as PEM.
func pubKeyPEM(privKey crypto.PrivateKey) (string, error) {
	if privKey == nil {
		return "", ErrNilPrivateKey
	}

	var pubKey crypto.PublicKey

	switch k := privKey.(type) {
	case *rsa.PrivateKey:
		pubKey = &k.PublicKey
	case *ecdsa.PrivateKey:
		pubKey = &k.PublicKey
	case ed25519.PrivateKey:
		pubKey = k.Public()
	case crypto.Signer:
		pubKey = k.Public()
	default:
		return "", &ErrUnsupportedPrivateKeyType{KeyType: fmt.Sprintf("%T", privKey)}
	}

	der, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", &ErrKeyOperation{Operation: "marshal public key", Err: err}
	}

	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}

	return string(pem.EncodeToMemory(block)), nil
}
