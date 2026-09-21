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

// Package ca defines CA operations that supplement the core ca.go: public
// Signer/PrivateKey/PubKey accessors, certificate retrieval helpers, blob
// helpers, CAConfig accessors, CA-key attribute selection, and the extended
// RevokeCert / CABundleFiltered methods that preserve wrapper semantics.
package ca

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"sync"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/storage"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// =============================================================================
// Signing Identity Accessors
// =============================================================================

// Signer returns a crypto.Signer for the CA's issuing identity. This is the
// public counterpart to the private getSigner() helper.
//
// Returns ErrNotInitialized if the CA has not been initialized, and
// ErrInvalidConfig when no issuing identity has been configured.
//
// Thread-safe: Yes
func (ca *CA) Signer(ctx context.Context) (crypto.Signer, error) {
	if !ca.initialized.Load() {
		return nil, ErrNotInitialized
	}
	return ca.getSigner(ctx)
}

// PrivateKey retrieves a key handle from the CA's keystore.
//
// Because not every KeyStore backend can surface raw private-key material
// (TPM- and HSM-backed keys cannot), callers should treat the returned
// crypto.PrivateKey as opaque and use it via a crypto.Signer assertion when
// cryptographic operations are required.
//
// Returns an error if attrs is nil or the keystore cannot locate the key.
//
// Thread-safe: Yes
func (ca *CA) PrivateKey(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if attrs == nil {
		return nil, &errs.Detail{Err: ErrInvalidConfig, Detail: "key attributes required"}
	}
	key, err := ca.keyStore.GetKey(ctx, attrs)
	if err != nil {
		return nil, &errs.Detail{Err: ErrKeyNotFound, Detail: fmt.Sprintf("failed to retrieve key: %v", err)}
	}
	return key, nil
}

// PubKey returns the public half of the key identified by attrs. Hardware-
// bound keys are handled correctly because keystore signers implement
// crypto.Signer.Public().
//
// Thread-safe: Yes
func (ca *CA) PubKey(ctx context.Context, attrs *types.KeyAttributes) (crypto.PublicKey, error) {
	if attrs == nil {
		return nil, &errs.Detail{Err: ErrInvalidConfig, Detail: "key attributes required"}
	}
	key, err := ca.keyStore.GetKey(ctx, attrs)
	if err != nil {
		return nil, &errs.Detail{Err: ErrKeyNotFound, Detail: fmt.Sprintf("failed to retrieve key: %v", err)}
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, &errs.Detail{Err: ErrKeyNotFound, Detail: "key does not implement crypto.Signer"}
	}
	return signer.Public(), nil
}

// SignedBlob computes a signature over arbitrary data using the CA's signing
// key. The hash function is derived from the CA's current key type (SHA-256
// for RSA/ECDSA, unhashed for Ed25519).
//
// Thread-safe: Yes
func (ca *CA) SignedBlob(ctx context.Context, data []byte) ([]byte, error) {
	if !ca.initialized.Load() {
		return nil, ErrNotInitialized
	}
	signer, err := ca.getSigner(ctx)
	if err != nil {
		return nil, &errs.Detail{Err: ErrSigningFailed, Detail: fmt.Sprintf("%v", err)}
	}

	hashFunc := ca.getSigningHashFunc()
	var digest []byte
	if hashFunc == 0 {
		// Ed25519 signs the message directly.
		digest = data
	} else {
		h := hashFunc.New()
		_, _ = h.Write(data)
		digest = h.Sum(nil)
	}
	sig, err := signer.Sign(nil, digest, hashFunc)
	if err != nil {
		return nil, &errs.Detail{Err: ErrSigningFailed, Detail: fmt.Sprintf("%v", err)}
	}
	return sig, nil
}

// =============================================================================
// Certificate Existence & Retrieval
// =============================================================================

// Exists reports whether a certificate for cn exists and matches the given
// public-key algorithm. Returns (false, nil) when no certificate is found or
// when the algorithm does not match.
//
// Thread-safe: Yes
func (ca *CA) Exists(ctx context.Context, cn string, algo x509.PublicKeyAlgorithm) (bool, error) {
	if cn == "" {
		return false, &errs.Detail{Err: ErrInvalidCertificate, Detail: "common name required"}
	}

	var cert *x509.Certificate
	var err error
	if ca.certStore != nil {
		cert, err = ca.certStore.GetCertificate(cn)
	}
	if cert == nil && ca.keyStore != nil {
		cert, err = ca.keyStore.GetCert(ctx, cn)
	}
	if cert == nil || err != nil {
		return false, nil
	}
	return cert.PublicKeyAlgorithm == algo, nil
}

// Certificate retrieves a certificate using KeyAttributes. It first checks
// the cached CA certificates, then the keystore, and finally the certStore.
//
// Thread-safe: Yes
func (ca *CA) Certificate(ctx context.Context, attrs *types.KeyAttributes) (*x509.Certificate, error) {
	if attrs == nil {
		return nil, &errs.Detail{Err: ErrInvalidCertificate, Detail: "key attributes required"}
	}

	ca.mu.RLock()
	rootCert := ca.rootCert
	intermediateCert := ca.intermediateCert
	ca.mu.RUnlock()

	if rootCert != nil && rootCert.Subject.CommonName == attrs.CN {
		return rootCert, nil
	}
	if intermediateCert != nil && intermediateCert.Subject.CommonName == attrs.CN {
		return intermediateCert, nil
	}

	if ca.keyStore != nil {
		if cert, err := ca.keyStore.GetCert(ctx, attrs.CN); err == nil && cert != nil {
			return cert, nil
		}
	}
	if ca.certStore != nil {
		if cert, err := ca.certStore.GetCertificate(attrs.CN); err == nil && cert != nil {
			return cert, nil
		}
	}
	return nil, &errs.Detail{Err: ErrCertificateNotFound, Detail: attrs.CN}
}

// CertificatePEM returns the certificate identified by cn in PEM form.
//
// Thread-safe: Yes
func (ca *CA) CertificatePEM(ctx context.Context, cn string) ([]byte, error) {
	cert, err := ca.Certificate(ctx, &types.KeyAttributes{CN: cn})
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}), nil
}

// ImportCertificate persists a certificate to the CA's stores. Both the
// keystore (best-effort) and the certStore receive a copy so subsequent
// lookups via either storage surface succeed.
//
// Thread-safe: Yes
func (ca *CA) ImportCertificate(ctx context.Context, cert *x509.Certificate) error {
	if cert == nil {
		return ErrInvalidCertificate
	}
	cn := cert.Subject.CommonName
	if cn == "" {
		return &errs.Detail{Err: ErrInvalidCertificate, Detail: "certificate has empty common name"}
	}

	// Best-effort keystore save: some backends are read-only for certs and
	// will surface errors that we can't reliably handle here. In all cases
	// the authoritative write is to certStore.
	if ca.keyStore != nil {
		_ = ca.keyStore.SaveCert(ctx, cn, cert)
	}
	if ca.certStore == nil {
		return ErrCertStoreRequired
	}
	if err := ca.certStore.StoreCertificate(cert); err != nil {
		return &errs.Detail{Err: ErrStorageError, Detail: fmt.Sprintf("%v", err)}
	}
	return nil
}

// ImportCertificatePEM parses a PEM-encoded certificate and stores it under
// cn (overriding the certificate's own Subject.CommonName when they differ).
//
// Thread-safe: Yes
func (ca *CA) ImportCertificatePEM(ctx context.Context, cn string, pemBytes []byte) error {
	if cn == "" {
		return &errs.Detail{Err: ErrInvalidCertificate, Detail: "common name required"}
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return &errs.Detail{Err: ErrInvalidPEM, Detail: "no PEM block found"}
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return &errs.Detail{Err: ErrInvalidCertificate, Detail: fmt.Sprintf("%v", err)}
	}

	if ca.keyStore != nil {
		_ = ca.keyStore.SaveCert(ctx, cn, cert)
	}
	if ca.certStore == nil {
		return ErrCertStoreRequired
	}
	if err := ca.certStore.StoreCertificate(cert); err != nil {
		return &errs.Detail{Err: ErrStorageError, Detail: fmt.Sprintf("%v", err)}
	}
	return nil
}

// PEM is an alias for CertificatePEM that takes KeyAttributes instead of a
// bare common name, matching the wrapper's method signature.
//
// Thread-safe: Yes
func (ca *CA) PEM(ctx context.Context, attrs *types.KeyAttributes) ([]byte, error) {
	if attrs == nil {
		return nil, &errs.Detail{Err: ErrInvalidCertificate, Detail: "key attributes required"}
	}
	return ca.CertificatePEM(ctx, attrs.CN)
}

// =============================================================================
// Object Store Blob Helpers
// =============================================================================

// Blob returns a raw blob stored in the object store under key.
//
// Thread-safe: Yes
func (ca *CA) Blob(key []byte) ([]byte, error) {
	if ca.objectStore == nil {
		return nil, ErrObjectStoreRequired
	}
	reader, err := ca.objectStore.Get(string(key))
	if err != nil {
		return nil, &errs.Detail{Err: ErrStorageError, Detail: fmt.Sprintf("%v", err)}
	}
	defer func() { _ = reader.Close() }()
	return io.ReadAll(reader)
}

// ImportBlob stores raw blob data in the object store under key.
//
// Thread-safe: Yes
func (ca *CA) ImportBlob(key, data []byte) error {
	if ca.objectStore == nil {
		return ErrObjectStoreRequired
	}
	if err := ca.objectStore.Put(string(key), bytes.NewReader(data)); err != nil {
		return &errs.Detail{Err: ErrStorageError, Detail: fmt.Sprintf("%v", err)}
	}
	return nil
}

// =============================================================================
// Configuration & Metadata
// =============================================================================

// builtinProfiles is the registry a CA falls back to when it was constructed
// without one. Issuance requires a profile for every certificate, so a CA that
// cannot resolve one is unusable; falling back to the built-ins keeps a
// minimally constructed CA working instead of failing at signing time.
var builtinProfiles = sync.OnceValue(NewDefaultProfileRegistry)

// Profiles returns the certificate profile registry this CA issues with.
//
// Composing services read the profile they need from here rather than
// constructing one, so that a profile registered against this CA reaches every
// certificate the deployment issues — including the per-tenant CAs the ACME
// admin service creates — and not only the ones pkg/ca issues directly.
//
// Thread-safe: Yes
func (ca *CA) Profiles() ProfileRegistry {
	if ca.profiles == nil {
		return builtinProfiles()
	}
	return ca.profiles
}

// DefaultKeyAlgorithm returns the public-key algorithm associated with the
// CA's issuing identity. Useful for profile-aware clients that want to
// generate a matching key for a CSR.
//
// Thread-safe: Yes
func (ca *CA) DefaultKeyAlgorithm() x509.PublicKeyAlgorithm {
	issuing := ca.config.IssuingIdentity()
	if issuing == nil || len(issuing.Keys) == 0 || issuing.Keys[0] == nil {
		return x509.UnknownPublicKeyAlgorithm
	}
	switch issuing.Keys[0].KeyAlgorithm {
	case types.AlgorithmRSA:
		return x509.RSA
	case types.AlgorithmECDSA:
		return x509.ECDSA
	case types.AlgorithmEd25519:
		return x509.Ed25519
	default:
		return x509.UnknownPublicKeyAlgorithm
	}
}

// DefaultSignatureAlgorithm returns the signature algorithm associated with
// the CA's issuing identity.
//
// Thread-safe: Yes
func (ca *CA) DefaultSignatureAlgorithm() x509.SignatureAlgorithm {
	issuing := ca.config.IssuingIdentity()
	if issuing == nil {
		return x509.UnknownSignatureAlgorithm
	}
	algo, err := issuing.GetSignatureAlgorithm()
	if err != nil {
		return x509.UnknownSignatureAlgorithm
	}
	return algo
}

// DefaultValidityPeriod returns the default number of days that issued
// certificates are valid for.
//
// Thread-safe: Yes
func (ca *CA) DefaultValidityPeriod() int {
	if ca.caConfig != nil && ca.caConfig.DefaultCertValidityDays > 0 {
		return ca.caConfig.DefaultCertValidityDays
	}
	return ca.config.GetDefaultValidityDays()
}

// Hash returns the hash function used by the CA for signing. Ed25519
// identities return crypto.Hash(0) because Ed25519 signs unhashed messages.
//
// Thread-safe: Yes
func (ca *CA) Hash() crypto.Hash {
	return ca.getSigningHashFunc()
}

// IssuingIdentity returns the Identity this CA is currently configured to
// issue certificates from — the intermediate identity if one is configured,
// otherwise the root identity. Returns a zero-value Identity when no
// identity is configured so callers can safely access its fields.
//
// When the CA was constructed via NewParentCA / NewIntermediateCA / NewCA
// the original Identity is preserved verbatim so the full Keys slice and
// any other identity-only fields survive the round trip through the flat
// CAConfig representation. When constructed via the bare New(*Params)
// constructor the Identity is reconstructed from the internal
// MultiIdentityCAConfig which carries a single KeyConfig derived from the
// caller-supplied KeyAttributes.
//
// Unlike Config() which returns a *Identity, this returns a value copy; the
// caller cannot mutate the running CA's configuration through the result.
//
// Thread-safe: Yes
func (ca *CA) IssuingIdentity() Identity {
	if ca.inputIdentity != nil {
		return *ca.inputIdentity
	}
	issuing := ca.config.IssuingIdentity()
	if issuing == nil {
		return Identity{}
	}
	return *issuing
}

// IsAutoImportingIssuerCAs returns whether automatic import of issuing CAs
// from AIA extensions has been enabled for this CA.
//
// Thread-safe: Yes
func (ca *CA) IsAutoImportingIssuerCAs() bool {
	if ca.caConfig == nil {
		return false
	}
	return ca.caConfig.AutoImportIssuingCA
}

// CAKeyAttributes returns the KeyAttributes for the CA's signing key in the
// specified store type. The requested store type must match the identity's
// configured KeystoreType.
//
// Thread-safe: Yes
func (ca *CA) CAKeyAttributes(storeType types.StoreType) (*types.KeyAttributes, error) {
	issuing := ca.config.IssuingIdentity()
	if issuing == nil {
		return nil, ErrInvalidConfig
	}
	configured := issuing.GetStoreType()
	if storeType != "" && configured != storeType {
		return nil, &errs.Detail{Err: ErrInvalidStoreType, Detail: fmt.Sprintf("requested store type %s does not match configured %s", storeType, configured)}
	}
	attrs, err := ca.getCAKeyAttributes(issuing)
	if err != nil {
		return nil, err
	}
	return attrs, nil
}

// CASigner returns a crypto.Signer for the CA's signing key constrained to
// the specified store type and public-key algorithm. Useful for callers that
// want to confirm they are signing with the expected backend/algorithm
// combination before delegating.
//
// Thread-safe: Yes
func (ca *CA) CASigner(ctx context.Context, storeType types.StoreType, algo x509.PublicKeyAlgorithm) (crypto.Signer, error) {
	attrs, err := ca.CAKeyAttributes(storeType)
	if err != nil {
		return nil, err
	}
	if algo != x509.UnknownPublicKeyAlgorithm && attrs.KeyAlgorithm != algo {
		return nil, &errs.Detail{Err: ErrInvalidKeyAlgorithm, Detail: fmt.Sprintf("CA key algorithm %v does not match requested %v", attrs.KeyAlgorithm, algo)}
	}
	return ca.keyStore.Signer(ctx, attrs)
}

// IdentityIssuer is implemented by CA instances that can issue from a
// specific configured identity by common name. It is deliberately a small
// standalone interface (rather than a TrustedCA method) so existing
// TrustedCA implementations and mocks remain source-compatible; consumers
// that need per-identity issuance type-assert to it.
type IdentityIssuer interface {
	IssuerForIdentity(ctx context.Context, cn string) (crypto.Signer, *x509.Certificate, error)
}

// Compile-time check: the concrete CA supports per-identity issuance.
var _ IdentityIssuer = (*CA)(nil)

// IssuerForIdentity returns the signer and certificate for the configured CA
// identity with the given common name, enabling issuance from a specific —
// possibly non-selected — identity. A dedicated cluster intermediate can sign
// Raft transport certificates this way while SelectedCA continues to issue
// workload certificates.
//
// The identity is resolved from the CA configuration by Subject.CommonName,
// its certificate is fetched from the certificate store, and its private key
// from the identity's configured keystore backend. Returns ErrIdentityNotFound
// when no configured identity matches.
//
// Thread-safe: Yes
func (ca *CA) IssuerForIdentity(ctx context.Context, cn string) (crypto.Signer, *x509.Certificate, error) {
	if !ca.initialized.Load() {
		return nil, nil, ErrNotInitialized
	}

	var identity *Identity
	for i := range ca.config.Identity {
		if ca.config.Identity[i].Subject.CommonName == cn {
			identity = &ca.config.Identity[i]
			break
		}
	}
	if identity == nil {
		return nil, nil, &ErrIdentityNotFound{CommonName: cn}
	}

	cert, err := ca.certStore.GetCertificate(cn)
	if err != nil {
		return nil, nil, &errs.Detail{Err: ErrCertificateNotFound, Detail: fmt.Sprintf("identity %q certificate: %v", cn, err)}
	}

	attrs, err := ca.getCAKeyAttributes(identity)
	if err != nil {
		return nil, nil, err
	}
	signer, err := ca.resolveKeyBackend(attrs.StoreType).Signer(ctx, attrs)
	if err != nil {
		return nil, nil, &errs.Detail{Err: ErrKeyStoreRequired, Detail: fmt.Sprintf("identity %q key: %v", cn, err)}
	}
	return signer, cert, nil
}

// =============================================================================
// Filtered CA Bundle & Extended Revocation
// =============================================================================

// CABundleFiltered returns a PEM bundle containing the CA certificates in the
// issuing chain, filtered by the provided store type and key algorithm. Pass
// the zero value for either filter to disable it.
//
// Thread-safe: Yes
func (ca *CA) CABundleFiltered(storeType types.StoreType, keyAlgorithm x509.PublicKeyAlgorithm) ([]byte, error) {
	if !ca.initialized.Load() {
		return nil, ErrNotInitialized
	}
	// When no filters are supplied the behaviour is equivalent to the
	// unfiltered CABundle.
	if storeType == "" && keyAlgorithm == x509.UnknownPublicKeyAlgorithm {
		return ca.CABundle()
	}

	ca.mu.RLock()
	rootCert := ca.rootCert
	intermediateCert := ca.intermediateCert
	ca.mu.RUnlock()

	var buf bytes.Buffer
	appendFiltered := func(cert *x509.Certificate) {
		if cert == nil {
			return
		}
		if keyAlgorithm != x509.UnknownPublicKeyAlgorithm && cert.PublicKeyAlgorithm != keyAlgorithm {
			return
		}
		// storeType filtering: when a storeType is specified, restrict the
		// bundle to CAs whose configured KeystoreType matches. We resolve via
		// the issuing identity (rootIdentity for root, intermediateIdentity
		// for intermediate).
		if storeType != "" {
			matched := false
			for _, id := range ca.config.Identity {
				if id.Subject.CommonName == cert.Subject.CommonName &&
					id.GetStoreType() == storeType {
					matched = true
					break
				}
			}
			if !matched {
				return
			}
		}
		_ = pem.Encode(&buf, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
	}

	appendFiltered(intermediateCert)
	appendFiltered(rootCert)

	if buf.Len() == 0 {
		return nil, &errs.Detail{Err: ErrInvalidCertificateChain, Detail: "no certificates match filter"}
	}
	return buf.Bytes(), nil
}

// RevokeCert is the extended revocation entry point used by the ACME and TCG
// workflows. Unlike Revoke(serial, reason), it accepts the certificate
// itself and a RevokeOptions struct so callers can request key deletion in
// the same call.
//
// When an object store is configured, the revocation record is persisted so
// that the revocation survives process restarts. On startup, Load() reads
// the persisted revocations back into the in-memory map. Without an object
// store the revocation is held in memory only and a warning is logged.
//
// Thread-safe: Yes
func (ca *CA) RevokeCert(ctx context.Context, cert *x509.Certificate, opts RevokeOptions) error {
	if cert == nil {
		return ErrInvalidCertificate
	}
	if !ca.initialized.Load() {
		return ErrNotInitialized
	}

	if err := ca.recordRevocation(ctx, cert.SerialNumber, opts.Reason, opts.DeleteKeys); err != nil {
		return err
	}

	if opts.DeleteKeys {
		// Build KeyAttributes for the certificate's CN. Deletion is
		// best-effort — hardware-bound keys may not be deletable and the
		// primary purpose of revocation is to invalidate the certificate.
		attrs := &types.KeyAttributes{
			CN:           cert.Subject.CommonName,
			KeyAlgorithm: cert.PublicKeyAlgorithm,
		}
		if ca.keyStore != nil {
			_ = ca.keyStore.DeleteKey(ctx, attrs)
			_ = ca.keyStore.DeleteCert(ctx, cert.Subject.CommonName)
		}
		if ca.certStore != nil {
			_ = ca.certStore.DeleteCertificate(cert.Subject.CommonName)
		}
	}
	return nil
}

// =============================================================================
// Revocation Persistence Helpers
// =============================================================================

// revocationKeyPrefix is the object-store key prefix used for revocation
// records. Each record lives at "revocations/<serial-decimal>.json".
const revocationKeyPrefix = "revocations/"

// persistedRevocation is the on-disk form of a revocation record. Keeping it
// separate from RevocationInfo lets us serialise stable JSON regardless of
// future additions to the in-memory type.
type persistedRevocation struct {
	Serial      string    `json:"serial"`
	Reason      int       `json:"reason"`
	RevokedAt   time.Time `json:"revoked_at"`
	DeletedKeys bool      `json:"deleted_keys"`
}

// revocationKey returns the object-store key for a given serial number.
func revocationKey(serial *big.Int) string {
	return revocationKeyPrefix + serial.Text(10)
}

// recordRevocation captures a revocation in the in-memory map and, when an
// object store is configured, persists the record. It is shared by Revoke
// (serial-based) and RevokeCert (certificate-based) to keep behaviour
// consistent.
func (ca *CA) recordRevocation(ctx context.Context, serial *big.Int, reason int, deletedKeys bool) error {
	if serial == nil {
		return ErrInvalidCertificate
	}

	key := serial.Text(10)
	now := time.Now()

	ca.revocationsMutex.Lock()
	if _, exists := ca.revocations[key]; exists {
		ca.revocationsMutex.Unlock()
		return ErrAlreadyRevoked
	}
	ca.revocations[key] = &RevocationInfo{
		SerialNumber:   serial,
		RevocationTime: now,
		Reason:         reason,
	}
	ca.revocationsMutex.Unlock()

	payload := persistedRevocation{
		Serial:      key,
		Reason:      reason,
		RevokedAt:   now,
		DeletedKeys: deletedKeys,
	}
	buf, err := json.Marshal(payload)
	if err != nil {
		return &errs.Detail{Err: ErrStorageError, Detail: fmt.Sprintf("marshal revocation: %v", err)}
	}
	persisted, err := ca.putRevocationBlob(ctx, serial, buf)
	if err != nil {
		return &errs.Detail{Err: ErrStorageError, Detail: fmt.Sprintf("persist revocation: %v", err)}
	}
	if !persisted {
		slog.Warn("ca: revocation recorded without persistence (no revocation store configured)",
			"serial", key, "reason", reason)
	}

	// Refresh the published CRL so it reflects this revocation without
	// waiting for its NextUpdate to lapse. Best-effort: the revocation
	// state above (what enforcement/IsRevoked/OCSP read) is already
	// durable, and a CRL refresh failure here self-heals on the next read
	// past NextUpdate (see CRL in crl_persistence.go) or the next
	// successful revocation.
	if _, err := ca.generateAndPersistCRL(ctx); err != nil {
		slog.Warn("ca: failed to refresh crl after revocation", "serial", key, "err", err)
	}

	return nil
}

// putRevocationBlob persists a serialized revocation record, preferring the
// datastore-backed revocation store and falling back to the legacy object
// store. Returns false when neither is configured (no persistence).
func (ca *CA) putRevocationBlob(ctx context.Context, serial *big.Int, buf []byte) (bool, error) {
	key := revocationKey(serial) + ".json"
	if ca.revocationStore != nil {
		if err := ca.revocationStore.Put(ctx, key, buf); err != nil {
			return false, err
		}
		return true, nil
	}
	if ca.objectStore != nil {
		if err := ca.objectStore.Put(key, bytes.NewReader(buf)); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}

// getRevocationBlob reads a single persisted revocation record, preferring
// the datastore-backed revocation store and falling back to the legacy
// object store -- the same preference order putRevocationBlob writes with.
// Returns ErrCRLNotFound when no record exists for serial or neither store
// is configured; the OCSP responder's cold path relies on that distinction
// to answer ocsp.Good rather than ocsp.Unknown for a never-revoked serial.
func (ca *CA) getRevocationBlob(ctx context.Context, serial *big.Int) ([]byte, error) {
	key := revocationKey(serial) + ".json"

	if ca.revocationStore != nil {
		data, err := ca.revocationStore.Get(ctx, key)
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				return nil, ErrCRLNotFound
			}
			return nil, &errs.Detail{Err: ErrStorageError, Detail: fmt.Sprintf("get revocation: %v", err)}
		}
		return data, nil
	}

	if ca.objectStore != nil {
		reader, err := ca.objectStore.Get(key)
		if err != nil {
			// List-and-scan fallback for backends that return opaque errors
			// on missing keys. Keeps callers robust against divergent store
			// implementations.
			keys, listErr := ca.objectStore.List(revocationKeyPrefix)
			if listErr != nil {
				return nil, &errs.Detail{Err: ErrStorageError, Detail: fmt.Sprintf("list revocations: %v", listErr)}
			}
			for _, k := range keys {
				if k == key {
					// Key exists in listing but Get failed — surface the
					// original Get error rather than pretending it's absent.
					return nil, &errs.Detail{Err: ErrStorageError, Detail: fmt.Sprintf("get revocation: %v", err)}
				}
			}
			return nil, ErrCRLNotFound
		}
		defer func() { _ = reader.Close() }()

		data, err := io.ReadAll(reader)
		if err != nil {
			return nil, &errs.Detail{Err: ErrStorageError, Detail: fmt.Sprintf("read revocation: %v", err)}
		}
		return data, nil
	}

	return nil, ErrCRLNotFound
}

// listRevocationBlobs reads all persisted revocation records (key -> JSON
// payload) from the configured store, preferring the datastore-backed
// revocation store and falling back to the legacy object store.
func (ca *CA) listRevocationBlobs(ctx context.Context) (map[string][]byte, error) {
	out := make(map[string][]byte)
	if ca.revocationStore != nil {
		err := ca.revocationStore.Scan(ctx, revocationKeyPrefix, func(k string, v []byte) error {
			out[k] = append([]byte(nil), v...)
			return nil
		})
		return out, err
	}
	if ca.objectStore != nil {
		keys, err := ca.objectStore.List(revocationKeyPrefix)
		if err != nil {
			return nil, err
		}
		for _, k := range keys {
			if len(k) == 0 || k[len(k)-1] == '/' {
				continue
			}
			reader, err := ca.objectStore.Get(k)
			if err != nil {
				slog.Warn("ca: failed to read persisted revocation", "key", k, "err", err)
				continue
			}
			data, err := io.ReadAll(reader)
			_ = reader.Close()
			if err != nil {
				slog.Warn("ca: failed to read persisted revocation body", "key", k, "err", err)
				continue
			}
			out[k] = data
		}
		return out, nil
	}
	return out, nil
}

// loadPersistedRevocations reads revocation records from the object store
// and merges them into the in-memory revocations map. It is called by Load()
// after the CA certs are loaded and before the CA is marked initialised so
// IsRevoked reflects persisted state from the first call.
//
// Missing or corrupt records are logged and skipped rather than aborting
// Load(); a single bad record should not render the CA inoperable.
func (ca *CA) loadPersistedRevocations(ctx context.Context) error {
	blobs, err := ca.listRevocationBlobs(ctx)
	if err != nil {
		return &errs.Detail{Err: ErrStorageError, Detail: fmt.Sprintf("list revocations: %v", err)}
	}
	for k, data := range blobs {
		var rec persistedRevocation
		if err := json.Unmarshal(data, &rec); err != nil {
			slog.Warn("ca: failed to unmarshal persisted revocation", "key", k, "err", err)
			continue
		}
		serial, ok := new(big.Int).SetString(rec.Serial, 10)
		if !ok {
			slog.Warn("ca: persisted revocation has invalid serial", "key", k, "serial", rec.Serial)
			continue
		}
		ca.revocationsMutex.Lock()
		if _, exists := ca.revocations[rec.Serial]; !exists {
			ca.revocations[rec.Serial] = &RevocationInfo{
				SerialNumber:   serial,
				RevocationTime: rec.RevokedAt,
				Reason:         rec.Reason,
			}
		}
		ca.revocationsMutex.Unlock()
	}
	return nil
}
