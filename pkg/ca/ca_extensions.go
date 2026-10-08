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
// keystore and the certStore receive a copy so subsequent lookups via either
// storage surface succeed. The certStore write is authoritative and always
// attempted; the keystore write is attempted first because some backends
// (e.g. hardware-bound keystores) are read-only for certs and would
// otherwise short-circuit the authoritative write. Either write's failure
// is now returned (joined when both fail) rather than discarded: a
// keystore save failure used to be silently swallowed, leaving the
// keystore's copy of a newly imported certificate missing with no signal
// to the caller.
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

	var keyStoreErr error
	if ca.keyStore != nil {
		if err := ca.keyStore.SaveCert(ctx, cn, cert); err != nil {
			keyStoreErr = &errs.Wrapped{Msg: "ca: keystore save cert failed", Err: err}
		}
	}
	if ca.certStore == nil {
		return errors.Join(keyStoreErr, ErrCertStoreRequired)
	}
	if err := ca.certStore.StoreCertificate(cert); err != nil {
		return errors.Join(keyStoreErr, &errs.Wrapped{Msg: "ca: certstore store certificate failed", Err: err})
	}
	return keyStoreErr
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

	var keyStoreErr error
	if ca.keyStore != nil {
		if err := ca.keyStore.SaveCert(ctx, cn, cert); err != nil {
			keyStoreErr = &errs.Wrapped{Msg: "ca: keystore save cert failed", Err: err}
		}
	}
	if ca.certStore == nil {
		return errors.Join(keyStoreErr, ErrCertStoreRequired)
	}
	if err := ca.certStore.StoreCertificate(cert); err != nil {
		return errors.Join(keyStoreErr, &errs.Wrapped{Msg: "ca: certstore store certificate failed", Err: err})
	}
	return keyStoreErr
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
	defer func() {
		if cerr := reader.Close(); cerr != nil {
			slog.Debug("ca: failed to close object store blob reader", "key", string(key), "error", cerr)
		}
	}()
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
// configured store type (GetStoreType, derived from Keys[0].StoreType).
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
	attrs, err := ca.getCAKeyAttributes(context.Background(), issuing)
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

	attrs, err := ca.getCAKeyAttributes(ctx, identity)
	if err != nil {
		return nil, nil, err
	}
	backend, err := ca.resolveKeyBackend(attrs.StoreType)
	if err != nil {
		return nil, nil, err
	}
	signer, err := backend.Signer(ctx, attrs)
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
	var encodeErr error
	appendFiltered := func(cert *x509.Certificate) {
		if cert == nil {
			return
		}
		if keyAlgorithm != x509.UnknownPublicKeyAlgorithm && cert.PublicKeyAlgorithm != keyAlgorithm {
			return
		}
		// storeType filtering: when a storeType is specified, restrict the
		// bundle to CAs whose configured store type (GetStoreType) matches.
		// We resolve via the issuing identity (rootIdentity for root,
		// intermediateIdentity for intermediate).
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
		if err := pem.Encode(&buf, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}); err != nil {
			encodeErr = errors.Join(encodeErr, err)
		}
	}

	appendFiltered(intermediateCert)
	appendFiltered(rootCert)
	if encodeErr != nil {
		return nil, &errs.Detail{Err: ErrCertificateEncoding, Detail: fmt.Sprintf("%v", encodeErr)}
	}

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

	if !opts.DeleteKeys {
		return nil
	}

	// The certificate is already revoked at this point: recordRevocation
	// above succeeded, and that record -- not the cleanup below -- is what
	// makes the certificate invalid. Every cleanup target is still
	// attempted even if an earlier one fails, and their errors are joined
	// into the return rather than discarded (go-xkms#687), so a real
	// storage failure is never silently swallowed.
	var cleanupErrs []error

	// Resolve the exact KeyAttributes the CA generated or resolved for this
	// certificate's key at issuance (go-xkms#751): the certificate alone
	// carries only its CN and public key algorithm, which is not enough to
	// satisfy types.KeyAttributes.Validate (StoreType, KeyType are also
	// required) or to name the same key ID generation stored it under. A
	// certificate signed from a caller-supplied CSR (SignCSR) -- or one
	// issued before this recording existed -- has no such record: the CA
	// never held that key, so deletion is correctly a no-op rather than a
	// failure.
	attrs, err := ca.resolveIssuedKeyAttributes(ctx, cert.SerialNumber)
	switch {
	case err != nil:
		cleanupErrs = append(cleanupErrs, &errs.Wrapped{Msg: "ca: resolve issued key attributes failed", Err: err})
	case attrs == nil:
		slog.Info("ca: revoke delete-keys: no CA-held key recorded for certificate; skipping key deletion",
			"serial", cert.SerialNumber.Text(10), "cn", cert.Subject.CommonName)
	default:
		if ca.keyStore == nil {
			cleanupErrs = append(cleanupErrs, ErrKeyStoreRequired)
		} else if err := ca.keyStore.DeleteKey(ctx, attrs); err != nil {
			cleanupErrs = append(cleanupErrs, &errs.Wrapped{Msg: "ca: keystore delete key failed", Err: err})
		} else if err := ca.deleteIssuedKeyRecord(ctx, cert.SerialNumber); err != nil {
			cleanupErrs = append(cleanupErrs, &errs.Wrapped{Msg: "ca: delete issued key record failed", Err: err})
		}
	}

	// certStore is the authoritative certificate store for every issuance
	// and import path (both IssueCertificateWithProfile/signCSR and
	// ImportCertificate/ImportCertificatePEM call StoreCertificate on it).
	// The keystore's own certificate side, by contrast, is never populated
	// for issued certificates -- only ImportCertificate/ImportCertificatePEM
	// call keyStore.SaveCert, and only best-effort -- so there is no
	// keyStore certificate copy to delete here.
	if ca.certStore != nil {
		if err := ca.certStore.DeleteCertificate(cert.Subject.CommonName); err != nil {
			cleanupErrs = append(cleanupErrs, &errs.Wrapped{Msg: "ca: certstore delete certificate failed", Err: err})
		}
	}

	if len(cleanupErrs) > 0 {
		return errors.Join(cleanupErrs...)
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

// recordRevocation captures a revocation in the datastore-backed revocation
// store and, once that write actually lands, in the in-memory map. It is
// shared by Revoke (serial-based) and RevokeCert (certificate-based) to keep
// behaviour consistent.
//
// Ordering matters (go-xkms#1131). The duplicate check reads through
// lookupRevocation -- the map, then the replicated store -- instead of the
// map alone, so a serial another cluster node already revoked is caught here
// rather than silently overwritten with this call's reason and time. The
// write itself goes to the store via putRevocationBlobIfAbsent before the map
// is touched: a store failure returns a typed error with the map left
// exactly as it was, so a caller can retry once the store recovers instead of
// a retry being rejected with ErrAlreadyRevoked for a record that was never
// actually persisted. Only a write that lands -- ours or, if we lost a race
// to another node between the duplicate check and the write, the one that
// beat us -- updates the map, via cacheRevocation.
//
// The store write uses PutIfAbsent, the one guarded primitive
// storage.Backend declares unconditionally (compare-and-swap and
// compare-and-delete are optional capabilities; create-if-absent is not).
// For a replicated backend (go-qrdb, in every configuration this package
// runs against) PutIfAbsent is a linearizable cross-node compare-and-swap
// keyed on "the record has never been written" -- see
// pkg/storage/qrdb/backend_putifabsent.go -- so two nodes racing to revoke
// the same serial can still both attempt the write, but only one of them
// stores it; the loser observes stored=false and reports ErrAlreadyRevoked
// with the winner's record rather than corrupting it. This closes the race
// the duplicate check alone cannot: the duplicate check and the write are
// two separate store operations, and PutIfAbsent -- not an extra check --
// is what makes the second one refuse when the first already landed
// elsewhere.
func (ca *CA) recordRevocation(ctx context.Context, serial *big.Int, reason int, deletedKeys bool) error {
	if serial == nil {
		return ErrInvalidCertificate
	}

	key := serial.Text(10)

	// Fail-closed duplicate check: a store read fault here must abort the
	// revocation attempt, never be treated as "not yet revoked".
	existing, err := ca.lookupRevocation(ctx, serial)
	if err != nil {
		return err
	}
	if existing != nil {
		return alreadyRevokedError(existing)
	}

	now := time.Now()
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

	stored, err := ca.putRevocationBlobIfAbsent(ctx, serial, buf)
	if err != nil {
		return &errs.Joined{Lead: ErrStorageError, Detail: "persist revocation", Cause: err}
	}
	if !stored {
		// Another writer's record for this serial landed between our
		// duplicate check and our write. Report ErrAlreadyRevoked with
		// whatever the store now holds; fall back to the bare sentinel if
		// even that read cannot complete, since the write's own stored=false
		// already proves a record exists.
		winner, lookupErr := ca.lookupRevocation(ctx, serial)
		if lookupErr == nil && winner != nil {
			return alreadyRevokedError(winner)
		}
		return ErrAlreadyRevoked
	}

	ca.cacheRevocation(&RevocationInfo{
		SerialNumber:   serial,
		RevocationTime: now,
		Reason:         reason,
	})

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

// alreadyRevokedError renders ErrAlreadyRevoked carrying info's original
// revocation time and reason, so a caller that loses a revocation race --
// either at recordRevocation's duplicate check or at its guarded write --
// learns what is already on record rather than only that it lost.
func alreadyRevokedError(info *RevocationInfo) error {
	return &errs.Detail{
		Err: ErrAlreadyRevoked,
		Detail: fmt.Sprintf("serial %s revoked at %s with reason %d",
			info.SerialNumber.Text(10), info.RevocationTime.Format(time.RFC3339), info.Reason),
	}
}

// putRevocationBlobIfAbsent persists a serialized revocation record to the
// datastore-backed revocation store via the guarded PutIfAbsent write,
// storage.Backend's create-if-absent primitive, the one guarded write every
// Backend implementation -- not just those that opt into CompareAndSwapper --
// must provide. It reports stored=false, not an error, when a record for
// this serial already exists: that is the guard doing its job, and
// recordRevocation reads it as "another writer already recorded this
// serial", never as a fault.
func (ca *CA) putRevocationBlobIfAbsent(ctx context.Context, serial *big.Int, buf []byte) (bool, error) {
	return ca.revocationStore.PutIfAbsent(ctx, revocationKey(serial)+".json", buf)
}

// getRevocationBlob reads a single persisted revocation record from the
// datastore-backed revocation store. Returns ErrCRLNotFound when no record
// exists for serial; lookupRevocation relies on that distinction to report
// "not revoked" only for a definite miss, never for a store fault.
func (ca *CA) getRevocationBlob(ctx context.Context, serial *big.Int) ([]byte, error) {
	data, err := ca.revocationStore.Get(ctx, revocationKey(serial)+".json")
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrCRLNotFound
		}
		return nil, &errs.Joined{Lead: ErrStorageError, Detail: "get revocation", Cause: err}
	}
	return data, nil
}

// listRevocationBlobs reads all persisted revocation records (key -> JSON
// payload) from the datastore-backed revocation store.
func (ca *CA) listRevocationBlobs(ctx context.Context) (map[string][]byte, error) {
	out := make(map[string][]byte)
	err := ca.revocationStore.Scan(ctx, revocationKeyPrefix, func(k string, v []byte) error {
		out[k] = append([]byte(nil), v...)
		return nil
	})
	return out, err
}

// decodeRevocationRecord decodes the persisted revocation record stored
// under key. It fails with ErrRevocationRecordCorrupt, naming key, when the
// payload is not a valid record or names a serial other than the one key
// was written for (revocationKey(serial)+".json"). Every reader of
// revocation state -- Load, IsRevoked, OCSP and CRL generation -- goes
// through here, so none of them can treat an unreadable record as "not
// revoked".
func decodeRevocationRecord(key string, data []byte) (*RevocationInfo, error) {
	var rec persistedRevocation
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, &errs.Detail{Err: ErrRevocationRecordCorrupt, Detail: fmt.Sprintf("key %q: %v", key, err)}
	}
	serial, ok := new(big.Int).SetString(rec.Serial, 10)
	if !ok {
		return nil, &errs.Detail{Err: ErrRevocationRecordCorrupt, Detail: fmt.Sprintf("key %q: invalid serial %q", key, rec.Serial)}
	}
	if revocationKey(serial)+".json" != key {
		return nil, &errs.Detail{Err: ErrRevocationRecordCorrupt, Detail: fmt.Sprintf("key %q: record names serial %s", key, rec.Serial)}
	}
	return &RevocationInfo{
		SerialNumber:   serial,
		RevocationTime: rec.RevokedAt,
		Reason:         rec.Reason,
	}, nil
}

// cacheRevocation records info in the in-memory revocations map unless an
// entry for the serial is already present, and returns the entry the map
// holds afterwards. Caching is safe without invalidation because revocation
// is permanent: this CA has no un-revoke or hold-release path, so a serial
// that is revoked in the store stays revoked. Only positive results are
// ever cached -- a miss is always re-read from the store, because another
// instance may revoke the serial at any time.
func (ca *CA) cacheRevocation(info *RevocationInfo) *RevocationInfo {
	key := info.SerialNumber.Text(10)
	ca.revocationsMutex.Lock()
	defer ca.revocationsMutex.Unlock()
	if existing, ok := ca.revocations[key]; ok {
		return existing
	}
	ca.revocations[key] = info
	return info
}

// lookupRevocation reports the revocation of serial, or nil when serial is
// not revoked. It is the one read path for a single serial, shared by
// IsRevoked (and so Verify and VerifyPeerCertificate) and the OCSP
// responder.
//
// The in-memory map is consulted first. On a miss the replicated
// revocationStore is read, so a revocation written by another instance in
// the cluster -- which never passes through this instance's map -- is
// still seen. A hit from the store is cached (see cacheRevocation).
//
// Only a definite storage.ErrNotFound means "not revoked". Any other store
// fault is returned wrapped in ErrStorageError and a record that cannot be
// decoded in ErrRevocationRecordCorrupt; neither is ever reported as "not
// revoked".
func (ca *CA) lookupRevocation(ctx context.Context, serial *big.Int) (*RevocationInfo, error) {
	ca.revocationsMutex.RLock()
	info, ok := ca.revocations[serial.Text(10)]
	ca.revocationsMutex.RUnlock()
	if ok {
		return info, nil
	}

	data, err := ca.getRevocationBlob(ctx, serial)
	if err != nil {
		if errors.Is(err, ErrCRLNotFound) {
			return nil, nil
		}
		return nil, err
	}
	info, err = decodeRevocationRecord(revocationKey(serial)+".json", data)
	if err != nil {
		return nil, err
	}
	return ca.cacheRevocation(info), nil
}

// loadPersistedRevocations reads every revocation record from the
// replicated revocationStore and merges it into the in-memory revocations
// map. Load() calls it before marking the CA initialised, and
// generateAndPersistCRL calls it before building a CRL so the CRL includes
// revocations recorded by every instance in the cluster, not only this one.
//
// It fails closed: a listing error is returned wrapped in ErrStorageError,
// and a record that cannot be decoded aborts with
// ErrRevocationRecordCorrupt naming its key. Skipping a corrupt record
// would silently un-revoke the certificate it describes.
func (ca *CA) loadPersistedRevocations(ctx context.Context) error {
	blobs, err := ca.listRevocationBlobs(ctx)
	if err != nil {
		return &errs.Joined{Lead: ErrStorageError, Detail: "list revocations", Cause: err}
	}
	for k, data := range blobs {
		info, err := decodeRevocationRecord(k, data)
		if err != nil {
			return err
		}
		ca.cacheRevocation(info)
	}
	return nil
}

// =============================================================================
// Issued-Key Persistence Helpers
// =============================================================================

// issuedKeyPrefix is the object-store key prefix for persisted issuance-time
// key attributes, a sibling of revocationKeyPrefix and crlKeyPrefix in the
// same store (ca.revocationStore): key state lives under
// "issued-keys/<serial-decimal>.json" instead of
// "revocations/<serial-decimal>.json" or "crl/<issuer-ski-hex>".
const issuedKeyPrefix = "issued-keys/"

// persistedIssuedKey is the on-disk form of the KeyAttributes IssueCertificate
// / IssueCertificateWithProfile captured when the CA itself generated or
// resolved a certificate's private key through ca.keyStore. It carries only
// the fields types.KeyAttributes.Validate and KeyAttributes.ID actually need
// to name and delete the same key later, not the full KeyAttributes type --
// kept separate so serialisation stays stable regardless of future additions
// to that type (mirrors persistedRevocation above).
type persistedIssuedKey struct {
	Serial       string                  `json:"serial"`
	CN           string                  `json:"cn"`
	TenantID     string                  `json:"tenant_id,omitempty"`
	Partition    string                  `json:"partition,omitempty"`
	Backend      string                  `json:"backend,omitempty"`
	StoreType    string                  `json:"store_type"`
	KeyType      types.KeyType           `json:"key_type"`
	KeyAlgorithm x509.PublicKeyAlgorithm `json:"key_algorithm"`
	ECCCurve     string                  `json:"ecc_curve,omitempty"`
	RSAKeySize   int                     `json:"rsa_key_size,omitempty"`
}

// issuedKeyStorageKey returns the object-store key for a given serial
// number's issued-key record.
func issuedKeyStorageKey(serial *big.Int) string {
	return issuedKeyPrefix + serial.Text(10) + ".json"
}

// recordIssuedKey persists the exact KeyAttributes a server-side key
// generation or resolution used for the certificate identified by serial, so
// RevokeCert's DeleteKeys option can resolve and delete precisely that key
// later instead of reconstructing incomplete attributes from the certificate
// alone (go-xkms#751). Callers must invoke this only when the CA itself holds
// the key (request.Signer == nil on the originating CertificateRequest); a
// CSR-signed certificate must never call this, because the CA never held the
// requester's key.
//
// attrs must be non-nil; a nil attrs is a caller error and returns
// ErrInvalidKeyAttributes rather than silently doing nothing.
func (ca *CA) recordIssuedKey(ctx context.Context, serial *big.Int, attrs *types.KeyAttributes) error {
	if attrs == nil {
		return ErrInvalidKeyAttributes
	}

	rec := persistedIssuedKey{
		Serial:       serial.Text(10),
		CN:           attrs.CN,
		TenantID:     attrs.TenantID,
		Partition:    string(attrs.Partition),
		Backend:      attrs.Backend,
		StoreType:    string(attrs.StoreType),
		KeyType:      attrs.KeyType,
		KeyAlgorithm: attrs.KeyAlgorithm,
	}
	if attrs.ECCAttributes != nil && attrs.ECCAttributes.Curve != nil {
		rec.ECCCurve = types.CurveName(attrs.ECCAttributes.Curve)
	}
	if attrs.RSAAttributes != nil {
		rec.RSAKeySize = attrs.RSAAttributes.KeySize
	}

	buf, err := json.Marshal(rec)
	if err != nil {
		return &errs.Wrapped{Msg: "ca: marshal issued key", Err: err}
	}
	if err := ca.revocationStore.Put(ctx, issuedKeyStorageKey(serial), buf); err != nil {
		return &errs.Wrapped{Msg: "ca: persist issued key", Err: err}
	}
	return nil
}

// resolveIssuedKeyAttributes reconstructs the KeyAttributes a server-side key
// generation or resolution used for the certificate with the given serial,
// from the record recordIssuedKey wrote at issuance.
//
// Returns (nil, nil) -- not an error -- when no record exists: that is the
// CSR-signed case (or a certificate issued before this recording existed),
// where the CA never held the requester's key, and RevokeCert's DeleteKeys
// must treat it as a no-op rather than a failure.
func (ca *CA) resolveIssuedKeyAttributes(ctx context.Context, serial *big.Int) (*types.KeyAttributes, error) {
	data, err := ca.revocationStore.Get(ctx, issuedKeyStorageKey(serial))
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, nil
		}
		return nil, &errs.Wrapped{Msg: "ca: get issued key", Err: err}
	}

	var rec persistedIssuedKey
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, &errs.Wrapped{Msg: "ca: unmarshal issued key", Err: err}
	}

	attrs := &types.KeyAttributes{
		CN:           rec.CN,
		TenantID:     rec.TenantID,
		Partition:    types.Partition(rec.Partition),
		Backend:      rec.Backend,
		StoreType:    types.StoreType(rec.StoreType),
		KeyType:      rec.KeyType,
		KeyAlgorithm: rec.KeyAlgorithm,
	}
	switch rec.KeyAlgorithm {
	case x509.RSA:
		attrs.RSAAttributes = &types.RSAAttributes{KeySize: rec.RSAKeySize}
	case x509.ECDSA:
		curve, err := types.ParseCurve(rec.ECCCurve)
		if err != nil {
			return nil, &errs.Wrapped{Msg: "ca: issued key curve", Err: err}
		}
		attrs.ECCAttributes = &types.ECCAttributes{Curve: curve}
	}
	return attrs, nil
}

// deleteIssuedKeyRecord removes the issued-key bookkeeping record for serial
// once RevokeCert has successfully deleted the key itself. A record that is
// already absent is not an error: it means either the key was already
// cleaned up by a previous revocation attempt, or none was ever written.
func (ca *CA) deleteIssuedKeyRecord(ctx context.Context, serial *big.Int) error {
	if err := ca.revocationStore.Delete(ctx, issuedKeyStorageKey(serial)); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil
		}
		return &errs.Wrapped{Msg: "ca: delete issued key record", Err: err}
	}
	return nil
}

// =============================================================================
// Certificate Tenant Persistence Helpers
// =============================================================================

// certTenantPrefix is the object-store key prefix for the tenant recorded
// against a certificate at issuance, a sibling of revocationKeyPrefix and
// issuedKeyPrefix in the same store (ca.revocationStore): key state lives
// under "cert-tenant/<serial-decimal>.json".
const certTenantPrefix = "cert-tenant/"

// persistedCertTenant is the on-disk form of a certificate's issuing-tenant
// record. Kept separate from any in-memory type for the same reason as
// persistedRevocation and persistedIssuedKey: stable JSON regardless of
// future additions elsewhere.
type persistedCertTenant struct {
	Serial   string `json:"serial"`
	TenantID string `json:"tenant_id,omitempty"`
}

// certTenantStorageKey returns the object-store key for a given serial
// number's issuing-tenant record.
func certTenantStorageKey(serial *big.Int) string {
	return certTenantPrefix + serial.Text(10) + ".json"
}

// recordCertTenant persists tenantID (empty for the system/platform scope)
// as the issuing tenant of the certificate identified by serial. signCSR
// calls this for every certificate it issues -- both direct CSR signing
// (SignCSR/SignCSRWithSPIFFE) and keypair issuance
// (IssueCertificate/IssueCertificateWithProfile, which routes through
// signCSR) -- so every certificate this CA issues through its end-entity
// path has an owning tenant on record before it is handed to the caller.
// RevokeCertificate (pkg/xkms/servicer_ca.go) reads the record back via
// CertificateTenant to refuse a revoke request from a caller bound to a
// different tenant (go-xkms#1229).
//
// TCG device-identity certificates (EK/AK/IDevID) and the CA's own
// root/intermediate certificates do not go through signCSR and so carry no
// record; CertificateTenant reports the system/platform scope for them,
// which only a cross-tenant (system) caller may address.
func (ca *CA) recordCertTenant(ctx context.Context, serial *big.Int, tenantID string) error {
	if serial == nil {
		return ErrInvalidCertificate
	}
	rec := persistedCertTenant{
		Serial:   serial.Text(10),
		TenantID: tenantID,
	}
	buf, err := json.Marshal(rec)
	if err != nil {
		return &errs.Wrapped{Msg: "ca: marshal cert tenant", Err: err}
	}
	if err := ca.revocationStore.Put(ctx, certTenantStorageKey(serial), buf); err != nil {
		return &errs.Wrapped{Msg: "ca: persist cert tenant", Err: err}
	}
	return nil
}

// CertificateTenant returns the tenant recorded at issuance for the
// certificate identified by serial, or the system/platform scope ("") when
// no record exists -- either because the certificate was issued through a
// path that does not record one (TCG device identity, CA hierarchy) or
// because it predates this recording. Either way, only a cross-tenant caller
// may then act on it; see recordCertTenant.
//
// Thread-safe: Yes
func (ca *CA) CertificateTenant(ctx context.Context, serial *big.Int) (string, error) {
	if serial == nil {
		return "", ErrInvalidCertificate
	}
	data, err := ca.revocationStore.Get(ctx, certTenantStorageKey(serial))
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return "", nil
		}
		return "", &errs.Wrapped{Msg: "ca: get cert tenant", Err: err}
	}
	var rec persistedCertTenant
	if err := json.Unmarshal(data, &rec); err != nil {
		return "", &errs.Wrapped{Msg: "ca: unmarshal cert tenant", Err: err}
	}
	return rec.TenantID, nil
}
