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

// Package attestation provides an auto-selecting attestation verifier that
// queries the xkey trust store by certificate purpose and merges in embedded
// manufacturer roots as fallback. It performs standard PKIX chain validation
// for TPM, Android hardware, and IDevID attestation chains.
package attestation

import (
	"crypto/x509"
	"fmt"
	"time"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/truststore"
)

// TrustLevel indicates the level of trust for a verified attestation.
type TrustLevel string

const (
	// TrustLevelHardware indicates the key is backed by hardware security
	// (TPM, Android TEE/StrongBox).
	TrustLevelHardware TrustLevel = "hardware"

	// TrustLevelSoftware indicates the key is software-backed.
	TrustLevelSoftware TrustLevel = "software"

	// TrustLevelExternalCA indicates the key was verified by an external CA.
	TrustLevelExternalCA TrustLevel = "external-ca"

	// TrustLevelUnknown indicates the trust level could not be determined.
	TrustLevelUnknown TrustLevel = "unknown"
)

// purposeTrustLevels maps certificate purposes to their default trust levels.
var purposeTrustLevels = map[truststore.CertPurpose]TrustLevel{
	truststore.PurposeTPMManufacturer: TrustLevelHardware,
	truststore.PurposeAndroidHardware: TrustLevelHardware,
	truststore.PurposeIDevIDIssuer:    TrustLevelHardware,
	truststore.PurposeUserCA:          TrustLevelExternalCA,
	truststore.PurposeBootstrapCA:     TrustLevelExternalCA,
	truststore.PurposeGeneral:         TrustLevelUnknown,
}

// VerificationResult contains the result of an attestation verification.
type VerificationResult struct {
	Verified    bool       `json:"verified"`
	TrustLevel  TrustLevel `json:"trust_level"`
	Subject     string     `json:"subject"`
	Issuer      string     `json:"issuer"`
	ChainLength int        `json:"chain_length"`
	Message     string     `json:"message,omitempty"`
}

// EmbeddedRootsLoader is a function that returns embedded root certificates
// for a given certificate purpose. This allows the verifier to merge in
// compiled-in manufacturer roots as a fallback when the trust store does
// not contain sufficient anchors.
type EmbeddedRootsLoader func(purpose truststore.CertPurpose) []*x509.Certificate

// Verifier performs attestation chain verification by auto-selecting trust
// anchors from the trust store based on certificate purpose, with optional
// embedded root fallback.
type Verifier struct {
	store          truststore.TrustStore
	embeddedLoader EmbeddedRootsLoader
}

// NewVerifier creates a new attestation verifier backed by the given trust store.
// An optional EmbeddedRootsLoader can be provided to supply compiled-in manufacturer
// roots as fallback trust anchors. Pass nil for embeddedLoader if no embedded
// roots are needed.
func NewVerifier(store truststore.TrustStore, embeddedLoader EmbeddedRootsLoader) (*Verifier, error) {
	if store == nil {
		return nil, ErrNilTrustStore
	}
	return &Verifier{
		store:          store,
		embeddedLoader: embeddedLoader,
	}, nil
}

// VerifyTPMAttestation verifies a TPM endorsement key certificate against
// TPM manufacturer trust anchors. It queries the trust store for certificates
// with PurposeTPMManufacturer and merges in any embedded manufacturer roots.
func (v *Verifier) VerifyTPMAttestation(ekCert *x509.Certificate) (*VerificationResult, error) {
	if ekCert == nil {
		return nil, ErrNilCertificate
	}

	roots, err := v.buildTrustPool(truststore.PurposeTPMManufacturer)
	if err != nil {
		return nil, err
	}

	chains, err := v.verifyLeaf(ekCert, nil, roots)
	if err != nil {
		return &VerificationResult{
			Verified:    false,
			TrustLevel:  TrustLevelUnknown,
			Subject:     ekCert.Subject.String(),
			Issuer:      ekCert.Issuer.String(),
			ChainLength: 1,
			Message:     fmt.Sprintf("chain verification failed: %v", err),
		}, fmt.Errorf("%w: %v", ErrChainVerification, err)
	}

	return &VerificationResult{
		Verified:    true,
		TrustLevel:  TrustLevelHardware,
		Subject:     ekCert.Subject.String(),
		Issuer:      ekCert.Issuer.String(),
		ChainLength: len(chains[0]),
		Message:     "TPM EK certificate verified against manufacturer root",
	}, nil
}

// VerifyAndroidAttestation verifies an Android hardware attestation certificate
// chain. The chain should be ordered as [leaf, intermediate(s)..., root].
// It queries the trust store for PurposeAndroidHardware certificates and
// merges in any embedded Google Hardware Attestation roots.
//
// If nonce is non-nil, it is noted for future Android attestation extension
// parsing (OID 1.3.6.1.4.1.11129.2.1.17). Currently nonce verification is
// deferred until full Android extension parsing is implemented.
func (v *Verifier) VerifyAndroidAttestation(chain []*x509.Certificate, nonce []byte) (*VerificationResult, error) {
	if len(chain) == 0 {
		return nil, ErrEmptyCertChain
	}

	leaf := chain[0]

	roots, err := v.buildTrustPool(truststore.PurposeAndroidHardware)
	if err != nil {
		return nil, err
	}

	// Extract intermediates from chain[1:len(chain)-1]. The final certificate
	// is assumed to be the root (or an anchor in the trust pool).
	var intermediates []*x509.Certificate
	if len(chain) > 2 {
		intermediates = chain[1 : len(chain)-1]
	}

	// If the chain has exactly 2 entries, chain[1] could be either an
	// intermediate or the root. Add it to both the intermediates pool and
	// let x509.Verify sort it out against the roots pool.
	if len(chain) == 2 {
		intermediates = chain[1:]
	}

	// TODO: When nonce is non-nil, extract the Android key attestation extension
	// (OID 1.3.6.1.4.1.11129.2.1.17) from the leaf certificate and verify
	// that the challenge/nonce matches. This requires deeper ASN.1 parsing
	// of the Android-specific extension structure.

	chains, err := v.verifyLeaf(leaf, intermediates, roots)
	if err != nil {
		return &VerificationResult{
			Verified:    false,
			TrustLevel:  TrustLevelUnknown,
			Subject:     leaf.Subject.String(),
			Issuer:      leaf.Issuer.String(),
			ChainLength: len(chain),
			Message:     fmt.Sprintf("chain verification failed: %v", err),
		}, fmt.Errorf("%w: %v", ErrChainVerification, err)
	}

	return &VerificationResult{
		Verified:    true,
		TrustLevel:  TrustLevelHardware,
		Subject:     leaf.Subject.String(),
		Issuer:      leaf.Issuer.String(),
		ChainLength: len(chains[0]),
		Message:     "Android attestation chain verified",
	}, nil
}

// VerifyIDevID verifies an IDevID certificate against IDevID issuer trust
// anchors. It queries the trust store for PurposeIDevIDIssuer certificates
// and merges in any embedded roots.
func (v *Verifier) VerifyIDevID(cert *x509.Certificate) (*VerificationResult, error) {
	if cert == nil {
		return nil, ErrNilCertificate
	}

	roots, err := v.buildTrustPool(truststore.PurposeIDevIDIssuer)
	if err != nil {
		return nil, err
	}

	chains, err := v.verifyLeaf(cert, nil, roots)
	if err != nil {
		return &VerificationResult{
			Verified:    false,
			TrustLevel:  TrustLevelUnknown,
			Subject:     cert.Subject.String(),
			Issuer:      cert.Issuer.String(),
			ChainLength: 1,
			Message:     fmt.Sprintf("chain verification failed: %v", err),
		}, fmt.Errorf("%w: %v", ErrChainVerification, err)
	}

	return &VerificationResult{
		Verified:    true,
		TrustLevel:  TrustLevelHardware,
		Subject:     cert.Subject.String(),
		Issuer:      cert.Issuer.String(),
		ChainLength: len(chains[0]),
		Message:     "IDevID certificate verified against issuer root",
	}, nil
}

// VerifyChain performs generic certificate chain verification for the given
// purpose. The chain should be ordered as [leaf, intermediate(s)...].
// Trust anchors are loaded from the trust store by purpose and merged with
// any embedded roots.
func (v *Verifier) VerifyChain(chain []*x509.Certificate, purpose truststore.CertPurpose) (*VerificationResult, error) {
	if len(chain) == 0 {
		return nil, ErrEmptyCertChain
	}

	if !truststore.IsValidPurpose(purpose) {
		return nil, ErrUnsupportedPurpose
	}

	leaf := chain[0]

	roots, err := v.buildTrustPool(purpose)
	if err != nil {
		return nil, err
	}

	var intermediates []*x509.Certificate
	if len(chain) > 1 {
		intermediates = chain[1:]
	}

	chains, err := v.verifyLeaf(leaf, intermediates, roots)
	if err != nil {
		return &VerificationResult{
			Verified:    false,
			TrustLevel:  TrustLevelUnknown,
			Subject:     leaf.Subject.String(),
			Issuer:      leaf.Issuer.String(),
			ChainLength: len(chain),
			Message:     fmt.Sprintf("chain verification failed: %v", err),
		}, fmt.Errorf("%w: %v", ErrChainVerification, err)
	}

	trustLevel, ok := purposeTrustLevels[purpose]
	if !ok {
		trustLevel = TrustLevelUnknown
	}

	return &VerificationResult{
		Verified:    true,
		TrustLevel:  trustLevel,
		Subject:     leaf.Subject.String(),
		Issuer:      leaf.Issuer.String(),
		ChainLength: len(chains[0]),
		Message:     fmt.Sprintf("chain verified for purpose %s", purpose),
	}, nil
}

// BuildTrustPool assembles an x509.CertPool for the given purpose by merging
// trust store certificates and embedded manufacturer roots. This is useful when
// callers need the pool for their own verification logic (e.g., Android extension
// parsing via android.VerifyKeyAttestation).
//
// Returns ErrNoTrustAnchors if both sources produce zero certificates.
func (v *Verifier) BuildTrustPool(purpose truststore.CertPurpose) (*x509.CertPool, error) {
	return v.buildTrustPool(purpose)
}

// buildTrustPool assembles an x509.CertPool from two sources:
// 1. Certificates in the trust store matching the given purpose
// 2. Embedded manufacturer roots from the optional EmbeddedRootsLoader
//
// Returns ErrNoTrustAnchors if both sources produce zero certificates.
func (v *Verifier) buildTrustPool(purpose truststore.CertPurpose) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	count := 0

	// Load purpose-scoped certificates from the trust store.
	storeCerts, err := v.store.CertificatesByPurpose(purpose)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTrustStoreQuery, err)
	}
	for _, cert := range storeCerts {
		pool.AddCert(cert)
		count++
	}

	// Load embedded manufacturer roots as fallback.
	if v.embeddedLoader != nil {
		embeddedCerts := v.embeddedLoader(purpose)
		for _, cert := range embeddedCerts {
			pool.AddCert(cert)
			count++
		}
	}

	if count == 0 {
		return nil, ErrNoTrustAnchors
	}

	return pool, nil
}

// verifyLeaf performs X.509 chain verification on the leaf certificate using
// the provided roots pool and optional intermediate certificates. It sets
// the verification time to the current time.
func (v *Verifier) verifyLeaf(leaf *x509.Certificate, intermediates []*x509.Certificate, roots *x509.CertPool) ([][]*x509.Certificate, error) {
	opts := x509.VerifyOptions{
		Roots:       roots,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		CurrentTime: time.Now(),
	}

	if len(intermediates) > 0 {
		intPool := x509.NewCertPool()
		for _, cert := range intermediates {
			intPool.AddCert(cert)
		}
		opts.Intermediates = intPool
	}

	chains, err := leaf.Verify(opts)
	if err != nil {
		return nil, err
	}

	return chains, nil
}
