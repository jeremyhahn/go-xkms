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

package image

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/encoding"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// RootStore is the trust-roots seam: it returns the trusted root
// certificates registered for a purpose. The trust-roots stores satisfy it
// with their own purpose type.
type RootStore[P ~string] interface {
	CertificatesByPurpose(purpose P) ([]*x509.Certificate, error)
}

// VerifierConfig configures an image Verifier.
type VerifierConfig[P ~string] struct {
	// Registry reads the image's attestations.
	Registry RegistryClient

	// Roots holds the trusted image-signer roots.
	Roots RootStore[P]

	// Purpose selects the image-signer roots in Roots.
	Purpose P

	// PredicateType, when set, is the predicate type an attestation must
	// have; any type is accepted when empty.
	PredicateType string

	// TimestampRoots, when set, verifies attestation timestamps, and a
	// verified timestamp's genTime replaces the current time when the
	// signing certificate's chain is checked.
	TimestampRoots *x509.CertPool

	// RequireTimestamp refuses attestations without a timestamp. It needs
	// TimestampRoots.
	RequireTimestamp bool

	// SigningKeys, when set, resolves the key that signs each repository,
	// and an attestation whose signing certificate carries any other key is
	// refused with ErrSigningKeyMismatch. The certificate must still chain
	// to Roots.
	SigningKeys SigningKeyResolver
}

// SigningKeyResolver returns the public key that signs a repository's
// images, such as a tenant's per-repository signing-key binding over its
// release key.
type SigningKeyResolver interface {
	SigningKey(ctx context.Context, repository string) (crypto.PublicKey, error)
}

// Verifier verifies image attestations against trust-roots.
type Verifier struct {
	registry         RegistryClient
	roots            func() (*x509.CertPool, error)
	predicateType    string
	timestampRoots   *x509.CertPool
	requireTimestamp bool
	signingKeys      SigningKeyResolver
}

// VerificationResult describes a verified image attestation.
type VerificationResult struct {
	// Digest is the verified manifest digest.
	Digest string

	// Statement is the verified in-toto statement.
	Statement *Statement

	// Certificate is the signing certificate.
	Certificate *x509.Certificate

	// Timestamp is the verified timestamp; nil when none was verified.
	Timestamp *TimestampInfo
}

// NewVerifier returns a Verifier for cfg.
func NewVerifier[P ~string](cfg *VerifierConfig[P]) (*Verifier, error) {
	if cfg == nil || cfg.Registry == nil {
		return nil, ErrRegistryRequired
	}
	if cfg.Roots == nil {
		return nil, ErrRootStoreRequired
	}
	if cfg.Purpose == "" {
		return nil, ErrRootPurposeRequired
	}
	if cfg.RequireTimestamp && cfg.TimestampRoots == nil {
		return nil, ErrTimestampRootsRequired
	}
	store, purpose := cfg.Roots, cfg.Purpose
	return &Verifier{
		registry:         cfg.Registry,
		roots:            func() (*x509.CertPool, error) { return rootPool(store, purpose) },
		predicateType:    cfg.PredicateType,
		timestampRoots:   cfg.TimestampRoots,
		requireTimestamp: cfg.RequireTimestamp,
		signingKeys:      cfg.SigningKeys,
	}, nil
}

// rootPool returns the roots store holds for purpose.
func rootPool[P ~string](store RootStore[P], purpose P) (*x509.CertPool, error) {
	certificates, err := store.CertificatesByPurpose(purpose)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrNoTrustedRoots, Cause: err}
	}
	if len(certificates) == 0 {
		return nil, &errs.Detail{Err: ErrNoTrustedRoots, Detail: "purpose " + string(purpose)}
	}
	pool := x509.NewCertPool()
	for _, certificate := range certificates {
		pool.AddCert(certificate)
	}
	return pool, nil
}

// VerifyImage resolves ref to its manifest digest and returns the first of
// the image's attestations that verifies: its envelope signature verifies
// under its certificate, its statement names the digest, its timestamp
// verifies when timestamps are checked, and its certificate chains to a
// trusted root for code signing. The roots are read on every call.
func (v *Verifier) VerifyImage(ctx context.Context, ref string) (*VerificationResult, error) {
	reference, err := ParseReference(ref)
	if err != nil {
		return nil, err
	}
	roots, err := v.roots()
	if err != nil {
		return nil, err
	}
	signingKey, err := v.signingKey(ctx, reference.Repository)
	if err != nil {
		return nil, err
	}
	subject, err := v.registry.Resolve(ctx, reference)
	if err != nil {
		return nil, err
	}
	pinned, err := reference.WithDigest(subject.Digest)
	if err != nil {
		return nil, err
	}
	attestations, err := v.registry.Attestations(ctx, pinned)
	if err != nil {
		return nil, err
	}
	if len(attestations) == 0 {
		return nil, &errs.Detail{Err: ErrNoAttestation, Detail: pinned.String()}
	}

	failures := make([]error, 0, len(attestations))
	for _, attestation := range attestations {
		result, err := v.verifyAttestation(attestation, subject.Digest, roots, signingKey)
		if err == nil {
			return result, nil
		}
		failures = append(failures, err)
	}
	return nil, &errs.Joined{Lead: ErrNoValidAttestation, Cause: errors.Join(failures...)}
}

// signingKey resolves the key that signs the repository; nil when the
// Verifier has no SigningKeys.
func (v *Verifier) signingKey(ctx context.Context, repository string) (crypto.PublicKey, error) {
	if v.signingKeys == nil {
		return nil, nil
	}
	return v.signingKeys.SigningKey(ctx, repository)
}

// equalPublicKey is the Equal method every standard library public key
// has.
type equalPublicKey interface {
	Equal(crypto.PublicKey) bool
}

// verifyAttestation verifies one attestation of the image digest. A non-nil
// signingKey is the only key the signing certificate may carry.
func (v *Verifier) verifyAttestation(attestation *Attestation, digest string, roots *x509.CertPool, signingKey crypto.PublicKey) (*VerificationResult, error) {
	if attestation.Invalid != nil {
		return nil, attestation.Invalid
	}
	certificate, intermediates, err := attestationCertificates(attestation)
	if err != nil {
		return nil, err
	}
	if signingKey != nil {
		key, ok := certificate.PublicKey.(equalPublicKey)
		if !ok || !key.Equal(signingKey) {
			return nil, &errs.Detail{Err: ErrSigningKeyMismatch, Detail: certificate.Subject.String()}
		}
	}
	if err := checkCodeSigningUsage(certificate); err != nil {
		return nil, err
	}
	env, err := parseEnvelope(attestation.Envelope)
	if err != nil {
		return nil, err
	}
	if err := verifyEnvelope(env, certificate.PublicKey); err != nil {
		return nil, err
	}
	statement, err := parseStatement(env.Payload)
	if err != nil {
		return nil, err
	}
	if !statement.names(digest) {
		return nil, &errs.Detail{Err: ErrSubjectMismatch, Detail: digest}
	}
	if v.predicateType != "" && statement.PredicateType != v.predicateType {
		return nil, &errs.Detail{Err: ErrPredicateTypeMismatch, Detail: statement.PredicateType}
	}

	timestamp, err := v.verifyTimestamp(attestation)
	if err != nil {
		return nil, err
	}
	verifiedAt := time.Now()
	if timestamp != nil {
		verifiedAt = timestamp.Time
	}
	if _, err := certificate.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   verifiedAt,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}); err != nil {
		return nil, &errs.Joined{Lead: ErrUntrustedSigner, Cause: err}
	}
	return &VerificationResult{Digest: digest, Statement: statement, Certificate: certificate, Timestamp: timestamp}, nil
}

// verifyTimestamp verifies the attestation's timestamp when the verifier
// checks timestamps; it returns nil when it does not or the attestation
// has none and none is required.
func (v *Verifier) verifyTimestamp(attestation *Attestation) (*TimestampInfo, error) {
	if len(attestation.Timestamp) == 0 {
		if v.requireTimestamp {
			return nil, ErrTimestampRequired
		}
		return nil, nil
	}
	if v.timestampRoots == nil {
		return nil, nil
	}
	return VerifyTimestamp(attestation.Timestamp, attestation.Envelope, v.timestampRoots)
}

// attestationCertificates returns the attestation's signing certificate
// and a pool of its chain.
func attestationCertificates(attestation *Attestation) (*x509.Certificate, *x509.CertPool, error) {
	if len(attestation.Certificate) == 0 {
		return nil, nil, &errs.Detail{Err: ErrInvalidAttestation, Detail: "no certificate"}
	}
	certificates, err := encoding.DecodeCertificateChainPEM(attestation.Certificate)
	if err != nil {
		return nil, nil, &errs.Joined{Lead: ErrInvalidAttestation, Detail: "certificate", Cause: err}
	}
	if len(certificates) != 1 {
		return nil, nil, &errs.Detail{Err: ErrInvalidAttestation, Detail: "more than one signing certificate"}
	}

	intermediates := x509.NewCertPool()
	if len(attestation.Chain) > 0 {
		chain, err := encoding.DecodeCertificateChainPEM(attestation.Chain)
		if err != nil {
			return nil, nil, &errs.Joined{Lead: ErrInvalidAttestation, Detail: "chain", Cause: err}
		}
		for _, certificate := range chain {
			intermediates.AddCert(certificate)
		}
	}
	return certificates[0], intermediates, nil
}
