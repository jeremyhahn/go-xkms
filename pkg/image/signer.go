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
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"slices"
	"strings"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/encoding"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// SignerConfig configures an image Signer.
type SignerConfig struct {
	// Signer is the KMS key that signs: a TPM, PKCS#11 or cloud KMS
	// crypto.Signer. pkg/image never loads a key file.
	Signer crypto.Signer

	// Certificate is Signer's code-signing certificate, issued under
	// TrustedCA's code-signing profile (see RequestCodeSigningCertificate).
	Certificate *x509.Certificate

	// Chain is Certificate's issuer chain up to, and including, the root.
	Chain []*x509.Certificate

	// Registry pushes the attestations.
	Registry RegistryClient

	// Timestamper, when set, adds an RFC 3161 timestamp over every
	// envelope.
	Timestamper Timestamper
}

// Signer signs container images: it attests an image digest in a DSSE
// envelope over an in-toto statement and pushes it to the image's
// registry.
type Signer struct {
	signer         crypto.Signer
	certificate    *x509.Certificate
	certificatePEM []byte
	chainPEM       []byte
	registry       RegistryClient
	timestamper    Timestamper
}

// SignOptions shapes the statement an image is attested with.
type SignOptions struct {
	// PredicateType is the statement's predicate type; PredicateTypeCosign
	// when empty.
	PredicateType string

	// Predicate is the statement's predicate, a JSON value. It may be empty
	// only for PredicateTypeCosign, which then wraps no data, timestamped
	// at signing.
	Predicate json.RawMessage
}

// SignResult describes a signed image.
type SignResult struct {
	// Digest is the signed manifest digest.
	Digest string

	// Envelope is the pushed DSSE envelope JSON.
	Envelope []byte

	// Timestamp is the DER RFC 3161 TimeStampResp over Envelope; empty
	// without a Timestamper.
	Timestamp []byte

	// Push describes where the registry stored the attestation.
	Push *PushResult
}

// ProfileCodeSigning is the registry name of TrustedCA's code-signing
// profile (ca.ProfileNameCodeSigning), under which
// RequestCodeSigningCertificate asks for a certificate. pkg/image names it
// itself rather than importing pkg/ca, which imports pkg/xkms, so that the
// service can sign images with pkg/image.
const ProfileCodeSigning = "code-signing"

// CertificateIssuer issues certificates from CSRs without storing them.
// TrustedCA (*ca.CA) satisfies it. The certificate is named after a
// caller-chosen repository and travels with the signature, so it is never
// stored where it could replace another certificate of that name. A zero
// validityDays takes the profile's default lifetime.
type CertificateIssuer interface {
	SignCSRUnstored(ctx context.Context, csrPEM []byte, profile string, validityDays int, tenantID string) (*x509.Certificate, error)
}

// NewSigner returns a Signer for cfg. The certificate must certify the
// signer's key for code signing and be valid now.
func NewSigner(cfg *SignerConfig) (*Signer, error) {
	if cfg == nil || cfg.Signer == nil {
		return nil, ErrSignerRequired
	}
	if cfg.Certificate == nil {
		return nil, ErrCertificateRequired
	}
	if cfg.Registry == nil {
		return nil, ErrRegistryRequired
	}
	if err := checkCodeSigning(cfg.Certificate, cfg.Signer.Public(), time.Now()); err != nil {
		return nil, err
	}

	certificatePEM, err := encoding.EncodeCertificatePEM(cfg.Certificate)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrEncodingFailed, Cause: err}
	}
	var chainPEM []byte
	if len(cfg.Chain) > 0 {
		chainPEM, err = encoding.EncodeCertificateChainPEM(cfg.Chain)
		if err != nil {
			return nil, &errs.Joined{Lead: ErrEncodingFailed, Cause: err}
		}
	}
	return &Signer{
		signer:         cfg.Signer,
		certificate:    cfg.Certificate,
		certificatePEM: certificatePEM,
		chainPEM:       chainPEM,
		registry:       cfg.Registry,
		timestamper:    cfg.Timestamper,
	}, nil
}

// SignImage resolves ref to its manifest digest, signs an in-toto
// statement with that digest as subject into a DSSE envelope, timestamps
// the envelope when the Signer has a Timestamper, and pushes it as an OCI
// 1.1 referrer and to the image's cosign ".att" tag. opts may be nil.
func (s *Signer) SignImage(ctx context.Context, ref string, opts *SignOptions) (*SignResult, error) {
	reference, err := ParseReference(ref)
	if err != nil {
		return nil, err
	}
	predicateType, predicate, err := opts.predicate(time.Now())
	if err != nil {
		return nil, err
	}
	if err := checkValidity(s.certificate, time.Now()); err != nil {
		return nil, err
	}

	subject, err := s.registry.Resolve(ctx, reference)
	if err != nil {
		return nil, err
	}
	pinned, err := reference.WithDigest(subject.Digest)
	if err != nil {
		return nil, err
	}
	statement, err := newStatement(reference.Name(), subject.Digest, predicateType, predicate)
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(statement)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrEncodingFailed, Detail: "statement", Cause: err}
	}
	env, err := signEnvelope(s.signer, PayloadTypeInToto, payload)
	if err != nil {
		return nil, err
	}
	envelope, err := json.Marshal(env)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrEncodingFailed, Detail: "envelope", Cause: err}
	}

	var timestamp []byte
	if s.timestamper != nil {
		timestamp, err = s.timestamper.Timestamp(ctx, envelope)
		if err != nil {
			return nil, err
		}
	}
	push, err := s.registry.PushAttestation(ctx, pinned, subject, &Attestation{
		Envelope:      envelope,
		PredicateType: predicateType,
		Certificate:   s.certificatePEM,
		Chain:         s.chainPEM,
		Timestamp:     timestamp,
	})
	if err != nil {
		return nil, err
	}
	return &SignResult{Digest: subject.Digest, Envelope: envelope, Timestamp: timestamp, Push: push}, nil
}

// predicate returns the statement's predicate type and predicate.
func (o *SignOptions) predicate(now time.Time) (string, json.RawMessage, error) {
	if o == nil {
		o = &SignOptions{}
	}
	predicateType := valueOr(o.PredicateType, PredicateTypeCosign)
	if len(o.Predicate) > 0 {
		return predicateType, o.Predicate, nil
	}
	if predicateType != PredicateTypeCosign {
		return "", nil, &errs.Detail{Err: ErrInvalidStatement, Detail: "no predicate for type " + predicateType}
	}
	predicate, err := json.Marshal(cosignPredicate{Timestamp: now.UTC().Format(time.RFC3339)})
	if err != nil {
		return "", nil, &errs.Joined{Lead: ErrEncodingFailed, Detail: "predicate", Cause: err}
	}
	return predicateType, predicate, nil
}

// RequestCodeSigningCertificate has issuer certify signer's key under
// TrustedCA's code-signing profile for commonName, in tenant tenantID, which
// the CA stamps as the certificate's first organizational unit. The key
// stays in its KMS: only the CSR it signs leaves it.
func RequestCodeSigningCertificate(ctx context.Context, issuer CertificateIssuer, signer crypto.Signer, tenantID, commonName string) (*x509.Certificate, error) {
	if issuer == nil {
		return nil, ErrIssuerRequired
	}
	if signer == nil {
		return nil, ErrSignerRequired
	}
	if strings.TrimSpace(tenantID) == "" {
		return nil, ErrTenantRequired
	}
	if strings.TrimSpace(commonName) == "" {
		return nil, ErrCommonNameRequired
	}

	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: commonName},
	}, signer)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrCSRFailed, Cause: err}
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: encoding.PEMTypeCertificateRequest, Bytes: der})

	certificate, err := issuer.SignCSRUnstored(ctx, csrPEM, ProfileCodeSigning, 0, tenantID)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrCertificateRequestFailed, Cause: err}
	}
	if err := checkCodeSigning(certificate, signer.Public(), time.Now()); err != nil {
		return nil, err
	}
	return certificate, nil
}

// checkCodeSigning returns nil when certificate certifies publicKey, a
// supported key, for code signing and is valid at now.
func checkCodeSigning(certificate *x509.Certificate, publicKey crypto.PublicKey, now time.Time) error {
	if _, _, err := signatureInput(publicKey, nil); err != nil {
		return err
	}
	key, ok := publicKey.(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !key.Equal(certificate.PublicKey) {
		return ErrKeyMismatch
	}
	if err := checkCodeSigningUsage(certificate); err != nil {
		return err
	}
	return checkValidity(certificate, now)
}

// checkCodeSigningUsage returns nil when certificate carries the codeSigning
// extended key usage and the digitalSignature key usage. The signer checks
// it before signing and the verifier before trusting a signature.
func checkCodeSigningUsage(certificate *x509.Certificate) error {
	if !slices.Contains(certificate.ExtKeyUsage, x509.ExtKeyUsageCodeSigning) {
		return &errs.Detail{Err: ErrNotCodeSigning, Detail: "no codeSigning extended key usage"}
	}
	if certificate.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return &errs.Detail{Err: ErrNotCodeSigning, Detail: "no digitalSignature key usage"}
	}
	return nil
}

// checkValidity returns nil when now is within certificate's validity.
func checkValidity(certificate *x509.Certificate, now time.Time) error {
	if now.Before(certificate.NotBefore) || now.After(certificate.NotAfter) {
		return &errs.Detail{
			Err:    ErrCertificateNotValid,
			Detail: "valid " + certificate.NotBefore.UTC().Format(time.RFC3339) + " to " + certificate.NotAfter.UTC().Format(time.RFC3339),
		}
	}
	return nil
}
