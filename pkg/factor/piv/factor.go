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

// Package piv exposes an qrdbsdk.AuthFactorPlugin adapter for NIST SP 800-73-4
// PIV smart cards backed by go-xkms's canonical PIV stack. It implements
// qrdb's qrdbsdk.AuthFactorPlugin interface by delegating Enroll, Challenge, and
// Verify to xkms primitives (xkms.PIVKeyGenerator, pivcert.PIVSlot) so the
// hardware-coupled logic lives in exactly one place.
//
// Usage:
//
//	gen := xkms.NewSoftwarePIVKeyGenerator()
//	f := piv.New(piv.Config{Generator: gen})
//	registry.Register(f)
//
// For hardware-backed deployments (PKCS#11 / TPM2), construct a
// PIVKeyGenerator that talks to the hardware backend and inject it via
// piv.Config.Generator. The Factor itself is hardware-agnostic.
//
// A deployment that asked for hardware by name should also set
// piv.Config.RequireGenerator, which turns a missing generator into a refusal
// at preflight rather than a silently software-backed credential.
package piv

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"strconv"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	xkms "github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// FactorName is the canonical Factor.Name() return value for PIV.
const FactorName = "piv"

const (
	defaultChallengeTTLSeconds = 5 * 60
	defaultAlgorithm           = "ecdsap256"
	defaultValidityDays        = 365 * 10
	nonceLength                = 32
)

// Config configures a PIV Factor. The zero value is valid: a software-only
// key generator is used by default with slot 9a and ecdsap256.
type Config struct {
	// Generator produces crypto.Signers for PIV slots. When nil, a
	// software-only generator (xkms.NewSoftwarePIVKeyGenerator) is used
	// unless RequireGenerator is set.
	Generator xkms.PIVKeyGenerator

	// RequireGenerator suppresses the software substitution above. With no
	// Generator attached the Factor then reports itself unavailable at
	// preflight and refuses to enroll, instead of quietly producing a
	// software credential that is recorded and used exactly like a hardware
	// one.
	//
	// Set it wherever the deployment asked for a smartcard by name — the
	// administrator-enrollment path does, from
	// AdminEnrollmentConfig.AllowSoftwarePIV. Leave it clear for tests and
	// software-only deployments, which legitimately want the substitution.
	RequireGenerator bool

	// DefaultSlot is the PIV slot used when params.MethodParams["slot"] is
	// not supplied. Defaults to pivcert.PIVSlotAuthentication ("9a").
	DefaultSlot pivcert.PIVSlot

	// DefaultAlgorithm is the key algorithm used when
	// params.MethodParams["algorithm"] is not supplied. Defaults to
	// "ecdsap256".
	DefaultAlgorithm string

	// ChallengeTTLSeconds controls how long issued challenges remain valid.
	// Zero defaults to 300 (five minutes).
	ChallengeTTLSeconds int
}

// Factor implements qrdbsdk.AuthFactorPlugin for PIV. It is cross-vendor: any
// PIVKeyGenerator that satisfies the xkms interface (software, PKCS#11,
// TPM2-backed, etc.) can be injected.
type Factor struct {
	cfg Config
}

// New constructs a PIV Factor. The cfg.Generator is the only injection
// point; everything else is optional and falls back to canonical defaults.
func New(cfg Config) *Factor {
	if cfg.Generator == nil && !cfg.RequireGenerator {
		cfg.Generator = xkms.NewSoftwarePIVKeyGenerator()
	}
	if cfg.DefaultSlot == "" {
		cfg.DefaultSlot = pivcert.PIVSlotAuthentication
	}
	if cfg.DefaultAlgorithm == "" {
		cfg.DefaultAlgorithm = defaultAlgorithm
	}
	if cfg.ChallengeTTLSeconds <= 0 {
		cfg.ChallengeTTLSeconds = defaultChallengeTTLSeconds
	}
	return &Factor{cfg: cfg}
}

// Name returns the canonical PIV factor identifier "piv".
func (f *Factor) Name() string { return FactorName }

// Enroll generates a PIV key in the requested slot (default 9a) and
// returns an Enrollment containing a self-signed certificate in PEM form.
// MethodParams accepts:
//
//	"slot"      string  PIV slot identifier (e.g., "9a", "9c"); defaults to 9a
//	"algorithm" string  Key algorithm: rsa2048|rsa4096|ecdsap256|ecdsap384|ed25519
func (f *Factor) Enroll(_ context.Context, params *qrdbsdk.AuthFactorEnrollParams) (*qrdbsdk.AuthFactorEnrollment, error) {
	if params == nil {
		return nil, &qrdbsdk.AuthFactorEnrollmentInvalidError{Reason: "params must not be nil"}
	}
	// Preflight is optional in the ceremony contract, so the refusal is
	// repeated here rather than trusted to Available alone.
	if f.cfg.Generator == nil {
		return nil, &GeneratorUnattachedError{}
	}

	slot := f.cfg.DefaultSlot
	if s, ok := params.MethodParams["slot"].(string); ok && s != "" {
		slot = pivcert.PIVSlot(s)
	}

	algorithm := f.cfg.DefaultAlgorithm
	if a, ok := params.MethodParams["algorithm"].(string); ok && a != "" {
		algorithm = a
	}

	cn := "PIV " + string(slot)
	signer, err := f.cfg.Generator.GeneratePIVKey(slot, algorithm, cn)
	if err != nil {
		return nil, &qrdbsdk.AuthFactorEnrollmentInvalidError{Reason: "piv: generate key: " + err.Error()}
	}

	certPEM, err := buildSelfSignedCert(signer, pkix.Name{CommonName: cn}, defaultValidityDays)
	if err != nil {
		return nil, &qrdbsdk.AuthFactorEnrollmentInvalidError{Reason: "piv: build certificate: " + err.Error()}
	}

	return &qrdbsdk.AuthFactorEnrollment{
		EnrollmentID: qrdbsdk.NewAuthFactorEnrollmentID(),
		UserID:       params.UserID,
		FactorName:   FactorName,
		TenantID:     params.TenantID,
		PublicKey:    certPEM,
		Metadata: map[string]string{
			"slot":      string(slot),
			"algorithm": algorithm,
			"cn":        cn,
			"ttl":       strconv.Itoa(f.cfg.ChallengeTTLSeconds),
		},
		EnrolledAt: time.Now().UTC(),
	}, nil
}

// Challenge produces a 32-byte random nonce the custodian must sign with
// the private key in their PIV slot.
func (f *Factor) Challenge(_ context.Context, enrollment *qrdbsdk.AuthFactorEnrollment) (*qrdbsdk.AuthFactorChallenge, error) {
	if enrollment == nil {
		return nil, &qrdbsdk.AuthFactorEnrollmentInvalidError{Reason: "enrollment must not be nil"}
	}
	nonce := make([]byte, nonceLength)
	if _, err := rand.Read(nonce); err != nil {
		return nil, &qrdbsdk.AuthFactorEnrollmentInvalidError{
			EnrollmentID: enrollment.EnrollmentID,
			Reason:       "piv: nonce rand.Read: " + err.Error(),
		}
	}
	ttl := f.cfg.ChallengeTTLSeconds
	if t, ok := enrollment.Metadata["ttl"]; ok {
		if v, err := strconv.Atoi(t); err == nil && v > 0 {
			ttl = v
		}
	}
	return &qrdbsdk.AuthFactorChallenge{
		ChallengeID:  qrdbsdk.NewAuthFactorChallengeID(),
		EnrollmentID: enrollment.EnrollmentID,
		Nonce:        nonce,
		ExpiresAt:    time.Now().UTC().Add(time.Duration(ttl) * time.Second),
		MethodData: map[string]any{
			"slot":      enrollment.Metadata["slot"],
			"algorithm": enrollment.Metadata["algorithm"],
		},
	}, nil
}

// Verify parses the PEM certificate from response.Metadata["public_key_pem"]
// and verifies the DER-encoded ECDSA signature in response.Value against
// the challenge nonce.
func (f *Factor) Verify(_ context.Context, challenge *qrdbsdk.AuthFactorChallenge, response *qrdbsdk.AuthFactorResponse) error {
	if challenge == nil {
		return &qrdbsdk.AuthFactorEnrollmentInvalidError{Reason: "challenge must not be nil"}
	}
	if response == nil {
		return &qrdbsdk.AuthFactorEnrollmentInvalidError{Reason: "response must not be nil"}
	}
	if challenge.Expired() {
		return &qrdbsdk.AuthFactorChallengeExpiredError{ChallengeID: challenge.ChallengeID}
	}
	pubPEM, ok := response.Metadata["public_key_pem"]
	if !ok {
		return &qrdbsdk.AuthFactorVerificationFailedError{
			FactorName: FactorName,
			Reason:     "public_key_pem missing from response metadata",
		}
	}
	pub, err := parsePublicKeyFromPEM([]byte(pubPEM))
	if err != nil {
		return &qrdbsdk.AuthFactorVerificationFailedError{FactorName: FactorName, Reason: "parse public key: " + err.Error()}
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return &qrdbsdk.AuthFactorVerificationFailedError{FactorName: FactorName, Reason: "public key is not ECDSA"}
	}
	return verifyECDSA(ecPub, challenge.Nonce, response.Value)
}

// SignNonce signs a nonce using a fresh signer obtained from the configured
// PIVKeyGenerator. Exposed so test/custodian-side code can produce a
// signature without re-implementing the signer lookup.
func (f *Factor) SignNonce(_ context.Context, slot pivcert.PIVSlot, nonce []byte) ([]byte, error) {
	if f.cfg.Generator == nil {
		return nil, &GeneratorUnattachedError{}
	}
	cn := "PIV " + string(slot)
	signer, err := f.cfg.Generator.GetPIVSigner(slot, cn)
	if err != nil {
		return nil, err
	}
	// Hash externally: hardware backends (TPM2/PKCS#11) often require the
	// pre-hashed digest. SHA-256 matches ecdsap256 and is the conventional
	// default for the software/PIV path.
	digest := sha256.Sum256(nonce)
	return signer.Sign(rand.Reader, digest[:], crypto.SHA256)
}

// selfSignedProfile is the certificate profile for a PIV factor's enrollment
// certificate: a digital-signature-only end-entity certificate proving
// possession of the enrolled slot's key. It carries no extended key usage —
// this certificate exists to be re-presented as a challenge-response public
// key during Verify, not to authenticate a TLS session.
func selfSignedProfile() ca.ProfileProvider {
	return ca.NewProfileBuilder("piv-factor-self-signed").
		WithKeyUsage(x509.KeyUsageDigitalSignature).
		Build()
}

// buildSelfSignedCert produces a PEM-encoded self-signed certificate for the
// supplied signer.
//
// Issuance is delegated to ca.Issuer (pkg/ca), the single implementer of
// certificate template construction and x509.CreateCertificate calls in
// go-xkms, rather than building the template and calling
// x509.CreateCertificate directly.
func buildSelfSignedCert(signer crypto.Signer, subject pkix.Name, validityDays int) ([]byte, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	cert, err := (&ca.Issuer{Signer: signer}).Issue(rand.Reader, &ca.CertificateSpec{
		Serial:    serial,
		Subject:   subject,
		NotBefore: time.Now().UTC(),
		NotAfter:  time.Now().UTC().AddDate(0, 0, validityDays),
		Profile:   selfSignedProfile(),
	})
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), nil
}

// parsePublicKeyFromPEM accepts either a CERTIFICATE PEM block (extracts
// the public key) or a PUBLIC KEY PEM block.
func parsePublicKeyFromPEM(data []byte) (any, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, &qrdbsdk.AuthFactorEnrollmentInvalidError{Reason: "piv: no PEM block found"}
	}
	switch block.Type {
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		return cert.PublicKey, nil
	case "PUBLIC KEY":
		return x509.ParsePKIXPublicKey(block.Bytes)
	default:
		return nil, &qrdbsdk.AuthFactorEnrollmentInvalidError{Reason: "piv: unexpected PEM block type " + block.Type}
	}
}

// verifyECDSA verifies a DER-encoded ECDSA signature over the SHA-256 of
// the nonce. The signer is expected to have hashed the nonce with SHA-256
// (see SignNonce). Curve must be supplied by the public key.
func verifyECDSA(pub *ecdsa.PublicKey, nonce, sig []byte) error {
	var dsaSig struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(sig, &dsaSig); err != nil {
		return &qrdbsdk.AuthFactorVerificationFailedError{FactorName: FactorName, Reason: "unmarshal signature: " + err.Error()}
	}
	digest := sha256.Sum256(nonce)
	if !ecdsa.Verify(pub, digest[:], dsaSig.R, dsaSig.S) {
		return &qrdbsdk.AuthFactorVerificationFailedError{FactorName: FactorName, Reason: "signature invalid"}
	}
	return nil
}

// Compile-time interface assertion.
var _ qrdbsdk.AuthFactorPlugin = (*Factor)(nil)
