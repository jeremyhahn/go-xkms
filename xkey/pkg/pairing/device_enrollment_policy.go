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

package pairing

import (
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// Enrollment policy failures. Each names a distinct reason so an operator can
// tell a device that is merely unenrolled from one that was actively refused,
// and so refusals can be filtered without parsing prose.
var (
	// ErrEnrollmentNoEvidence means the phone sent no attestation chain.
	ErrEnrollmentNoEvidence = errors.New("enrollment: no attestation evidence")

	// ErrEnrollmentUnknownFormat means the evidence is in a format this CA
	// does not verify. Refusing beats guessing at the bytes.
	ErrEnrollmentUnknownFormat = errors.New("enrollment: unrecognised attestation format")

	// ErrEnrollmentChainUntrusted means the chain does not reach a trusted
	// hardware root, so nothing about it is hardware-backed.
	ErrEnrollmentChainUntrusted = errors.New("enrollment: attestation chain is not trusted")

	// ErrEnrollmentStaleChallenge means the attested challenge is not the one
	// this CA issued, so the evidence could be a replay.
	ErrEnrollmentStaleChallenge = errors.New("enrollment: attestation challenge does not match")

	// ErrEnrollmentKeyMismatch means the CSR asks the CA to certify a key the
	// attestation does not cover.
	ErrEnrollmentKeyMismatch = errors.New("enrollment: CSR key is not the attested key")

	// ErrEnrollmentBootState means verified boot or the bootloader lock is not
	// in the state policy requires.
	ErrEnrollmentBootState = errors.New("enrollment: device boot state is not acceptable")

	// ErrEnrollmentSecurityLevel means the key is not held at the required
	// level -- software where TEE or StrongBox was demanded.
	ErrEnrollmentSecurityLevel = errors.New("enrollment: key security level is below policy")
)

// EnrollmentPolicy is what an enterprise CA enforces before it will certify a
// phone, and how long that certificate stands.
//
// # Re-attestation cadence
//
// There is deliberately no "re-attest every N days" setting. The cadence is
// Validity: the credential expires, and to obtain another the device must
// present fresh attestation. Expressed that way it is enforceable by any RFC
// 5280 verifier with no bespoke logic, and it sits with the relying party
// rather than with the device being judged -- a device should not get to
// nominate how often it is audited.
//
// This follows IEEE 802.1AR, where an IDevID is the long-lived birth identity
// and an LDevID is the locally significant credential that is re-issued. What
// this CA hands out is an LDevID.
type EnrollmentPolicy struct {
	// Validity is how long an issued credential stands, and therefore how
	// often the device must re-attest. Zero means DefaultEnrollmentValidity.
	Validity time.Duration `json:"validity" yaml:"validity"`

	// ApplicationPolicy lists the application builds this CA will enroll.
	// Empty denies every enrollment: a CA that certifies any application that
	// asks is not an enterprise CA. It is the same allow-list, matched by the
	// same code, that pairing and re-attestation apply.
	ApplicationPolicy `yaml:",inline"`

	// MinSecurityLevel is the weakest key protection accepted. Empty means
	// SecurityLevelTEE -- software-held keys are refused, because a software
	// key is exactly what an attacker who owns the OS can produce.
	MinSecurityLevel string `json:"min_security_level" yaml:"min_security_level"`

	// RequireVerifiedBoot demands verified boot and a locked bootloader.
	// Defaults on via NewEnrollmentPolicy; an unlocked device can run modified
	// system code, and the whole chain of reasoning depends on it not doing so.
	RequireVerifiedBoot bool `json:"require_verified_boot" yaml:"require_verified_boot"`

	// TrustedRoots verifies the attestation chain. Nil denies every
	// enrollment: without roots the chain proves nothing.
	TrustedRoots *x509.CertPool `json:"-" yaml:"-"`
}

// DefaultEnrollmentValidity is the default LDevID lifetime, and so the default
// re-attestation cadence.
//
// Ninety days is short enough that a device which has since been unlocked,
// rooted or rolled back to a vulnerable patch level loses its standing within a
// quarter, and long enough not to demand user presence weekly.
const DefaultEnrollmentValidity = 90 * 24 * time.Hour

// NewEnrollmentPolicy returns a policy that fails closed: no application is
// allowed, no root is trusted, keys must be hardware-held and boot must be
// verified. A caller opts into each relaxation deliberately.
func NewEnrollmentPolicy() *EnrollmentPolicy {
	return &EnrollmentPolicy{
		Validity:            DefaultEnrollmentValidity,
		MinSecurityLevel:    SecurityLevelTEE,
		RequireVerifiedBoot: true,
	}
}

// EnrollmentDecision is what the policy concluded about one request.
type EnrollmentDecision struct {
	// PackageName is the application the evidence names.
	PackageName string

	// SigningDigest is that application's signing certificate digest, hex.
	SigningDigest string

	// SecurityLevel is where the attested key is held.
	SecurityLevel string

	// DeviceLocked reports the bootloader lock state.
	DeviceLocked bool

	// NotAfter is when the credential should expire, and so when the device
	// must attest again.
	NotAfter time.Time
}

// effectiveValidity resolves the configured validity, falling back to the
// default rather than issuing a certificate that has already expired.
func (p *EnrollmentPolicy) effectiveValidity() time.Duration {
	if p.Validity <= 0 {
		return DefaultEnrollmentValidity
	}
	return p.Validity
}

// minSecurityRank maps the configured minimum to a comparable rank.
func (p *EnrollmentPolicy) minSecurityRank() int {
	level := p.MinSecurityLevel
	if level == "" {
		level = SecurityLevelTEE
	}
	return securityRank(level)
}

// securityRank orders the key protection levels. An unrecognised name ranks
// with software, so a typo in configuration cannot silently weaken the policy.
func securityRank(level string) int {
	switch level {
	case SecurityLevelStrongBox:
		return 2
	case SecurityLevelTEE:
		return 1
	default:
		return 0
	}
}

// securityLevelName renders a parsed attestation level as its wire name.
func securityLevelName(level xkms.AndroidSecurityLevel) string {
	switch level {
	case xkms.AndroidSecurityLevelStrongBox:
		return SecurityLevelStrongBox
	case xkms.AndroidSecurityLevelTrustedEnvironment:
		return SecurityLevelTEE
	default:
		return SecurityLevelSoftware
	}
}

// Evaluate decides whether to enroll the device that produced result, given the
// nonce this CA issued and the moment to date the credential from.
//
// The order is deliberate: cheap structural checks first, then the chain, then
// the claims inside it. Nothing in the evidence is believed until the chain has
// been verified, because until then it is only bytes the phone sent.
func (p *EnrollmentPolicy) Evaluate(
	result *LocalGetDeviceEnrollmentRequestResult,
	expectedNonce []byte,
	now time.Time,
) (*EnrollmentDecision, error) {
	if result == nil || len(result.AttestationChain) == 0 {
		return nil, ErrEnrollmentNoEvidence
	}
	if result.Format != "" && result.Format != AttestationFormatAndroidKey {
		return nil, fmt.Errorf("%w: %q", ErrEnrollmentUnknownFormat, result.Format)
	}
	if p.TrustedRoots == nil {
		return nil, fmt.Errorf("%w: no trusted attestation roots configured",
			ErrEnrollmentChainUntrusted)
	}
	if !p.Configured() {
		return nil, ErrApplicationPolicyUnconfigured
	}

	chain, err := decodeAttestationChain(result.AttestationChain)
	if err != nil {
		return nil, err
	}

	desc, err := xkms.VerifyAndroidKeyAttestation(chain, &xkms.AndroidVerifyOptions{
		TrustedRoots:  p.TrustedRoots,
		ExpectedNonce: expectedNonce,
		// The security level and boot state are judged below so each refusal
		// carries its own sentinel; the verifier collapses them into one error.
		MinSecurityLevel: xkms.AndroidSecurityLevelSoftware,
		VerifyBootState:  false,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEnrollmentChainUntrusted, err)
	}

	// Re-check the challenge rather than trusting the verifier to have done it:
	// ExpectedNonce is optional in VerifyOptions, and an empty one there means
	// "do not check". A replayed attestation is the whole risk this closes.
	if len(expectedNonce) == 0 {
		return nil, fmt.Errorf("%w: no challenge was issued", ErrEnrollmentStaleChallenge)
	}
	if !bytesEqual(desc.AttestationChallenge, expectedNonce) {
		return nil, ErrEnrollmentStaleChallenge
	}

	// The check that is easy to omit and fatal to skip: the CSR must ask for
	// the key the attestation covers. Otherwise a caller pairs somebody else's
	// genuine evidence with a CSR for a key it holds privately.
	if err := csrMatchesAttestedKey(result.CSR, chain[0]); err != nil {
		return nil, err
	}

	level := securityLevelName(desc.AttestationSecurityLevel)
	if securityRank(level) < p.minSecurityRank() {
		return nil, fmt.Errorf("%w: key is %s, policy requires at least %s",
			ErrEnrollmentSecurityLevel, level, p.MinSecurityLevel)
	}

	rot := desc.TeeEnforced.RootOfTrust
	if rot == nil {
		rot = desc.SoftwareEnforced.RootOfTrust
	}
	if p.RequireVerifiedBoot {
		if rot == nil {
			return nil, fmt.Errorf("%w: no root of trust was attested", ErrEnrollmentBootState)
		}
		if !rot.DeviceLocked {
			return nil, fmt.Errorf("%w: the bootloader is unlocked", ErrEnrollmentBootState)
		}
		if rot.VerifiedBootState != xkms.AndroidVerifiedBootVerified {
			return nil, fmt.Errorf("%w: verified boot is %s",
				ErrEnrollmentBootState, rot.VerifiedBootState)
		}
	}

	pkg, digest, err := p.Match(AttestedApplication(desc))
	if err != nil {
		return nil, err
	}

	decision := &EnrollmentDecision{
		PackageName:   pkg,
		SigningDigest: digest,
		SecurityLevel: level,
		NotAfter:      now.Add(p.effectiveValidity()),
	}
	if rot != nil {
		decision.DeviceLocked = rot.DeviceLocked
	}
	return decision, nil
}
