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
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/attestation"
	android "github.com/jeremyhahn/go-xkms/pkg/attestation/android"
)

// AttestationFormatAndroidKey is the wire tag for Android key attestation
// evidence presented with a CSR.
//
// It aliases the canonical constant in pkg/attestation so this repo carries
// exactly one literal for the tag: the phone, xkey and xkms must all agree on
// it, and a second copy here is a place they could silently diverge.
const AttestationFormatAndroidKey = attestation.FormatAndroidKey

// Android enrollment refusals.
var (
	// ErrAndroidAttestationStale means the challenge in the attestation is not
	// the one this server issued, so the evidence may be a recording.
	ErrAndroidAttestationStale = errors.New("ca: android attestation challenge does not match")

	// ErrAndroidAttestationKeyMismatch means the CSR asks the CA to certify a
	// key the attestation does not cover.
	ErrAndroidAttestationKeyMismatch = errors.New("ca: CSR key is not the attested key")

	// ErrAndroidAttestationBootState means verified boot or the bootloader
	// lock is not in the state policy requires.
	ErrAndroidAttestationBootState = errors.New("ca: android device boot state is not acceptable")

	// ErrAndroidAttestationAppDenied means the requesting application is not
	// on the allow-list, by package name or signing certificate digest.
	ErrAndroidAttestationAppDenied = errors.New("ca: android application is not allowed")

	// ErrAndroidPolicyNotConfigured means an Android attestation arrived but
	// no enrollment policy was set, so the server has no allow-list to judge
	// it against and refuses rather than signing on chain provenance alone.
	ErrAndroidPolicyNotConfigured = errors.New("ca: no android enrollment policy configured")
)

// AndroidEnrollmentPolicy is what this CA demands of an Android device before
// it will certify one, beyond the chain reaching a Google hardware root.
//
// Chain provenance alone is not enough, and that is the point of this type.
// A verified chain says "some key in some Google-rooted keystore" -- it does
// not say the evidence is fresh, that it covers the key being certified, that
// the bootloader is locked, or which application is asking. Each of those is
// checked here.
type AndroidEnrollmentPolicy struct {
	// AllowedPackages maps an Android package name to the hex SHA-256 digests
	// of signing certificates accepted for it. Empty denies everything: a CA
	// that certifies any application that asks is not an enterprise CA.
	//
	// The package name alone is not an identity -- anybody can build an APK
	// claiming any package name. The signing digest is what pins the build.
	AllowedPackages map[string][]string

	// AllowUnpinnedSignatures honours an entry with no digests. Useful against
	// a debug build; in production it means any APK claiming the package name
	// enrolls.
	AllowUnpinnedSignatures bool

	// RequireVerifiedBoot demands verified boot and a locked bootloader.
	RequireVerifiedBoot bool

	// MinSecurityLevel is the weakest key protection accepted: "software",
	// "trusted_environment" or "strongbox". Empty means trusted_environment.
	MinSecurityLevel string
}

// NewAndroidEnrollmentPolicy returns a policy that fails closed.
func NewAndroidEnrollmentPolicy() *AndroidEnrollmentPolicy {
	return &AndroidEnrollmentPolicy{
		AllowedPackages:     map[string][]string{},
		RequireVerifiedBoot: true,
		MinSecurityLevel:    "trusted_environment",
	}
}

// SetAndroidEnrollmentPolicy installs the policy applied to CSRs presenting
// Android key attestation. Passing nil clears it, which makes every such CSR
// fail closed.
func (s *XKMSService) SetAndroidEnrollmentPolicy(policy *AndroidEnrollmentPolicy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.androidEnrollmentPolicy = policy
}

// androidEnrollmentPolicySnapshot reads the policy under the lock.
func (s *XKMSService) androidEnrollmentPolicySnapshot() *AndroidEnrollmentPolicy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.androidEnrollmentPolicy
}

// androidSecurityRank orders key protection levels. An unrecognised name ranks
// with software, so a typo in configuration cannot silently weaken the policy.
func androidSecurityRank(level string) int {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "strongbox":
		return 2
	case "trusted_environment":
		return 1
	default:
		return 0
	}
}

// verifyAndroidCSRAttestation applies the Android-specific checks that generic
// chain anchoring cannot express.
//
// It runs *after* the chain has been anchored, so everything read out of the
// attestation extension here has already been shown to come from a certificate
// a Google root signed.
func (s *XKMSService) verifyAndroidCSRAttestation(req *transport.SignCSRRequest) error {
	policy := s.androidEnrollmentPolicySnapshot()
	if policy == nil {
		slog.Warn("android CSR refused: no enrollment policy configured")
		return ErrAndroidPolicyNotConfigured
	}
	if len(policy.AllowedPackages) == 0 {
		slog.Warn("android CSR refused: the application allow-list is empty")
		return fmt.Errorf("%w: the allow-list is empty", ErrAndroidAttestationAppDenied)
	}

	leaf, err := x509.ParseCertificate(req.AttestationChain[0])
	if err != nil {
		return fmt.Errorf("%w: attestation leaf does not parse: %v",
			ErrAttestationVerificationFailed, err)
	}

	desc, err := android.ParseKeyAttestation(leaf)
	if err != nil {
		return fmt.Errorf("%w: attestation extension does not parse: %v",
			ErrAttestationVerificationFailed, err)
	}

	// Freshness and key binding are invariants enforced for every format by
	// enforceAttestationInvariants before this runs, so they are not repeated
	// here. What follows is the part that is specific to Android.

	rot := desc.TeeEnforced.RootOfTrust
	if rot == nil {
		rot = desc.SoftwareEnforced.RootOfTrust
	}
	if policy.RequireVerifiedBoot {
		if rot == nil {
			return fmt.Errorf("%w: no root of trust was attested",
				ErrAndroidAttestationBootState)
		}
		if !rot.DeviceLocked {
			return fmt.Errorf("%w: the bootloader is unlocked",
				ErrAndroidAttestationBootState)
		}
		if rot.VerifiedBootState != android.VerifiedBootVerified {
			return fmt.Errorf("%w: verified boot is %s",
				ErrAndroidAttestationBootState, rot.VerifiedBootState)
		}
	}

	level := "software"
	switch desc.AttestationSecurityLevel {
	case android.SecurityLevelStrongBox:
		level = "strongbox"
	case android.SecurityLevelTrustedEnvironment:
		level = "trusted_environment"
	}
	minLevel := policy.MinSecurityLevel
	if minLevel == "" {
		minLevel = "trusted_environment"
	}
	if androidSecurityRank(level) < androidSecurityRank(minLevel) {
		return fmt.Errorf("%w: key is %s, policy requires at least %s",
			ErrAttestationVerificationFailed, level, minLevel)
	}

	appID := desc.SoftwareEnforced.AttestationApplicationID
	if appID == nil {
		appID = desc.TeeEnforced.AttestationApplicationID
	}
	pkg, digest, err := policy.matchApplication(appID)
	if err != nil {
		return err
	}

	slog.Info("android attestation accepted",
		"package", pkg,
		"signing_digest", digest,
		"security_level", level,
		"device_locked", rot != nil && rot.DeviceLocked)
	return nil
}

// matchApplication checks the attested application against the allow-list.
func (p *AndroidEnrollmentPolicy) matchApplication(
	appID *android.AttestationApplicationID,
) (string, string, error) {
	if appID == nil || len(appID.Packages) == 0 {
		return "", "", fmt.Errorf("%w: the attestation names no application",
			ErrAndroidAttestationAppDenied)
	}

	digests := make([]string, 0, len(appID.SignatureDigests))
	for _, d := range appID.SignatureDigests {
		digests = append(digests, hex.EncodeToString(d))
	}

	for _, pkg := range appID.Packages {
		allowed, ok := p.lookup(pkg.Name)
		if !ok {
			continue
		}

		if len(allowed) == 0 {
			if !p.AllowUnpinnedSignatures {
				return "", "", fmt.Errorf(
					"%w: %s is listed without a signing digest and unpinned "+
						"signatures are disabled", ErrAndroidAttestationAppDenied, pkg.Name)
			}
			if len(digests) == 0 {
				return pkg.Name, "", nil
			}
			return pkg.Name, digests[0], nil
		}

		for _, want := range allowed {
			for _, got := range digests {
				if strings.EqualFold(strings.TrimSpace(want), got) {
					return pkg.Name, got, nil
				}
			}
		}

		return "", "", fmt.Errorf("%w: %s is listed but its signing digest %v is not",
			ErrAndroidAttestationAppDenied, pkg.Name, digests)
	}

	names := make([]string, 0, len(appID.Packages))
	for _, pkg := range appID.Packages {
		names = append(names, pkg.Name)
	}
	return "", "", fmt.Errorf("%w: %v", ErrAndroidAttestationAppDenied, names)
}

// lookup resolves a package name case-insensitively.
func (p *AndroidEnrollmentPolicy) lookup(name string) ([]string, bool) {
	if digests, ok := p.AllowedPackages[name]; ok {
		return digests, true
	}
	for pkg, digests := range p.AllowedPackages {
		if strings.EqualFold(pkg, name) {
			return digests, true
		}
	}
	return nil, false
}

// parseCSRAny accepts a CSR as PEM or bare DER.
//
// SignCSRRequest names the field CSRPEM, but the Android path carries DER: the
// phone builds a PKCS#10 and there is no reason to armour it just to strip the
// armour again. Accepting both means the caller need not care.
func parseCSRAny(csrBytes []byte) (*x509.CertificateRequest, error) {
	if block, _ := pem.Decode(csrBytes); block != nil {
		return x509.ParseCertificateRequest(block.Bytes)
	}
	return x509.ParseCertificateRequest(csrBytes)
}
