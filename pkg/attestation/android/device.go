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

package android

import (
	"crypto/x509"
	"errors"
	"fmt"
	"slices"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// Device-key policy errors. Each names the one claim a hardware-held
// device key failed to make.
var (
	// ErrNilKeyDescription is returned when a policy check is given no
	// key description to inspect.
	ErrNilKeyDescription = errors.New("android: nil key description")

	// ErrNoRootOfTrust is returned when the hardware-enforced list carries
	// no RootOfTrust, so the attestation makes no claim about the boot chain.
	ErrNoRootOfTrust = errors.New("android: attestation carries no root of trust")

	// ErrBootloaderUnlocked is returned when the RootOfTrust reports an
	// unlocked bootloader, so the boot chain can be replaced at will.
	ErrBootloaderUnlocked = errors.New("android: device bootloader is unlocked")

	// ErrKeyOriginNotGenerated is returned when the hardware-enforced
	// Origin (tag 702) is not GENERATED: the key was imported, derived, or
	// the hardware made no origin claim at all (go-xkms#132).
	ErrKeyOriginNotGenerated = errors.New("android: key was not generated in secure hardware")

	// ErrKeyPurposeNotSign is returned when the hardware-enforced Purpose
	// (tag 1) does not include SIGN (go-xkms#132).
	ErrKeyPurposeNotSign = errors.New("android: key purpose does not include sign")

	// ErrNilApplicationMatcher is returned when RequireAttestedApplication
	// is given no application policy to match against.
	ErrNilApplicationMatcher = errors.New("android: nil application matcher")

	// ErrApplicationRefused is returned when the attesting application does
	// not satisfy the caller's application policy. The policy's own error is
	// joined to it, so errors.Is matches either.
	ErrApplicationRefused = errors.New("android: attesting application refused")

	// ErrKeyNoAuthRequired is returned when either authorization list
	// carries noAuthRequired (tag 503): the key signs without any user
	// authentication.
	ErrKeyNoAuthRequired = errors.New("android: key may be used without user authentication")

	// ErrKeyUserAuthTypeNotUserVerification is returned when the
	// hardware-enforced userAuthType (tag 504) names no user-verification
	// method: absent, or a value with any bit beyond the device credential
	// and the biometric.
	ErrKeyUserAuthTypeNotUserVerification = errors.New("android: key user authentication is not biometric or device credential")

	// ErrKeyAuthTimeout is returned when the hardware-enforced list carries
	// authTimeout (tag 505): one authentication unlocks the key for a
	// period, so a signature does not prove the user was verified for it.
	ErrKeyAuthTimeout = errors.New("android: key does not require authentication on every use")

	// ErrKeyAllowWhileOnBody is returned when the hardware-enforced list
	// carries allowWhileOnBody (tag 506): the key stays unlocked while the
	// device is worn.
	ErrKeyAllowWhileOnBody = errors.New("android: key stays usable while the device is on body")
)

// ApplicationMatcher decides whether an attested application is allowed.
// Match returns the matched package name and signing digest, or an error
// saying why the application is refused.
type ApplicationMatcher interface {
	Match(appID *AttestationApplicationID) (pkg string, digest string, err error)
}

// DeviceVerifyOptions returns the verification bar for a hardware-held
// device key: the chain must anchor in roots, the key must live in at
// least a TEE, and an explicitly unverified boot state is refused.
//
// ExpectedNonce is deliberately unset (go-xkms#129). Android fixes the
// attestation challenge when the key is generated, so a persistent device
// key carries its genesis challenge for life and could never match a live
// nonce. Freshness is proven instead by the key signing the live nonce,
// which shows the key's holder is present now rather than that a
// certificate was once minted for the nonce. The caller checks that
// signature and, separately, what the genesis challenge can still say.
//
// VerifyBootState only refuses a RootOfTrust that is present and not
// verified; a chain without one passes. RequireAttestedBootState enforces
// that the claim is present.
//
// roots must be non-nil: a nil TrustedRoots skips chain verification in
// VerifyKeyAttestation altogether.
func DeviceVerifyOptions(roots *x509.CertPool) *VerifyOptions {
	return &VerifyOptions{
		TrustedRoots:     roots,
		MinSecurityLevel: SecurityLevelTrustedEnvironment,
		VerifyBootState:  true,
	}
}

// RequireAttestedBootState requires the hardware-enforced RootOfTrust to be
// present, the bootloader locked and the verified boot state VERIFIED, and
// returns that RootOfTrust.
func RequireAttestedBootState(desc *KeyDescription) (*RootOfTrust, error) {
	if desc == nil {
		return nil, ErrNilKeyDescription
	}
	rot := desc.TeeEnforced.RootOfTrust
	if rot == nil {
		return nil, ErrNoRootOfTrust
	}
	if !rot.DeviceLocked {
		return nil, ErrBootloaderUnlocked
	}
	if rot.VerifiedBootState != VerifiedBootVerified {
		return nil, &errs.Detail{Err: ErrUnverifiedBoot, Detail: fmt.Sprintf("device reports %q", rot.VerifiedBootState.String())}
	}
	return rot, nil
}

// RequireAttestedKeyOrigin requires the hardware-enforced list to claim the
// key was GENERATED in secure hardware and may SIGN. Only TeeEnforced is
// consulted: a claim in softwareEnforced is not hardware-backed.
func RequireAttestedKeyOrigin(desc *KeyDescription) error {
	if desc == nil {
		return ErrNilKeyDescription
	}
	tee := desc.TeeEnforced
	if tee.Origin != OriginGenerated {
		return &errs.Detail{Err: ErrKeyOriginNotGenerated, Detail: fmt.Sprintf("got %d, want %d", tee.Origin, OriginGenerated)}
	}
	if !slices.Contains(tee.Purpose, PurposeSign) {
		return &errs.Detail{Err: ErrKeyPurposeNotSign, Detail: fmt.Sprintf("got %v", tee.Purpose)}
	}
	return nil
}

// RequireAttestedPerUseUserVerification refuses an attested key that the
// hardware does not unlock with a fresh user verification on every use. It is
// the key policy of a user-verification key, the one a signature by which
// proves the user was verified for that signature: generated by
// setUserAuthenticationRequired(true) with
// setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG |
// AUTH_DEVICE_CREDENTIAL).
//
// The claims are read from teeEnforced -- for a StrongBox key that list is
// StrongBox's own -- since only a hardware-enforced claim binds the key:
// userAuthType (tag 504) is UserAuthTypePassword (1), UserAuthTypeFingerprint
// (2) or both (3), each of which is user verification under CTAP 2.1 (owner
// ruling 180); authTimeout (tag 505) and allowWhileOnBody (tag 506) are
// absent. noAuthRequired (tag 503) is refused in either list, so no list says
// the key needs nothing.
func RequireAttestedPerUseUserVerification(desc *KeyDescription) error {
	if desc == nil {
		return ErrNilKeyDescription
	}
	tee := desc.TeeEnforced
	if tee.NoAuthRequired || desc.SoftwareEnforced.NoAuthRequired {
		return ErrKeyNoAuthRequired
	}
	if !isUserVerificationAuthType(tee.UserAuthType) {
		return &errs.Detail{Err: ErrKeyUserAuthTypeNotUserVerification, Detail: fmt.Sprintf("got %d, want %d, %d or %d",
			tee.UserAuthType, UserAuthTypePassword, UserAuthTypeFingerprint, userAuthTypeUserVerification)}
	}
	if tee.HasAuthTimeout {
		return &errs.Detail{Err: ErrKeyAuthTimeout, Detail: fmt.Sprintf("authTimeout %d s", tee.AuthTimeout)}
	}
	if tee.AllowWhileOnBody {
		return ErrKeyAllowWhileOnBody
	}
	return nil
}

// userAuthTypeUserVerification is the userAuthType mask of every
// user-verification method a user-verification key may name: the device
// credential and the biometric.
const userAuthTypeUserVerification = UserAuthTypePassword | UserAuthTypeFingerprint

// isUserVerificationAuthType reports whether authType names at least one
// user-verification method and nothing else.
func isUserVerificationAuthType(authType int) bool {
	return authType != UserAuthTypeNone && authType&^userAuthTypeUserVerification == 0
}

// RequireAttestedApplication requires the attesting application to satisfy
// apps.
func RequireAttestedApplication(desc *KeyDescription, apps ApplicationMatcher) error {
	if desc == nil {
		return ErrNilKeyDescription
	}
	if apps == nil {
		return ErrNilApplicationMatcher
	}
	if _, _, err := apps.Match(desc.AttestedApplication()); err != nil {
		return &errs.Joined{Lead: ErrApplicationRefused, Cause: err}
	}
	return nil
}

// AttestedApplication returns the attestationApplicationId the Keystore
// daemon wrote. It is normally in softwareEnforced; some devices place it
// in the hardware-enforced list instead, which is used when the software
// list has none. It returns nil for a nil description or when neither list
// carries one.
func (d *KeyDescription) AttestedApplication() *AttestationApplicationID {
	if d == nil {
		return nil
	}
	if appID := d.SoftwareEnforced.AttestationApplicationID; appID != nil {
		return appID
	}
	return d.TeeEnforced.AttestationApplicationID
}
