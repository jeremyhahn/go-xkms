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
	"fmt"

	attestandroid "github.com/jeremyhahn/go-xkms/pkg/attestation/android"
	"github.com/jeremyhahn/go-xkms/pkg/backend/phone"
)

// PlatformAndroid is the platform identifier for Android.
const PlatformAndroid = "android"

func init() {
	phone.RegisterPlatform(PlatformAndroid, NewAndroidVerifier)
}

// securityLevelMapping provides O(1) constant-time lookup for mapping
// attestation security level config strings to attestandroid.SecurityLevel values.
var securityLevelMapping = map[string]attestandroid.SecurityLevel{
	"software":  attestandroid.SecurityLevelSoftware,
	"tee":       attestandroid.SecurityLevelTrustedEnvironment,
	"strongbox": attestandroid.SecurityLevelStrongBox,
}

// securityLevelToBackend provides O(1) constant-time mapping from verified
// attestandroid.SecurityLevel values to attestation backend identifier strings.
var securityLevelToBackend = map[attestandroid.SecurityLevel]string{
	attestandroid.SecurityLevelSoftware:           "android-keystore-software",
	attestandroid.SecurityLevelTrustedEnvironment: "android-keystore-tee",
	attestandroid.SecurityLevelStrongBox:          "android-keystore-strongbox",
}

// AndroidVerifier implements phone.PlatformVerifier for Android Key Attestation.
// It verifies attestation certificate chains produced by Android Keystore
// hardware (TEE/StrongBox) using the Android Key Attestation extension.
type AndroidVerifier struct {
	trustPool       *x509.CertPool
	minSecLevel     attestandroid.SecurityLevel
	verifyBootState bool
}

// NewAndroidVerifier creates a new AndroidVerifier from the phone backend's
// attestation configuration. This function satisfies the phone.PlatformVerifierFactory
// signature.
func NewAndroidVerifier(trustPool *x509.CertPool, cfg *phone.AttestationConfig) (phone.PlatformVerifier, error) {
	minSecLevel := attestandroid.SecurityLevelSoftware
	verifyBootState := false

	if cfg != nil {
		minSecLevel = mapMinSecurityLevel(cfg.MinSecurityLevel)
		verifyBootState = cfg.VerifyBootState
	}

	return &AndroidVerifier{
		trustPool:       trustPool,
		minSecLevel:     minSecLevel,
		verifyBootState: verifyBootState,
	}, nil
}

// Platform returns the platform identifier for Android.
func (v *AndroidVerifier) Platform() string {
	return PlatformAndroid
}

// VerifyAttestation verifies the Android Key Attestation certificate chain
// and returns a platform-agnostic result with the parsed KeyDescription as
// PlatformData.
func (v *AndroidVerifier) VerifyAttestation(derChain [][]byte, nonce []byte) (*phone.VerifiedAttestation, error) {
	if len(derChain) == 0 {
		return nil, phone.ErrChainVerificationFailed
	}

	chain := make([]*x509.Certificate, 0, len(derChain))
	for i, der := range derChain {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("%w: certificate at index %d: %v", phone.ErrInvalidCertificate, i, err)
		}
		chain = append(chain, cert)
	}

	verifyOpts := &attestandroid.VerifyOptions{
		TrustedRoots:     v.trustPool,
		ExpectedNonce:    nonce,
		MinSecurityLevel: v.minSecLevel,
		VerifyBootState:  v.verifyBootState,
	}

	desc, err := attestandroid.VerifyKeyAttestation(chain, verifyOpts)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", phone.ErrChainVerificationFailed, err)
	}

	return &phone.VerifiedAttestation{
		SecurityBackend: mapSecurityLevel(desc.AttestationSecurityLevel),
		PlatformData:    desc,
	}, nil
}

// mapMinSecurityLevel converts a config string to an attestandroid.SecurityLevel.
// Returns SecurityLevelSoftware for unrecognized or empty values.
func mapMinSecurityLevel(level string) attestandroid.SecurityLevel {
	if sl, ok := securityLevelMapping[level]; ok {
		return sl
	}
	return attestandroid.SecurityLevelSoftware
}

// mapSecurityLevel converts a verified attestandroid.SecurityLevel to an
// attestation backend identifier string.
func mapSecurityLevel(level attestandroid.SecurityLevel) string {
	if backend, ok := securityLevelToBackend[level]; ok {
		return backend
	}
	return fmt.Sprintf("android-keystore-unknown(%d)", int(level))
}
