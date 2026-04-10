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

package phone

import (
	"crypto/x509"
	"sync"
)

// PlatformVerifier verifies attestation certificate chains from phone secure
// hardware. Each phone platform (Android, iOS) has its own attestation format,
// certificate chain structure, and root CAs.
type PlatformVerifier interface {
	// VerifyAttestation verifies the attestation certificate chain and returns
	// a platform-agnostic result. derChain is the DER-encoded certificate chain.
	// nonce is the challenge for freshness verification.
	VerifyAttestation(derChain [][]byte, nonce []byte) (*VerifiedAttestation, error)

	// Platform returns the platform identifier (e.g., "android", "ios").
	Platform() string
}

// VerifiedAttestation is the platform-agnostic attestation verification result.
type VerifiedAttestation struct {
	// SecurityBackend identifies the security level
	// (e.g., "android-keystore-strongbox", "ios-secure-enclave").
	SecurityBackend string

	// PlatformData contains platform-specific parsed attestation data.
	// Callers type-assert based on the platform.
	PlatformData any
}

// PlatformVerifierFactory creates a PlatformVerifier for a given platform.
// The trustPool provides the root certificates for chain verification, and
// cfg provides the attestation configuration.
type PlatformVerifierFactory func(trustPool *x509.CertPool, cfg *AttestationConfig) (PlatformVerifier, error)

// platformVerifiers is the registry of platform verifier factories, keyed by
// platform identifier. Uses map-based dispatch for O(1) constant-time lookup.
var (
	platformVerifiers   = map[string]PlatformVerifierFactory{}
	platformVerifiersMu sync.RWMutex
)

// RegisterPlatform registers a PlatformVerifierFactory for the given platform
// identifier. Platform packages call this from init() to register themselves.
func RegisterPlatform(platform string, factory PlatformVerifierFactory) {
	platformVerifiersMu.Lock()
	defer platformVerifiersMu.Unlock()
	platformVerifiers[platform] = factory
}

// NewPlatformVerifier creates a PlatformVerifier for the given platform using
// the registered factory. Returns ErrUnsupportedPlatform if no factory is
// registered for the platform.
func NewPlatformVerifier(platform string, trustPool *x509.CertPool, cfg *AttestationConfig) (PlatformVerifier, error) {
	platformVerifiersMu.RLock()
	factory, ok := platformVerifiers[platform]
	platformVerifiersMu.RUnlock()

	if !ok {
		return nil, ErrUnsupportedPlatform
	}

	return factory(trustPool, cfg)
}
