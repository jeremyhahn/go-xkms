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
	"context"
	"fmt"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	phoneproto "github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
)

// Compile-time interface check.
var _ types.AttestingKeyProvider = (*Backend)(nil)

// AttestationResult contains the attestation statement from the phone.
type AttestationResult struct {
	// Format identifies the attestation format (e.g., "android-keystore").
	Format string

	// CertificateChain is the X.509 attestation certificate chain.
	CertificateChain [][]byte

	// AttestationData contains format-specific attestation evidence.
	AttestationData []byte

	// Nonce is the echoed challenge nonce for freshness verification.
	Nonce []byte

	// Backend identifies the security level (e.g., "android-keystore-strongbox", "android-keystore-tee").
	Backend string

	// Verified indicates whether the certificate chain and attestation extension
	// have been verified against the configured trust store.
	Verified bool

	// PlatformData contains platform-specific parsed attestation data.
	// For Android, this is *android.KeyDescription. Callers type-assert
	// based on the platform.
	PlatformData any
}

// securityLevelMapping provides O(1) constant-time lookup for mapping phone
// security level strings to attestation backend identifiers.
var securityLevelMapping = map[string]string{
	"strongbox": "android-keystore-strongbox",
	"tee":       "android-keystore-tee",
}

// mapSecurityLevel converts a phone security level string to an attestation
// backend identifier. Unknown levels are prefixed with "android-keystore-".
func mapSecurityLevel(level string) string {
	if backend, ok := securityLevelMapping[level]; ok {
		return backend
	}
	return fmt.Sprintf("android-keystore-%s", level)
}

// AttestKey generates an attestation statement proving a key on the phone is hardware-backed.
// It sends a local.attestKey JSON-RPC request to the phone, which returns an attestation
// X.509 certificate chain proving the key resides in secure hardware.
//
// The nonce parameter provides freshness to prevent replay attacks.
//
// When attestation verification is configured (config.Attestation is non-nil with a trust
// store), the method delegates verification to the registered PlatformVerifier, which
// validates the certificate chain, attestation extension, security level, and optionally
// the device boot state.
//
// When no attestation config is present, the raw result from the phone is returned
// without verification (suitable for development/testing).
func (b *Backend) AttestKey(attrs *types.KeyAttributes, nonce []byte) (interface{}, error) {
	if b.closed.Load() {
		return nil, ErrBackendClosed
	}
	if attrs == nil {
		return nil, ErrInvalidConfig
	}

	params := &phoneproto.LocalAttestKeyParams{
		KeyID: attrs.CN,
		Nonce: nonce,
	}

	ctx, cancel := context.WithTimeout(context.Background(), b.config.RequestTimeout)
	defer cancel()

	resp, err := b.sendLocalRequest(ctx, phoneproto.MethodLocalAttestKey, params)
	if err != nil {
		return nil, err
	}

	result, err := phoneproto.DecodeResult[phoneproto.LocalAttestKeyResult](resp)
	if err != nil {
		return nil, ErrInvalidResponse
	}

	// If no platform verifier is configured, return the raw result without verification.
	if b.verifier == nil {
		return &AttestationResult{
			Format:           result.Format,
			CertificateChain: result.CertificateChain,
			Nonce:            result.Nonce,
			Backend:          mapSecurityLevel(result.SecurityLevel),
			Verified:         false,
		}, nil
	}

	// Delegate attestation verification to the platform verifier.
	verified, err := b.verifier.VerifyAttestation(result.CertificateChain, nonce)
	if err != nil {
		b.logger.Error("attestation verification failed",
			"error", err,
			"platform", b.verifier.Platform(),
			"chain_length", len(result.CertificateChain),
		)
		return nil, err
	}

	b.logger.Info("attestation verified",
		"platform", b.verifier.Platform(),
		"security_backend", verified.SecurityBackend,
	)

	return &AttestationResult{
		Format:           result.Format,
		CertificateChain: result.CertificateChain,
		Nonce:            result.Nonce,
		Backend:          verified.SecurityBackend,
		Verified:         true,
		PlatformData:     verified.PlatformData,
	}, nil
}
