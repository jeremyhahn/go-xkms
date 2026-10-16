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

package attestation

import "errors"

var (
	// ErrAttestationKeyOriginNotGenerated indicates the attested key's
	// TEE-enforced Origin claim is not GENERATED: the key was derived,
	// imported, or the TEE made no origin claim at all (go-xkms#132).
	ErrAttestationKeyOriginNotGenerated = errors.New("attestation: attested key's TEE-enforced origin is not GENERATED")

	// ErrAttestationKeyPurposeNotSign indicates the attested key's
	// TEE-enforced Purpose set does not include SIGN (go-xkms#132).
	ErrAttestationKeyPurposeNotSign = errors.New("attestation: attested key's TEE-enforced purpose does not include SIGN")
)

// SentinelCauseError attaches an underlying cause to a package sentinel
// error so errors.Is matches both the sentinel and the cause.
type SentinelCauseError struct {
	Sentinel error
	Cause    error
}

// Error implements the error interface.
func (e *SentinelCauseError) Error() string {
	return e.Sentinel.Error() + ": " + e.Cause.Error()
}

// Unwrap returns the sentinel and the cause for errors.Is / errors.As.
func (e *SentinelCauseError) Unwrap() []error {
	return []error{e.Sentinel, e.Cause}
}
