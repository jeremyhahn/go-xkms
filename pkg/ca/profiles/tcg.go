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

package profiles

import (
	"crypto/x509"
)

// TCG profile names.
const (
	// TCGEKProfileName is the profile name for TCG Endorsement Key certificates.
	TCGEKProfileName = "tcg-ek"

	// TCGAKProfileName is the profile name for TCG Attestation Key certificates.
	TCGAKProfileName = "tcg-ak"

	// TCGIDevIDProfileName is the profile name for TCG IDevID certificates.
	TCGIDevIDProfileName = "tcg-idevid"
)

// TCG certificate validity: indefinite (max representable) expressed as ~100 years
// in days. The actual certificates use 99991231235959Z as NotAfter, which is
// handled by the TCG certificate issuance code. This constant is used by the
// profile's DefaultValidity() for informational purposes.
const tcgIndefiniteValidityDays = 36500 // ~100 years

// NewTCGEKProfile creates a certificate profile for TCG Endorsement Key certificates.
//
// Per TCG EK Credential Profile:
//   - KeyUsage: KeyEncipherment (encryption EKs)
//   - ExtKeyUsage: ClientAuth, ServerAuth
//   - Validity: Indefinite (99991231235959Z)
func NewTCGEKProfile() *BaseProfile {
	return NewBaseProfile(TCGEKProfileName,
		WithDescription("TCG Endorsement Key certificate per TCG EK Credential Profile"),
		WithKeyUsage(x509.KeyUsageKeyEncipherment),
		WithExtKeyUsage(x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth),
		WithValidity(tcgIndefiniteValidityDays),
	)
}

// NewTCGAKProfile creates a certificate profile for TCG Attestation Key certificates.
//
// Per TCG TPM 2.0 Keys for Device Identity and Attestation:
//   - KeyUsage: DigitalSignature (attestation, quotes)
//   - ExtKeyUsage: ClientAuth, ServerAuth
//   - Validity: Indefinite (99991231235959Z)
func NewTCGAKProfile() *BaseProfile {
	return NewBaseProfile(TCGAKProfileName,
		WithDescription("TCG Attestation Key certificate for TPM attestation and quote signing"),
		WithKeyUsage(x509.KeyUsageDigitalSignature),
		WithExtKeyUsage(x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth),
		WithValidity(tcgIndefiniteValidityDays),
	)
}

// NewTCGIDevIDProfile creates a certificate profile for TCG IDevID certificates.
//
// Per TCG TPM 2.0 Keys for Device Identity and Attestation:
//   - KeyUsage: DigitalSignature | KeyEncipherment (device identity)
//   - ExtKeyUsage: ClientAuth, ServerAuth
//   - Validity: Indefinite (99991231235959Z)
func NewTCGIDevIDProfile() *BaseProfile {
	return NewBaseProfile(TCGIDevIDProfileName,
		WithDescription("TCG Initial Device Identifier certificate for device identity"),
		WithKeyUsage(x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment),
		WithExtKeyUsage(x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth),
		WithValidity(tcgIndefiniteValidityDays),
	)
}

// RegisterTCGProfiles registers all TCG certificate profiles with the given registry.
func RegisterTCGProfiles(registry *Registry) error {
	profiles := []ProfileProvider{
		NewTCGEKProfile(),
		NewTCGAKProfile(),
		NewTCGIDevIDProfile(),
	}
	for _, p := range profiles {
		if err := registry.Register(p); err != nil {
			return err
		}
	}
	return nil
}

// AllTCGProfiles returns all TCG certificate profiles.
func AllTCGProfiles() []ProfileProvider {
	return []ProfileProvider{
		NewTCGEKProfile(),
		NewTCGAKProfile(),
		NewTCGIDevIDProfile(),
	}
}
