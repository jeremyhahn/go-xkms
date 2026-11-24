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

package config

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/attestation"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/peergate"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/truststore"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// Attestation configuration errors.
var (
	// ErrAttestationFormatEmpty indicates an attestation format key is blank.
	ErrAttestationFormatEmpty = errors.New("attestation: empty format identifier")

	// ErrAttestationTrustStoreMissing indicates an attestation format was
	// declared without a trust store, which would leave it unanchored.
	ErrAttestationTrustStoreMissing = errors.New("attestation: trust store required for format")

	// ErrAttestationTrustStoreEmpty indicates an attestation format's trust
	// store loaded successfully but contains no root certificates.
	ErrAttestationTrustStoreEmpty = errors.New("attestation: trust store contains no roots for format")

	// ErrAndroidApplicationTenantEmpty indicates a blank tenant key in
	// attestation.android_applications.
	ErrAndroidApplicationTenantEmpty = errors.New("attestation: empty tenant in android_applications")

	// ErrAndroidApplicationPackageEmpty indicates a blank package key in
	// attestation.android_applications.
	ErrAndroidApplicationPackageEmpty = errors.New("attestation: empty package in android_applications")

	// ErrAndroidApplicationDigestInvalid indicates a package with no
	// digests, or a digest that is not 64 hex characters (SHA-256).
	ErrAndroidApplicationDigestInvalid = errors.New("attestation: android_applications digest must be 64 hex characters")
)

// AttestationConfig configures the hardware-attestation trust anchors used to
// verify the attestation certificate chain a client presents alongside a CSR.
//
// Anchors are declared per attestation format so that a chain can only be
// validated by anchors belonging to that format's device vendor: a YubiKey PIV
// chain must terminate at the Yubico PIV Root CA, a TPM 2.0 chain at the TPM
// manufacturer root. A format with no declared anchors is refused at the gate.
type AttestationConfig struct {
	// Formats maps an attestation format identifier as it appears on the wire
	// ("tpm2", "yubikey-piv") to the trust store holding that format's root
	// certificates. Format keys are matched case-insensitively.
	Formats map[string]*truststore.Config `yaml:"formats"`

	// PeerGate is the attested-caller gate's mode (pkg/attestation/peergate):
	// "off" or unset installs nothing; "optional" or "required" installs the
	// gate on the embedded qrdb node. The quote policy it verifies under is
	// the embedder's (server.WithAttestedCallerPolicy); go-xkms ships no
	// reference values.
	PeerGate string `yaml:"peer_gate,omitempty"`

	// AndroidApplications is each tenant's Android application allow-list
	// for the attestation Verifier: tenant ID -> package name -> the hex
	// SHA-256 signing-certificate digests the package may be signed with.
	// A tenant absent from it keeps Android appraisal refused
	// (appraisal.ErrNoApplicationAllowList).
	AndroidApplications map[string]map[string][]string `yaml:"android_applications,omitempty"`
}

// ValidateAndroidApplications checks AndroidApplications: no blank tenant
// or package key, and every digest 64 hex characters (a SHA-256). A nil
// config or an absent allow-list is valid.
func (a *AttestationConfig) ValidateAndroidApplications() error {
	if a == nil {
		return nil
	}
	for tenant, packages := range a.AndroidApplications {
		if strings.TrimSpace(tenant) == "" {
			return ErrAndroidApplicationTenantEmpty
		}
		for pkg, digests := range packages {
			if strings.TrimSpace(pkg) == "" {
				return &errs.Detail{Err: ErrAndroidApplicationPackageEmpty, Detail: tenant}
			}
			if len(digests) == 0 {
				return &errs.Detail{Err: ErrAndroidApplicationDigestInvalid, Detail: tenant + "/" + pkg + ": no digests"}
			}
			for _, digest := range digests {
				if !isSHA256Hex(digest) {
					return &errs.Detail{Err: ErrAndroidApplicationDigestInvalid, Detail: tenant + "/" + pkg}
				}
			}
		}
	}
	return nil
}

// isSHA256Hex reports whether s is 64 hex characters.
func isSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// PeerGateMode is the configured attested-caller gate mode. A nil config is
// peergate.ModeOff; an unknown value is a *peergate.ModeError.
func (a *AttestationConfig) PeerGateMode() (peergate.Mode, error) {
	if a == nil {
		return peergate.ModeOff, nil
	}
	return peergate.ParseMode(a.PeerGate)
}

// Verifiers builds the per-format attestation verifiers described by the
// configuration. Every declared format must resolve to at least one root
// certificate; a format that would produce an anchorless verifier is a
// configuration error rather than a permissive default.
func (c *AttestationConfig) Verifiers() (map[string]*attestation.Verifier, error) {
	if c == nil {
		return nil, nil
	}

	verifiers := make(map[string]*attestation.Verifier, len(c.Formats))
	for format, storeConfig := range c.Formats {
		key := strings.ToLower(strings.TrimSpace(format))
		if key == "" {
			return nil, ErrAttestationFormatEmpty
		}
		if storeConfig == nil {
			return nil, &errs.Detail{Err: ErrAttestationTrustStoreMissing, Detail: key}
		}

		store, err := truststore.New(storeConfig)
		if err != nil {
			return nil, &errs.Wrapped{Msg: fmt.Sprintf("attestation: trust store for format %q", key), Err: err}
		}
		roots, err := store.Certificates()
		if err != nil {
			return nil, &errs.Wrapped{Msg: fmt.Sprintf("attestation: trust store for format %q", key), Err: err}
		}
		if len(roots) == 0 {
			return nil, &errs.Detail{Err: ErrAttestationTrustStoreEmpty, Detail: key}
		}

		verifiers[key] = attestation.NewVerifier(roots)
	}

	return verifiers, nil
}
