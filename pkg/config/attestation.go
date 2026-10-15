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
