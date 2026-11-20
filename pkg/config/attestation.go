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
	"context"
	"crypto/x509"
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
//
// roots is the persisted, purpose-classified trust-root store; when non-nil
// every verifier appraises over it (Verifier.BuildTrustPool), so a root
// installed through the trust_roots verbs is trusted without a config edit.
// A nil roots leaves the purpose-pooled checks failing closed. When roots
// is writable (truststore.DAOStore), the config-file roots of a format with
// a chain purpose are imported into it once (an existing entry, and its
// quarantine, is kept) and chain appraisal anchors on the store alone.
func (c *AttestationConfig) Verifiers(roots truststore.PurposeLister) (map[string]*attestation.Verifier, error) {
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
		anchors, err := store.Certificates()
		if err != nil {
			return nil, &errs.Wrapped{Msg: fmt.Sprintf("attestation: trust store for format %q", key), Err: err}
		}
		if len(anchors) == 0 {
			return nil, &errs.Detail{Err: ErrAttestationTrustStoreEmpty, Detail: key}
		}

		var opts []attestation.VerifierOption
		if roots != nil {
			opts = append(opts, attestation.WithTrustStore(roots, nil))
			if purpose, ok := formatChainPurpose(key); ok {
				opts = append(opts, attestation.WithChainPurpose(purpose))
				if importer, ok := roots.(configRootImporter); ok {
					if err := importConfigRoots(importer, anchors, purpose); err != nil {
						return nil, &errs.Wrapped{Msg: fmt.Sprintf("attestation: import config roots for format %q", key), Err: err}
					}
					// The store is authoritative from here on: a config
					// root anchors only through its store entry, so a
					// quarantine or removal there takes effect.
					anchors = nil
				}
			}
		}
		verifiers[key] = attestation.NewVerifier(anchors, opts...)
	}

	return verifiers, nil
}

// formatChainPurpose names the persisted trust-root purpose whose roots anchor
// a format's attestation chains. Formats without one anchor at their
// configured roots only.
func formatChainPurpose(format string) (truststore.CertPurpose, bool) {
	switch {
	case format == "tpm" || format == "tpm2":
		return truststore.PurposeTPMManufacturer, true
	case strings.HasPrefix(format, "android"):
		return truststore.PurposeAndroidHardware, true
	case strings.HasPrefix(format, "yubikey"):
		return truststore.PurposeYubiKeyAttestation, true
	case strings.HasPrefix(format, "apple"):
		return truststore.PurposeAppleAttestation, true
	case format == "dice":
		return truststore.PurposeDICEAttestation, true
	}
	return "", false
}

// configRootImporter is the writable trust-root store Verifiers migrates
// config-file roots into (truststore.DAOStore).
type configRootImporter interface {
	Add(ctx context.Context, cert *x509.Certificate, opts *truststore.AddCertificateOptions) error
}

// configRootSource tags the store entries imported from the config file. A
// removed config root leaves a tombstone in the store, so this import does
// not bring it back (DAOStore.Delete).
const configRootSource = truststore.SourceConfig

// importConfigRoots adds each config-file root to the store under purpose,
// keyed by fingerprint. A root the store already holds keeps its entry and
// purpose, so an earlier quarantine (PurposeSynced) survives a restart.
func importConfigRoots(store configRootImporter, roots []*x509.Certificate, purpose truststore.CertPurpose) error {
	for _, root := range roots {
		err := store.Add(context.Background(), root, &truststore.AddCertificateOptions{Purpose: purpose, Source: configRootSource})
		if err != nil && !errors.Is(err, truststore.ErrCertificateExists) {
			return err
		}
	}
	return nil
}
