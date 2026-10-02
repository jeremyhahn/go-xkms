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

package tpm2

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"log/slog"

	"github.com/google/go-tpm/tpm2"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// CreateLAK creates the device's Local Attestation Key (go-xkms#715): a
// Restricted, Sign-only child key of the Platform SRK, following TCG TPM 2.0
// Keys for Device Identity and Attestation v1.10 r9 §5.3/§6.3's "Owner
// Creation of a LAK Certificate based on an IAK Certificate".
//
// Unlike the IAK and IDevID, which are OEM-provisioned primary keys of the
// Endorsement hierarchy derived from a deterministic template, the LAK is an
// ordinary TPM2_Create child key: it is created once, then made persistent at
// the handle tpm.config.LAK.Handle names via TPM2_EvictControl, exactly as
// CreateIAK persists the IAK. TPM2_EvictControl always authorizes under the
// Owner (or Platform) hierarchy regardless of which hierarchy created the
// object (TCG TPM 2.0 Part 3, section 12.9), so ownerAuth is the Owner
// hierarchy authorization -- the Security Officer PIN when one has been set,
// empty otherwise -- never the Platform SRK's own authValue.
//
// Returns ErrLAKConfigNil when tpm.config.LAK is nil.
func (tpm *TPM2) CreateLAK(
	ownerAuth types.Password,
	backend store.KeyBackend,
	overwrite bool) (*types.KeyAttributes, error) {

	if tpm.config.LAK == nil {
		return nil, ErrLAKConfigNil
	}

	srkAttrs, err := tpm.PlatformSRKAttributes()
	if err != nil {
		return nil, err
	}

	lakAttrs, err := LAKAttributesFromConfig(ownerAuth, tpm.config.LAK)
	if err != nil {
		tpm.logger.Error("failed to create LAK attributes from config", slog.String("error", err.Error()))
		return nil, &errs.Detail{Err: ErrLAKConfigFailed, Detail: fmt.Sprintf("%v", err)}
	}
	lakAttrs.Parent = srkAttrs

	if err := tpm.createLAKKeyPair(lakAttrs, backend, overwrite); err != nil {
		return nil, err
	}

	// CreateECDSA/CreateRSA flush the transient object they create once its
	// blobs are saved -- nothing in ordinary key creation needs it loaded
	// afterward -- so the LAK must be reloaded before TPM2_EvictControl can
	// make it persistent.
	loadResp, err := tpm.LoadKeyPair(lakAttrs, nil, backend)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to reload LAK for persistence", Err: err}
	}

	var hierarchyAuthBytes []byte
	if ownerAuth != nil {
		hierarchyAuthBytes = ownerAuth.Bytes()
	}

	persistentHandle := tpm2.TPMHandle(tpm.config.LAK.Handle)
	if err := tpm.evictControl(tpm2.TPMRHOwner, hierarchyAuthBytes, tpm2.NamedHandle{
		Handle: loadResp.ObjectHandle,
		Name:   loadResp.Name,
	}, persistentHandle); err != nil {
		tpm.flushSilent(loadResp.ObjectHandle)
		return nil, &errs.Wrapped{Msg: "failed to persist LAK", Err: err}
	}
	tpm.flushSilent(loadResp.ObjectHandle)

	// Re-derive the cached attributes from the persisted handle itself,
	// exactly as the restart path (LAKAttributes) does, so a key created in
	// this process and one rebuilt after a restart are described identically.
	persistedAttrs, err := tpm.KeyAttributes(persistentHandle)
	if err != nil {
		return nil, err
	}
	if err := tpm.applyLAKConfig(persistedAttrs); err != nil {
		return nil, err
	}
	persistedAttrs.Parent = srkAttrs

	tpm.lakAttrs = persistedAttrs
	return persistedAttrs, nil
}

// createLAKKeyPair creates the LAK's asymmetric key material under
// lakAttrs.Parent (the Platform SRK), dispatching on lakAttrs.KeyAlgorithm the
// same way pkg/backend/tpm2's generic key creation does.
func (tpm *TPM2) createLAKKeyPair(lakAttrs *types.KeyAttributes, backend store.KeyBackend, overwrite bool) error {
	if lakAttrs.KeyAlgorithm == x509.RSA {
		_, err := tpm.CreateRSA(lakAttrs, backend, overwrite)
		return err
	}
	_, err := tpm.CreateECDSA(lakAttrs, backend, overwrite)
	return err
}

// LAKAttributes returns the Local Attestation Key attributes, rebuilding them
// from the persisted handle tpm.config.LAK.Handle names on first use -- the
// restart path, exactly as IAKAttributes rebuilds the IAK.
//
// Returns ErrLAKConfigNil if tpm.config.LAK is nil.
func (tpm *TPM2) LAKAttributes() (*types.KeyAttributes, error) {
	if tpm.lakAttrs == nil {
		if tpm.config.LAK == nil {
			return nil, ErrLAKConfigNil
		}
		lakHandle := tpm2.TPMHandle(tpm.config.LAK.Handle)
		lakAttrs, err := tpm.KeyAttributes(lakHandle)
		if err != nil {
			return nil, err
		}
		if err := tpm.applyLAKConfig(lakAttrs); err != nil {
			return nil, err
		}

		srkAttrs, err := tpm.PlatformSRKAttributes()
		if err != nil {
			return nil, err
		}
		lakAttrs.Parent = srkAttrs

		tpm.lakAttrs = lakAttrs
	}
	return tpm.lakAttrs, nil
}

// applyLAKConfig assigns to attrs every LAK attribute that comes from
// configuration rather than from the TPM, mirroring applyIAKConfig: the
// Common Name, key type, platform binding, signature algorithm and
// authValue. It is the one place both CreateLAK and the restart path
// (LAKAttributes) take those from.
func (tpm *TPM2) applyLAKConfig(attrs *types.KeyAttributes) error {
	cfg := tpm.config.LAK
	cn := cfg.CN
	if cn == "" {
		cn = "lak"
	}
	sigAlgo, err := types.ParseSignatureAlgorithm(cfg.SignatureAlgorithm)
	if err != nil {
		return err
	}
	return applyDevIDConfig(attrs, types.KeyTypeLAK, cn, sigAlgo, cfg.PlatformPolicy, cfg.Password)
}

// LAK returns the Local Attestation Key's public key.
//
// Returns ErrLAKNotInitialized if LAKAttributes has not been called yet.
func (tpm *TPM2) LAK() (crypto.PublicKey, error) {
	if tpm.lakAttrs == nil {
		return nil, ErrLAKNotInitialized
	}
	pub, err := x509.ParsePKIXPublicKey(tpm.lakAttrs.TPMAttributes.PublicKeyBytes)
	if err != nil {
		tpm.logger.Error("failed to parse LAK public key", slog.String("error", err.Error()))
		return nil, &errs.Detail{Err: ErrLAKPublicParse, Detail: fmt.Sprintf("%v", err)}
	}
	return pub, nil
}

// CertifyLAK certifies the device's Local Attestation Key under its Initial
// Attestation Key via TPM2_Certify, producing the TCG v1.10 r9 §5.3/§6.3
// evidence a CA verifies (tpm2.VerifyCertifyByCertificate) before issuing the
// LAK's WebAuthn Level 2 §8.3.1 profile certificate (go-xkms#715): empty
// Subject, critical TCG subjectAltName, tcg-kp-AIKCertificate EKU, CA:false.
//
// Returns ErrIAKNotProvisioned if the device's IAK has not been provisioned.
func (tpm *TPM2) CertifyLAK(nonce []byte, backend store.KeyBackend) (*CertifyResult, error) {
	if tpm.iakAttrs == nil {
		return nil, ErrIAKNotProvisioned
	}
	lakAttrs, err := tpm.LAKAttributes()
	if err != nil {
		return nil, err
	}
	return tpm.certifyKeyAs(tpm.iakAttrs, lakAttrs, nonce, backend)
}

// CertifyKeyWithLAK certifies keyAttrs under the device's Local Attestation
// Key via TPM2_Certify. xkey's TPM-backed WebAuthn/FIDO2 authenticator uses
// this to produce the "tpm" attestation statement's certInfo/sig for each
// credential key (go-xkms#715): the LAK, carrying a WebAuthn-profile
// certificate, is the attesting key x5c[0] names -- never the IAK, whose
// certificate keeps its TCG DevID Subject and so fails a strict relying
// party's WebAuthn L2 §8.3.1 requirement 2 ("Subject field MUST be empty").
//
// Returns ErrLAKConfigNil (via LAKAttributes) if the LAK has not been
// provisioned.
func (tpm *TPM2) CertifyKeyWithLAK(keyAttrs *types.KeyAttributes, nonce []byte, backend store.KeyBackend) (*CertifyResult, error) {
	lakAttrs, err := tpm.LAKAttributes()
	if err != nil {
		return nil, err
	}
	return tpm.certifyKeyAs(lakAttrs, keyAttrs, nonce, backend)
}
