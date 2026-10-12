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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"fmt"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/types"

	"github.com/google/go-tpm/tpm2"
)

// ActivationKey is a transient key created purely to answer an EK
// credential challenge (see CreateActivationKey / AnswerCredentialChallenge).
// It carries no hierarchy auth and no object auth, and is never persisted:
// AnswerCredentialChallenge flushes it once the challenge has been answered,
// exactly like any other transient object.
type ActivationKey struct {
	// Handle is the transient object handle CreateActivationKey loaded the
	// key at. It is valid only until AnswerCredentialChallenge consumes it
	// (or the TPM session ends).
	Handle tpm2.TPMHandle

	// Name is the key's TPM Name (nameAlg || digest). A verifier computes
	// the same value from Public with ActivationKeyName and passes it to
	// NewCredentialChallenge as activationKeyName.
	Name tpm2.TPM2BName

	// Public is the key's public area, sent to the verifier so it can
	// independently recompute Name (ActivationKeyName) rather than trust
	// the device's claimed Name outright.
	Public tpm2.TPMTPublic
}

// CreateActivationKey creates a transient, unrestricted signing key in the
// TPM's null hierarchy (TPM2_CreatePrimary under TPM_RH_NULL) purely to
// answer an EK credential challenge (NewCredentialChallenge /
// AnswerCredentialChallenge). The null hierarchy's seed is re-randomized on
// every TPM reset (TCG TPM 2.0 Part 1, section 24.4) and needs no
// authorization to use, so the key needs, and gets, no hierarchy auth and no
// object auth: whatever proof of possession a caller needs from the key is
// established by the credential challenge itself, not by key persistence or
// a password.
//
// This is the primitive an install-time caller uses when no IAK exists yet
// (go-xkms#798) -- proving possession of a device's EK before any identity
// has been provisioned. ActivateCredential's hardcoded IAK path remains for
// the already-provisioned enrollment flow (enroll-01), which continues to
// use it.
func (tpm *TPM2) CreateActivationKey() (*ActivationKey, error) {
	template, err := tpm.KeyTemplate(KeyTemplateSpec{})
	if err != nil {
		return nil, &errs.Detail{Err: ErrActivationKeyCreate, Detail: fmt.Sprintf("build template: %v", err)}
	}

	rsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHNull,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2B(template),
	}.Execute(tpm.transport)
	if err != nil {
		return nil, &errs.Detail{Err: ErrActivationKeyCreate, Detail: fmt.Sprintf("%v", err)}
	}

	pub, err := rsp.OutPublic.Contents()
	if err != nil {
		tpm.flushSilent(rsp.ObjectHandle)
		return nil, &errs.Detail{Err: ErrActivationKeyCreate, Detail: fmt.Sprintf("read public area: %v", err)}
	}

	return &ActivationKey{
		Handle: rsp.ObjectHandle,
		Name:   rsp.Name,
		Public: *pub,
	}, nil
}

// AnswerCredentialChallenge answers a credential challenge built by
// NewCredentialChallenge, using an activation key this TPM created with
// CreateActivationKey. It generalises the flow ActivateCredential
// hard-codes to the IAK (go-xkms#798): both perform TPM2_ActivateCredential
// against this TPM's EK, differing only in which key answers and how that
// key's ADMIN-role authorization is satisfied -- key's own (empty) password
// auth here, versus the IAK's TCG Key Policy in ActivateCredential.
//
// The activation key is flushed before AnswerCredentialChallenge returns,
// whether or not activation succeeds: CreateActivationKey/
// AnswerCredentialChallenge is a single challenge-response round trip, not
// a key the caller reuses.
//
// When no EK is loaded at the configured persistent handle -- the EK
// certificate is in NV but the EK was never persisted, or TPM2_Clear
// evicted it -- the EK is created transiently instead (see
// createTransientEK) and flushed before AnswerCredentialChallenge returns.
// The persistent EK is never created or re-persisted here.
func (tpm *TPM2) AnswerCredentialChallenge(
	key *ActivationKey, challenge *CredentialChallenge) ([]byte, error) {

	if key == nil {
		return nil, ErrActivationKeyRequired
	}
	if challenge == nil {
		return nil, ErrCredentialChallengeRequired
	}
	defer tpm.flushSilent(key.Handle)

	ekAttrs, err := tpm.EKAttributes()
	if err != nil {
		// EKAttributes reports an absent persistent EK only when no EK
		// certificate is in NV either.
		if isAbsentHandle(err) {
			return nil, &errs.Joined{Lead: ErrEKCertNotInNV, Cause: err}
		}
		return nil, err
	}

	_, _, err = tpm.ReadHandle(ekAttrs.TPMAttributes.Handle)
	if err != nil {
		if !isAbsentHandle(err) {
			return nil, err
		}
		ekAttrs, err = tpm.createTransientEK(ekAttrs)
		if err != nil {
			return nil, err
		}
		defer tpm.flushSilent(ekAttrs.TPMAttributes.Handle)
	}

	return tpm.activateCredential(
		ekAttrs, key.Handle, key.Name, tpm2.PasswordAuth(nil),
		challenge.CredentialBlob, challenge.EncryptedSecret)
}

// ekCertHighRangeStart is the first EK certificate NV index of the TCG EK
// Credential Profile high range. High-range EKs come from the H templates,
// whose auth policy is not the TPM2_PolicySecret(RH_ENDORSEMENT) policy
// activateCredential satisfies.
const ekCertHighRangeStart = 0x01C00012

// createTransientEK recreates, as a transient object, the EK that the
// certificate at ekAttrs' NV certificate index certifies. The EK is a
// primary key, so the endorsement seed derives the same key from the same
// template every time; the template is the TCG EK Credential Profile
// low-range template matching the certificate's key (see transientEKTemplate).
//
// The created key is checked against the certificate before it is used: a
// mismatch is flushed and refused with ErrEKPublicKeyMismatch rather than
// answering a challenge with a key the certificate does not vouch for. On
// success the returned attributes name the transient handle, which the
// caller flushes.
func (tpm *TPM2) createTransientEK(ekAttrs *types.KeyAttributes) (*types.KeyAttributes, error) {
	certIndex := ekAttrs.TPMAttributes.CertHandle
	cert, err := tpm.readEKCertFromNV(certIndex)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrEKCertNotInNV, Cause: err}
	}

	template, err := transientEKTemplate(certIndex, cert)
	if err != nil {
		return nil, err
	}

	var hierarchyAuth []byte
	if ekAttrs.TPMAttributes.HierarchyAuth != nil {
		hierarchyAuth = ekAttrs.TPMAttributes.HierarchyAuth.Bytes()
	}
	rsp, err := tpm.createPrimary(tpm2.TPMRHEndorsement, hierarchyAuth, tpm2.CreatePrimary{
		InPublic: tpm2.New2B(template),
	})
	if err != nil {
		return nil, err
	}

	ekPub, err := ExtractPublicKeyFromTPMPublic(rsp.OutPublic.Bytes())
	if err != nil {
		tpm.flushSilent(rsp.ObjectHandle)
		return nil, &errs.Joined{Lead: ErrEKPublicRead, Cause: err}
	}
	certPub, ok := cert.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !certPub.Equal(ekPub) {
		tpm.flushSilent(rsp.ObjectHandle)
		return nil, &errs.Detail{
			Err:    ErrEKPublicKeyMismatch,
			Detail: fmt.Sprintf("certificate at NV index 0x%08X", certIndex),
		}
	}

	return &types.KeyAttributes{
		KeyType:   types.KeyTypeEndorsement,
		StoreType: types.StoreTPM2,
		TPMAttributes: &types.TPMAttributes{
			CertHandle:    certIndex,
			Handle:        rsp.ObjectHandle,
			HandleType:    tpm2.TPMHTTransient,
			Hierarchy:     tpm2.TPMRHEndorsement,
			HierarchyAuth: ekAttrs.TPMAttributes.HierarchyAuth,
			Name:          rsp.Name,
		},
	}, nil
}

// transientEKTemplate returns the TCG EK Credential Profile low-range
// template for the key cert certifies -- template L-1 for RSA-2048, L-2 for
// ECC NIST P-256 -- the same templates EKAttributesFromConfig provisions an
// EK from. A certificate in the high range, or for any other key, has no
// template here and is refused with ErrEKTemplateUnsupported.
func transientEKTemplate(certIndex tpm2.TPMHandle, cert *x509.Certificate) (tpm2.TPMTPublic, error) {
	if certIndex >= ekCertHighRangeStart {
		return tpm2.TPMTPublic{}, &errs.Detail{
			Err:    ErrEKTemplateUnsupported,
			Detail: fmt.Sprintf("high-range certificate index 0x%08X", certIndex),
		}
	}

	var keyDesc string
	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if key.N.BitLen() == 2048 {
			return tpm2.RSAEKTemplate, nil
		}
		keyDesc = fmt.Sprintf("RSA-%d", key.N.BitLen())
	case *ecdsa.PublicKey:
		if key.Curve == elliptic.P256() {
			return tpm2.ECCEKTemplate, nil
		}
		keyDesc = key.Curve.Params().Name
	default:
		keyDesc = fmt.Sprintf("%T", key)
	}
	return tpm2.TPMTPublic{}, &errs.Detail{
		Err:    ErrEKTemplateUnsupported,
		Detail: fmt.Sprintf("certificate key %s", keyDesc),
	}
}
