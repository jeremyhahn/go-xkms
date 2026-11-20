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
	"bytes"
	"fmt"
	"log/slog"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// Object policy: how a child object's USER role is bound when it is created
// (bindObjectPolicy) and answered when it is used (objectSession). Every
// child object go-xkms creates under an SRK -- sealed data, symmetric keys,
// RSA, ECDSA and AES keys -- goes through both, and the platform-policy NV
// indices through platformPCRPolicyDigest and platformPCRBranchSession.
//
// The invariant is that an object with a policy can only be used through
// that policy:
//
//   - USERWITHAUTH is cleared whenever the object has an authPolicy, so its
//     authValue alone never satisfies the USER role (TPM 2.0 Part 1,
//     Section 19.7.5). A password on a policy-bound object counts only where
//     the policy asks for it with PolicyAuthValue.
//   - The platform policy gets its PolicyAuthValue branch only when the
//     object has a password. PolicyAuthValue proves knowledge of the
//     authValue, and an empty one is known to everyone.

// bindObjectPolicy applies keyAttrs' policy to the template of a new child
// object whose auth value is password (nil when it has none) and sets
// USERWITHAUTH to match:
//
//   - the platform policy: PolicyOR(PolicyPCR, PolicyAuthValue) with a
//     password, PolicyPCR alone without one, computed from a pin of the live
//     platform PCR that is returned so the caller can record it beside the
//     object's blobs;
//   - a named, authorized policy: see namedPolicyBinding, whose binding is
//     returned for the caller to record;
//   - no policy: the template is left as it is.
//
// Both returns are nil when the object has no such policy.
func (tpm *TPM2) bindObjectPolicy(
	keyAttrs *types.KeyAttributes,
	template *tpm2.TPMTPublic,
	password []byte) (*store.PlatformPolicyPin, *store.TPMPolicyBinding, error) {

	var pin *store.PlatformPolicyPin
	if keyAttrs.TPMPolicy == types.TPMPolicyPlatform {
		var err error
		pcrs, err := tpm.sealPCRSet(keyAttrs)
		if err != nil {
			return nil, nil, err
		}
		pin, err = tpm.capturePlatformPolicyPinOver(pcrs)
		if err != nil {
			return nil, nil, err
		}
		policyDigestFromPin := platformPolicyDigestFromPin
		if len(password) == 0 {
			policyDigestFromPin = platformPCRPolicyDigestFromPin
		}
		policyDigest, err := policyDigestFromPin(pin)
		if err != nil {
			return nil, nil, err
		}
		tpm.logger.Debug("tpm: binding object to the platform policy",
			slog.String("cn", keyAttrs.CN),
			slog.Bool("auth_value_branch", len(password) > 0),
			slog.String("policy_digest", fmt.Sprintf("%x", policyDigest.Buffer)),
			slog.String("pcr_digest", fmt.Sprintf("%x", pin.PCRDigest)))
		template.AuthPolicy = policyDigest
	}

	binding, err := tpm.namedPolicyBinding(keyAttrs, template)
	if err != nil {
		return nil, nil, err
	}
	restrictUserRole(template)
	return pin, binding, nil
}

// restrictUserRole sets USERWITHAUTH on a child object's template so its USER
// role answers only what protects the object: CLEAR when the object has an
// authPolicy -- the platform policy or a named policy -- so only a policy
// session satisfies it, and SET when it has none, so its
// auth value does.
func restrictUserRole(template *tpm2.TPMTPublic) {
	template.ObjectAttributes.UserWithAuth = len(template.AuthPolicy.Buffer) == 0
}

// objectSession returns the session that authorizes the USER role of the
// loaded child object at handle. The object itself, not the caller's
// attributes, decides which policy has to be satisfied, because
// bindObjectPolicy clears USERWITHAUTH on every object with a policy and no
// other authorization is then accepted:
//
//   - an object bound to a named policy is authorized through it;
//   - an IDevID or IAK through devidKeySession;
//   - an object with no authPolicy by its password alone;
//   - any other authPolicy is the platform policy: its PolicyAuthValue
//     branch when the caller presents a password, and otherwise the
//     PolicyPCR branch the object carries (platformPCRBranchSession).
//
// backend may be nil, in which case the platform backend is used.
func (tpm *TPM2) objectSession(
	keyAttrs *types.KeyAttributes,
	backend store.KeyBackend,
	handle tpm2.TPMHandle) (tpm2.Session, func() error, error) {

	binding, err := tpm.loadPolicyBinding(keyAttrs, backend)
	if err != nil {
		return nil, noopCloser, err
	}
	if binding != nil {
		return tpm.authorizedPolicySession(keyAttrs, binding)
	}
	if kind, isDevID := devidKeyKindOf(keyAttrs.KeyType); isDevID {
		return tpm.devidKeySession(kind, keyAttrs)
	}

	authPolicy, err := tpm.objectAuthPolicy(handle)
	if err != nil {
		return nil, noopCloser, err
	}
	if len(authPolicy) == 0 {
		return tpm.passwordKeySession(keyAttrs)
	}
	if keyAuthValue(keyAttrs) == nil {
		pcrs, err := tpm.objectPCRSet(keyAttrs, backend)
		if err != nil {
			return nil, noopCloser, err
		}
		return tpm.platformPCRBranchSessionOver(pcrs, authPolicy)
	}
	pcrs, err := tpm.objectPCRSet(keyAttrs, backend)
	if err != nil {
		return nil, noopCloser, err
	}
	return tpm.platformKeySessionOver(keyAttrs, backend, pcrs, authPolicy)
}

// platformKeySessionOver opens the password branch of an object sealed to
// the platform policy whose PolicyPCR branch covers pcrs. PolicyOR is built
// over the stored pin when it records the same selection; otherwise (no pin,
// as for inline blobs unsealed against an empty key backend, or a pin a later
// seal under the same CN wrote over another selection) over pcrs' live
// values, so an object sealed over an expanded selection still opens with its
// password while those PCRs are unchanged.
func (tpm *TPM2) platformKeySessionOver(
	keyAttrs *types.KeyAttributes,
	backend store.KeyBackend,
	pcrs PCRSet,
	authPolicy []byte) (tpm2.Session, func() error, error) {

	keyAuth := keyAuthValue(keyAttrs)
	if len(keyAuth) == 0 {
		return tpm.platformKeySession(keyAttrs, backend)
	}
	pin, err := tpm.loadPlatformPolicyPin(keyAttrs, backend)
	if err != nil {
		return nil, noopCloser, err
	}
	if pin != nil && pin.PCRSelect == pcrs.Mask() {
		return tpm.platformPolicySession(keyAuth, pin)
	}
	// A pin recorded over another selection still belongs to this object
	// when its PolicyOR is the object's authPolicy: an object sealed before
	// the expanded selection carries the platform set's policy, and the
	// recorded pin opens it.
	if pin != nil && len(authPolicy) > 0 {
		if recorded, err := platformPolicyDigestFromPin(pin); err == nil &&
			bytes.Equal(recorded.Buffer, authPolicy) {
			return tpm.platformPolicySession(keyAuth, pin)
		}
	}
	if pin == nil && pcrs.Mask() == tpm.config.PlatformPCRs.Mask() {
		return tpm.platformPolicySession(keyAuth, nil)
	}
	live, err := tpm.capturePlatformPolicyPinOver(pcrs)
	if err != nil {
		return nil, noopCloser, err
	}
	return tpm.platformPolicySession(keyAuth, live)
}

// objectAuthPolicy returns the authPolicy of the loaded object at handle,
// read back from the TPM so it describes the object actually loaded.
func (tpm *TPM2) objectAuthPolicy(handle tpm2.TPMHandle) ([]byte, error) {
	pub, err := tpm2.ReadPublic{ObjectHandle: handle}.Execute(tpm.transport)
	if err != nil {
		return nil, err
	}
	public, err := pub.OutPublic.Contents()
	if err != nil {
		return nil, err
	}
	return public.AuthPolicy.Buffer, nil
}

// platformPCRBranchSession returns the session that takes the PolicyPCR
// branch of an object or NV index bound to the platform policy whose
// authPolicy is authPolicy: a PolicyPCR session when authPolicy is the
// PolicyPCR branch alone, as for everything bound without a password, and
// the PCR branch of the platform PolicyOR otherwise.
//
// The choice is made against the live platform PCR. Once the PCR has moved
// neither form matches and the PolicyOR session is returned, which the TPM
// refuses with TPM_RC_POLICY_FAIL exactly as it would the PolicyPCR one. The
// choice only selects which session to build: the TPM still checks the
// session against the object, so a wrong choice can only fail.
func (tpm *TPM2) platformPCRBranchSession(authPolicy []byte) (tpm2.Session, func() error, error) {
	return tpm.platformPCRBranchSessionOver(tpm.config.PlatformPCRs, authPolicy)
}

// platformPCRBranchSessionOver is platformPCRBranchSession for an object
// whose PolicyPCR branch covers pcrs (sealPCRSet) rather than the configured
// platform set.
func (tpm *TPM2) platformPCRBranchSessionOver(pcrs PCRSet, authPolicy []byte) (tpm2.Session, func() error, error) {
	pin, err := tpm.capturePlatformPolicyPinOver(pcrs)
	if err != nil {
		return nil, noopCloser, err
	}
	pcrPolicy, err := platformPCRPolicyDigestFromPin(pin)
	if err != nil {
		return nil, noopCloser, err
	}
	if bytes.Equal(pcrPolicy.Buffer, authPolicy) {
		return tpm.platformPCRSessionOver(pcrs)
	}
	if pcrs.Mask() != tpm.config.PlatformPCRs.Mask() {
		// An object sealed with a recovery PIN over the expanded selection
		// carries PolicyOR(PolicyPCR(pcrs), PolicyAuthValue): open its PCR
		// branch over the same selection.
		orPolicy, err := platformPolicyDigestFromPin(pin)
		if err != nil {
			return nil, noopCloser, err
		}
		if bytes.Equal(orPolicy.Buffer, authPolicy) {
			return tpm.platformORPCRSessionOver(pcrs)
		}
		// An object whose PCRSelection is not part of its policy (an AK's
		// creation PCRs, say) keeps the platform set's session.
		return tpm.platformPCRBranchSession(authPolicy)
	}
	return tpm.PlatformPolicySession(nil)
}

// sealPCRSet returns the PCRs the PolicyPCR branch of an object sealed to
// the platform policy covers: the configured platform set joined with the
// caller's keyAttrs.TPMAttributes.PCRSelection (#2226). With no selection,
// or one inside the platform set, it is the platform set itself, so such an
// object's policy digest is unchanged. A selection in a bank other than the
// platform bank cannot join the platform PolicyPCR and is refused.
func (tpm *TPM2) sealPCRSet(keyAttrs *types.KeyAttributes) (PCRSet, error) {
	platform := tpm.config.PlatformPCRs
	if keyAttrs.TPMAttributes == nil ||
		len(keyAttrs.TPMAttributes.PCRSelection.PCRSelections) == 0 {
		return platform, nil
	}
	bank, err := ParsePCRBankAlgID(tpm.config.PlatformPCRBank)
	if err != nil {
		return nil, &errs.Detail{Err: ErrPlatformPolicyDigestCompute, Detail: fmt.Sprintf("%v", err)}
	}
	selection := keyAttrs.TPMAttributes.PCRSelection
	for _, s := range selection.PCRSelections {
		if s.Hash == bank {
			continue
		}
		for _, b := range s.PCRSelect {
			if b != 0 {
				return nil, &errs.Detail{
					Err: ErrPlatformPolicyDigestCompute,
					Detail: fmt.Sprintf("sealed PCR selection in bank 0x%04x, platform bank 0x%04x",
						uint16(s.Hash), uint16(bank)),
				}
			}
		}
	}
	union := platform.Mask() | pcrSetFromSelection(selection, bank).Mask()
	if union == platform.Mask() {
		return platform, nil
	}
	return PCRSetFromMask(union), nil
}

// objectPCRSet returns the PCRs the PolicyPCR branch of an existing object
// covers. A PCRSelection in the attributes wins: the caller named it, or
// applySealedPCRSelection recovered it from an inline blob's own metadata,
// and a pin under the same CN may be a later seal's. With no selection, the
// one recorded in the platform policy pin beside the object's blobs is used,
// so an Unseal whose attributes were reconstructed from the key ID still
// opens an object sealed over an extra PCR; the digest is computed from the
// live values of those PCRs. With neither, it is the platform PCR set.
func (tpm *TPM2) objectPCRSet(keyAttrs *types.KeyAttributes, backend store.KeyBackend) (PCRSet, error) {
	// A selection in the attributes (the caller's, or an inline blob's own
	// recovered by applySealedPCRSelection) belongs to this object; a pin
	// stored under the CN may belong to a later seal that overwrote it.
	if keyAttrs.TPMAttributes != nil &&
		len(keyAttrs.TPMAttributes.PCRSelection.PCRSelections) > 0 {
		return tpm.sealPCRSet(keyAttrs)
	}
	// The pin only names the selection here: the PCR branch never depends
	// on its digest, so an unreadable record falls back to the caller's
	// selection and the TPM decides.
	pin, err := tpm.loadPlatformPolicyPin(keyAttrs, backend)
	if err != nil {
		tpm.logger.Debug("tpm: platform policy pin unreadable; using the requested PCR selection",
			slog.String("cn", keyAttrs.CN), slog.String("error", err.Error()))
		pin = nil
	}
	if pin != nil && pin.PCRSelect != 0 {
		bank, err := ParsePCRBankAlgID(tpm.config.PlatformPCRBank)
		if err == nil && uint16(bank) == pin.PCRBank {
			return PCRSetFromMask(pin.PCRSelect), nil
		}
	}
	return tpm.sealPCRSet(keyAttrs)
}

// platformPCRPolicyDigest returns the PolicyPCR branch of the platform
// policy over the platform PCR as it reads now: the authPolicy of an object
// or NV index bound to the platform policy without a password.
func (tpm *TPM2) platformPCRPolicyDigest() (tpm2.TPM2BDigest, error) {
	pin, err := tpm.capturePlatformPolicyPin()
	if err != nil {
		return tpm2.TPM2BDigest{}, err
	}
	return platformPCRPolicyDigestFromPin(pin)
}
