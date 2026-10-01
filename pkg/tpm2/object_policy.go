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
		pin, err = tpm.capturePlatformPolicyPin()
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
		return tpm.platformPCRBranchSession(authPolicy)
	}
	return tpm.platformKeySession(keyAttrs, backend)
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
	pcrPolicy, err := tpm.platformPCRPolicyDigest()
	if err != nil {
		return nil, noopCloser, err
	}
	if bytes.Equal(pcrPolicy.Buffer, authPolicy) {
		return tpm.platformPCRSession()
	}
	return tpm.PlatformPolicySession(nil)
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
