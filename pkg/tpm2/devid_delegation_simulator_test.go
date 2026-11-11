//go:build tpm_simulator

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
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/testutil/secrettest"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests exercise Delegated Usage of a Recoverable IDevID/IAK Key, TCG
// "TPM 2.0 Keys for Device Identity and Attestation" v1.00 r12 section 7.3,
// against the TPM simulator: the Owner defines the Policy NV Index to
// Template I-1 (section 7.3.5), the Privacy Administrator writes a Delegation
// Policy into it (section 7.2.4), and a delegated entity then uses the key
// through TPM2_PolicyAuthorizeNV -- or is refused when the index holds some
// other policy, or the platform state the policy names has moved.

// delegationHarness is a provisioned simulator that owns an IAK and an RSASSA
// IDevID, with the endorsement/owner authorization Provision set.
type delegationHarness struct {
	*simHarness
	IAK           *types.KeyAttributes
	IDevID        *types.KeyAttributes
	IDevIDPublic  *rsa.PublicKey
	IDevIDName    tpm2.TPM2BName
	HierarchyAuth []byte
}

func newDelegationHarness(t *testing.T, mutate func(*Config)) *delegationHarness {
	t.Helper()
	h := newSimHarness(t, func(c *Config) {
		c.IdentityProvisioningStrategy = string(EnrollmentStrategyIAK_IDEVID_SINGLE_PASS)
		c.IAK.SignatureAlgorithm = x509.SHA256WithRSA.String()
		c.IDevID = idevidTestConfig("device-id-001", x509.SHA256WithRSA.String())
		if mutate != nil {
			mutate(c)
		}
	})
	iakAttrs, err := h.TPM.IAKAttributes()
	require.NoError(t, err)
	ekPub, err := h.TPM.EKRSA()
	require.NoError(t, err)
	idevidAttrs, _, err := h.TPM.CreateIDevID(iakAttrs, selfSignedCertForKey(t, ekPub), nil)
	require.NoError(t, err, "the TPM must be able to mint an IDevID")

	readPub, err := tpm2.ReadPublic{ObjectHandle: idevidAttrs.TPMAttributes.Handle}.Execute(h.TPM.transport)
	require.NoError(t, err)

	require.NotNil(t, iakAttrs.Parent)
	var hierarchyAuth []byte
	if iakAttrs.Parent.TPMAttributes != nil && iakAttrs.Parent.TPMAttributes.HierarchyAuth != nil {
		hierarchyAuth = iakAttrs.Parent.TPMAttributes.HierarchyAuth.Bytes()
	}
	return &delegationHarness{
		simHarness:    h,
		IAK:           iakAttrs,
		IDevID:        idevidAttrs,
		IDevIDPublic:  rsaPublicKeyOf(t, idevidAttrs),
		IDevIDName:    readPub.Name,
		HierarchyAuth: hierarchyAuth,
	}
}

// readPolicyNV reads the Policy NV Index's public area and, when written, its
// payload, through the index's own empty authValue (TPMA_NV_AUTHREAD).
func (h *delegationHarness) readPolicyNV(t *testing.T, kind DevIDKeyKind) (*tpm2.TPMSNVPublic, tpm2.TPM2BName, []byte) {
	t.Helper()
	index, err := DevIDPolicyNVIndex(kind, tpm2.TPMAlgSHA256)
	require.NoError(t, err)
	rsp, err := tpm2.NVReadPublic{NVIndex: index}.Execute(h.TPM.transport)
	require.NoError(t, err, "the Policy NV Index must exist")
	public, err := rsp.NVPublic.Contents()
	require.NoError(t, err)
	if !public.Attributes.Written {
		return public, rsp.NVName, nil
	}
	read, err := tpm2.NVRead{
		AuthHandle: tpm2.AuthHandle{Handle: index, Name: rsp.NVName, Auth: tpm2.PasswordAuth(nil)},
		NVIndex:    tpm2.NamedHandle{Handle: index, Name: rsp.NVName},
		Size:       public.DataSize,
	}.Execute(h.TPM.transport)
	require.NoError(t, err, "Template I-0 makes the index readable with its authValue")
	return public, rsp.NVName, read.Data.Buffer
}

// signIDevID issues TPM2_Sign on the IDevID under the given authorization,
// the way (*TPM2).Sign does for an unrestricted RSASSA key.
func (h *delegationHarness) signIDevID(auth tpm2.Session, digest []byte) ([]byte, error) {
	rsp, err := tpm2.Sign{
		KeyHandle: tpm2.AuthHandle{
			Handle: h.IDevID.TPMAttributes.Handle,
			Name:   h.IDevIDName,
			Auth:   auth,
		},
		Digest: tpm2.TPM2BDigest{Buffer: digest},
		InScheme: tpm2.TPMTSigScheme{
			Scheme:  tpm2.TPMAlgRSASSA,
			Details: tpm2.NewTPMUSigScheme(tpm2.TPMAlgRSASSA, &tpm2.TPMSSchemeHash{HashAlg: tpm2.TPMAlgSHA256}),
		},
		Validation: tpm2.TPMTTKHashCheck{Tag: tpm2.TPMSTHashCheck},
	}.Execute(h.TPM.transport)
	if err != nil {
		return nil, err
	}
	sig, err := rsp.Signature.Signature.RSASSA()
	if err != nil {
		return nil, err
	}
	return sig.Sig.Buffer, nil
}

func unwrittenPolicyNVName(t *testing.T, kind DevIDKeyKind) []byte {
	t.Helper()
	public, err := DevIDPolicyNVPublic(kind, tpm2.TPMAlgSHA256)
	require.NoError(t, err)
	public.Attributes.Written = false
	name, err := tpm2.NVName(&public)
	require.NoError(t, err)
	return name.Buffer
}

// Section 7.3.5: the Owner defines the index to Template I-1 under Owner
// authorization; section 7.3.6.5 / Table 18: once written its Name is the
// one the key policy was computed over. Defining twice is harmless.
func TestDefineDevIDPolicyNV_DefinesTemplateI1AndIsIdempotent(t *testing.T) {
	h := newDelegationHarness(t, nil)

	require.NoError(t, h.TPM.DefineDevIDPolicyNV(DevIDKeySigning, tpm2.TPMAlgSHA256, h.HierarchyAuth))

	public, name, payload := h.readPolicyNV(t, DevIDKeySigning)
	want, err := DevIDPolicyNVPublic(DevIDKeySigning, tpm2.TPMAlgSHA256)
	require.NoError(t, err)
	assert.Equal(t, want.NVIndex, public.NVIndex)
	assert.Equal(t, want.DataSize, public.DataSize, "dataSize 0x0022: a TPMT_HA")
	assert.Equal(t, want.AuthPolicy.Buffer, public.AuthPolicy.Buffer, "authPolicy is PolicyUser")
	assert.False(t, public.Attributes.Written, "nothing has been written yet")
	wantAttrs := want.Attributes
	wantAttrs.Written = false
	assert.Equal(t, wantAttrs, public.Attributes, "TPMA_NV 0x220F1008 less the WRITTEN bit the TPM owns")
	assert.Equal(t, unwrittenPolicyNVName(t, DevIDKeySigning), name.Buffer)
	assert.Nil(t, payload)

	require.NoError(t, h.TPM.DefineDevIDPolicyNV(DevIDKeySigning, tpm2.TPMAlgSHA256, h.HierarchyAuth),
		"defining an index that already matches the template is not an error")

	delegation, err := DevIDSigningDelegation(tpm2.TPMAlgSHA256, tpm2.TPMCCSign)
	require.NoError(t, err)
	require.NoError(t, h.TPM.WriteDevIDDelegationPolicy(DevIDKeySigning, tpm2.TPMAlgSHA256, delegation.Digest, h.HierarchyAuth))

	public, name, payload = h.readPolicyNV(t, DevIDKeySigning)
	assert.True(t, public.Attributes.Written)
	assert.Equal(t, mustHex(t, tcgPolicyIndexNameSHA256[DevIDKeySigning]), name.Buffer,
		"once written, the index carries the Table 18 Name the PolicyDelegationNV branch was computed over")
	assert.Equal(t, mustHex(t, tcgSigningDelegationPolicy[tpm2.TPMAlgSHA256]), payload,
		"the index holds Table 20's Signing Delegation Policy with its leading hash ID")

	require.NoError(t, h.TPM.DefineDevIDPolicyNV(DevIDKeySigning, tpm2.TPMAlgSHA256, h.HierarchyAuth),
		"a written index with the specification's Name is accepted as-is")
}

// One attribute bit away from Template I-0 is a different Name, and a
// different Name can never satisfy PolicyAuthorizeNV for this key. The index
// is refused, for defining and for writing, rather than silently written.
func TestDefineDevIDPolicyNV_RefusesAnIndexWithAForeignPublicArea(t *testing.T) {
	h := newDelegationHarness(t, nil)

	foreign, err := DevIDPolicyNVPublic(DevIDKeySigning, tpm2.TPMAlgSHA256)
	require.NoError(t, err)
	foreign.Attributes.Written = false
	foreign.Attributes.OwnerWrite = true
	_, err = tpm2.NVDefineSpace{
		AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(h.HierarchyAuth)},
		PublicInfo: tpm2.New2B(foreign),
	}.Execute(h.TPM.transport)
	require.NoError(t, err, "test setup: an index at DS1 with TPMA_NV_OWNERWRITE set")

	err = h.TPM.DefineDevIDPolicyNV(DevIDKeySigning, tpm2.TPMAlgSHA256, h.HierarchyAuth)
	assert.ErrorIs(t, err, ErrDevIDPolicyNVIndex)

	delegation, err := DevIDSigningDelegation(tpm2.TPMAlgSHA256, tpm2.TPMCCSign)
	require.NoError(t, err)
	err = h.TPM.WriteDevIDDelegationPolicy(DevIDKeySigning, tpm2.TPMAlgSHA256, delegation.Digest, h.HierarchyAuth)
	assert.ErrorIs(t, err, ErrDevIDPolicyNVIndex, "nothing is written into an index that cannot delegate the key")

	public, _, _ := h.readPolicyNV(t, DevIDKeySigning)
	assert.False(t, public.Attributes.Written, "the foreign index was left untouched")
}

// "a Policy NV Index MAY be defined by the device Owner using Owner
// Authorization" (section 7.3.5) -- and by nobody else.
func TestDefineDevIDPolicyNV_RequiresOwnerAuth(t *testing.T) {
	h := newDelegationHarness(t, nil)

	err := h.TPM.DefineDevIDPolicyNV(DevIDKeySigning, tpm2.TPMAlgSHA256, append([]byte("not-"), h.HierarchyAuth...))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDevIDDelegation)

	index, err := DevIDPolicyNVIndex(DevIDKeySigning, tpm2.TPMAlgSHA256)
	require.NoError(t, err)
	_, err = tpm2.NVReadPublic{NVIndex: index}.Execute(h.TPM.transport)
	assert.Error(t, err, "the refusal left nothing defined")

	_, _, err = h.TPM.DevIDDelegatedSession(DevIDKeySigning, tpm2.TPMAlgSHA256, DevIDDelegation{NameAlg: tpm2.TPMAlgSHA384})
	assert.ErrorIs(t, err, ErrDevIDPolicySession, "a delegation in another algorithm cannot reach a SHA256 key policy")
	_, _, err = h.TPM.DevIDDelegatedSession(DevIDKeySigning, tpm2.TPMAlgSHA256, DevIDDelegation{NameAlg: tpm2.TPMAlgSHA256})
	assert.ErrorIs(t, err, ErrDevIDPolicySession, "a delegation with nothing to satisfy is refused before a session opens")
}

// Only the Privacy Administrator writes the Delegation Policy (section
// 7.3.1: "the NV Index can be written only with Privacy Administrator
// authorization (TPM2_PolicySecret for the Endorsement Hierarchy)").
func TestWriteDevIDDelegationPolicy_RequiresTheEndorsementAuth(t *testing.T) {
	h := newDelegationHarness(t, nil)
	delegation, err := DevIDSigningDelegation(tpm2.TPMAlgSHA256, tpm2.TPMCCSign)
	require.NoError(t, err)

	err = h.TPM.WriteDevIDDelegationPolicy(DevIDKeySigning, tpm2.TPMAlgSHA256, delegation.Digest, h.HierarchyAuth)
	assert.ErrorIs(t, err, ErrDevIDDelegation, "an index that was never defined cannot be written")

	require.NoError(t, h.TPM.DefineDevIDPolicyNV(DevIDKeySigning, tpm2.TPMAlgSHA256, h.HierarchyAuth))

	err = h.TPM.WriteDevIDDelegationPolicy(DevIDKeySigning, tpm2.TPMAlgSHA256, delegation.Digest, append([]byte("not-"), h.HierarchyAuth...))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDevIDDelegation)

	err = h.TPM.WriteDevIDDelegationPolicy(DevIDKeySigning, tpm2.TPMAlgSHA256, delegation.Digest[:31], h.HierarchyAuth)
	assert.ErrorIs(t, err, ErrDevIDPolicyDigestCompute, "a digest of the wrong size is not a TPMT_HA for this index")

	public, _, _ := h.readPolicyNV(t, DevIDKeySigning)
	assert.False(t, public.Attributes.Written, "every refusal left the index unwritten")
}

// Section 7.3: "any entity authorized by that Delegation Policy can use the
// recreated IDevID/IAK key." With Table 20's Signing Delegation Policy in
// the index, a session that asserts PolicyCommandCode(Sign) signs; the same
// session cannot do anything else, and a session for a different command
// set does not reach the index's digest at all.
func TestDevIDDelegatedSession_SignsUnderTheDelegationPolicy(t *testing.T) {
	h := newDelegationHarness(t, nil)
	require.NoError(t, h.TPM.DefineDevIDPolicyNV(DevIDKeySigning, tpm2.TPMAlgSHA256, h.HierarchyAuth))
	signing, err := DevIDSigningDelegation(tpm2.TPMAlgSHA256, tpm2.TPMCCSign)
	require.NoError(t, err)
	require.NoError(t, h.TPM.WriteDevIDDelegationPolicy(DevIDKeySigning, tpm2.TPMAlgSHA256, signing.Digest, h.HierarchyAuth))

	digest := sha256.Sum256([]byte("delegated signing"))

	session, closer, err := h.TPM.DevIDDelegatedSession(DevIDKeySigning, tpm2.TPMAlgSHA256, signing)
	require.NoError(t, err, "the delegated session must reach the key policy through PolicyAuthorizeNV")
	defer func() { _ = closer() }()

	signature, err := h.signIDevID(session, digest[:])
	require.NoError(t, err, "the IDevID must sign under the delegated USER role")
	assert.NoError(t, rsa.VerifyPKCS1v15(h.IDevIDPublic, crypto.SHA256, digest[:], signature))

	t.Run("a session for another command in the same policy cannot sign", func(t *testing.T) {
		certifyOnly, err := DevIDSigningDelegation(tpm2.TPMAlgSHA256, tpm2.TPMCCCertify)
		require.NoError(t, err)
		session, closer, err := h.TPM.DevIDDelegatedSession(DevIDKeySigning, tpm2.TPMAlgSHA256, certifyOnly)
		require.NoError(t, err, "Certify is admitted by the policy, so the session builds")
		defer func() { _ = closer() }()
		_, err = h.signIDevID(session, digest[:])
		require.Error(t, err)
		assert.ErrorIs(t, err, tpm2.TPMRCPolicyCC, "the command code in the session confines it")
	})

	t.Run("a session for a policy the index does not hold is refused", func(t *testing.T) {
		quoteOnly, err := DevIDCommandDelegation(tpm2.TPMAlgSHA256, tpm2.TPMCCQuote, tpm2.TPMCCQuote)
		require.NoError(t, err)
		_, closer, err := h.TPM.DevIDDelegatedSession(DevIDKeySigning, tpm2.TPMAlgSHA256, quoteOnly)
		if closer != nil {
			_ = closer()
		}
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrDevIDPolicySession)
		assert.ErrorIs(t, err, tpm2.TPMRCValue, "PolicyAuthorizeNV compares the session digest to the index and refuses")
	})
}

// The Privacy Administrator replaces the Delegation Policy at will (section
// 7.3.1). Once the index holds the attestation policy, the signing
// delegation that used to work is refused -- the index, not the key, decides.
func TestDevIDDelegatedSession_IsRefusedWhenTheIndexHoldsAnotherPolicy(t *testing.T) {
	h := newDelegationHarness(t, nil)
	require.NoError(t, h.TPM.DefineDevIDPolicyNV(DevIDKeySigning, tpm2.TPMAlgSHA256, h.HierarchyAuth))
	signing, err := DevIDSigningDelegation(tpm2.TPMAlgSHA256, tpm2.TPMCCSign)
	require.NoError(t, err)
	require.NoError(t, h.TPM.WriteDevIDDelegationPolicy(DevIDKeySigning, tpm2.TPMAlgSHA256, signing.Digest, h.HierarchyAuth))

	session, closer, err := h.TPM.DevIDDelegatedSession(DevIDKeySigning, tpm2.TPMAlgSHA256, signing)
	require.NoError(t, err)
	require.NoError(t, closer())
	require.NotNil(t, session)

	attestation, err := DevIDAttestationDelegation(tpm2.TPMAlgSHA256, tpm2.TPMCCQuote)
	require.NoError(t, err)
	require.NoError(t, h.TPM.WriteDevIDDelegationPolicy(DevIDKeySigning, tpm2.TPMAlgSHA256, attestation.Digest, h.HierarchyAuth),
		"the Privacy Administrator may replace the Delegation Policy at any time")
	_, _, payload := h.readPolicyNV(t, DevIDKeySigning)
	assert.Equal(t, mustHex(t, tcgAttestationDelegationPolicy[tpm2.TPMAlgSHA256]), payload)

	_, closer, err = h.TPM.DevIDDelegatedSession(DevIDKeySigning, tpm2.TPMAlgSHA256, signing)
	if closer != nil {
		_ = closer()
	}
	require.Error(t, err, "the signing delegation no longer matches what the index holds")
	assert.ErrorIs(t, err, ErrDevIDPolicySession)
	assert.ErrorIs(t, err, tpm2.TPMRCValue)
}

// Section 7.2.4 keeps the authValue as a USER-role path on Template H-0
// whatever the index holds. A configured password is therefore used in
// preference to the delegation, and keeps signing after the platform moves;
// making platform state the only path means giving the key an authValue
// nobody knows, which is the Owner's choice, not this library's.
func TestCreateIDevID_PlatformPolicyKeepsTheAuthValuePath(t *testing.T) {
	h := newDelegationHarness(t, func(c *Config) {
		c.IDevID.PlatformPolicy = true
		c.IDevID.Password = secrettest.Literal(t, []byte("idevid-user-secret"))

	})
	public, _, _ := h.readPolicyNV(t, DevIDKeySigning)
	require.True(t, public.Attributes.Written, "the delegation is provisioned regardless of the password")

	h.extendPlatformPCR(t, []byte("post-update-measurement"))

	digest := sha256.Sum256([]byte("password signing"))
	signature, err := h.TPM.Sign(rand.Reader, digest[:], &store.SignerOpts{KeyAttributes: h.IDevID, Backend: h.Backend})
	require.NoError(t, err, "the authValue authorizes the USER role on its own (section 7.2.4)")
	assert.NoError(t, rsa.VerifyPKCS1v15(h.IDevIDPublic, crypto.SHA256, digest[:], signature))

	wrong := *h.IDevID
	wrong.Password = mustPassword(t, []byte("not-the-secret"))
	_, err = h.TPM.Sign(rand.Reader, digest[:], &store.SignerOpts{KeyAttributes: &wrong, Backend: h.Backend})
	require.Error(t, err, "a wrong authValue does not fall back to anything")
}

// The same provisioning rule for the IAK: PlatformPolicy writes PolicyPCR
// into DA1, and a Quote is authorized through the delegated session until
// the platform moves, after which the index no longer matches.
func TestCreateIAK_PlatformPolicyProvisionsThePlatformDelegation(t *testing.T) {
	h := newDelegationHarness(t, func(c *Config) { c.IAK.PlatformPolicy = true })

	public, name, payload := h.readPolicyNV(t, DevIDKeyAttestation)
	require.True(t, public.Attributes.Written, "provisioning wrote the IAK Delegation Policy")
	assert.Equal(t, mustHex(t, tcgPolicyIndexNameSHA256[DevIDKeyAttestation]), name.Buffer)
	platform, err := h.TPM.DevIDPlatformDelegation(tpm2.TPMAlgSHA256)
	require.NoError(t, err)
	wantPayload, err := DevIDDelegationPolicyPayload(tpm2.TPMAlgSHA256, platform.Digest)
	require.NoError(t, err)
	assert.Equal(t, wantPayload, payload)

	quote := func(auth tpm2.Session) error {
		_, err := tpm2.Quote{
			SignHandle: tpm2.AuthHandle{
				Handle: h.IAK.TPMAttributes.Handle,
				Name:   h.IAK.TPMAttributes.Name,
				Auth:   auth,
			},
			QualifyingData: tpm2.TPM2BData{Buffer: []byte("nonce")},
			InScheme:       tpm2.TPMTSigScheme{Scheme: tpm2.TPMAlgNull},
			PCRSelect: tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{{
				Hash:      tpm2.TPMAlgSHA256,
				PCRSelect: tpm2.PCClientCompatible.PCRs(0),
			}}},
		}.Execute(h.TPM.transport)
		return err
	}

	session, closer, err := h.TPM.DevIDDelegatedSession(DevIDKeyAttestation, tpm2.TPMAlgSHA256, platform)
	require.NoError(t, err)
	assert.NoError(t, quote(session), "the IAK quotes under the platform delegation")
	require.NoError(t, closer())

	h.extendPlatformPCR(t, []byte("post-update-measurement"))

	_, closer, err = h.TPM.DevIDDelegatedSession(DevIDKeyAttestation, tpm2.TPMAlgSHA256, platform)
	if closer != nil {
		_ = closer()
	}
	require.Error(t, err, "the recorded platform state no longer matches the PCR")
	assert.ErrorIs(t, err, ErrDevIDPolicySession)
}

// The IAK half of the same rule: IAKAttributes' cold-cache rebuild keeps
// platform-policy, CreateKeySession hands out the delegated session for the
// rebuilt key, and that session no longer builds once the platform moves.
func TestIAKAttributes_ColdCacheKeepsPlatformPolicy(t *testing.T) {
	h := newDelegationHarness(t, func(c *Config) { c.IAK.PlatformPolicy = true })
	require.True(t, (h.IAK.TPMPolicy == types.TPMPolicyPlatform), "provisioning recorded platform-policy")

	h.TPM.iakAttrs = nil // the cold cache a restarted process sees
	cold, err := h.TPM.IAKAttributes()
	require.NoError(t, err)
	assert.True(t, (cold.TPMPolicy == types.TPMPolicyPlatform),
		"a rebuild from configuration must keep platform-policy, or the binding is lost on restart")

	quote := func(auth tpm2.Session) error {
		_, err := tpm2.Quote{
			SignHandle: tpm2.AuthHandle{
				Handle: cold.TPMAttributes.Handle,
				Name:   cold.TPMAttributes.Name,
				Auth:   auth,
			},
			QualifyingData: tpm2.TPM2BData{Buffer: []byte("nonce")},
			InScheme:       tpm2.TPMTSigScheme{Scheme: tpm2.TPMAlgNull},
			PCRSelect: tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{{
				Hash:      tpm2.TPMAlgSHA256,
				PCRSelect: tpm2.PCClientCompatible.PCRs(0),
			}}},
		}.Execute(h.TPM.transport)
		return err
	}

	session, closer, err := h.TPM.CreateKeySession(cold)
	require.NoError(t, err, "the rebuilt IAK's session is the platform delegation")
	assert.NoError(t, quote(session), "the IAK quotes under the delegation after a restart")
	require.NoError(t, closer())

	h.extendPlatformPCR(t, []byte("post-update-measurement"))

	_, closer, err = h.TPM.CreateKeySession(cold)
	if closer != nil {
		_ = closer()
	}
	require.Error(t, err, "after a restart the moved platform must still be refused")
	assert.ErrorIs(t, err, ErrDevIDPolicySession)
}
