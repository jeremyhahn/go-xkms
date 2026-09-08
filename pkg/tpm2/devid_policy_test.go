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
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every value in this file is copied from TCG "TPM 2.0 Keys for Device
// Identity and Attestation", Version 1.00, Revision 12, section 7.3.6,
// Tables 14 through 19. The tests pin go-tpm's trial-policy arithmetic to
// the specification's published results: two independent implementations of
// TPM2_PolicyUpdate must agree, or the key policy this package attaches to
// every IDevID and IAK is not the one the specification defines.
//
// The reference document is checked in at
// docs/references/TCG-TPM-2.0-Keys-for-Device-Identity-and-Attestation-v1.00-r12.pdf.

// Table 14 - PolicyUser values.
var tcgPolicyUser = map[tpm2.TPMAlgID]string{
	tpm2.TPMAlgSHA256: "837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1da1b331469aa",
	tpm2.TPMAlgSHA384: "8bbf2266537c171cb56e403c4dc1d4b64f432611dc386e6f532050c3278c930e143e8bb1133824ccb431053871c6db53",
	tpm2.TPMAlgSHA512: "1e3b76502c8a1425aa0b7b3fc646a1b0fae063b03b5368f9c4cddecaff0891dd682bac1a85d4d832b781ea451915de5fc5bf0dc4a1917cd42fa041e3f998e0ee",
}

// Table 15 - PolicyCertify values.
var tcgPolicyCertify = map[tpm2.TPMAlgID]string{
	tpm2.TPMAlgSHA256: "b2a69e6391e2684a0fe752d39e14acd2e5cb922e4bd035830eea31f2aabe9870",
	tpm2.TPMAlgSHA384: "ad6007596907528f059a6121a5293c8ea3539f025640bc0920e1c9f779085934ef907a94469e25df22dbec6663b4f128",
	tpm2.TPMAlgSHA512: "bdcf7b666007254939c5fa725cb876e94ac17e033d9335a3f40267abc35b1e3e323597cd1585d991aee2d6a20e3322eae8b6f87b12953248aeb7441c01f12e60",
}

// Table 16 - PolicyActivateCredential values.
var tcgPolicyActivateCredential = map[tpm2.TPMAlgID]string{
	tpm2.TPMAlgSHA256: "cd9917cf18c3848c3a2e606986a066c68142f9bc2710a278287a650ca3bbf245",
	tpm2.TPMAlgSHA384: "0a55d64c633cff7b4c782ee5464d0868a8c4d18d636f2d91f0cfc7b1beaadc1edeb6b4f545aace6d5c5cfc80c0a82492",
	tpm2.TPMAlgSHA512: "d291c51ea9eeabad3d858c6f4fd8bcb385e357598ff95d225405041df9ea50563f2a1c1942cb4a955ad89a6684c57365e64b208b059e188d6170825d91778342",
}

// Table 18 - NV Index Policy Names, SHA256 rows.
var tcgPolicyIndexNameSHA256 = map[DevIDKeyKind]string{
	DevIDKeySigning:     "000bd910fb32da43317c5e7780c0ef8c4d92d9c13505267ce1fa27acc9f9478ac412",
	DevIDKeyAttestation: "000bfa2483df71a51f073fb0480b78cea608af43fa6e0fe584a570bcdb26a7dc4a74",
}

// Table 17 - Policy Authorize NV values, SHA256 rows.
var tcgPolicyDelegationNVSHA256 = map[DevIDKeyKind]string{
	DevIDKeySigning:     "629c50b05f1adb5b4297feb241549d4217a1c792c162feb861022def88fa9501",
	DevIDKeyAttestation: "101e689dadf145222412c05b76e14532af1e5c74208e0ae7cdb0cff1906c8a09",
}

// Table 19 - IDevID/IAK Key Policy values, SHA256 rows.
var tcgKeyPolicySHA256 = map[DevIDKeyKind]string{
	DevIDKeySigning:     "ad6b3a2284fd698a0710bf5cc1b9bdf15e2532e3f601fa4b93a6a8fa8de579ea",
	DevIDKeyAttestation: "5437182326e414fca797d5f174615a1641f61255797c3a2b22c21d120b2d1e07",
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err, "test vector must be valid hex: %q", s)
	return b
}

func TestDevIDPolicyUserDigest_MatchesTCGTable14(t *testing.T) {
	for alg, want := range tcgPolicyUser {
		t.Run(fmt.Sprintf("0x%04x", uint16(alg)), func(t *testing.T) {
			got, err := DevIDPolicyUserDigest(alg)
			require.NoError(t, err)
			assert.Equal(t, mustHex(t, want), got,
				"PolicyUser must equal H(Zero || TPM_CC_PolicySecret || TPM_RH_ENDORSEMENT) then H(that)")
		})
	}
}

func TestDevIDPolicyCertifyDigest_MatchesTCGTable15(t *testing.T) {
	for alg, want := range tcgPolicyCertify {
		t.Run(fmt.Sprintf("0x%04x", uint16(alg)), func(t *testing.T) {
			got, err := DevIDPolicyCertifyDigest(alg)
			require.NoError(t, err)
			assert.Equal(t, mustHex(t, want), got,
				"PolicyCertify must extend PolicyUser with TPM2_PolicyCommandCode(TPM_CC_Certify)")
		})
	}
}

func TestDevIDPolicyActivateCredentialDigest_MatchesTCGTable16(t *testing.T) {
	for alg, want := range tcgPolicyActivateCredential {
		t.Run(fmt.Sprintf("0x%04x", uint16(alg)), func(t *testing.T) {
			got, err := DevIDPolicyActivateCredentialDigest(alg)
			require.NoError(t, err)
			assert.Equal(t, mustHex(t, want), got,
				"PolicyActivateCredential must extend PolicyUser with TPM2_PolicyCommandCode(TPM_CC_ActivateCredential)")
		})
	}
}

func TestDevIDPolicyNVName_MatchesTCGTable18(t *testing.T) {
	for kind, want := range tcgPolicyIndexNameSHA256 {
		t.Run(kind.String(), func(t *testing.T) {
			got, err := DevIDPolicyNVName(kind, tpm2.TPMAlgSHA256)
			require.NoError(t, err)
			assert.Equal(t, mustHex(t, want), got.Buffer,
				"the Policy NV Index Name must be nameAlg || H(nvIndex || nameAlg || 0x220F1008 || authPolicy || dataSize)")
		})
	}
}

func TestDevIDPolicyDelegationNVDigest_MatchesTCGTable17(t *testing.T) {
	for kind, want := range tcgPolicyDelegationNVSHA256 {
		t.Run(kind.String(), func(t *testing.T) {
			got, err := DevIDPolicyDelegationNVDigest(kind, tpm2.TPMAlgSHA256)
			require.NoError(t, err)
			assert.Equal(t, mustHex(t, want), got,
				"PolicyDelegationNV must equal H(Zero || TPM_CC_PolicyAuthorizeNV || Name of the Policy NV Index)")
		})
	}
}

func TestDevIDKeyPolicyDigest_MatchesTCGTable19(t *testing.T) {
	for kind, want := range tcgKeyPolicySHA256 {
		t.Run(kind.String(), func(t *testing.T) {
			got, err := DevIDKeyPolicyDigest(kind, tpm2.TPMAlgSHA256)
			require.NoError(t, err)
			assert.Equal(t, mustHex(t, want), got,
				"the IDevID/IAK Key Policy must be TPM2_PolicyOR over User, Certify, ActivateCredential, DelegationNV in that order")
		})
	}
}

// The two key kinds differ only in their Policy NV Index, so their key
// policies must differ and their first three branches must be identical.
func TestDevIDKeyPolicyBranches_KindsShareAllButTheDelegationBranch(t *testing.T) {
	signing, err := DevIDKeyPolicyBranches(DevIDKeySigning, tpm2.TPMAlgSHA256)
	require.NoError(t, err)
	attest, err := DevIDKeyPolicyBranches(DevIDKeyAttestation, tpm2.TPMAlgSHA256)
	require.NoError(t, err)
	require.Len(t, signing.Digests, 4)
	require.Len(t, attest.Digests, 4)
	for i := 0; i < 3; i++ {
		assert.Equal(t, signing.Digests[i].Buffer, attest.Digests[i].Buffer,
			"branch %d does not depend on the key kind", i+1)
	}
	assert.NotEqual(t, signing.Digests[3].Buffer, attest.Digests[3].Buffer,
		"the DelegationNV branch is bound to a kind-specific NV index")
}

func TestDevIDPolicyNVPublic_IsTemplateI1(t *testing.T) {
	public, err := DevIDPolicyNVPublic(DevIDKeySigning, tpm2.TPMAlgSHA256)
	require.NoError(t, err)
	assert.Equal(t, tpm2.TPMHandle(0x01C90010), public.NVIndex, "DS1")
	assert.Equal(t, tpm2.TPMAlgSHA256, public.NameAlg)
	assert.Equal(t, uint16(0x0022), public.DataSize,
		"section 7.3.6.5: dataSize is a TPMT_HA, two bytes of hash ID plus one SHA256 digest")
	assert.Equal(t, mustHex(t, tcgPolicyUser[tpm2.TPMAlgSHA256]), public.AuthPolicy.Buffer,
		"the index's own authPolicy is PolicyUser, so only the Privacy Administrator can write it")

	// TPMA_NV 0x220F1008 (Table 9), bit by bit.
	a := public.Attributes
	assert.True(t, a.PolicyWrite && a.WriteAll && a.PPRead && a.OwnerRead && a.AuthRead && a.PolicyRead && a.NoDA && a.Written,
		"the set bits of 0x220F1008")
	assert.False(t, a.PPWrite || a.OwnerWrite || a.AuthWrite || a.PolicyDelete || a.WriteLocked || a.WriteDefine ||
		a.WriteSTClear || a.GlobalLock || a.Orderly || a.ClearSTClear || a.ReadLocked || a.PlatformCreate || a.ReadSTClear,
		"the clear bits of 0x220F1008")
	assert.Equal(t, tpm2.TPMNTOrdinary, a.NT)
}

func TestDevIDPolicyNVIndex_CoversEveryTemplateAndRefusesTheRest(t *testing.T) {
	cases := []struct {
		kind DevIDKeyKind
		alg  tpm2.TPMAlgID
		want tpm2.TPMHandle
	}{
		{DevIDKeySigning, tpm2.TPMAlgSHA256, 0x01C90010},
		{DevIDKeySigning, tpm2.TPMAlgSHA384, 0x01C90011},
		{DevIDKeySigning, tpm2.TPMAlgSHA512, 0x01C90012},
		{DevIDKeyAttestation, tpm2.TPMAlgSHA256, 0x01C90018},
		{DevIDKeyAttestation, tpm2.TPMAlgSHA384, 0x01C90019},
		{DevIDKeyAttestation, tpm2.TPMAlgSHA512, 0x01C9001A},
	}
	for _, tc := range cases {
		got, err := DevIDPolicyNVIndex(tc.kind, tc.alg)
		require.NoError(t, err)
		assert.Equal(t, tc.want, got, "%s/0x%04x", tc.kind, uint16(tc.alg))
	}

	_, err := DevIDPolicyNVIndex(DevIDKeySigning, tpm2.TPMAlgSHA1)
	assert.ErrorIs(t, err, ErrDevIDPolicyUnsupported, "no template exists for SHA1")
	_, err = DevIDPolicyNVIndex(DevIDKeyKind(0), tpm2.TPMAlgSHA256)
	assert.ErrorIs(t, err, ErrDevIDPolicyUnsupported, "an undefined kind has no index")
	_, err = DevIDKeyPolicyDigest(DevIDKeySigning, tpm2.TPMAlgSHA1)
	assert.True(t, errors.Is(err, ErrDevIDPolicyUnsupported),
		"an unsupported algorithm must be refused before any digest is produced")
}
