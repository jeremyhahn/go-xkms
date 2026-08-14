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

package services

import (
	"errors"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// platformSRKConfig builds the Platform SRK configuration a TPM carries when
// the platform key store is provisioned at the given handle.
func platformSRKConfig(handle uint32) *xkms.PlatformSRKConfig {
	return &xkms.PlatformSRKConfig{SRKHandle: handle}
}

// --- public area fixtures -------------------------------------------------

// rsaPublic builds the public area of an RSA object the way a TPM reports it
// from TPM2_ReadPublic: the scheme and modulus size live in the RSA parameter
// block, not in the object attributes.
func rsaPublic(scheme tpm2.TPMAlgID, keyBits tpm2.TPMKeyBits, attrs tpm2.TPMAObject) tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type:             tpm2.TPMAlgRSA,
		NameAlg:          tpm2.TPMAlgSHA256,
		ObjectAttributes: attrs,
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgRSA, &tpm2.TPMSRSAParms{
			Scheme:  tpm2.TPMTRSAScheme{Scheme: scheme},
			KeyBits: keyBits,
		}),
	}
}

// eccPublic builds the public area of an ECC object.
func eccPublic(scheme tpm2.TPMAlgID, curve tpm2.TPMECCCurve, attrs tpm2.TPMAObject) tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type:             tpm2.TPMAlgECC,
		NameAlg:          tpm2.TPMAlgSHA256,
		ObjectAttributes: attrs,
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			Scheme:  tpm2.TPMTECCScheme{Scheme: scheme},
			CurveID: curve,
		}),
	}
}

// keyedHashPublic builds the public area of a keyedhash object. A scheme of
// TPM_ALG_NULL with neither sign nor decrypt set is a sealed data object.
func keyedHashPublic(scheme tpm2.TPMAlgID, attrs tpm2.TPMAObject) tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type:             tpm2.TPMAlgKeyedHash,
		NameAlg:          tpm2.TPMAlgSHA256,
		ObjectAttributes: attrs,
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgKeyedHash, &tpm2.TPMSKeyedHashParms{
			Scheme: tpm2.TPMTKeyedHashScheme{Scheme: scheme},
		}),
	}
}

// symCipherPublic builds the public area of a symmetric cipher object.
func symCipherPublic(alg tpm2.TPMAlgID, keyBits tpm2.TPMKeyBits) tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type:             tpm2.TPMAlgSymCipher,
		NameAlg:          tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{Decrypt: true, SignEncrypt: true},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgSymCipher, &tpm2.TPMSSymCipherParms{
			Sym: tpm2.TPMTSymDefObject{
				Algorithm: alg,
				KeyBits:   tpm2.NewTPMUSymKeyBits(alg, keyBits),
			},
		}),
	}
}

// storageParent are the attributes of a restricted decryption key: an SRK.
var storageParent = tpm2.TPMAObject{
	FixedTPM:            true,
	FixedParent:         true,
	SensitiveDataOrigin: true,
	UserWithAuth:        true,
	Restricted:          true,
	Decrypt:             true,
}

// attestationKey are the attributes of a restricted signing key: an IAK.
var attestationKey = tpm2.TPMAObject{
	FixedTPM:            true,
	FixedParent:         true,
	SensitiveDataOrigin: true,
	UserWithAuth:        true,
	Restricted:          true,
	SignEncrypt:         true,
}

// signingKey are the attributes of an unrestricted signing key.
var signingKey = tpm2.TPMAObject{
	FixedTPM:            true,
	FixedParent:         true,
	SensitiveDataOrigin: true,
	UserWithAuth:        true,
	SignEncrypt:         true,
}

// --- ListKeys -------------------------------------------------------------

// TestListKeys_ReportsProvisionedKeys is the regression guard for the shipped
// stub that returned a hard-coded empty slice: a TPM holding an EK, an SSRK
// and an IAK must report all three, with the algorithm, size and purpose read
// off each object's public area.
func TestListKeys_ReportsProvisionedKeys(t *testing.T) {
	mock := defaultMockTPM()
	mock.persistentHandles = []tpm2.TPMHandle{0x81000001, 0x81010001, 0x81020001}
	mock.handlePublics = map[tpm2.TPMHandle]tpm2.TPMTPublic{
		0x81000001: rsaPublic(tpm2.TPMAlgNull, 2048, storageParent),
		0x81010001: rsaPublic(tpm2.TPMAlgNull, 2048, storageParent),
		0x81020001: rsaPublic(tpm2.TPMAlgRSAPSS, 2048, attestationKey),
	}
	svc, _ := createTestTPMService(t, mock)

	keys, err := svc.ListKeys()
	require.NoError(t, err)
	require.Len(t, keys, 3)

	// The TCG shared SRK: a restricted decryption key with no signing scheme.
	assert.Equal(t, "0x81000001", keys[0].ID)
	assert.Equal(t, "RSA", keys[0].Algorithm)
	assert.Equal(t, 2048, keys[0].KeySize)
	assert.True(t, keys[0].Persistent)
	assert.Equal(t, "TCG Shared SRK (RSA)", keys[0].Purpose)

	// The endorsement key, named by the TCG well-known handle registry.
	assert.Equal(t, "0x81010001", keys[1].ID)
	assert.Equal(t, "Endorsement Key (EK-RSA)", keys[1].Purpose)

	// The IAK signs with RSA-PSS; reporting it as RSA-SSA would send a caller
	// to the wrong verification path.
	assert.Equal(t, "0x81020001", keys[2].ID)
	assert.Equal(t, "RSA-PSS", keys[2].Algorithm)
	assert.Equal(t, 2048, keys[2].KeySize)
	assert.Equal(t, "Initial Attestation Key (IAK)", keys[2].Purpose)
}

// TestListKeys_ReportsEveryObjectType covers the object types a persistent
// handle may hold. KeyAttributes rejects everything that is not RSA or ECC,
// which is why enumeration reads the public area instead.
func TestListKeys_ReportsEveryObjectType(t *testing.T) {
	mock := defaultMockTPM()
	mock.persistentHandles = []tpm2.TPMHandle{0x81000010, 0x81000011, 0x81000012, 0x81000013}
	mock.handlePublics = map[tpm2.TPMHandle]tpm2.TPMTPublic{
		0x81000010: eccPublic(tpm2.TPMAlgECDSA, tpm2.TPMECCNistP384, signingKey),
		0x81000011: keyedHashPublic(tpm2.TPMAlgHMAC, signingKey),
		0x81000012: keyedHashPublic(tpm2.TPMAlgNull, tpm2.TPMAObject{FixedTPM: true, UserWithAuth: true}),
		0x81000013: symCipherPublic(tpm2.TPMAlgAES, 256),
	}
	svc, _ := createTestTPMService(t, mock)

	keys, err := svc.ListKeys()
	require.NoError(t, err)
	require.Len(t, keys, 4)

	assert.Equal(t, "ECDSA", keys[0].Algorithm)
	assert.Equal(t, 384, keys[0].KeySize)
	assert.Equal(t, "Signing", keys[0].Purpose)

	assert.Equal(t, "HMAC", keys[1].Algorithm)
	assert.Equal(t, 0, keys[1].KeySize)
	assert.Equal(t, "Signing", keys[1].Purpose)

	assert.Equal(t, "KeyedHash", keys[2].Algorithm)
	assert.Equal(t, "Sealed Data", keys[2].Purpose)

	assert.Equal(t, "AES", keys[3].Algorithm)
	assert.Equal(t, 256, keys[3].KeySize)
}

// TestListKeys_LabelsPlatformSRKAndUserDescriptions checks the two labels that
// do not come from the TCG registry: the Platform SRK the TPM is configured
// with, and a description the operator set on a handle.
func TestListKeys_LabelsPlatformSRKAndUserDescriptions(t *testing.T) {
	mock := defaultMockTPM()
	mock.config.PlatformSRK = platformSRKConfig(0x81000003)
	mock.persistentHandles = []tpm2.TPMHandle{0x81000003, 0x81000004}
	mock.handlePublics = map[tpm2.TPMHandle]tpm2.TPMTPublic{
		0x81000003: rsaPublic(tpm2.TPMAlgNull, 2048, storageParent),
		0x81000004: eccPublic(tpm2.TPMAlgECDSA, tpm2.TPMECCNistP256, signingKey),
	}
	svc, _ := createTestTPMService(t, mock)

	require.NoError(t, svc.SetHandleDescription("0x81000004", "Fleet signing key"))

	keys, err := svc.ListKeys()
	require.NoError(t, err)
	require.Len(t, keys, 2)
	assert.Equal(t, "Platform SRK", keys[0].Purpose)
	assert.Equal(t, "Fleet signing key", keys[1].Purpose)
}

// TestListKeys_UnprovisionedTPMIsNotAnError pins the contract the GUI depends
// on: a TPM with nothing persisted renders an empty keys tab, not an error
// banner.
func TestListKeys_UnprovisionedTPMIsNotAnError(t *testing.T) {
	mock := defaultMockTPM()
	mock.persistentHandles = nil
	svc, _ := createTestTPMService(t, mock)

	keys, err := svc.ListKeys()
	require.NoError(t, err)
	assert.Empty(t, keys)
	assert.NotNil(t, keys)
}

// TestListKeys_UnreadablePublicAreaStillListsTheKey covers the race between
// the capability query and the public-area read. The handle exists, so it must
// still appear -- the handles tab would show it either way.
func TestListKeys_UnreadablePublicAreaStillListsTheKey(t *testing.T) {
	mock := defaultMockTPM()
	mock.persistentHandles = []tpm2.TPMHandle{0x81000001}
	mock.readHandleErr = errors.New("TPM_RC_HANDLE")
	svc, _ := createTestTPMService(t, mock)

	keys, err := svc.ListKeys()
	require.NoError(t, err)
	require.Len(t, keys, 1)
	assert.Equal(t, "0x81000001", keys[0].ID)
	assert.Equal(t, unknownTPMValue, keys[0].Algorithm)
	assert.Equal(t, 0, keys[0].KeySize)
	// The TCG registry still names the handle even when the object cannot be
	// read, so the operator is not left guessing.
	assert.Equal(t, "TCG Shared SRK (RSA)", keys[0].Purpose)
}

// TestListKeys_UnnamedUnreadableHandleReportsUnknown checks the purpose
// fallback for a handle that neither the registry nor the public area can
// describe. An empty string would render as a blank cell.
func TestListKeys_UnnamedUnreadableHandleReportsUnknown(t *testing.T) {
	mock := defaultMockTPM()
	mock.persistentHandles = []tpm2.TPMHandle{0x81000042}
	mock.readHandleErr = errors.New("TPM_RC_HANDLE")
	svc, _ := createTestTPMService(t, mock)

	keys, err := svc.ListKeys()
	require.NoError(t, err)
	require.Len(t, keys, 1)
	assert.Equal(t, unknownTPMValue, keys[0].Purpose)
	assert.Equal(t, unknownTPMValue, keys[0].Algorithm)
}

// TestListKeys_CapabilityQueryError surfaces a failed capability read instead
// of reporting an empty inventory.
func TestListKeys_CapabilityQueryError(t *testing.T) {
	mock := defaultMockTPM()
	mock.fixedPropsErr = errors.New("capability query failed")
	svc, _ := createTestTPMService(t, mock)

	keys, err := svc.ListKeys()
	require.Error(t, err)
	assert.Nil(t, keys)
	assert.Contains(t, err.Error(), "capability query failed")
}

// TestListKeys_NilPropertiesIsEmpty guards the nil-without-error case: a TPM
// that reports no fixed properties has no persistent inventory to enumerate,
// and must not panic the service.
func TestListKeys_NilPropertiesIsEmpty(t *testing.T) {
	mock := defaultMockTPM()
	mock.fixedProps = nil
	svc, _ := createTestTPMService(t, mock)

	keys, err := svc.ListKeys()
	require.NoError(t, err)
	assert.Empty(t, keys)
}

// --- public area derivation ------------------------------------------------

func TestTPMPublicAlgorithm(t *testing.T) {
	tests := []struct {
		name string
		pub  tpm2.TPMTPublic
		want string
	}{
		{"rsa restricted storage key", rsaPublic(tpm2.TPMAlgNull, 2048, storageParent), "RSA"},
		{"rsa pss signing key", rsaPublic(tpm2.TPMAlgRSAPSS, 2048, signingKey), "RSA-PSS"},
		{"rsa ssa signing key", rsaPublic(tpm2.TPMAlgRSASSA, 2048, signingKey), "RSA-SSA"},
		{"rsa oaep decryption key", rsaPublic(tpm2.TPMAlgOAEP, 2048, storageParent), "RSA-OAEP"},
		{"rsa es decryption key", rsaPublic(tpm2.TPMAlgRSAES, 2048, storageParent), "RSA-ES"},
		{"ecc restricted storage key", eccPublic(tpm2.TPMAlgNull, tpm2.TPMECCNistP256, storageParent), "ECC"},
		{"ecdsa signing key", eccPublic(tpm2.TPMAlgECDSA, tpm2.TPMECCNistP256, signingKey), "ECDSA"},
		{"ecdaa signing key", eccPublic(tpm2.TPMAlgECDAA, tpm2.TPMECCNistP256, signingKey), "ECDAA"},
		{"ec schnorr signing key", eccPublic(tpm2.TPMAlgECSchnorr, tpm2.TPMECCNistP256, signingKey), "EC-Schnorr"},
		{"sm2 signing key", eccPublic(tpm2.TPMAlgSM2, tpm2.TPMECCSM2P256, signingKey), "SM2"},
		{"hmac key", keyedHashPublic(tpm2.TPMAlgHMAC, signingKey), "HMAC"},
		{"xor key", keyedHashPublic(tpm2.TPMAlgXOR, signingKey), "XOR"},
		{"sealed data", keyedHashPublic(tpm2.TPMAlgNull, tpm2.TPMAObject{FixedTPM: true}), "KeyedHash"},
		{"aes key", symCipherPublic(tpm2.TPMAlgAES, 128), "AES"},
		{"sm4 key", symCipherPublic(tpm2.TPMAlgSM4, 128), "SM4"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tpmPublicAlgorithm(tt.pub))
		})
	}
}

// TestTPMPublicAlgorithm_MalformedPublicArea: an object whose parameter block
// does not match its type, or whose type the TPM 2.0 spec does not define as a
// public object, must degrade to the base algorithm name rather than panic.
func TestTPMPublicAlgorithm_MalformedPublicArea(t *testing.T) {
	tests := []struct {
		name string
		pub  tpm2.TPMTPublic
		want string
	}{
		{"rsa without parameters", tpm2.TPMTPublic{Type: tpm2.TPMAlgRSA}, "RSA"},
		{"ecc without parameters", tpm2.TPMTPublic{Type: tpm2.TPMAlgECC}, "ECC"},
		{"keyedhash without parameters", tpm2.TPMTPublic{Type: tpm2.TPMAlgKeyedHash}, "KeyedHash"},
		{"symcipher without parameters", tpm2.TPMTPublic{Type: tpm2.TPMAlgSymCipher}, "SymCipher"},
		{"unknown symmetric cipher", symCipherPublic(tpm2.TPMAlgXOR, 128), "SymCipher"},
		{"zero value", tpm2.TPMTPublic{}, unknownTPMValue},
		{"unsupported type", tpm2.TPMTPublic{Type: tpm2.TPMAlgSHA256}, unknownTPMValue},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tpmPublicAlgorithm(tt.pub))
		})
	}
}

func TestTPMPublicKeySize(t *testing.T) {
	tests := []struct {
		name string
		pub  tpm2.TPMTPublic
		want int
	}{
		{"rsa 2048", rsaPublic(tpm2.TPMAlgNull, 2048, storageParent), 2048},
		{"rsa 3072", rsaPublic(tpm2.TPMAlgNull, 3072, storageParent), 3072},
		{"nist p256", eccPublic(tpm2.TPMAlgECDSA, tpm2.TPMECCNistP256, signingKey), 256},
		{"nist p384", eccPublic(tpm2.TPMAlgECDSA, tpm2.TPMECCNistP384, signingKey), 384},
		{"nist p521", eccPublic(tpm2.TPMAlgECDSA, tpm2.TPMECCNistP521, signingKey), 521},
		{"brainpool p512r1", eccPublic(tpm2.TPMAlgECDSA, tpm2.TPMECCBrainpoolP512R1, signingKey), 512},
		{"aes 128", symCipherPublic(tpm2.TPMAlgAES, 128), 128},
		{"sealed data has no key size", keyedHashPublic(tpm2.TPMAlgNull, tpm2.TPMAObject{}), 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tpmPublicKeySize(tt.pub))
		})
	}
}

// TestTPMPublicKeySize_UnreportableSize: a malformed parameter block or an
// unknown curve has no honest size, and 0 is how the GUI is told to omit it.
func TestTPMPublicKeySize_UnreportableSize(t *testing.T) {
	tests := []struct {
		name string
		pub  tpm2.TPMTPublic
	}{
		{"rsa without parameters", tpm2.TPMTPublic{Type: tpm2.TPMAlgRSA}},
		{"ecc without parameters", tpm2.TPMTPublic{Type: tpm2.TPMAlgECC}},
		{"symcipher without parameters", tpm2.TPMTPublic{Type: tpm2.TPMAlgSymCipher}},
		{"unknown curve", eccPublic(tpm2.TPMAlgECDSA, tpm2.TPMECCCurve(0x7FFF), signingKey)},
		{"xor keybits are not a key size", symCipherPublic(tpm2.TPMAlgXOR, 128)},
		{"zero value", tpm2.TPMTPublic{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, 0, tpmPublicKeySize(tt.pub))
		})
	}
}

func TestTPMPublicPurpose(t *testing.T) {
	tests := []struct {
		name string
		pub  tpm2.TPMTPublic
		want string
	}{
		{"restricted decryption key is a storage parent", rsaPublic(tpm2.TPMAlgNull, 2048, storageParent), "Storage"},
		{"restricted signing key is an attestation key", rsaPublic(tpm2.TPMAlgRSAPSS, 2048, attestationKey), "Attestation"},
		{"unrestricted signing key", rsaPublic(tpm2.TPMAlgRSASSA, 2048, signingKey), "Signing"},
		{"decryption key", rsaPublic(tpm2.TPMAlgOAEP, 2048, tpm2.TPMAObject{Decrypt: true}), "Decryption"},
		{"dual purpose key", rsaPublic(tpm2.TPMAlgNull, 2048, tpm2.TPMAObject{Decrypt: true, SignEncrypt: true}), "Signing and Decryption"},
		{"sealed data", keyedHashPublic(tpm2.TPMAlgNull, tpm2.TPMAObject{FixedTPM: true}), "Sealed Data"},
		{"no usable attributes", tpm2.TPMTPublic{Type: tpm2.TPMAlgRSA}, unknownTPMValue},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tpmPublicPurpose(tt.pub))
		})
	}
}

// --- handle labeling -------------------------------------------------------

func TestDescribeHandle(t *testing.T) {
	descriptions := map[string]string{"0x81000005": "Fleet signing key"}

	tests := []struct {
		name        string
		platformSRK string
		handle      string
		want        string
	}{
		{"operator description wins", "0x81000005", "0x81000005", "Fleet signing key"},
		{"configured platform srk", "0x81000002", "0x81000002", "Platform SRK"},
		{"tcg well-known handle", "", "0x81010001", "Endorsement Key (EK-RSA)"},
		{"unconfigured platform srk falls back to the registry", "", "0x81000002", "TCG Shared SRK (ECC)"},
		{"unknown handle has no label", "", "0x81000099", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, describeHandle(descriptions, tt.platformSRK, tt.handle))
		})
	}
}

func TestFormatTPMHandle(t *testing.T) {
	assert.Equal(t, "0x81010001", formatTPMHandle(tpm2.TPMHandle(0x81010001)))
	assert.Equal(t, "0x00000000", formatTPMHandle(tpm2.TPMHandle(0)))
}

func TestPlatformSRKHandleHex(t *testing.T) {
	configured := defaultMockTPM()
	configured.config.PlatformSRK = platformSRKConfig(0x81000002)
	assert.Equal(t, "0x81000002", platformSRKHandleHex(configured))

	unset := defaultMockTPM()
	unset.config.PlatformSRK = nil
	assert.Equal(t, "", platformSRKHandleHex(unset))

	zeroHandle := defaultMockTPM()
	zeroHandle.config.PlatformSRK = platformSRKConfig(0)
	assert.Equal(t, "", platformSRKHandleHex(zeroHandle))

	noConfig := defaultMockTPM()
	noConfig.config = nil
	assert.Equal(t, "", platformSRKHandleHex(noConfig))
}
