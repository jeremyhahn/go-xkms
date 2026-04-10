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

package tpm2

import (
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMarshalPublic(t *testing.T) {
	// Create a simple TPMTPublic structure
	pub := &tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt: true,
			FixedTPM:    true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				KeyBits: 2048,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{
				Buffer: make([]byte, 256),
			},
		),
	}

	// Marshal should produce some output
	data := MarshalPublic(pub)
	assert.NotNil(t, data)
	assert.Greater(t, len(data), 0)
}

func TestUnmarshalPublic(t *testing.T) {
	// Create and marshal a TPMTPublic structure
	original := &tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt: true,
			FixedTPM:    true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				KeyBits: 2048,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{
				Buffer: make([]byte, 256),
			},
		),
	}

	data := MarshalPublic(original)
	require.NotNil(t, data)

	// Unmarshal the data
	unmarshaled, err := UnmarshalPublic(data)
	require.NoError(t, err)
	require.NotNil(t, unmarshaled)

	// Verify key properties match
	assert.Equal(t, original.Type, unmarshaled.Type)
	assert.Equal(t, original.NameAlg, unmarshaled.NameAlg)
	assert.Equal(t, original.ObjectAttributes.SignEncrypt, unmarshaled.ObjectAttributes.SignEncrypt)
	assert.Equal(t, original.ObjectAttributes.FixedTPM, unmarshaled.ObjectAttributes.FixedTPM)
}

func TestUnmarshalPublic_InvalidData(t *testing.T) {
	// Test with invalid data
	invalidData := []byte{0x00, 0x01, 0x02, 0x03}
	_, err := UnmarshalPublic(invalidData)
	assert.Error(t, err)
}

func TestUnmarshalPublic_EmptyData(t *testing.T) {
	// Test with empty data
	_, err := UnmarshalPublic([]byte{})
	assert.Error(t, err)
}

func TestMarshalUnmarshalPublic_RoundTrip(t *testing.T) {
	testCases := []struct {
		name string
		pub  *tpm2.TPMTPublic
	}{
		{
			name: "RSA with SHA256",
			pub: &tpm2.TPMTPublic{
				Type:    tpm2.TPMAlgRSA,
				NameAlg: tpm2.TPMAlgSHA256,
				ObjectAttributes: tpm2.TPMAObject{
					SignEncrypt: true,
					FixedTPM:    true,
					FixedParent: true,
				},
				Parameters: tpm2.NewTPMUPublicParms(
					tpm2.TPMAlgRSA,
					&tpm2.TPMSRSAParms{
						KeyBits: 2048,
					},
				),
				Unique: tpm2.NewTPMUPublicID(
					tpm2.TPMAlgRSA,
					&tpm2.TPM2BPublicKeyRSA{
						Buffer: make([]byte, 256),
					},
				),
			},
		},
		{
			name: "ECC P256",
			pub: &tpm2.TPMTPublic{
				Type:    tpm2.TPMAlgECC,
				NameAlg: tpm2.TPMAlgSHA256,
				ObjectAttributes: tpm2.TPMAObject{
					SignEncrypt: true,
					FixedTPM:    true,
				},
				Parameters: tpm2.NewTPMUPublicParms(
					tpm2.TPMAlgECC,
					&tpm2.TPMSECCParms{
						CurveID: tpm2.TPMECCNistP256,
					},
				),
				Unique: tpm2.NewTPMUPublicID(
					tpm2.TPMAlgECC,
					&tpm2.TPMSECCPoint{
						X: tpm2.TPM2BECCParameter{Buffer: make([]byte, 32)},
						Y: tpm2.TPM2BECCParameter{Buffer: make([]byte, 32)},
					},
				),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Marshal
			data := MarshalPublic(tc.pub)
			require.NotNil(t, data)
			require.Greater(t, len(data), 0)

			// Unmarshal
			unmarshaled, err := UnmarshalPublic(data)
			require.NoError(t, err)
			require.NotNil(t, unmarshaled)

			// Verify
			assert.Equal(t, tc.pub.Type, unmarshaled.Type)
			assert.Equal(t, tc.pub.NameAlg, unmarshaled.NameAlg)
		})
	}
}

func TestReexportedConstants(t *testing.T) {
	// Verify algorithm constants match
	assert.Equal(t, tpm2.TPMAlgKeyedHash, TPMAlgKeyedHash)
	assert.Equal(t, tpm2.TPMAlgRSA, TPMAlgRSA)
	assert.Equal(t, tpm2.TPMAlgECC, TPMAlgECC)
	assert.Equal(t, tpm2.TPMAlgSHA1, TPMAlgSHA1)
	assert.Equal(t, tpm2.TPMAlgSHA256, TPMAlgSHA256)
	assert.Equal(t, tpm2.TPMAlgSHA384, TPMAlgSHA384)
	assert.Equal(t, tpm2.TPMAlgSHA512, TPMAlgSHA512)
	assert.Equal(t, tpm2.TPMAlgNull, TPMAlgNull)

	// Verify handle type constants match
	assert.Equal(t, tpm2.TPMHTTransient, TPMHTTransient)
	assert.Equal(t, tpm2.TPMHTPersistent, TPMHTPersistent)

	// Verify hierarchy constants match
	assert.Equal(t, tpm2.TPMRHOwner, TPMRHOwner)
	assert.Equal(t, tpm2.TPMRHEndorsement, TPMRHEndorsement)
	assert.Equal(t, tpm2.TPMRHPlatform, TPMRHPlatform)
	assert.Equal(t, tpm2.TPMRHNull, TPMRHNull)
}

func TestReexportedTemplates(t *testing.T) {
	// Verify templates are properly re-exported
	assert.Equal(t, tpm2.TPMAlgRSA, RSASRKTemplate.Type)
	assert.Equal(t, tpm2.TPMAlgECC, ECCSRKTemplate.Type)
	assert.Equal(t, tpm2.TPMAlgRSA, RSAEKTemplate.Type)
	assert.Equal(t, tpm2.TPMAlgECC, ECCEKTemplate.Type)
}

func TestTypeAliases(t *testing.T) {
	// Test that type aliases work correctly

	// TPMHandle
	var handle TPMHandle = 0x81000001
	assert.Equal(t, tpm2.TPMHandle(0x81000001), handle)

	// TPMAlgID
	var algID = tpm2.TPMAlgSHA256
	assert.Equal(t, tpm2.TPMAlgSHA256, algID)

	// TPMIAlgHash
	var hashAlg = tpm2.TPMAlgSHA256
	assert.Equal(t, tpm2.TPMIAlgHash(tpm2.TPMAlgSHA256), hashAlg)

	// TPMIRHHierarchy
	var hierarchy = tpm2.TPMRHOwner
	assert.Equal(t, tpm2.TPMRHOwner, hierarchy)
}
