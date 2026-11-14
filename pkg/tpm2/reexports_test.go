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
