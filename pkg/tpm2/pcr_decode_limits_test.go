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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fullPCRBanks is the largest read ReadPCRs can report: every PCR of four
// banks, each at the SHA-512 digest size.
func fullPCRBanks() []PCRBank {
	banks := make([]PCRBank, 0, 4)
	for _, alg := range []string{"SHA1", "SHA256", "SHA384", "SHA512"} {
		pcrs := make([]PCR, 0, maxPCRIndex+1)
		for id := int32(0); id <= maxPCRIndex; id++ {
			pcrs = append(pcrs, PCR{ID: id, Value: make([]byte, maxPCRDigestSize)})
		}
		banks = append(banks, PCRBank{Algorithm: alg, PCRs: pcrs})
	}
	return banks
}

func TestDecodePCRs_LargestGenuineReadAccepted(t *testing.T) {
	banks := fullPCRBanks()
	encoded, err := EncodePCRs(banks)
	require.NoError(t, err)
	require.Less(t, len(encoded), maxEncodedPCRBytes, "the size cap must leave room for a full read")

	decoded, err := DecodePCRs(encoded)
	require.NoError(t, err)
	assert.Equal(t, banks, decoded)
}

func TestDecodePCRs_OversizedInputRefused(t *testing.T) {
	_, err := DecodePCRs(make([]byte, maxEncodedPCRBytes+1))
	assert.ErrorIs(t, err, ErrPCRDataTooLarge)
}

func TestDecodePCRs_ImpossibleContentRefused(t *testing.T) {
	tooManyBanks := make([]PCRBank, maxPCRBanks+1)
	for i := range tooManyBanks {
		tooManyBanks[i] = PCRBank{Algorithm: "SHA256"}
	}
	tooManyPCRs := make([]PCR, maxPCRIndex+2)

	tests := map[string][]PCRBank{
		"too many banks":        tooManyBanks,
		"too many PCRs in bank": {{Algorithm: "SHA256", PCRs: tooManyPCRs}},
		"index above range":     {{Algorithm: "SHA256", PCRs: []PCR{{ID: maxPCRIndex + 1, Value: make([]byte, 32)}}}},
		"negative index":        {{Algorithm: "SHA256", PCRs: []PCR{{ID: -1, Value: make([]byte, 32)}}}},
		"value above digest":    {{Algorithm: "SHA256", PCRs: []PCR{{ID: 0, Value: make([]byte, maxPCRDigestSize+1)}}}},
	}
	for name, banks := range tests {
		t.Run(name, func(t *testing.T) {
			encoded, err := EncodePCRs(banks)
			require.NoError(t, err)

			_, err = DecodePCRs(encoded)
			assert.ErrorIs(t, err, ErrInvalidPCRData)
		})
	}
}
