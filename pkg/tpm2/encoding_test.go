package tpm2

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeQuote(t *testing.T) {
	tests := []struct {
		name        string
		setup       func() []byte
		expectError bool
		validate    func(*testing.T, Quote)
	}{
		{
			name: "valid encoded quote",
			setup: func() []byte {
				q := Quote{
					Quoted:    []byte{0x01, 0x02, 0x03},
					Signature: []byte{0x04, 0x05, 0x06},
					Nonce:     []byte{0x07, 0x08, 0x09},
					PCRs:      []byte{0x0A, 0x0B, 0x0C},
					EventLog:  []byte{0x0D, 0x0E, 0x0F},
				}
				encoded, _ := EncodeQuote(q)
				return encoded
			},
			expectError: false,
			validate: func(t *testing.T, q Quote) {
				assert.Equal(t, []byte{0x01, 0x02, 0x03}, q.Quoted)
				assert.Equal(t, []byte{0x04, 0x05, 0x06}, q.Signature)
				assert.Equal(t, []byte{0x07, 0x08, 0x09}, q.Nonce)
				assert.Equal(t, []byte{0x0A, 0x0B, 0x0C}, q.PCRs)
				assert.Equal(t, []byte{0x0D, 0x0E, 0x0F}, q.EventLog)
			},
		},
		{
			name: "empty quote",
			setup: func() []byte {
				q := Quote{}
				encoded, _ := EncodeQuote(q)
				return encoded
			},
			expectError: false,
			validate: func(t *testing.T, q Quote) {
				assert.Nil(t, q.Quoted)
				assert.Nil(t, q.Signature)
			},
		},
		{
			name: "invalid gob data",
			setup: func() []byte {
				return []byte{0xFF, 0xFF, 0xFF, 0xFF}
			},
			expectError: true,
			validate:    nil,
		},
		{
			name: "empty byte slice",
			setup: func() []byte {
				return []byte{}
			},
			expectError: true,
			validate:    nil,
		},
		{
			name: "truncated data",
			setup: func() []byte {
				q := Quote{
					Quoted: []byte{0x01, 0x02, 0x03},
				}
				encoded, _ := EncodeQuote(q)
				return encoded[:len(encoded)/2]
			},
			expectError: true,
			validate:    nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data := tc.setup()
			quote, err := DecodeQuote(data)
			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tc.validate != nil {
					tc.validate(t, quote)
				}
			}
		})
	}
}

func TestDecodePCRs(t *testing.T) {
	tests := []struct {
		name        string
		setup       func() []byte
		expectError bool
		validate    func(*testing.T, []PCRBank)
	}{
		{
			name: "valid encoded PCR banks",
			setup: func() []byte {
				banks := []PCRBank{
					{
						Algorithm: "SHA256",
						PCRs: []PCR{
							{ID: 0, Value: []byte{0x01, 0x02, 0x03}},
							{ID: 1, Value: []byte{0x04, 0x05, 0x06}},
						},
					},
				}
				encoded, _ := EncodePCRs(banks)
				return encoded
			},
			expectError: false,
			validate: func(t *testing.T, banks []PCRBank) {
				require.Len(t, banks, 1)
				assert.Equal(t, "SHA256", banks[0].Algorithm)
				require.Len(t, banks[0].PCRs, 2)
				assert.Equal(t, int32(0), banks[0].PCRs[0].ID)
				assert.Equal(t, []byte{0x01, 0x02, 0x03}, banks[0].PCRs[0].Value)
			},
		},
		{
			name: "empty PCR banks",
			setup: func() []byte {
				banks := []PCRBank{}
				encoded, _ := EncodePCRs(banks)
				return encoded
			},
			expectError: false,
			validate: func(t *testing.T, banks []PCRBank) {
				assert.Len(t, banks, 0)
			},
		},
		{
			name: "invalid gob data",
			setup: func() []byte {
				return []byte{0xFF, 0xFF, 0xFF, 0xFF}
			},
			expectError: true,
			validate:    nil,
		},
		{
			name: "empty byte slice",
			setup: func() []byte {
				return []byte{}
			},
			expectError: true,
			validate:    nil,
		},
		{
			name: "truncated data",
			setup: func() []byte {
				banks := []PCRBank{
					{
						Algorithm: "SHA256",
						PCRs: []PCR{
							{ID: 0, Value: make([]byte, 32)},
						},
					},
				}
				encoded, _ := EncodePCRs(banks)
				return encoded[:len(encoded)/2]
			},
			expectError: true,
			validate:    nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data := tc.setup()
			banks, err := DecodePCRs(data)
			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tc.validate != nil {
					tc.validate(t, banks)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Hex encoding length, stdlib compatibility, and TPM-specific encoding tests
// (merged from encoding_unit_test.go)
// ---------------------------------------------------------------------------

func TestAlgorithmIDEncoding(t *testing.T) {
	// Test encoding of TPM algorithm IDs
	algorithms := map[string][]byte{
		"TPM_ALG_SHA1":   {0x00, 0x04},
		"TPM_ALG_SHA256": {0x00, 0x0B},
		"TPM_ALG_SHA384": {0x00, 0x0C},
		"TPM_ALG_SHA512": {0x00, 0x0D},
		"TPM_ALG_RSA":    {0x00, 0x01},
		"TPM_ALG_ECC":    {0x00, 0x23},
	}

	for name, algID := range algorithms {
		encoded := Encode(algID)
		if len(encoded) != 4 {
			t.Errorf("%s: encoded length = %d, want 4", name, len(encoded))
		}

		decoded, err := Decode(encoded)
		if err != nil {
			t.Errorf("%s: decode error: %v", name, err)
			continue
		}

		if decoded[0] != algID[0] || decoded[1] != algID[1] {
			t.Errorf("%s: algorithm ID mismatch", name)
		}
	}
}
