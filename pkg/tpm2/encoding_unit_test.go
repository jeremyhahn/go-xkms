package tpm2

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncode(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "empty bytes",
			input:    []byte{},
			expected: "",
		},
		{
			name:     "single byte",
			input:    []byte{0x00},
			expected: "00",
		},
		{
			name:     "multiple bytes",
			input:    []byte{0x01, 0x02, 0x03},
			expected: "010203",
		},
		{
			name:     "hex values",
			input:    []byte{0xAB, 0xCD, 0xEF},
			expected: "abcdef",
		},
		{
			name:     "all zeros",
			input:    []byte{0x00, 0x00, 0x00, 0x00},
			expected: "00000000",
		},
		{
			name:     "all ones (0xFF)",
			input:    []byte{0xFF, 0xFF, 0xFF, 0xFF},
			expected: "ffffffff",
		},
		{
			name:     "mixed values",
			input:    []byte{0x48, 0x65, 0x6C, 0x6C, 0x6F},
			expected: "48656c6c6f",
		},
		{
			name:     "SHA256 hash size",
			input:    make([]byte, 32),
			expected: "0000000000000000000000000000000000000000000000000000000000000000",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := Encode(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestDecode(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    []byte
		expectError bool
	}{
		{
			name:        "empty string",
			input:       "",
			expected:    []byte{},
			expectError: false,
		},
		{
			name:        "single byte",
			input:       "00",
			expected:    []byte{0x00},
			expectError: false,
		},
		{
			name:        "multiple bytes lowercase",
			input:       "010203",
			expected:    []byte{0x01, 0x02, 0x03},
			expectError: false,
		},
		{
			name:        "multiple bytes uppercase",
			input:       "ABCDEF",
			expected:    []byte{0xAB, 0xCD, 0xEF},
			expectError: false,
		},
		{
			name:        "mixed case",
			input:       "AbCdEf",
			expected:    []byte{0xAB, 0xCD, 0xEF},
			expectError: false,
		},
		{
			name:        "all zeros",
			input:       "00000000",
			expected:    []byte{0x00, 0x00, 0x00, 0x00},
			expectError: false,
		},
		{
			name:        "all ones",
			input:       "ffffffff",
			expected:    []byte{0xFF, 0xFF, 0xFF, 0xFF},
			expectError: false,
		},
		{
			name:        "invalid hex character",
			input:       "GGHHII",
			expected:    nil,
			expectError: true,
		},
		{
			name:        "odd length string",
			input:       "123",
			expected:    nil,
			expectError: true,
		},
		{
			name:        "special characters",
			input:       "12!@34",
			expected:    nil,
			expectError: true,
		},
		{
			name:        "spaces in string",
			input:       "12 34",
			expected:    nil,
			expectError: true,
		},
		{
			name:        "newline in string",
			input:       "12\n34",
			expected:    nil,
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := Decode(tc.input)
			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{
			name:  "empty bytes",
			input: []byte{},
		},
		{
			name:  "single byte",
			input: []byte{0x42},
		},
		{
			name:  "SHA256 digest",
			input: []byte{0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name:  "random data",
			input: []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			encoded := Encode(tc.input)
			decoded, err := Decode(encoded)
			require.NoError(t, err)
			assert.Equal(t, tc.input, decoded)
		})
	}
}

func TestEncodeQuote(t *testing.T) {
	tests := []struct {
		name        string
		quote       Quote
		expectError bool
	}{
		{
			name: "valid quote with all fields",
			quote: Quote{
				Quoted:    []byte{0x01, 0x02, 0x03},
				Signature: []byte{0x04, 0x05, 0x06},
				Nonce:     []byte{0x07, 0x08, 0x09},
				PCRs:      []byte{0x0A, 0x0B, 0x0C},
				EventLog:  []byte{0x0D, 0x0E, 0x0F},
			},
			expectError: false,
		},
		{
			name: "empty quote",
			quote: Quote{
				Quoted:    []byte{},
				Signature: []byte{},
				Nonce:     []byte{},
				PCRs:      []byte{},
				EventLog:  []byte{},
			},
			expectError: false,
		},
		{
			name:        "zero value quote",
			quote:       Quote{},
			expectError: false,
		},
		{
			name: "large quote data",
			quote: Quote{
				Quoted:    make([]byte, 1024),
				Signature: make([]byte, 512),
				Nonce:     make([]byte, 32),
				PCRs:      make([]byte, 2048),
				EventLog:  make([]byte, 4096),
			},
			expectError: false,
		},
		{
			name: "quote with nil fields",
			quote: Quote{
				Quoted:    nil,
				Signature: nil,
				Nonce:     nil,
				PCRs:      nil,
				EventLog:  nil,
			},
			expectError: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := EncodeQuote(tc.quote)
			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, encoded)
				assert.Greater(t, len(encoded), 0)
			}
		})
	}
}

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

func TestEncodeQuoteDecodeQuoteRoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		quote Quote
	}{
		{
			name: "full quote",
			quote: Quote{
				Quoted:    []byte("quoted data"),
				Signature: []byte("signature data"),
				Nonce:     []byte("nonce"),
				PCRs:      []byte("pcr data"),
				EventLog:  []byte("event log"),
			},
		},
		{
			name:  "empty quote",
			quote: Quote{},
		},
		{
			name: "large quote",
			quote: Quote{
				Quoted:    make([]byte, 10000),
				Signature: make([]byte, 5000),
				Nonce:     make([]byte, 64),
				PCRs:      make([]byte, 20000),
				EventLog:  make([]byte, 50000),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := EncodeQuote(tc.quote)
			require.NoError(t, err)

			decoded, err := DecodeQuote(encoded)
			require.NoError(t, err)

			assert.Equal(t, tc.quote, decoded)
		})
	}
}

func TestEncodePCRs(t *testing.T) {
	tests := []struct {
		name        string
		pcrBanks    []PCRBank
		expectError bool
	}{
		{
			name:        "empty PCR banks",
			pcrBanks:    []PCRBank{},
			expectError: false,
		},
		{
			name:        "nil PCR banks",
			pcrBanks:    nil,
			expectError: false,
		},
		{
			name: "single PCR bank with single PCR",
			pcrBanks: []PCRBank{
				{
					Algorithm: "SHA256",
					PCRs: []PCR{
						{ID: 0, Value: []byte{0x01, 0x02, 0x03}},
					},
				},
			},
			expectError: false,
		},
		{
			name: "single PCR bank with multiple PCRs",
			pcrBanks: []PCRBank{
				{
					Algorithm: "SHA256",
					PCRs: []PCR{
						{ID: 0, Value: make([]byte, 32)},
						{ID: 1, Value: make([]byte, 32)},
						{ID: 2, Value: make([]byte, 32)},
					},
				},
			},
			expectError: false,
		},
		{
			name: "multiple PCR banks",
			pcrBanks: []PCRBank{
				{
					Algorithm: "SHA1",
					PCRs: []PCR{
						{ID: 0, Value: make([]byte, 20)},
					},
				},
				{
					Algorithm: "SHA256",
					PCRs: []PCR{
						{ID: 0, Value: make([]byte, 32)},
					},
				},
				{
					Algorithm: "SHA384",
					PCRs: []PCR{
						{ID: 0, Value: make([]byte, 48)},
					},
				},
			},
			expectError: false,
		},
		{
			name: "PCR bank with empty PCRs",
			pcrBanks: []PCRBank{
				{
					Algorithm: "SHA256",
					PCRs:      []PCR{},
				},
			},
			expectError: false,
		},
		{
			name: "PCR bank with nil PCRs",
			pcrBanks: []PCRBank{
				{
					Algorithm: "SHA256",
					PCRs:      nil,
				},
			},
			expectError: false,
		},
		{
			name: "PCR with empty value",
			pcrBanks: []PCRBank{
				{
					Algorithm: "SHA256",
					PCRs: []PCR{
						{ID: 0, Value: []byte{}},
					},
				},
			},
			expectError: false,
		},
		{
			name: "full PCR set 0-23",
			pcrBanks: func() []PCRBank {
				pcrs := make([]PCR, 24)
				for i := 0; i < 24; i++ {
					pcrs[i] = PCR{ID: int32(i), Value: make([]byte, 32)}
				}
				return []PCRBank{
					{Algorithm: "SHA256", PCRs: pcrs},
				}
			}(),
			expectError: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := EncodePCRs(tc.pcrBanks)
			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, encoded)
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

func TestEncodePCRsDecodePCRsRoundTrip(t *testing.T) {
	tests := []struct {
		name     string
		pcrBanks []PCRBank
	}{
		{
			name:     "empty banks",
			pcrBanks: []PCRBank{},
		},
		{
			name: "single bank single PCR",
			pcrBanks: []PCRBank{
				{
					Algorithm: "SHA256",
					PCRs: []PCR{
						{ID: 0, Value: []byte{0xDE, 0xAD, 0xBE, 0xEF}},
					},
				},
			},
		},
		{
			name: "multiple banks",
			pcrBanks: []PCRBank{
				{
					Algorithm: "SHA1",
					PCRs: []PCR{
						{ID: 0, Value: make([]byte, 20)},
						{ID: 7, Value: make([]byte, 20)},
					},
				},
				{
					Algorithm: "SHA256",
					PCRs: []PCR{
						{ID: 0, Value: make([]byte, 32)},
						{ID: 7, Value: make([]byte, 32)},
					},
				},
			},
		},
		{
			name: "full PCR bank",
			pcrBanks: func() []PCRBank {
				pcrs := make([]PCR, 24)
				for i := 0; i < 24; i++ {
					val := make([]byte, 32)
					val[0] = byte(i)
					pcrs[i] = PCR{ID: int32(i), Value: val}
				}
				return []PCRBank{{Algorithm: "SHA256", PCRs: pcrs}}
			}(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := EncodePCRs(tc.pcrBanks)
			require.NoError(t, err)

			decoded, err := DecodePCRs(encoded)
			require.NoError(t, err)

			assert.Equal(t, tc.pcrBanks, decoded)
		})
	}
}

func TestEncodeNilInput(t *testing.T) {
	result := Encode(nil)
	assert.Equal(t, "", result)
}

func TestDecodeValidHexStrings(t *testing.T) {
	validStrings := []string{
		"deadbeef",
		"DEADBEEF",
		"DeAdBeEf",
		"0123456789abcdef",
		"0123456789ABCDEF",
	}

	for _, s := range validStrings {
		t.Run(s, func(t *testing.T) {
			result, err := Decode(s)
			assert.NoError(t, err)
			assert.NotNil(t, result)
		})
	}
}
