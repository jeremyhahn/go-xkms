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

package deviceattest01

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Mock implementations for testing

type mockCA struct {
	verifyError         error
	verifyAKChainError  error
	verifyAKChainCount  int
	verifyAKChainCalled bool
}

func (m *mockCA) VerifyAttestationObject(obj *AttestationObject, expectedChallenge []byte) error {
	if m.verifyError != nil {
		return m.verifyError
	}
	return nil
}

func (m *mockCA) VerifyAKCertificateChain(certs [][]byte) error {
	m.verifyAKChainCalled = true
	m.verifyAKChainCount++
	if m.verifyAKChainError != nil {
		return m.verifyAKChainError
	}
	return nil
}

func TestAttestationFormat_String(t *testing.T) {
	format := FormatTPM
	if format.String() != "tpm" {
		t.Errorf("Expected 'tpm', got %q", format.String())
	}
}

// attestationPayload is the body a client POSTs for obj.
func attestationPayload(t *testing.T, obj *AttestationObject) []byte {
	t.Helper()
	payload, err := EncodeAttestationRequest(obj)
	require.NoError(t, err)
	return payload
}

// structurallyValidTPMObject is an attestation object whose layers decode but
// whose evidence is not real: enough to reach the verifier's policy checks.
func structurallyValidTPMObject() *AttestationObject {
	return &AttestationObject{
		Format: "tpm",
		AttStatement: AttestationStatement{
			Ver:      "2.0",
			Alg:      -257,
			X5c:      []interface{}{[]byte("cert-bytes")},
			Sig:      []byte("signature"),
			CertInfo: []byte("cert-info-with-keyauth"),
			PubArea:  []byte("pub-area"),
		},
	}
}

func TestVerify_NoVerifier(t *testing.T) {
	_, err := VerifyAttestation(context.Background(), nil, attestationPayload(t, structurallyValidTPMObject()), "keyauth")
	assert.ErrorIs(t, err, ErrNoAttestationVerifier)
}

func TestVerify_PayloadLayers(t *testing.T) {
	validCBOR, err := cbor.Marshal(structurallyValidTPMObject())
	require.NoError(t, err)

	tests := []struct {
		name    string
		payload []byte
		detail  string
	}{
		{"not JSON", []byte("not valid json"), "not a JSON attestation request"},
		{"attObj absent", []byte(`{}`), "attObj is absent"},
		{"attObj padded base64url", []byte(`{"attObj":"` + base64.URLEncoding.EncodeToString(validCBOR) + `"}`), "not unpadded base64url"},
		{"attObj standard base64", []byte(`{"attObj":"+/+/"}`), "not unpadded base64url"},
		{"attObj not CBOR", []byte(`{"attObj":"` + base64.RawURLEncoding.EncodeToString([]byte("not valid cbor")) + `"}`), "not a CBOR attestation object"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := VerifyAttestation(context.Background(), &mockCA{}, tt.payload, "keyauth")
			require.Error(t, err)
			assert.Contains(t, err.Error(), "device-attest-01")
			assert.Contains(t, err.Error(), tt.detail)

			_, parseErr := ParseAttestationRequest(tt.payload)
			assert.ErrorIs(t, parseErr, ErrAttestationPayloadInvalid)
		})
	}
}

func TestVerify_InvalidAttestationFormat(t *testing.T) {
	obj := structurallyValidTPMObject()
	obj.Format = "invalid-format"

	_, err := VerifyAttestation(context.Background(), &mockCA{}, attestationPayload(t, obj), "keyauth")
	assert.ErrorIs(t, err, ErrInvalidAttestationFormat)
}

func TestVerify_CAVerificationError(t *testing.T) {
	ca := &mockCA{verifyError: errors.New("CA verification failed")}

	_, err := VerifyAttestation(context.Background(), ca, attestationPayload(t, structurallyValidTPMObject()), "keyauth")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "attestation verification failed")
	assert.False(t, ca.verifyAKChainCalled, "the chain is not anchored once the object was refused")
}

func TestVerify_AKCertificateChainError(t *testing.T) {
	cause := errors.New("AK chain verification failed")
	ca := &mockCA{verifyAKChainError: cause}

	_, err := VerifyAttestation(context.Background(), ca, attestationPayload(t, structurallyValidTPMObject()), "keyauth")
	assert.ErrorIs(t, err, ErrCertificateChainInvalid)
	assert.ErrorIs(t, err, cause, "the verifier's reason is kept")
}

func TestVerify_X5cEntryNotACertificate(t *testing.T) {
	obj := structurallyValidTPMObject()
	obj.AttStatement.X5c = []interface{}{"not a byte string"}

	_, err := VerifyAttestation(context.Background(), &mockCA{}, attestationPayload(t, obj), "keyauth")
	assert.ErrorIs(t, err, ErrCertificateChainInvalid)
}

func TestAttestationRequest_RoundTrip(t *testing.T) {
	obj := structurallyValidTPMObject()

	parsed, err := ParseAttestationRequest(attestationPayload(t, obj))
	require.NoError(t, err)
	assert.Equal(t, obj.Format, parsed.Format)
	assert.Equal(t, obj.AttStatement.Sig, parsed.AttStatement.Sig)
}

func TestParseAttestationObject_Success(t *testing.T) {
	obj := &AttestationObject{
		Format: "tpm",
		AttStatement: AttestationStatement{
			Ver:      "2.0",
			Alg:      -257,
			X5c:      []interface{}{[]byte("cert-bytes")},
			Sig:      []byte("signature"),
			CertInfo: []byte("cert-info"),
			PubArea:  []byte("pub-area"),
		},
	}

	data, err := cbor.Marshal(obj)
	if err != nil {
		t.Fatalf("Failed to marshal test object: %v", err)
	}

	parsed, err := ParseAttestationObject(data)
	if err != nil {
		t.Fatalf("ParseAttestationObject() failed: %v", err)
	}

	if parsed.Format != "tpm" {
		t.Errorf("Expected format 'tpm', got %q", parsed.Format)
	}

	if parsed.AttStatement.Ver != "2.0" {
		t.Errorf("Expected version '2.0', got %q", parsed.AttStatement.Ver)
	}

	if parsed.AttStatement.Alg != -257 {
		t.Errorf("Expected algorithm -257, got %d", parsed.AttStatement.Alg)
	}
}

func TestParseAttestationObject_InvalidCBOR(t *testing.T) {
	invalidData := []byte("not-valid-cbor")

	_, err := ParseAttestationObject(invalidData)
	if err == nil {
		t.Error("ParseAttestationObject() should fail with invalid CBOR")
	}
}

func TestValidateAttestationFormat_TPM(t *testing.T) {
	if !ValidateAttestationFormat(FormatTPM) {
		t.Error("ValidateAttestationFormat() should return true for FormatTPM")
	}
}

func TestValidateAttestationFormat_Invalid(t *testing.T) {
	if ValidateAttestationFormat(AttestationFormat("invalid")) {
		t.Error("ValidateAttestationFormat() should return false for invalid format")
	}

	if ValidateAttestationFormat(AttestationFormat("fido-u2f")) {
		t.Error("ValidateAttestationFormat() should return false for unsupported format")
	}

	if ValidateAttestationFormat(AttestationFormat("")) {
		t.Error("ValidateAttestationFormat() should return false for empty format")
	}
}

// Tests for EncodeAttestationForSubmission

func TestEncodeAttestationForSubmission_Success(t *testing.T) {
	obj := &AttestationObject{
		Format: "tpm",
		AttStatement: AttestationStatement{
			Ver:      "2.0",
			Alg:      -257,
			X5c:      []interface{}{[]byte("cert-bytes")},
			Sig:      []byte("signature"),
			CertInfo: []byte("cert-info"),
			PubArea:  []byte("pub-area"),
		},
	}

	encoded, err := EncodeAttestationForSubmission(obj)
	if err != nil {
		t.Fatalf("EncodeAttestationForSubmission() failed: %v", err)
	}

	if encoded == "" {
		t.Error("EncodeAttestationForSubmission() should return non-empty string")
	}

	// Verify it's valid base64 URL encoding
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("EncodeAttestationForSubmission() should produce valid base64URL: %v", err)
	}

	// Verify it decodes back to the same object
	var decodedObj AttestationObject
	if err := cbor.Unmarshal(decoded, &decodedObj); err != nil {
		t.Fatalf("Decoded data should be valid CBOR: %v", err)
	}

	if decodedObj.Format != obj.Format {
		t.Errorf("Format mismatch: expected %q, got %q", obj.Format, decodedObj.Format)
	}

	if decodedObj.AttStatement.Ver != obj.AttStatement.Ver {
		t.Errorf("Version mismatch: expected %q, got %q", obj.AttStatement.Ver, decodedObj.AttStatement.Ver)
	}

	if decodedObj.AttStatement.Alg != obj.AttStatement.Alg {
		t.Errorf("Algorithm mismatch: expected %d, got %d", obj.AttStatement.Alg, decodedObj.AttStatement.Alg)
	}
}

func TestEncodeAttestationForSubmission_EmptyObject(t *testing.T) {
	obj := &AttestationObject{}

	encoded, err := EncodeAttestationForSubmission(obj)
	if err != nil {
		t.Fatalf("EncodeAttestationForSubmission() should handle empty object: %v", err)
	}

	if encoded == "" {
		t.Error("EncodeAttestationForSubmission() should return non-empty string")
	}

	// Verify it decodes
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("Should produce valid base64URL: %v", err)
	}

	var decodedObj AttestationObject
	if err := cbor.Unmarshal(decoded, &decodedObj); err != nil {
		t.Fatalf("Decoded data should be valid CBOR: %v", err)
	}
}

func TestEncodeAttestationForSubmission_WithStatement(t *testing.T) {
	obj := &AttestationObject{
		Format: "tpm",
		AttStatement: AttestationStatement{
			Ver:      "2.0",
			Alg:      -257,
			Sig:      []byte("test-signature"),
			CertInfo: []byte("test-certinfo"),
		},
	}

	encoded, err := EncodeAttestationForSubmission(obj)
	require.NoError(t, err)
	assert.NotEmpty(t, encoded)

	// Verify roundtrip
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	require.NoError(t, err)

	var decodedObj AttestationObject
	err = cbor.Unmarshal(decoded, &decodedObj)
	require.NoError(t, err)
	assert.Equal(t, obj.Format, decodedObj.Format)
	assert.Equal(t, obj.AttStatement.Alg, decodedObj.AttStatement.Alg)
}

func TestEncodeAttestationForSubmission_LargeObject(t *testing.T) {
	// Create a large attestation object
	largeCertChain := make([]interface{}, 10)
	for i := 0; i < 10; i++ {
		largeCertChain[i] = make([]byte, 1024) // 1KB per cert
	}

	obj := &AttestationObject{
		Format: "tpm",
		AttStatement: AttestationStatement{
			Ver:      "2.0",
			Alg:      -257,
			X5c:      largeCertChain,
			Sig:      make([]byte, 256),
			CertInfo: make([]byte, 512),
			PubArea:  make([]byte, 256),
		},
	}

	encoded, err := EncodeAttestationForSubmission(obj)
	require.NoError(t, err)
	assert.NotEmpty(t, encoded)

	// Verify roundtrip
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	require.NoError(t, err)

	var decodedObj AttestationObject
	err = cbor.Unmarshal(decoded, &decodedObj)
	require.NoError(t, err)
	assert.Equal(t, obj.Format, decodedObj.Format)
}

func TestEncodeAttestationForSubmission_MinimalObject(t *testing.T) {
	obj := &AttestationObject{
		Format: "tpm",
	}

	encoded, err := EncodeAttestationForSubmission(obj)
	require.NoError(t, err)
	assert.NotEmpty(t, encoded)

	// Verify it's valid base64url
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	require.NoError(t, err)
	assert.NotEmpty(t, decoded)
}

func TestEncodeAttestationForSubmission_AllAlgorithms(t *testing.T) {
	algorithms := []int64{
		-257, // RS256
		-7,   // ES256
		-8,   // EdDSA
	}

	for _, alg := range algorithms {
		t.Run(algorithmName(alg), func(t *testing.T) {
			obj := &AttestationObject{
				Format: "tpm",
				AttStatement: AttestationStatement{
					Ver:      "2.0",
					Alg:      alg,
					Sig:      []byte("test-signature"),
					CertInfo: []byte("test-certinfo"),
				},
			}

			encoded, err := EncodeAttestationForSubmission(obj)
			require.NoError(t, err)
			assert.NotEmpty(t, encoded)

			// Verify roundtrip preserves algorithm
			decoded, err := base64.RawURLEncoding.DecodeString(encoded)
			require.NoError(t, err)

			var decodedObj AttestationObject
			err = cbor.Unmarshal(decoded, &decodedObj)
			require.NoError(t, err)
			assert.Equal(t, alg, decodedObj.AttStatement.Alg)
		})
	}
}

// algorithmName returns a human-readable name for a COSE algorithm
func algorithmName(alg int64) string {
	switch alg {
	case -257:
		return "RS256"
	case -7:
		return "ES256"
	case -8:
		return "EdDSA"
	default:
		return "Unknown"
	}
}

func TestEncodeAttestationForSubmission_SpecialCharacters(t *testing.T) {
	obj := &AttestationObject{
		Format: "tpm",
		AttStatement: AttestationStatement{
			Ver:      "2.0",
			Alg:      -257,
			Sig:      []byte{0x00, 0xFF, 0xFE, 0x01, 0x02}, // Binary data
			CertInfo: []byte("cert-info-with-\x00-null"),
			PubArea:  []byte{0xDE, 0xAD, 0xBE, 0xEF},
		},
	}

	encoded, err := EncodeAttestationForSubmission(obj)
	require.NoError(t, err)
	assert.NotEmpty(t, encoded)

	// Verify roundtrip preserves binary data
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	require.NoError(t, err)

	var decodedObj AttestationObject
	err = cbor.Unmarshal(decoded, &decodedObj)
	require.NoError(t, err)
	assert.Equal(t, obj.AttStatement.Sig, decodedObj.AttStatement.Sig)
}

func TestEncodeAttestationForSubmission_NilValues(t *testing.T) {
	obj := &AttestationObject{
		Format: "tpm",
		AttStatement: AttestationStatement{
			Ver:      "2.0",
			Alg:      -257,
			X5c:      nil,
			Sig:      nil,
			CertInfo: nil,
			PubArea:  nil,
		},
	}

	encoded, err := EncodeAttestationForSubmission(obj)
	require.NoError(t, err)
	assert.NotEmpty(t, encoded)
}

func TestEncodeAttestationForSubmission_EmptyX5c(t *testing.T) {
	obj := &AttestationObject{
		Format: "tpm",
		AttStatement: AttestationStatement{
			Ver:      "2.0",
			Alg:      -257,
			X5c:      []interface{}{},
			Sig:      []byte("signature"),
			CertInfo: []byte("certinfo"),
			PubArea:  []byte("pubarea"),
		},
	}

	encoded, err := EncodeAttestationForSubmission(obj)
	require.NoError(t, err)
	assert.NotEmpty(t, encoded)

	// Verify roundtrip
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	require.NoError(t, err)

	var decodedObj AttestationObject
	err = cbor.Unmarshal(decoded, &decodedObj)
	require.NoError(t, err)
	assert.Equal(t, 0, len(decodedObj.AttStatement.X5c))
}

func TestEncodeAttestationForSubmission_Deterministic(t *testing.T) {
	obj := &AttestationObject{
		Format: "tpm",
		AttStatement: AttestationStatement{
			Ver:      "2.0",
			Alg:      -257,
			X5c:      []interface{}{[]byte("cert")},
			Sig:      []byte("signature"),
			CertInfo: []byte("certinfo"),
			PubArea:  []byte("pubarea"),
		},
	}

	// Encode multiple times
	encoded1, err1 := EncodeAttestationForSubmission(obj)
	require.NoError(t, err1)

	encoded2, err2 := EncodeAttestationForSubmission(obj)
	require.NoError(t, err2)

	encoded3, err3 := EncodeAttestationForSubmission(obj)
	require.NoError(t, err3)

	// All encodings should be identical
	assert.Equal(t, encoded1, encoded2)
	assert.Equal(t, encoded2, encoded3)
}

func TestEncodeAttestationForSubmission_LargePayload(t *testing.T) {
	// Create attestation object with large payload
	largeCert := make([]byte, 4096)
	for i := range largeCert {
		largeCert[i] = byte(i % 256)
	}

	obj := &AttestationObject{
		Format: "tpm",
		AttStatement: AttestationStatement{
			Ver:      "2.0",
			Alg:      -257,
			X5c:      []interface{}{largeCert},
			Sig:      make([]byte, 512),
			CertInfo: make([]byte, 1024),
			PubArea:  make([]byte, 256),
		},
	}

	encoded, err := EncodeAttestationForSubmission(obj)
	assert.NoError(t, err)
	assert.NotEmpty(t, encoded)

	// Verify the encoded string is valid base64url
	assert.NotContains(t, encoded, "+")
	assert.NotContains(t, encoded, "/")
	assert.NotContains(t, encoded, "=")
}

func TestEncodeAttestationForSubmission_CBORMarshalError(t *testing.T) {
	// cbor.Marshal returns an error when it encounters unsupported types like
	// channels or functions. The X5c field is []interface{} which can contain
	// any type, including unsupported ones.
	t.Run("unsupported_type_channel_in_x5c", func(t *testing.T) {
		obj := &AttestationObject{
			Format: FormatTPM.String(),
			AttStatement: AttestationStatement{
				Ver: "2.0",
				Alg: int64(-257),
				// Put a channel in X5c - cbor cannot marshal channels
				X5c: []interface{}{make(chan int)},
			},
		}

		encoded, err := EncodeAttestationForSubmission(obj)
		require.Error(t, err)
		assert.Empty(t, encoded)
		assert.Contains(t, err.Error(), "unsupported type")
	})

	t.Run("unsupported_type_function_in_x5c", func(t *testing.T) {
		obj := &AttestationObject{
			Format: FormatTPM.String(),
			AttStatement: AttestationStatement{
				Ver: "2.0",
				Alg: int64(-257),
				// Put a function in X5c - cbor cannot marshal functions
				X5c: []interface{}{func() {}},
			},
		}

		encoded, err := EncodeAttestationForSubmission(obj)
		require.Error(t, err)
		assert.Empty(t, encoded)
		assert.Contains(t, err.Error(), "unsupported type")
	})

	t.Run("mixed_valid_and_invalid_types_in_x5c", func(t *testing.T) {
		obj := &AttestationObject{
			Format: FormatTPM.String(),
			AttStatement: AttestationStatement{
				Ver: "2.0",
				Alg: int64(-257),
				// Mix of valid bytes and invalid channel
				X5c: []interface{}{
					[]byte("valid-cert"),
					make(chan struct{}),
				},
			},
		}

		encoded, err := EncodeAttestationForSubmission(obj)
		require.Error(t, err)
		assert.Empty(t, encoded)
	})

	t.Run("nested_unsupported_type", func(t *testing.T) {
		// Create a nested structure with an unsupported type
		type nestedWithFunc struct {
			F func()
		}

		obj := &AttestationObject{
			Format: FormatTPM.String(),
			AttStatement: AttestationStatement{
				Ver: "2.0",
				Alg: int64(-257),
				X5c: []interface{}{nestedWithFunc{F: func() {}}},
			},
		}

		encoded, err := EncodeAttestationForSubmission(obj)
		require.Error(t, err)
		assert.Empty(t, encoded)
	})
}

// Tests for AttestationObject CBOR roundtrip

func TestAttestationObject_CBORRoundtrip(t *testing.T) {
	original := &AttestationObject{
		Format: "tpm",
		AttStatement: AttestationStatement{
			Ver:      "2.0",
			Alg:      -7,
			X5c:      []interface{}{[]byte("cert1"), []byte("cert2")},
			Sig:      []byte("test-signature"),
			CertInfo: []byte("test-certinfo"),
			PubArea:  []byte("test-pubarea"),
		},
	}

	// Encode
	encoded, err := cbor.Marshal(original)
	require.NoError(t, err)

	// Decode
	var decoded AttestationObject
	err = cbor.Unmarshal(encoded, &decoded)
	require.NoError(t, err)

	// Verify
	assert.Equal(t, original.Format, decoded.Format)
	assert.Equal(t, original.AttStatement.Ver, decoded.AttStatement.Ver)
	assert.Equal(t, original.AttStatement.Alg, decoded.AttStatement.Alg)
	assert.Equal(t, original.AttStatement.Sig, decoded.AttStatement.Sig)
	assert.Equal(t, original.AttStatement.CertInfo, decoded.AttStatement.CertInfo)
	assert.Equal(t, original.AttStatement.PubArea, decoded.AttStatement.PubArea)
}

// Tests for type validation and error definitions

func TestValidateAttestationFormat_AllFormats(t *testing.T) {
	t.Run("valid_tpm", func(t *testing.T) {
		assert.True(t, ValidateAttestationFormat(FormatTPM))
	})

	t.Run("invalid_unknown", func(t *testing.T) {
		assert.False(t, ValidateAttestationFormat(AttestationFormat("unknown")))
	})

	t.Run("invalid_empty", func(t *testing.T) {
		assert.False(t, ValidateAttestationFormat(AttestationFormat("")))
	})

	t.Run("invalid_packed", func(t *testing.T) {
		assert.False(t, ValidateAttestationFormat(AttestationFormat("packed")))
	})
}

func TestParseAttestationObject_AllPaths(t *testing.T) {
	t.Run("valid_object", func(t *testing.T) {
		obj := &AttestationObject{
			Format: FormatTPM.String(),
			AttStatement: AttestationStatement{
				Ver: "2.0",
				Alg: int64(-257),
			},
		}

		encoded, err := cbor.Marshal(obj)
		require.NoError(t, err)

		parsed, err := ParseAttestationObject(encoded)
		require.NoError(t, err)
		assert.Equal(t, obj.Format, parsed.Format)
	})

	t.Run("invalid_cbor", func(t *testing.T) {
		_, err := ParseAttestationObject([]byte("not-cbor"))
		assert.Error(t, err)
	})

	t.Run("empty_data", func(t *testing.T) {
		_, err := ParseAttestationObject([]byte{})
		assert.Error(t, err)
	})
}

// TestAttestationRequest_WireName pins the draft-ietf-acme-device-attest
// payload member name: a client and server that disagree on it never interoperate.
func TestAttestationRequest_WireName(t *testing.T) {
	payload, err := json.Marshal(AttestationRequest{AttObj: "abc"})
	require.NoError(t, err)
	assert.JSONEq(t, `{"attObj":"abc"}`, string(payload))
}

func TestErrorVariables(t *testing.T) {
	assert.NotNil(t, ErrInvalidKeyAlgorithm)
	assert.NotNil(t, ErrInvalidAttestationFormat)
	assert.NotNil(t, ErrInvalidAttestationObject)
	assert.NotNil(t, ErrTPMAttestationInvalid)
	assert.NotNil(t, ErrAIKCertificateInvalid)
	assert.NotNil(t, ErrCertificateChainInvalid)

	assert.Contains(t, ErrInvalidKeyAlgorithm.Error(), "invalid key algorithm")
	assert.Contains(t, ErrInvalidAttestationFormat.Error(), "invalid attestation format")
	assert.Contains(t, ErrInvalidAttestationObject.Error(), "invalid attestation object")
	assert.Contains(t, ErrTPMAttestationInvalid.Error(), "tpm attestation statement invalid")
	assert.Contains(t, ErrAIKCertificateInvalid.Error(), "AIK certificate")
	assert.Contains(t, ErrCertificateChainInvalid.Error(), "certificate chain invalid")
}

func TestAttestationStatement_EmptyFields(t *testing.T) {
	stmt := AttestationStatement{}

	assert.Equal(t, "", stmt.Ver)
	assert.Equal(t, int64(0), stmt.Alg)
	assert.Nil(t, stmt.X5c)
	assert.Nil(t, stmt.Sig)
	assert.Nil(t, stmt.CertInfo)
	assert.Nil(t, stmt.PubArea)
}

func TestAttestationObject_EmptyFields(t *testing.T) {
	obj := AttestationObject{}

	assert.Equal(t, "", obj.Format)
	assert.Equal(t, "", obj.AttStatement.Ver)
}

// Benchmarks

func BenchmarkParseAttestationObject(b *testing.B) {
	obj := &AttestationObject{
		Format: "tpm",
		AttStatement: AttestationStatement{
			Ver:      "2.0",
			Alg:      -257,
			X5c:      []interface{}{[]byte("cert-bytes")},
			Sig:      []byte("signature"),
			CertInfo: []byte("cert-info"),
			PubArea:  []byte("pub-area"),
		},
	}

	data, _ := cbor.Marshal(obj)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseAttestationObject(data)
	}
}

// draft-ietf-acme-device-attest: authData "SHOULD be omitted", and a server
// "MUST ignore unrecognized fields in the challenge response". A client that
// sends either is not refused.
func TestParseAttestationRequest_IgnoresWhatTheDraftSaysToIgnore(t *testing.T) {
	object := map[string]interface{}{
		"fmt":      "tpm",
		"attStmt":  map[string]interface{}{"ver": "2.0"},
		"authData": []byte("browser-context-data"),
	}
	encoded, err := cbor.Marshal(object)
	require.NoError(t, err)
	payload := []byte(`{"attObj":"` + base64.RawURLEncoding.EncodeToString(encoded) + `","extra":{"anything":1}}`)

	parsed, err := ParseAttestationRequest(payload)

	require.NoError(t, err)
	assert.Equal(t, "tpm", parsed.Format)
	assert.Equal(t, "2.0", parsed.AttStatement.Ver)
}
