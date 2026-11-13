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

// TestAttestationRequest_WireName pins the draft-ietf-acme-device-attest-10
// payload member name: a client and server that disagree on it never interoperate.
func TestAttestationRequest_WireName(t *testing.T) {
	payload, err := json.Marshal(AttestationRequest{AttObj: "abc"})
	require.NoError(t, err)
	assert.JSONEq(t, `{"attObj":"abc"}`, string(payload))
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

// draft-ietf-acme-device-attest-10: authData "SHOULD be omitted", and a server
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
