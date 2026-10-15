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

package keybackend

import (
	"crypto"
	"crypto/x509"
	"encoding/binary"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCoseAlgorithmFromCBORValue covers every decoded CBOR integer shape
// fxamacker/cbor produces for a COSE_Key "alg" label when the target is
// interface{}, plus the refusal of anything else.
func TestCoseAlgorithmFromCBORValue(t *testing.T) {
	tests := []struct {
		name    string
		value   interface{}
		want    int
		wantErr bool
	}{
		{"int64", int64(-7), COSEAlgES256, false},
		{"uint64", uint64(3), 3, false},
		{"int", int(-257), COSEAlgRS256, false},
		{"unsupported type", "not-a-number", 0, true},
		{"nil value", nil, 0, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := coseAlgorithmFromCBORValue(tc.value)
			if tc.wantErr {
				require.ErrorIs(t, err, ErrAttestationAuthDataInvalid)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestCoseAlgorithmFromSignatureAlgorithm covers every x509 signature
// algorithm an IAK's TCG key template can carry and the refusal of anything
// else (e.g. Ed25519, which no TCG IDevID/IAK template produces).
func TestCoseAlgorithmFromSignatureAlgorithm(t *testing.T) {
	tests := []struct {
		sigAlg x509.SignatureAlgorithm
		want   int
	}{
		{x509.ECDSAWithSHA256, COSEAlgES256},
		{x509.ECDSAWithSHA384, COSEAlgES384},
		{x509.ECDSAWithSHA512, COSEAlgES512},
		{x509.SHA256WithRSA, COSEAlgRS256},
		{x509.SHA384WithRSA, COSEAlgRS384},
		{x509.SHA512WithRSA, COSEAlgRS512},
		{x509.SHA256WithRSAPSS, COSEAlgPS256},
		{x509.SHA384WithRSAPSS, COSEAlgPS384},
		{x509.SHA512WithRSAPSS, COSEAlgPS512},
	}
	for _, tc := range tests {
		t.Run(tc.sigAlg.String(), func(t *testing.T) {
			got, err := coseAlgorithmFromSignatureAlgorithm(tc.sigAlg)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}

	t.Run("unsupported", func(t *testing.T) {
		_, err := coseAlgorithmFromSignatureAlgorithm(x509.PureEd25519)
		require.ErrorIs(t, err, ErrUnsupportedAttestationKey)
	})
}

// TestHashForSignatureAlgorithm covers every digest family an IAK signature
// algorithm can carry and the refusal of anything else.
func TestHashForSignatureAlgorithm(t *testing.T) {
	tests := []struct {
		sigAlg x509.SignatureAlgorithm
		want   crypto.Hash
	}{
		{x509.ECDSAWithSHA256, crypto.SHA256},
		{x509.SHA256WithRSA, crypto.SHA256},
		{x509.SHA256WithRSAPSS, crypto.SHA256},
		{x509.ECDSAWithSHA384, crypto.SHA384},
		{x509.SHA384WithRSA, crypto.SHA384},
		{x509.SHA384WithRSAPSS, crypto.SHA384},
		{x509.ECDSAWithSHA512, crypto.SHA512},
		{x509.SHA512WithRSA, crypto.SHA512},
		{x509.SHA512WithRSAPSS, crypto.SHA512},
	}
	for _, tc := range tests {
		t.Run(tc.sigAlg.String(), func(t *testing.T) {
			got, err := hashForSignatureAlgorithm(tc.sigAlg)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}

	t.Run("unsupported", func(t *testing.T) {
		_, err := hashForSignatureAlgorithm(x509.PureEd25519)
		require.ErrorIs(t, err, ErrUnsupportedAttestationKey)
	})
}

// buildTPMAuthDataRaw hand-assembles WebAuthn L2 §6.5.1 authenticator data
// carrying attested credential data with an arbitrary trailing COSE_Key,
// independent of buildAuthData in the simulator test file (which is guarded
// by the tpm_simulator build tag and unavailable to this file).
func buildTPMAuthDataRaw(credentialID, coseKeyBytes []byte) []byte {
	buf := make([]byte, 0, 37+16+2+len(credentialID)+len(coseKeyBytes))
	buf = append(buf, make([]byte, 32)...)
	buf = append(buf, authDataFlagAttestedCredentialData)
	buf = append(buf, 0, 0, 0, 1)
	buf = append(buf, make([]byte, aaguidSize)...)
	credIDLen := make([]byte, 2)
	binary.BigEndian.PutUint16(credIDLen, uint16(len(credentialID)))
	buf = append(buf, credIDLen...)
	buf = append(buf, credentialID...)
	buf = append(buf, coseKeyBytes...)
	return buf
}

// buildTPMAuthData is buildTPMAuthDataRaw with a canonical COSE_Key carrying
// alg as its only label.
func buildTPMAuthData(t *testing.T, credentialID []byte, alg int) []byte {
	t.Helper()

	coseKeyBytes, err := cbor.Marshal(map[int]interface{}{1: COSEKeyTypeEC2, 3: alg})
	require.NoError(t, err)

	return buildTPMAuthDataRaw(credentialID, coseKeyBytes)
}

// TestCredentialFromAuthData covers the happy path and every way §6.5.1
// authenticator data can be malformed.
func TestCredentialFromAuthData(t *testing.T) {
	t.Run("extracts credential ID and algorithm", func(t *testing.T) {
		authData := buildTPMAuthData(t, []byte("credential-1"), COSEAlgES256)

		id, alg, err := credentialFromAuthData(authData)

		require.NoError(t, err)
		assert.Equal(t, []byte("credential-1"), id)
		assert.Equal(t, COSEAlgES256, alg)
	})

	t.Run("rejects data too short to carry an AAGUID and length", func(t *testing.T) {
		_, _, err := credentialFromAuthData(make([]byte, 40))
		require.ErrorIs(t, err, ErrAttestationAuthDataInvalid)
	})

	t.Run("rejects data with no attested credential data flag", func(t *testing.T) {
		authData := buildTPMAuthData(t, []byte("credential-1"), COSEAlgES256)
		authData[32] = 0 // clear the AT flag

		_, _, err := credentialFromAuthData(authData)
		require.ErrorIs(t, err, ErrAttestationAuthDataInvalid)
	})

	t.Run("rejects a zero-length credential ID", func(t *testing.T) {
		authData := buildTPMAuthData(t, nil, COSEAlgES256)

		_, _, err := credentialFromAuthData(authData)
		require.ErrorIs(t, err, ErrAttestationAuthDataInvalid)
	})

	t.Run("rejects a credential ID length that overruns the buffer", func(t *testing.T) {
		authData := buildTPMAuthData(t, []byte("credential-1"), COSEAlgES256)
		// Claim a credential ID far longer than what follows. The 2-byte
		// length field immediately follows the AAGUID.
		credIDLenOffset := authDataAAGUIDOffset + aaguidSize
		binary.BigEndian.PutUint16(authData[credIDLenOffset:], 0xFFFF)

		_, _, err := credentialFromAuthData(authData)
		require.ErrorIs(t, err, ErrAttestationAuthDataInvalid)
	})

	t.Run("rejects a COSE key that fails to decode", func(t *testing.T) {
		authData := buildTPMAuthData(t, []byte("credential-1"), COSEAlgES256)
		// Truncate the trailing CBOR map so the decoder fails.
		authData = authData[:len(authData)-1]

		_, _, err := credentialFromAuthData(authData)
		require.ErrorIs(t, err, ErrAttestationAuthDataInvalid)
	})

	t.Run("rejects a COSE key with a non-integer alg label", func(t *testing.T) {
		coseKeyBytes, err := cbor.Marshal(map[int]interface{}{1: COSEKeyTypeEC2, 3: "not-a-number"})
		require.NoError(t, err)

		authData := buildTPMAuthDataRaw([]byte("credential-1"), coseKeyBytes)

		_, _, err = credentialFromAuthData(authData)
		require.ErrorIs(t, err, ErrAttestationAuthDataInvalid)
	})
}

// TestTPM2AttestingBackend_GetAttestationStatement_FormatAndNilTPM covers the
// two guard clauses GetAttestationStatement checks before it ever touches
// hardware: an unrequested format and a backend with no TPM collaborator.
// Neither requires the simulator, so both run under the package's default
// build tags.
func TestTPM2AttestingBackend_GetAttestationStatement_FormatAndNilTPM(t *testing.T) {
	backend := NewTPM2AttestingBackend(nil, nil, nil)

	t.Run("rejects an unrequested format", func(t *testing.T) {
		_, err := backend.GetAttestationStatement("packed", nil, nil)
		require.ErrorIs(t, err, ErrAttestationNotSupported)
	})

	t.Run("rejects a backend with no TPM", func(t *testing.T) {
		_, err := backend.GetAttestationStatement(AttestationFormatTPM, nil, nil)
		require.ErrorIs(t, err, ErrNoAttestationKey)
	})
}
