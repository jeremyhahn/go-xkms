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

package authenticator

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"log/slog"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/authenticator/keybackend"
	"github.com/stretchr/testify/require"
)

// createMakeCredentialTestAuthenticator creates an authenticator for MakeCredential tests.
func createMakeCredentialTestAuthenticator(t *testing.T) *Authenticator {
	t.Helper()

	storage := NewMemoryStorage()
	config := &Config{
		AAGUID:                     DefaultAAGUID,
		SupportedAlgorithms:        []int{COSEAlgES256, COSEAlgES384, COSEAlgEdDSA},
		MaxCredentials:             100,
		MaxResidentCredentials:     25,
		PINMinLength:               4,
		PINMaxRetries:              8,
		EnablePIN:                  true,
		EnableResidentKey:          true,
		EnableCredentialManagement: true,
		EnableHMACSecret:           true,
		Storage:                    storage,
	}

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)

	return auth
}

func TestMakeCredential_Success(t *testing.T) {
	auth := createMakeCredentialTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	clientData := []byte("test client data for hashing")
	clientDataHash := sha256.Sum256(clientData)

	rp := RelyingParty{
		ID:   "example.com",
		Name: "Example Corp",
	}

	user := User{
		ID:          []byte("user-123"),
		Name:        "john.doe@example.com",
		DisplayName: "John Doe",
	}

	pubKeyCredParams := []PublicKeyCredentialParam{
		{Type: "public-key", Alg: COSEAlgES256},
	}

	t.Run("successful credential creation", func(t *testing.T) {
		resp, err := auth.MakeCredential(clientDataHash[:], rp, user, pubKeyCredParams, nil)
		require.NoError(t, err)
		require.NotNil(t, resp)

		require.Equal(t, AttestationFormatNone, resp.Fmt)
		require.NotEmpty(t, resp.AuthData)
		require.NotNil(t, resp.AttStmt)

		// Parse the auth data to verify it's valid
		authData, err := ParseAuthData(resp.AuthData)
		require.NoError(t, err)

		require.True(t, authData.HasAttestedCredentialData())
		require.True(t, authData.UserPresent())
		require.NotEmpty(t, authData.CredentialID)
		require.NotEmpty(t, authData.PublicKey)

		// Verify the credential was stored
		cred, err := auth.storage.Load(authData.CredentialID)
		require.NoError(t, err)
		require.Equal(t, rp.ID, cred.RPID)
		require.Equal(t, user.ID, cred.UserID)
	})

	t.Run("with resident key option", func(t *testing.T) {
		opts := &MakeCredentialOptions{
			Options: map[string]bool{
				"rk": true,
			},
		}

		resp, err := auth.MakeCredential(clientDataHash[:], rp, user, pubKeyCredParams, opts)
		require.NoError(t, err)

		authData, err := ParseAuthData(resp.AuthData)
		require.NoError(t, err)

		cred, err := auth.storage.Load(authData.CredentialID)
		require.NoError(t, err)
		require.True(t, cred.Discoverable)
	})

	t.Run("with hmac-secret extension", func(t *testing.T) {
		opts := &MakeCredentialOptions{
			Extensions: map[string]interface{}{
				"hmac-secret": true,
			},
		}

		resp, err := auth.MakeCredential(clientDataHash[:], rp, user, pubKeyCredParams, opts)
		require.NoError(t, err)

		authData, err := ParseAuthData(resp.AuthData)
		require.NoError(t, err)

		cred, err := auth.storage.Load(authData.CredentialID)
		require.NoError(t, err)
		require.Len(t, cred.HMACSecretKey, HMACSecretKeySize)

		// Extension outputs are included in authData (ED flag set) for
		// Chrome CTAP2 compatibility.
		require.True(t, authData.HasExtensions())
	})

	t.Run("with user verification", func(t *testing.T) {
		// Set up a valid PIN protocol state with a known token so that
		// VerifyPinUvAuthToken can validate the pinUvAuthParam.
		pinToken := make([]byte, 32)
		for i := range pinToken {
			pinToken[i] = byte(i)
		}
		auth.pinState.protocol = &pinProtocolState{
			pinUvAuthToken:   pinToken,
			tokenPermissions: PINPermissionMakeCredential,
		}

		// Compute valid pinUvAuthParam: HMAC-SHA-256(pinToken, clientDataHash)[:16]
		mac := hmac.New(sha256.New, pinToken)
		mac.Write(clientDataHash[:])
		pinUvAuthParam := mac.Sum(nil)[:16]

		opts := &MakeCredentialOptions{
			Options: map[string]bool{
				"uv": true,
			},
			PINUVAuthParam:    pinUvAuthParam,
			PINUVAuthProtocol: 1,
		}

		resp, err := auth.MakeCredential(clientDataHash[:], rp, user, pubKeyCredParams, opts)
		require.NoError(t, err)

		authData, err := ParseAuthData(resp.AuthData)
		require.NoError(t, err)
		require.True(t, authData.UserVerified())
	})
}

func TestMakeCredential_Errors(t *testing.T) {
	auth := createMakeCredentialTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	clientDataHash := make([]byte, ClientDataHashSize)
	rp := RelyingParty{ID: "example.com", Name: "Example"}
	user := User{ID: []byte("user-123"), Name: "test@example.com"}
	pubKeyCredParams := []PublicKeyCredentialParam{{Type: "public-key", Alg: COSEAlgES256}}

	t.Run("invalid clientDataHash length", func(t *testing.T) {
		shortHash := make([]byte, 16) // Should be 32 bytes
		_, err := auth.MakeCredential(shortHash, rp, user, pubKeyCredParams, nil)
		require.ErrorIs(t, err, ErrInvalidClientDataHash)
	})

	t.Run("empty rp.id", func(t *testing.T) {
		emptyRP := RelyingParty{ID: "", Name: "Test"}
		_, err := auth.MakeCredential(clientDataHash, emptyRP, user, pubKeyCredParams, nil)
		require.ErrorIs(t, err, ErrMissingRPID)
	})

	t.Run("empty user.id", func(t *testing.T) {
		emptyUser := User{ID: nil, Name: "test"}
		_, err := auth.MakeCredential(clientDataHash, rp, emptyUser, pubKeyCredParams, nil)
		require.ErrorIs(t, err, ErrMissingUserID)
	})

	t.Run("empty pubKeyCredParams", func(t *testing.T) {
		_, err := auth.MakeCredential(clientDataHash, rp, user, nil, nil)
		require.ErrorIs(t, err, ErrMissingPubKeyCredParams)
	})

	t.Run("no supported algorithm", func(t *testing.T) {
		unsupportedParams := []PublicKeyCredentialParam{
			{Type: "public-key", Alg: COSEAlgRS256}, // RS256 is not implemented
		}
		_, err := auth.MakeCredential(clientDataHash, rp, user, unsupportedParams, nil)
		require.ErrorIs(t, err, ErrNoSupportedAlgorithm)
	})

	t.Run("credential excluded", func(t *testing.T) {
		// First, create a credential
		resp, err := auth.MakeCredential(clientDataHash, rp, user, pubKeyCredParams, nil)
		require.NoError(t, err)

		authData, _ := ParseAuthData(resp.AuthData)

		// Try to create another credential with the first one in exclude list
		opts := &MakeCredentialOptions{
			ExcludeList: []CredentialDescriptor{
				{Type: "public-key", ID: authData.CredentialID},
			},
		}

		_, err = auth.MakeCredential(clientDataHash, rp, user, pubKeyCredParams, opts)
		require.ErrorIs(t, err, ErrCredentialExcluded)
	})

	t.Run("invalid pinUvAuthParam", func(t *testing.T) {
		// Set up PIN protocol state with known token
		pinToken := make([]byte, 32)
		for i := range pinToken {
			pinToken[i] = byte(i)
		}
		auth.pinState.protocol = &pinProtocolState{
			pinUvAuthToken:   pinToken,
			tokenPermissions: PINPermissionMakeCredential,
		}

		// Use deliberately wrong pinUvAuthParam
		opts := &MakeCredentialOptions{
			PINUVAuthParam:    []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
			PINUVAuthProtocol: 1,
		}

		_, err := auth.MakeCredential(clientDataHash, rp, user, pubKeyCredParams, opts)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrPINAuthInvalid)
	})

	t.Run("PIN required when no pinUvAuthParam and PIN is set", func(t *testing.T) {
		// Create authenticator with PIN enabled and set
		storage := NewMemoryStorage()
		state := NewAuthenticatorState()
		state.AAGUID = DefaultAAGUID
		state.PINSet = true
		err := storage.SaveState(state)
		require.NoError(t, err)

		config := DefaultConfig()
		config.Storage = storage
		config.EnablePIN = true

		pinAuth, err := NewAuthenticator(config)
		require.NoError(t, err)
		defer func() { _ = pinAuth.Close() }()

		// Call MakeCredential WITHOUT pinUvAuthParam — should return ErrPINRequired
		_, err = pinAuth.MakeCredential(clientDataHash, rp, user, pubKeyCredParams, nil)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrPINRequired)
	})
}

func TestMakeCredential_Limits(t *testing.T) {
	t.Run("credential limit reached", func(t *testing.T) {
		storage := NewMemoryStorage()
		config := &Config{
			AAGUID:                 DefaultAAGUID,
			SupportedAlgorithms:    []int{COSEAlgES256},
			MaxCredentials:         2, // Very small limit for testing
			MaxResidentCredentials: 1,
			PINMinLength:           4,
			PINMaxRetries:          8,
			EnableResidentKey:      true,
			Storage:                storage,
		}

		auth, err := NewAuthenticator(config)
		require.NoError(t, err)
		defer func() { _ = auth.Close() }()

		clientDataHash := make([]byte, ClientDataHashSize)
		rp := RelyingParty{ID: "example.com"}
		pubKeyCredParams := []PublicKeyCredentialParam{{Type: "public-key", Alg: COSEAlgES256}}

		// Create credentials up to the limit
		for i := 0; i < 2; i++ {
			user := User{ID: []byte{byte(i)}, Name: "user"}
			_, err := auth.MakeCredential(clientDataHash, rp, user, pubKeyCredParams, nil)
			require.NoError(t, err)
		}

		// Next one should fail
		user := User{ID: []byte{99}, Name: "excess"}
		_, err = auth.MakeCredential(clientDataHash, rp, user, pubKeyCredParams, nil)
		require.ErrorIs(t, err, ErrCredentialLimitReached)
	})

	t.Run("resident key limit reached", func(t *testing.T) {
		storage := NewMemoryStorage()
		config := &Config{
			AAGUID:                 DefaultAAGUID,
			SupportedAlgorithms:    []int{COSEAlgES256},
			MaxCredentials:         10,
			MaxResidentCredentials: 1, // Very small limit for testing
			PINMinLength:           4,
			PINMaxRetries:          8,
			EnableResidentKey:      true,
			Storage:                storage,
		}

		auth, err := NewAuthenticator(config)
		require.NoError(t, err)
		defer func() { _ = auth.Close() }()

		clientDataHash := make([]byte, ClientDataHashSize)
		rp := RelyingParty{ID: "example.com"}
		user := User{ID: []byte("user"), Name: "user"}
		pubKeyCredParams := []PublicKeyCredentialParam{{Type: "public-key", Alg: COSEAlgES256}}

		opts := &MakeCredentialOptions{
			Options: map[string]bool{"rk": true},
		}

		// Create one resident key
		_, err = auth.MakeCredential(clientDataHash, rp, user, pubKeyCredParams, opts)
		require.NoError(t, err)

		// Second resident key should fail
		user2 := User{ID: []byte("user2"), Name: "user2"}
		_, err = auth.MakeCredential(clientDataHash, rp, user2, pubKeyCredParams, opts)
		require.ErrorIs(t, err, ErrResidentKeyLimitReached)
	})
}

func TestProcessCBOR_MakeCredential(t *testing.T) {
	auth := createMakeCredentialTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	clientDataHash := make([]byte, ClientDataHashSize)

	t.Run("successful CBOR request via ProcessCBOR", func(t *testing.T) {
		// Build a CBOR-encoded request
		reqMap := map[int]interface{}{
			makeCredentialKeyClientDataHash: clientDataHash,
			makeCredentialKeyRP: map[string]interface{}{
				"id":   "example.com",
				"name": "Example",
			},
			makeCredentialKeyUser: map[string]interface{}{
				"id":          []byte("user-123"),
				"name":        "test@example.com",
				"displayName": "Test User",
			},
			makeCredentialKeyPubKeyCredParams: []interface{}{
				map[string]interface{}{"type": "public-key", "alg": COSEAlgES256},
			},
		}

		reqData, err := cbor.Marshal(reqMap)
		require.NoError(t, err)

		respData, err := auth.ProcessCBOR(CmdMakeCredential, reqData)
		require.NoError(t, err)

		// First byte should be status OK
		require.Equal(t, byte(StatusOK), respData[0])

		// Decode the response (skip status byte)
		var respMap map[int]interface{}
		err = cbor.Unmarshal(respData[1:], &respMap)
		require.NoError(t, err)

		require.Equal(t, AttestationFormatNone, respMap[makeCredentialResponseKeyFmt])

		authDataBytes, ok := respMap[makeCredentialResponseKeyAuthData].([]byte)
		require.True(t, ok)
		require.NotEmpty(t, authDataBytes)
		require.NotNil(t, respMap[makeCredentialResponseKeyAttStmt])
	})
}

func TestDecodeMakeCredentialRequest(t *testing.T) {
	clientDataHash := make([]byte, ClientDataHashSize)

	t.Run("complete request", func(t *testing.T) {
		reqMap := map[int]interface{}{
			makeCredentialKeyClientDataHash: clientDataHash,
			makeCredentialKeyRP: map[string]interface{}{
				"id":   "example.com",
				"name": "Example Corp",
				"icon": "https://example.com/icon.png",
			},
			makeCredentialKeyUser: map[string]interface{}{
				"id":          []byte("user-id"),
				"name":        "user@example.com",
				"displayName": "User",
			},
			makeCredentialKeyPubKeyCredParams: []interface{}{
				map[string]interface{}{"type": "public-key", "alg": COSEAlgES256},
				map[string]interface{}{"type": "public-key", "alg": COSEAlgEdDSA},
			},
			makeCredentialKeyExcludeList: []interface{}{
				map[string]interface{}{
					"type":       "public-key",
					"id":         []byte("excluded-cred"),
					"transports": []interface{}{"usb", "nfc"},
				},
			},
			makeCredentialKeyExtensions: map[string]interface{}{
				"hmac-secret": true,
				"credProtect": uint8(2),
			},
			makeCredentialKeyOptions: map[string]interface{}{
				"rk": true,
				"uv": false,
			},
			makeCredentialKeyPINUVAuthParam:    []byte("auth-param"),
			makeCredentialKeyPINUVAuthProtocol: uint8(1),
		}

		reqData, err := cbor.Marshal(reqMap)
		require.NoError(t, err)

		req, err := DecodeMakeCredentialRequest(reqData)
		require.NoError(t, err)

		require.Len(t, req.ClientDataHash, ClientDataHashSize)
		require.Equal(t, "example.com", req.RP.ID)
		require.Equal(t, "Example Corp", req.RP.Name)
		require.Equal(t, []byte("user-id"), req.User.ID)
		require.Len(t, req.PubKeyCredParams, 2)
		require.Len(t, req.ExcludeList, 1)
		require.Equal(t, true, req.Extensions["hmac-secret"])
		require.Equal(t, true, req.Options["rk"])
		require.Len(t, req.PINUVAuthParam, 10)
		require.Equal(t, uint8(1), req.PINUVAuthProtocol)
	})

	t.Run("missing clientDataHash", func(t *testing.T) {
		reqMap := map[int]interface{}{
			makeCredentialKeyRP:               map[string]interface{}{"id": "example.com"},
			makeCredentialKeyUser:             map[string]interface{}{"id": []byte("user")},
			makeCredentialKeyPubKeyCredParams: []interface{}{map[string]interface{}{"type": "public-key", "alg": -7}},
		}
		reqData, _ := cbor.Marshal(reqMap)

		_, err := DecodeMakeCredentialRequest(reqData)
		require.ErrorIs(t, err, ErrMissingClientDataHash)
	})

	t.Run("missing rp", func(t *testing.T) {
		reqMap := map[int]interface{}{
			makeCredentialKeyClientDataHash:   clientDataHash,
			makeCredentialKeyUser:             map[string]interface{}{"id": []byte("user")},
			makeCredentialKeyPubKeyCredParams: []interface{}{map[string]interface{}{"type": "public-key", "alg": -7}},
		}
		reqData, _ := cbor.Marshal(reqMap)

		_, err := DecodeMakeCredentialRequest(reqData)
		require.ErrorIs(t, err, ErrMissingRP)
	})

	t.Run("missing user", func(t *testing.T) {
		reqMap := map[int]interface{}{
			makeCredentialKeyClientDataHash:   clientDataHash,
			makeCredentialKeyRP:               map[string]interface{}{"id": "example.com"},
			makeCredentialKeyPubKeyCredParams: []interface{}{map[string]interface{}{"type": "public-key", "alg": -7}},
		}
		reqData, _ := cbor.Marshal(reqMap)

		_, err := DecodeMakeCredentialRequest(reqData)
		require.ErrorIs(t, err, ErrMissingUser)
	})

	t.Run("missing pubKeyCredParams", func(t *testing.T) {
		reqMap := map[int]interface{}{
			makeCredentialKeyClientDataHash: clientDataHash,
			makeCredentialKeyRP:             map[string]interface{}{"id": "example.com"},
			makeCredentialKeyUser:           map[string]interface{}{"id": []byte("user")},
		}
		reqData, _ := cbor.Marshal(reqMap)

		_, err := DecodeMakeCredentialRequest(reqData)
		require.ErrorIs(t, err, ErrMissingPubKeyCredParams)
	})

	t.Run("empty data", func(t *testing.T) {
		_, err := DecodeMakeCredentialRequest([]byte{})
		require.ErrorIs(t, err, ErrInvalidParameter)
	})
}

func TestEncodeMakeCredentialResponse(t *testing.T) {
	t.Run("valid response", func(t *testing.T) {
		resp := &MakeCredentialResponse{
			Fmt:      AttestationFormatNone,
			AuthData: []byte("test-auth-data"),
			AttStmt:  make(map[string]interface{}),
		}

		data, err := EncodeMakeCredentialResponse(resp)
		require.NoError(t, err)

		// Decode and verify
		var decoded map[int]interface{}
		err = cbor.Unmarshal(data, &decoded)
		require.NoError(t, err)
		require.Equal(t, AttestationFormatNone, decoded[makeCredentialResponseKeyFmt])
	})

	t.Run("nil response", func(t *testing.T) {
		_, err := EncodeMakeCredentialResponse(nil)
		require.ErrorIs(t, err, ErrInvalidParameter)
	})
}

func TestAlgorithmSelection(t *testing.T) {
	auth := createMakeCredentialTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	t.Run("prefers ES256", func(t *testing.T) {
		params := []PublicKeyCredentialParam{
			{Type: "public-key", Alg: COSEAlgEdDSA},
			{Type: "public-key", Alg: COSEAlgES256},
			{Type: "public-key", Alg: COSEAlgES384},
		}

		alg, err := auth.selectAlgorithm(params)
		require.NoError(t, err)
		require.Equal(t, COSEAlgES256, alg)
	})

	t.Run("falls back to supported algorithm", func(t *testing.T) {
		params := []PublicKeyCredentialParam{
			{Type: "public-key", Alg: COSEAlgRS256}, // Not supported
			{Type: "public-key", Alg: COSEAlgEdDSA},
		}

		alg, err := auth.selectAlgorithm(params)
		require.NoError(t, err)
		require.Equal(t, COSEAlgEdDSA, alg)
	})

	t.Run("skips invalid type", func(t *testing.T) {
		params := []PublicKeyCredentialParam{
			{Type: "invalid-type", Alg: COSEAlgES256},
			{Type: "public-key", Alg: COSEAlgES384},
		}

		alg, err := auth.selectAlgorithm(params)
		require.NoError(t, err)
		require.Equal(t, COSEAlgES384, alg)
	})

	t.Run("no supported algorithm", func(t *testing.T) {
		params := []PublicKeyCredentialParam{
			{Type: "public-key", Alg: COSEAlgRS256},
		}

		_, err := auth.selectAlgorithm(params)
		require.ErrorIs(t, err, ErrNoSupportedAlgorithm)
	})
}

func TestCredProtectExtension(t *testing.T) {
	auth := createMakeCredentialTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	clientDataHash := make([]byte, ClientDataHashSize)
	rp := RelyingParty{ID: "example.com"}
	user := User{ID: []byte("user"), Name: "user"}
	pubKeyCredParams := []PublicKeyCredentialParam{{Type: "public-key", Alg: COSEAlgES256}}

	t.Run("credProtect level 2", func(t *testing.T) {
		opts := &MakeCredentialOptions{
			Extensions: map[string]interface{}{
				"credProtect": uint8(CredProtectUserVerificationOptionalWithList),
			},
		}

		resp, err := auth.MakeCredential(clientDataHash, rp, user, pubKeyCredParams, opts)
		require.NoError(t, err)

		authData, err := ParseAuthData(resp.AuthData)
		require.NoError(t, err)

		// Chrome requires the ED flag and credProtect output in MakeCredential
		// responses when the credProtect extension was requested.
		require.True(t, authData.HasExtensions())

		cred, err := auth.storage.Load(authData.CredentialID)
		require.NoError(t, err)
		require.Equal(t, CredProtectUserVerificationOptionalWithList, cred.CredProtect)
	})
}

func TestMultipleAlgorithms(t *testing.T) {
	auth := createMakeCredentialTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	clientDataHash := make([]byte, ClientDataHashSize)
	rp := RelyingParty{ID: "example.com"}
	user := User{ID: []byte("user"), Name: "user"}

	algorithms := []struct {
		name string
		alg  int
	}{
		{"ES256", COSEAlgES256},
		{"ES384", COSEAlgES384},
		{"EdDSA", COSEAlgEdDSA},
	}

	for _, tc := range algorithms {
		t.Run(tc.name, func(t *testing.T) {
			pubKeyCredParams := []PublicKeyCredentialParam{
				{Type: "public-key", Alg: tc.alg},
			}

			resp, err := auth.MakeCredential(clientDataHash, rp, user, pubKeyCredParams, nil)
			require.NoError(t, err)

			authData, err := ParseAuthData(resp.AuthData)
			require.NoError(t, err)

			// Verify the public key can be decoded
			pubKey, alg, err := DecodeCOSEPublicKey(authData.PublicKey)
			require.NoError(t, err)
			require.Equal(t, tc.alg, alg)
			require.NotNil(t, pubKey)
		})
	}
}

func TestMakeCredentialToIntConverters(t *testing.T) {
	t.Run("makeCredentialToInt with various types", func(t *testing.T) {
		testCases := []struct {
			input    interface{}
			expected int
		}{
			{int(42), 42},
			{int8(42), 42},
			{int16(42), 42},
			{int32(42), 42},
			{int64(42), 42},
			{uint(42), 42},
			{uint8(42), 42},
			{uint16(42), 42},
			{uint32(42), 42},
			{uint64(42), 42},
		}

		for _, tc := range testCases {
			result, err := makeCredentialToInt(tc.input)
			require.NoError(t, err)
			require.Equal(t, tc.expected, result)
		}
	})

	t.Run("makeCredentialToInt with invalid type", func(t *testing.T) {
		_, err := makeCredentialToInt("not a number")
		require.Error(t, err)
	})

	t.Run("makeCredentialToUint8 with various types", func(t *testing.T) {
		testCases := []struct {
			input    interface{}
			expected uint8
		}{
			{int(42), 42},
			{int8(42), 42},
			{int16(42), 42},
			{int32(42), 42},
			{int64(42), 42},
			{uint(42), 42},
			{uint8(42), 42},
			{uint16(42), 42},
			{uint32(42), 42},
			{uint64(42), 42},
		}

		for _, tc := range testCases {
			result, err := makeCredentialToUint8(tc.input)
			require.NoError(t, err)
			require.Equal(t, tc.expected, result)
		}
	})

	t.Run("makeCredentialToUint8 with invalid type", func(t *testing.T) {
		_, err := makeCredentialToUint8("not a number")
		require.Error(t, err)
	})
}

func TestMakeCredentialToStringKeyMap(t *testing.T) {
	t.Run("string keyed map", func(t *testing.T) {
		input := map[string]interface{}{
			"key1": "value1",
			"key2": 42,
		}

		result, ok := makeCredentialToStringKeyMap(input)
		require.True(t, ok)
		require.Equal(t, "value1", result["key1"])
		require.Equal(t, 42, result["key2"])
	})

	t.Run("interface keyed map", func(t *testing.T) {
		input := map[interface{}]interface{}{
			"key1": "value1",
			"key2": 42,
			123:    "ignored", // non-string key
		}

		result, ok := makeCredentialToStringKeyMap(input)
		require.True(t, ok)
		require.Equal(t, "value1", result["key1"])
		require.Equal(t, 42, result["key2"])
		require.Nil(t, result["123"])
	})

	t.Run("unsupported type", func(t *testing.T) {
		_, ok := makeCredentialToStringKeyMap("not a map")
		require.False(t, ok)
	})
}

// Additional tests to improve coverage for HandleMakeCredential

func TestHandleMakeCredential_CBOREntryPoint(t *testing.T) {
	auth := createMakeCredentialTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	clientDataHash := make([]byte, ClientDataHashSize)

	t.Run("successful CBOR request via HandleMakeCredential", func(t *testing.T) {
		reqMap := map[int]interface{}{
			makeCredentialKeyClientDataHash: clientDataHash,
			makeCredentialKeyRP: map[string]interface{}{
				"id":   "example.com",
				"name": "Example",
			},
			makeCredentialKeyUser: map[string]interface{}{
				"id":          []byte("user-123"),
				"name":        "test@example.com",
				"displayName": "Test User",
			},
			makeCredentialKeyPubKeyCredParams: []interface{}{
				map[string]interface{}{"type": "public-key", "alg": COSEAlgES256},
			},
		}

		reqData, err := cbor.Marshal(reqMap)
		require.NoError(t, err)

		respData, err := auth.HandleMakeCredential(reqData)
		require.NoError(t, err)
		require.NotEmpty(t, respData)

		// Response should start with status byte
		require.Equal(t, byte(StatusOK), respData[0])
	})

	t.Run("HandleMakeCredential with invalid CBOR data", func(t *testing.T) {
		// Send invalid CBOR data
		_, err := auth.HandleMakeCredential([]byte{0xFF, 0xFF, 0xFF})
		require.Error(t, err)
		require.ErrorIs(t, err, ErrInvalidParameter)
	})

	t.Run("HandleMakeCredential with validation error", func(t *testing.T) {
		// Missing required fields
		reqMap := map[int]interface{}{
			makeCredentialKeyClientDataHash: make([]byte, 16), // Invalid size
			makeCredentialKeyRP: map[string]interface{}{
				"id": "example.com",
			},
			makeCredentialKeyUser: map[string]interface{}{
				"id": []byte("user"),
			},
			makeCredentialKeyPubKeyCredParams: []interface{}{
				map[string]interface{}{"type": "public-key", "alg": COSEAlgES256},
			},
		}

		reqData, err := cbor.Marshal(reqMap)
		require.NoError(t, err)

		_, err = auth.HandleMakeCredential(reqData)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrInvalidClientDataHash)
	})

	t.Run("HandleMakeCredential with exclude list match", func(t *testing.T) {
		// First create a credential
		reqMap1 := map[int]interface{}{
			makeCredentialKeyClientDataHash: clientDataHash,
			makeCredentialKeyRP: map[string]interface{}{
				"id": "example.com",
			},
			makeCredentialKeyUser: map[string]interface{}{
				"id": []byte("user"),
			},
			makeCredentialKeyPubKeyCredParams: []interface{}{
				map[string]interface{}{"type": "public-key", "alg": COSEAlgES256},
			},
		}

		reqData1, err := cbor.Marshal(reqMap1)
		require.NoError(t, err)

		respData, err := auth.HandleMakeCredential(reqData1)
		require.NoError(t, err)

		// Parse response to get credential ID
		var respMap map[int]interface{}
		err = cbor.Unmarshal(respData[1:], &respMap)
		require.NoError(t, err)

		authDataBytes := respMap[makeCredentialResponseKeyAuthData].([]byte)
		authData, err := ParseAuthData(authDataBytes)
		require.NoError(t, err)

		// Now try to create with the existing credential in exclude list
		reqMap2 := map[int]interface{}{
			makeCredentialKeyClientDataHash: clientDataHash,
			makeCredentialKeyRP: map[string]interface{}{
				"id": "example.com",
			},
			makeCredentialKeyUser: map[string]interface{}{
				"id": []byte("user2"),
			},
			makeCredentialKeyPubKeyCredParams: []interface{}{
				map[string]interface{}{"type": "public-key", "alg": COSEAlgES256},
			},
			makeCredentialKeyExcludeList: []interface{}{
				map[string]interface{}{
					"type": "public-key",
					"id":   authData.CredentialID,
				},
			},
		}

		reqData2, err := cbor.Marshal(reqMap2)
		require.NoError(t, err)

		_, err = auth.HandleMakeCredential(reqData2)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrCredentialExcluded)
	})

	t.Run("HandleMakeCredential with extensions via CBOR", func(t *testing.T) {
		reqMap := map[int]interface{}{
			makeCredentialKeyClientDataHash: clientDataHash,
			makeCredentialKeyRP: map[string]interface{}{
				"id": "example.com",
			},
			makeCredentialKeyUser: map[string]interface{}{
				"id": []byte("user-ext"),
			},
			makeCredentialKeyPubKeyCredParams: []interface{}{
				map[string]interface{}{"type": "public-key", "alg": COSEAlgES256},
			},
			makeCredentialKeyExtensions: map[string]interface{}{
				"hmac-secret": true,
				"credProtect": uint8(CredProtectUserVerificationRequired),
			},
			makeCredentialKeyOptions: map[string]interface{}{
				"rk": true,
				"uv": true,
			},
		}

		reqData, err := cbor.Marshal(reqMap)
		require.NoError(t, err)

		respData, err := auth.HandleMakeCredential(reqData)
		require.NoError(t, err)
		require.Equal(t, byte(StatusOK), respData[0])
	})
}

// Tests for parsePubKeyCredParams

func TestParsePubKeyCredParams(t *testing.T) {
	t.Run("valid params array", func(t *testing.T) {
		paramsRaw := []interface{}{
			map[string]interface{}{"type": "public-key", "alg": COSEAlgES256},
			map[string]interface{}{"type": "public-key", "alg": COSEAlgEdDSA},
		}

		params, err := parsePubKeyCredParams(paramsRaw)
		require.NoError(t, err)
		require.Len(t, params, 2)
		require.Equal(t, "public-key", params[0].Type)
		require.Equal(t, COSEAlgES256, params[0].Alg)
	})

	t.Run("not an array", func(t *testing.T) {
		_, err := parsePubKeyCredParams("not an array")
		require.Error(t, err)
		require.ErrorIs(t, err, ErrInvalidParameter)
	})

	t.Run("empty array", func(t *testing.T) {
		_, err := parsePubKeyCredParams([]interface{}{})
		require.Error(t, err)
		require.ErrorIs(t, err, ErrMissingPubKeyCredParams)
	})

	t.Run("item not a map", func(t *testing.T) {
		paramsRaw := []interface{}{
			"not a map",
			map[string]interface{}{"type": "public-key", "alg": COSEAlgES256},
		}

		params, err := parsePubKeyCredParams(paramsRaw)
		require.NoError(t, err)
		// Should skip invalid item
		require.Len(t, params, 1)
	})

	t.Run("missing type field", func(t *testing.T) {
		paramsRaw := []interface{}{
			map[string]interface{}{"alg": COSEAlgES256}, // missing type
			map[string]interface{}{"type": "public-key", "alg": COSEAlgEdDSA},
		}

		params, err := parsePubKeyCredParams(paramsRaw)
		require.NoError(t, err)
		// Should skip item without type
		require.Len(t, params, 1)
	})

	t.Run("missing alg field", func(t *testing.T) {
		paramsRaw := []interface{}{
			map[string]interface{}{"type": "public-key"}, // missing alg
			map[string]interface{}{"type": "public-key", "alg": COSEAlgEdDSA},
		}

		params, err := parsePubKeyCredParams(paramsRaw)
		require.NoError(t, err)
		// Should skip item without alg
		require.Len(t, params, 1)
	})

	t.Run("invalid alg type", func(t *testing.T) {
		paramsRaw := []interface{}{
			map[string]interface{}{"type": "public-key", "alg": "not-int"},
			map[string]interface{}{"type": "public-key", "alg": COSEAlgEdDSA},
		}

		params, err := parsePubKeyCredParams(paramsRaw)
		require.NoError(t, err)
		// Should skip item with invalid alg
		require.Len(t, params, 1)
	})

	t.Run("all items invalid results in error", func(t *testing.T) {
		paramsRaw := []interface{}{
			"not a map",
			map[string]interface{}{"alg": COSEAlgES256}, // missing type
		}

		_, err := parsePubKeyCredParams(paramsRaw)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrMissingPubKeyCredParams)
	})

	t.Run("type not string", func(t *testing.T) {
		paramsRaw := []interface{}{
			map[string]interface{}{"type": 123, "alg": COSEAlgES256}, // type not string
		}

		_, err := parsePubKeyCredParams(paramsRaw)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrMissingPubKeyCredParams)
	})
}

// Tests for parseMakeCredentialUser

func TestParseMakeCredentialUser(t *testing.T) {
	t.Run("complete user", func(t *testing.T) {
		userRaw := map[string]interface{}{
			"id":          []byte("user-123"),
			"name":        "john@example.com",
			"displayName": "John Doe",
			"icon":        "https://example.com/icon.png",
		}

		user, err := parseMakeCredentialUser(userRaw)
		require.NoError(t, err)
		require.Equal(t, []byte("user-123"), user.ID)
		require.Equal(t, "john@example.com", user.Name)
		require.Equal(t, "John Doe", user.DisplayName)
		require.Equal(t, "https://example.com/icon.png", user.Icon)
	})

	t.Run("minimal user - id only", func(t *testing.T) {
		userRaw := map[string]interface{}{
			"id": []byte("user-123"),
		}

		user, err := parseMakeCredentialUser(userRaw)
		require.NoError(t, err)
		require.Equal(t, []byte("user-123"), user.ID)
		require.Empty(t, user.Name)
		require.Empty(t, user.DisplayName)
		require.Empty(t, user.Icon)
	})

	t.Run("not a map", func(t *testing.T) {
		_, err := parseMakeCredentialUser("not a map")
		require.Error(t, err)
		require.ErrorIs(t, err, ErrInvalidParameter)
	})

	t.Run("missing user id", func(t *testing.T) {
		userRaw := map[string]interface{}{
			"name": "john@example.com",
		}

		_, err := parseMakeCredentialUser(userRaw)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrMissingUserID)
	})

	t.Run("user id not bytes", func(t *testing.T) {
		userRaw := map[string]interface{}{
			"id": "not-bytes",
		}

		_, err := parseMakeCredentialUser(userRaw)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrMissingUserID)
	})

	t.Run("interface keyed map", func(t *testing.T) {
		userRaw := map[interface{}]interface{}{
			"id":          []byte("user-123"),
			"name":        "john@example.com",
			"displayName": "John Doe",
			"icon":        "https://example.com/icon.png",
		}

		user, err := parseMakeCredentialUser(userRaw)
		require.NoError(t, err)
		require.Equal(t, []byte("user-123"), user.ID)
		require.Equal(t, "john@example.com", user.Name)
	})
}

// Tests for storeCredential with storage failures

func TestStoreNewCredential_StorageFailures(t *testing.T) {
	t.Run("storage error on store", func(t *testing.T) {
		storage := &failingStorage{
			storeErr: errors.New("storage failure"),
		}

		config := &Config{
			AAGUID:                 DefaultAAGUID,
			SupportedAlgorithms:    []int{COSEAlgES256},
			MaxCredentials:         100,
			MaxResidentCredentials: 25,
			PINMinLength:           4,
			PINMaxRetries:          8,
			Storage:                storage,
		}

		auth, err := NewAuthenticator(config)
		require.NoError(t, err)
		defer func() { _ = auth.Close() }()

		clientDataHash := make([]byte, ClientDataHashSize)
		rp := RelyingParty{ID: "example.com"}
		user := User{ID: []byte("user"), Name: "user"}
		pubKeyCredParams := []PublicKeyCredentialParam{{Type: "public-key", Alg: COSEAlgES256}}

		_, err = auth.MakeCredential(clientDataHash, rp, user, pubKeyCredParams, nil)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrStorageError)
	})
}

// Tests for checkCredentialLimits with storage errors

func TestCheckCredentialLimits_StorageErrors(t *testing.T) {
	t.Run("count error", func(t *testing.T) {
		storage := &failingStorage{
			countErr: errors.New("count failure"),
		}

		config := &Config{
			AAGUID:                 DefaultAAGUID,
			SupportedAlgorithms:    []int{COSEAlgES256},
			MaxCredentials:         100,
			MaxResidentCredentials: 25,
			PINMinLength:           4,
			PINMaxRetries:          8,
			Storage:                storage,
		}

		auth, err := NewAuthenticator(config)
		require.NoError(t, err)
		defer func() { _ = auth.Close() }()

		clientDataHash := make([]byte, ClientDataHashSize)
		rp := RelyingParty{ID: "example.com"}
		user := User{ID: []byte("user"), Name: "user"}
		pubKeyCredParams := []PublicKeyCredentialParam{{Type: "public-key", Alg: COSEAlgES256}}

		_, err = auth.MakeCredential(clientDataHash, rp, user, pubKeyCredParams, nil)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrStorageError)
	})

	t.Run("count discoverable error", func(t *testing.T) {
		storage := &failingStorage{
			countDiscoverableErr: errors.New("count discoverable failure"),
		}

		config := &Config{
			AAGUID:                 DefaultAAGUID,
			SupportedAlgorithms:    []int{COSEAlgES256},
			MaxCredentials:         100,
			MaxResidentCredentials: 25,
			PINMinLength:           4,
			PINMaxRetries:          8,
			EnableResidentKey:      true,
			Storage:                storage,
		}

		auth, err := NewAuthenticator(config)
		require.NoError(t, err)
		defer func() { _ = auth.Close() }()

		clientDataHash := make([]byte, ClientDataHashSize)
		rp := RelyingParty{ID: "example.com"}
		user := User{ID: []byte("user"), Name: "user"}
		pubKeyCredParams := []PublicKeyCredentialParam{{Type: "public-key", Alg: COSEAlgES256}}

		opts := &MakeCredentialOptions{
			Options: map[string]bool{"rk": true},
		}

		_, err = auth.MakeCredential(clientDataHash, rp, user, pubKeyCredParams, opts)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrStorageError)
	})
}

// Tests for shouldCreateDiscoverable

func TestShouldCreateDiscoverable(t *testing.T) {
	t.Run("resident key disabled in config", func(t *testing.T) {
		storage := NewMemoryStorage()
		config := &Config{
			AAGUID:                 DefaultAAGUID,
			SupportedAlgorithms:    []int{COSEAlgES256},
			MaxCredentials:         100,
			MaxResidentCredentials: 25,
			PINMinLength:           4,
			PINMaxRetries:          8,
			EnableResidentKey:      false, // Disabled
			Storage:                storage,
		}

		auth, err := NewAuthenticator(config)
		require.NoError(t, err)
		defer func() { _ = auth.Close() }()

		// Even if rk is requested, should return false
		options := map[string]bool{"rk": true}
		result := auth.shouldCreateDiscoverable(options)
		require.False(t, result)
	})

	t.Run("rk explicitly false", func(t *testing.T) {
		auth := createMakeCredentialTestAuthenticator(t)
		defer func() { _ = auth.Close() }()

		options := map[string]bool{"rk": false}
		result := auth.shouldCreateDiscoverable(options)
		require.False(t, result)
	})

	t.Run("rk not specified", func(t *testing.T) {
		auth := createMakeCredentialTestAuthenticator(t)
		defer func() { _ = auth.Close() }()

		options := map[string]bool{}
		result := auth.shouldCreateDiscoverable(options)
		require.False(t, result)
	})

	t.Run("nil options", func(t *testing.T) {
		auth := createMakeCredentialTestAuthenticator(t)
		defer func() { _ = auth.Close() }()

		result := auth.shouldCreateDiscoverable(nil)
		require.False(t, result)
	})
}

// Tests for user verification satisfaction

func TestUserVerificationSatisfied(t *testing.T) {
	auth := createMakeCredentialTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	t.Run("uv not requested", func(t *testing.T) {
		req := &MakeCredentialRequest{
			Options: map[string]bool{},
		}
		result := auth.userVerificationSatisfied(req)
		require.False(t, result)
	})

	t.Run("uv requested but false", func(t *testing.T) {
		req := &MakeCredentialRequest{
			Options: map[string]bool{"uv": false},
		}
		result := auth.userVerificationSatisfied(req)
		require.False(t, result)
	})

	t.Run("uv requested and PIN set with auth param", func(t *testing.T) {
		auth.state.PINSet = true
		req := &MakeCredentialRequest{
			Options:           map[string]bool{"uv": true},
			PINUVAuthParam:    []byte{1, 2, 3},
			PINUVAuthProtocol: 1,
		}
		result := auth.userVerificationSatisfied(req)
		require.True(t, result)
	})

	t.Run("uv requested without pinUvAuthParam", func(t *testing.T) {
		req := &MakeCredentialRequest{
			Options: map[string]bool{"uv": true},
		}
		result := auth.userVerificationSatisfied(req)
		require.False(t, result) // UV requires pinUvAuthParam; uv option alone is insufficient
	})
}

// Tests for CBOR decoding edge cases

func TestDecodeMakeCredentialRequest_EdgeCases(t *testing.T) {
	clientDataHash := make([]byte, ClientDataHashSize)

	t.Run("invalid CBOR", func(t *testing.T) {
		_, err := DecodeMakeCredentialRequest([]byte{0xFF, 0xFF})
		require.Error(t, err)
		require.ErrorIs(t, err, ErrInvalidParameter)
	})

	t.Run("clientDataHash not bytes", func(t *testing.T) {
		reqMap := map[int]interface{}{
			makeCredentialKeyClientDataHash:   "not-bytes",
			makeCredentialKeyRP:               map[string]interface{}{"id": "example.com"},
			makeCredentialKeyUser:             map[string]interface{}{"id": []byte("user")},
			makeCredentialKeyPubKeyCredParams: []interface{}{map[string]interface{}{"type": "public-key", "alg": -7}},
		}
		reqData, _ := cbor.Marshal(reqMap)

		_, err := DecodeMakeCredentialRequest(reqData)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrInvalidClientDataHash)
	})

	t.Run("rp parsing error", func(t *testing.T) {
		reqMap := map[int]interface{}{
			makeCredentialKeyClientDataHash:   clientDataHash,
			makeCredentialKeyRP:               "not-a-map",
			makeCredentialKeyUser:             map[string]interface{}{"id": []byte("user")},
			makeCredentialKeyPubKeyCredParams: []interface{}{map[string]interface{}{"type": "public-key", "alg": -7}},
		}
		reqData, _ := cbor.Marshal(reqMap)

		_, err := DecodeMakeCredentialRequest(reqData)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrInvalidParameter)
	})

	t.Run("user parsing error", func(t *testing.T) {
		reqMap := map[int]interface{}{
			makeCredentialKeyClientDataHash:   clientDataHash,
			makeCredentialKeyRP:               map[string]interface{}{"id": "example.com"},
			makeCredentialKeyUser:             "not-a-map",
			makeCredentialKeyPubKeyCredParams: []interface{}{map[string]interface{}{"type": "public-key", "alg": -7}},
		}
		reqData, _ := cbor.Marshal(reqMap)

		_, err := DecodeMakeCredentialRequest(reqData)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrInvalidParameter)
	})

	t.Run("pubKeyCredParams parsing error", func(t *testing.T) {
		reqMap := map[int]interface{}{
			makeCredentialKeyClientDataHash:   clientDataHash,
			makeCredentialKeyRP:               map[string]interface{}{"id": "example.com"},
			makeCredentialKeyUser:             map[string]interface{}{"id": []byte("user")},
			makeCredentialKeyPubKeyCredParams: "not-an-array",
		}
		reqData, _ := cbor.Marshal(reqMap)

		_, err := DecodeMakeCredentialRequest(reqData)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrInvalidParameter)
	})

	t.Run("extensions with interface keyed map", func(t *testing.T) {
		reqMap := map[int]interface{}{
			makeCredentialKeyClientDataHash: clientDataHash,
			makeCredentialKeyRP: map[string]interface{}{
				"id": "example.com",
			},
			makeCredentialKeyUser: map[string]interface{}{
				"id": []byte("user"),
			},
			makeCredentialKeyPubKeyCredParams: []interface{}{
				map[string]interface{}{"type": "public-key", "alg": COSEAlgES256},
			},
			makeCredentialKeyExtensions: map[interface{}]interface{}{
				"hmac-secret": true,
			},
		}
		reqData, _ := cbor.Marshal(reqMap)

		req, err := DecodeMakeCredentialRequest(reqData)
		require.NoError(t, err)
		require.Equal(t, true, req.Extensions["hmac-secret"])
	})

	t.Run("enterprise attestation parsing", func(t *testing.T) {
		reqMap := map[int]interface{}{
			makeCredentialKeyClientDataHash: clientDataHash,
			makeCredentialKeyRP: map[string]interface{}{
				"id": "example.com",
			},
			makeCredentialKeyUser: map[string]interface{}{
				"id": []byte("user"),
			},
			makeCredentialKeyPubKeyCredParams: []interface{}{
				map[string]interface{}{"type": "public-key", "alg": COSEAlgES256},
			},
			makeCredentialKeyEnterpriseAttestation: uint8(1),
		}
		reqData, _ := cbor.Marshal(reqMap)

		req, err := DecodeMakeCredentialRequest(reqData)
		require.NoError(t, err)
		require.Equal(t, uint8(1), req.EnterpriseAttestation)
	})

	t.Run("exclude list parsing error handling", func(t *testing.T) {
		reqMap := map[int]interface{}{
			makeCredentialKeyClientDataHash: clientDataHash,
			makeCredentialKeyRP: map[string]interface{}{
				"id": "example.com",
			},
			makeCredentialKeyUser: map[string]interface{}{
				"id": []byte("user"),
			},
			makeCredentialKeyPubKeyCredParams: []interface{}{
				map[string]interface{}{"type": "public-key", "alg": COSEAlgES256},
			},
			makeCredentialKeyExcludeList: "not-an-array",
		}
		reqData, _ := cbor.Marshal(reqMap)

		req, err := DecodeMakeCredentialRequest(reqData)
		require.NoError(t, err)
		// Should just ignore invalid exclude list
		require.Empty(t, req.ExcludeList)
	})

	t.Run("options parsing error handling", func(t *testing.T) {
		reqMap := map[int]interface{}{
			makeCredentialKeyClientDataHash: clientDataHash,
			makeCredentialKeyRP: map[string]interface{}{
				"id": "example.com",
			},
			makeCredentialKeyUser: map[string]interface{}{
				"id": []byte("user"),
			},
			makeCredentialKeyPubKeyCredParams: []interface{}{
				map[string]interface{}{"type": "public-key", "alg": COSEAlgES256},
			},
			makeCredentialKeyOptions: "not-a-map",
		}
		reqData, _ := cbor.Marshal(reqMap)

		req, err := DecodeMakeCredentialRequest(reqData)
		require.NoError(t, err)
		// Should just ignore invalid options
		require.Empty(t, req.Options)
	})
}

// Tests for parseMakeCredentialRP

func TestParseMakeCredentialRP(t *testing.T) {
	t.Run("complete RP", func(t *testing.T) {
		rpRaw := map[string]interface{}{
			"id":   "example.com",
			"name": "Example Corp",
			"icon": "https://example.com/icon.png",
		}

		rp, err := parseMakeCredentialRP(rpRaw)
		require.NoError(t, err)
		require.Equal(t, "example.com", rp.ID)
		require.Equal(t, "Example Corp", rp.Name)
		require.Equal(t, "https://example.com/icon.png", rp.Icon)
	})

	t.Run("RP with id only", func(t *testing.T) {
		rpRaw := map[string]interface{}{
			"id": "example.com",
		}

		rp, err := parseMakeCredentialRP(rpRaw)
		require.NoError(t, err)
		require.Equal(t, "example.com", rp.ID)
		require.Empty(t, rp.Name)
		require.Empty(t, rp.Icon)
	})

	t.Run("not a map", func(t *testing.T) {
		_, err := parseMakeCredentialRP("not-a-map")
		require.Error(t, err)
		require.ErrorIs(t, err, ErrInvalidParameter)
	})

	t.Run("missing RP ID", func(t *testing.T) {
		rpRaw := map[string]interface{}{
			"name": "Example Corp",
		}

		_, err := parseMakeCredentialRP(rpRaw)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrMissingRPID)
	})

	t.Run("RP ID not string", func(t *testing.T) {
		rpRaw := map[string]interface{}{
			"id": 123,
		}

		_, err := parseMakeCredentialRP(rpRaw)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrMissingRPID)
	})

	t.Run("interface keyed map", func(t *testing.T) {
		rpRaw := map[interface{}]interface{}{
			"id":   "example.com",
			"name": "Example Corp",
		}

		rp, err := parseMakeCredentialRP(rpRaw)
		require.NoError(t, err)
		require.Equal(t, "example.com", rp.ID)
	})
}

// Tests for parseMakeCredentialExcludeList

func TestParseMakeCredentialExcludeList(t *testing.T) {
	t.Run("valid exclude list", func(t *testing.T) {
		excludeRaw := []interface{}{
			map[string]interface{}{
				"type":       "public-key",
				"id":         []byte("cred-1"),
				"transports": []interface{}{"usb", "nfc"},
			},
			map[string]interface{}{
				"type": "public-key",
				"id":   []byte("cred-2"),
			},
		}

		excludeList, err := parseMakeCredentialExcludeList(excludeRaw)
		require.NoError(t, err)
		require.Len(t, excludeList, 2)
		require.Equal(t, []byte("cred-1"), excludeList[0].ID)
		require.Equal(t, []string{"usb", "nfc"}, excludeList[0].Transports)
	})

	t.Run("not an array", func(t *testing.T) {
		excludeList, err := parseMakeCredentialExcludeList("not-an-array")
		require.NoError(t, err)
		require.Nil(t, excludeList)
	})

	t.Run("item not a map", func(t *testing.T) {
		excludeRaw := []interface{}{
			"not-a-map",
			map[string]interface{}{
				"type": "public-key",
				"id":   []byte("cred-1"),
			},
		}

		excludeList, err := parseMakeCredentialExcludeList(excludeRaw)
		require.NoError(t, err)
		require.Len(t, excludeList, 1)
	})

	t.Run("missing id", func(t *testing.T) {
		excludeRaw := []interface{}{
			map[string]interface{}{
				"type": "public-key",
			},
		}

		excludeList, err := parseMakeCredentialExcludeList(excludeRaw)
		require.NoError(t, err)
		require.Empty(t, excludeList)
	})

	t.Run("id not bytes", func(t *testing.T) {
		excludeRaw := []interface{}{
			map[string]interface{}{
				"type": "public-key",
				"id":   "not-bytes",
			},
		}

		excludeList, err := parseMakeCredentialExcludeList(excludeRaw)
		require.NoError(t, err)
		require.Empty(t, excludeList)
	})

	t.Run("transports with non-string", func(t *testing.T) {
		excludeRaw := []interface{}{
			map[string]interface{}{
				"type":       "public-key",
				"id":         []byte("cred-1"),
				"transports": []interface{}{"usb", 123, "nfc"},
			},
		}

		excludeList, err := parseMakeCredentialExcludeList(excludeRaw)
		require.NoError(t, err)
		require.Len(t, excludeList, 1)
		require.Equal(t, []string{"usb", "nfc"}, excludeList[0].Transports)
	})
}

// Tests for parseMakeCredentialOptions

func TestParseMakeCredentialOptions(t *testing.T) {
	t.Run("valid options", func(t *testing.T) {
		optRaw := map[string]interface{}{
			"rk": true,
			"uv": false,
		}

		options, err := parseMakeCredentialOptions(optRaw)
		require.NoError(t, err)
		require.Equal(t, true, options["rk"])
		require.Equal(t, false, options["uv"])
	})

	t.Run("not a map", func(t *testing.T) {
		options, err := parseMakeCredentialOptions("not-a-map")
		require.NoError(t, err)
		require.Empty(t, options)
	})

	t.Run("non-bool values ignored", func(t *testing.T) {
		optRaw := map[string]interface{}{
			"rk":      true,
			"invalid": "not-bool",
		}

		options, err := parseMakeCredentialOptions(optRaw)
		require.NoError(t, err)
		require.Equal(t, true, options["rk"])
		_, exists := options["invalid"]
		require.False(t, exists)
	})

	t.Run("interface keyed map", func(t *testing.T) {
		optRaw := map[interface{}]interface{}{
			"rk": true,
			"uv": false,
		}

		options, err := parseMakeCredentialOptions(optRaw)
		require.NoError(t, err)
		require.Equal(t, true, options["rk"])
	})
}

// failingStorage is a test storage that returns errors
type failingStorage struct {
	storeErr             error
	loadErr              error
	countErr             error
	countDiscoverableErr error
}

func (s *failingStorage) Store(credential *StoredCredential) error {
	if s.storeErr != nil {
		return s.storeErr
	}
	return nil
}

func (s *failingStorage) Load(credentialID []byte) (*StoredCredential, error) {
	if s.loadErr != nil {
		return nil, s.loadErr
	}
	return nil, ErrCredentialNotFound
}

func (s *failingStorage) LoadByRPID(rpID string) ([]*StoredCredential, error) {
	return nil, nil
}

func (s *failingStorage) Delete(credentialID []byte) error {
	return nil
}

func (s *failingStorage) Count() (int, error) {
	if s.countErr != nil {
		return 0, s.countErr
	}
	return 0, nil
}

func (s *failingStorage) CountDiscoverable() (int, error) {
	if s.countDiscoverableErr != nil {
		return 0, s.countDiscoverableErr
	}
	return 0, nil
}

func (s *failingStorage) SaveState(state *AuthenticatorState) error {
	return nil
}

func (s *failingStorage) LoadState() (*AuthenticatorState, error) {
	return nil, ErrStateNotFound
}

func (s *failingStorage) Close() error {
	return nil
}

// Tests for processMakeCredentialExtensions

func TestProcessMakeCredentialExtensions(t *testing.T) {
	auth := createMakeCredentialTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	t.Run("hmac-secret enabled", func(t *testing.T) {
		extensions := map[string]interface{}{}
		outputs := auth.processMakeCredentialExtensions(extensions, true)
		require.Equal(t, true, outputs["hmac-secret"])
	})

	t.Run("hmac-secret disabled", func(t *testing.T) {
		extensions := map[string]interface{}{}
		outputs := auth.processMakeCredentialExtensions(extensions, false)
		_, exists := outputs["hmac-secret"]
		require.False(t, exists)
	})

	t.Run("credProtect valid levels", func(t *testing.T) {
		// Level 1
		extensions := map[string]interface{}{
			"credProtect": uint8(CredProtectUserVerificationOptional),
		}
		outputs := auth.processMakeCredentialExtensions(extensions, false)
		require.Equal(t, CredProtectUserVerificationOptional, outputs["credProtect"])

		// Level 2
		extensions = map[string]interface{}{
			"credProtect": uint8(CredProtectUserVerificationOptionalWithList),
		}
		outputs = auth.processMakeCredentialExtensions(extensions, false)
		require.Equal(t, CredProtectUserVerificationOptionalWithList, outputs["credProtect"])

		// Level 3
		extensions = map[string]interface{}{
			"credProtect": uint8(CredProtectUserVerificationRequired),
		}
		outputs = auth.processMakeCredentialExtensions(extensions, false)
		require.Equal(t, CredProtectUserVerificationRequired, outputs["credProtect"])
	})

	t.Run("credProtect invalid level", func(t *testing.T) {
		extensions := map[string]interface{}{
			"credProtect": uint8(0), // Invalid level
		}
		outputs := auth.processMakeCredentialExtensions(extensions, false)
		_, exists := outputs["credProtect"]
		require.False(t, exists)
	})

	t.Run("credProtect above valid range", func(t *testing.T) {
		extensions := map[string]interface{}{
			"credProtect": uint8(4), // Above valid range
		}
		outputs := auth.processMakeCredentialExtensions(extensions, false)
		_, exists := outputs["credProtect"]
		require.False(t, exists)
	})
}

// Tests for buildAttestationStatement

// mockAttestingKeyBackend implements FIDO2AttestingKeyBackend for testing
type mockAttestingKeyBackend struct {
	keybackend.FIDO2KeyBackend
	attestationStmt *keybackend.FIDO2AttestationStatement
	attestationErr  error
	backendType     types.BackendType
}

func (m *mockAttestingKeyBackend) Type() types.BackendType {
	if m.backendType != "" {
		return m.backendType
	}
	return types.BackendTypeSoftware
}

func (m *mockAttestingKeyBackend) Capabilities() keybackend.FIDO2KeyCapabilities {
	return keybackend.FIDO2KeyCapabilities{
		SupportedAlgorithms: []int{COSEAlgES256},
		SupportsExport:      true,
		SupportsImport:      true,
		SupportsAttestation: true,
		HardwareBacked:      false,
	}
}

func (m *mockAttestingKeyBackend) GenerateCredentialKey(algorithm int, credentialID []byte) (keybackend.KeyHandle, []byte, error) {
	return &mockKeyHandle{credID: credentialID, alg: algorithm}, []byte("mock-public-key-cose"), nil
}

func (m *mockAttestingKeyBackend) Sign(handle keybackend.KeyHandle, algorithm int, data []byte) ([]byte, error) {
	return []byte("mock-signature"), nil
}

func (m *mockAttestingKeyBackend) LoadKey(credentialID []byte, algorithm int) (keybackend.KeyHandle, error) {
	return &mockKeyHandle{credID: credentialID, alg: algorithm}, nil
}

func (m *mockAttestingKeyBackend) DeleteKey(handle keybackend.KeyHandle) error {
	return nil
}

func (m *mockAttestingKeyBackend) ExportPrivateKey(handle keybackend.KeyHandle) ([]byte, error) {
	return []byte("mock-private-key"), nil
}

func (m *mockAttestingKeyBackend) ImportPrivateKey(credentialID []byte, algorithm int, pkcs8Key []byte) (keybackend.KeyHandle, error) {
	return &mockKeyHandle{credID: credentialID, alg: algorithm}, nil
}

func (m *mockAttestingKeyBackend) Close() error {
	return nil
}

func (m *mockAttestingKeyBackend) GenerateAttestationKey() (keybackend.KeyHandle, []byte, error) {
	return &mockKeyHandle{}, []byte("attestation-key-cose"), nil
}

func (m *mockAttestingKeyBackend) GetAttestationStatement(format string, authData, clientDataHash []byte) (*keybackend.FIDO2AttestationStatement, error) {
	if m.attestationErr != nil {
		return nil, m.attestationErr
	}
	return m.attestationStmt, nil
}

func (m *mockAttestingKeyBackend) AttestationCertificateChain() ([]*x509.Certificate, error) {
	if m.attestationStmt != nil && len(m.attestationStmt.CertificateChain) > 0 {
		return m.attestationStmt.CertificateChain, nil
	}
	return nil, nil
}

type mockKeyHandle struct {
	credID []byte
	alg    int
}

func (m *mockKeyHandle) CredentialID() []byte {
	return m.credID
}

func (m *mockKeyHandle) Algorithm() int {
	return m.alg
}

func (m *mockKeyHandle) BackendID() types.BackendType {
	return types.BackendTypeSoftware
}

// mockNonAttestingKeyBackend implements only FIDO2KeyBackend (no attestation)
type mockNonAttestingKeyBackend struct {
	keybackend.FIDO2KeyBackend
}

func (m *mockNonAttestingKeyBackend) Type() types.BackendType {
	return types.BackendTypeSoftware
}

func (m *mockNonAttestingKeyBackend) Capabilities() keybackend.FIDO2KeyCapabilities {
	return keybackend.FIDO2KeyCapabilities{
		SupportedAlgorithms: []int{COSEAlgES256},
		SupportsExport:      true,
		SupportsImport:      true,
		SupportsAttestation: false,
		HardwareBacked:      false,
	}
}

func (m *mockNonAttestingKeyBackend) GenerateCredentialKey(algorithm int, credentialID []byte) (keybackend.KeyHandle, []byte, error) {
	return &mockKeyHandle{credID: credentialID, alg: algorithm}, []byte("mock-public-key-cose"), nil
}

func (m *mockNonAttestingKeyBackend) Sign(handle keybackend.KeyHandle, algorithm int, data []byte) ([]byte, error) {
	return []byte("mock-signature"), nil
}

func (m *mockNonAttestingKeyBackend) LoadKey(credentialID []byte, algorithm int) (keybackend.KeyHandle, error) {
	return &mockKeyHandle{credID: credentialID, alg: algorithm}, nil
}

func (m *mockNonAttestingKeyBackend) DeleteKey(handle keybackend.KeyHandle) error {
	return nil
}

func (m *mockNonAttestingKeyBackend) ExportPrivateKey(handle keybackend.KeyHandle) ([]byte, error) {
	return []byte("mock-private-key"), nil
}

func (m *mockNonAttestingKeyBackend) ImportPrivateKey(credentialID []byte, algorithm int, pkcs8Key []byte) (keybackend.KeyHandle, error) {
	return &mockKeyHandle{credID: credentialID, alg: algorithm}, nil
}

func (m *mockNonAttestingKeyBackend) Close() error {
	return nil
}

func TestBuildAttestationStatement(t *testing.T) {
	t.Run("none format returns empty statement", func(t *testing.T) {
		storage := NewMemoryStorage()
		config := &Config{
			AAGUID:              DefaultAAGUID,
			SupportedAlgorithms: []int{COSEAlgES256},
			MaxCredentials:      100,
			PINMinLength:        4,
			PINMaxRetries:       8,
			AttestationFormat:   AttestationFormatNone,
			Storage:             storage,
		}

		auth, err := NewAuthenticator(config)
		require.NoError(t, err)
		defer func() { _ = auth.Close() }()

		authData := []byte("mock-auth-data")
		clientDataHash := make([]byte, 32)

		fmt, attStmt := auth.buildAttestationStatement(authData, clientDataHash)
		require.Equal(t, AttestationFormatNone, fmt)
		require.Empty(t, attStmt)
	})

	t.Run("empty format defaults to none", func(t *testing.T) {
		storage := NewMemoryStorage()
		config := &Config{
			AAGUID:              DefaultAAGUID,
			SupportedAlgorithms: []int{COSEAlgES256},
			MaxCredentials:      100,
			PINMinLength:        4,
			PINMaxRetries:       8,
			AttestationFormat:   "", // Empty
			Storage:             storage,
		}

		auth, err := NewAuthenticator(config)
		require.NoError(t, err)
		defer func() { _ = auth.Close() }()

		authData := []byte("mock-auth-data")
		clientDataHash := make([]byte, 32)

		fmt, attStmt := auth.buildAttestationStatement(authData, clientDataHash)
		require.Equal(t, AttestationFormatNone, fmt)
		require.Empty(t, attStmt)
	})

	t.Run("packed format with attesting backend", func(t *testing.T) {
		storage := NewMemoryStorage()
		mockBackend := &mockAttestingKeyBackend{
			attestationStmt: &keybackend.FIDO2AttestationStatement{
				Format:    AttestationFormatPacked,
				Algorithm: COSEAlgES256,
				Signature: []byte("test-signature"),
				CertificateChain: []*x509.Certificate{
					{Raw: []byte("cert-der-1")},
					{Raw: []byte("cert-der-2")},
				},
			},
		}

		config := &Config{
			AAGUID:              DefaultAAGUID,
			SupportedAlgorithms: []int{COSEAlgES256},
			MaxCredentials:      100,
			PINMinLength:        4,
			PINMaxRetries:       8,
			AttestationFormat:   AttestationFormatPacked,
			KeyBackend:          mockBackend,
			Storage:             storage,
		}

		auth, err := NewAuthenticator(config)
		require.NoError(t, err)
		defer func() { _ = auth.Close() }()

		authData := []byte("mock-auth-data")
		clientDataHash := make([]byte, 32)

		fmt, attStmt := auth.buildAttestationStatement(authData, clientDataHash)
		require.Equal(t, AttestationFormatPacked, fmt)
		require.Equal(t, COSEAlgES256, attStmt["alg"])
		require.Equal(t, []byte("test-signature"), attStmt["sig"])

		x5c, ok := attStmt["x5c"].([][]byte)
		require.True(t, ok)
		require.Len(t, x5c, 2)
		require.Equal(t, []byte("cert-der-1"), x5c[0])
		require.Equal(t, []byte("cert-der-2"), x5c[1])
	})

	t.Run("packed format without certificate chain (self-attestation)", func(t *testing.T) {
		storage := NewMemoryStorage()
		mockBackend := &mockAttestingKeyBackend{
			attestationStmt: &keybackend.FIDO2AttestationStatement{
				Format:           AttestationFormatPacked,
				Algorithm:        COSEAlgES256,
				Signature:        []byte("self-attestation-sig"),
				CertificateChain: nil, // No certificate chain
			},
		}

		config := &Config{
			AAGUID:              DefaultAAGUID,
			SupportedAlgorithms: []int{COSEAlgES256},
			MaxCredentials:      100,
			PINMinLength:        4,
			PINMaxRetries:       8,
			AttestationFormat:   AttestationFormatPacked,
			KeyBackend:          mockBackend,
			Storage:             storage,
		}

		auth, err := NewAuthenticator(config)
		require.NoError(t, err)
		defer func() { _ = auth.Close() }()

		authData := []byte("mock-auth-data")
		clientDataHash := make([]byte, 32)

		fmt, attStmt := auth.buildAttestationStatement(authData, clientDataHash)
		require.Equal(t, AttestationFormatPacked, fmt)
		require.Equal(t, COSEAlgES256, attStmt["alg"])
		require.Equal(t, []byte("self-attestation-sig"), attStmt["sig"])

		_, hasX5c := attStmt["x5c"]
		require.False(t, hasX5c)
	})

	t.Run("tpm format with attesting backend", func(t *testing.T) {
		storage := NewMemoryStorage()
		mockBackend := &mockAttestingKeyBackend{
			backendType: types.BackendTypeTPM2,
			attestationStmt: &keybackend.FIDO2AttestationStatement{
				Format:    AttestationFormatTPM,
				Algorithm: COSEAlgES256,
				Signature: []byte("tpm-signature"),
				TPMData:   []byte("tpm-certinfo-and-pubarea"),
				CertificateChain: []*x509.Certificate{
					{Raw: []byte("aik-cert")},
				},
			},
		}

		config := &Config{
			AAGUID:              DefaultAAGUID,
			SupportedAlgorithms: []int{COSEAlgES256},
			MaxCredentials:      100,
			PINMinLength:        4,
			PINMaxRetries:       8,
			AttestationFormat:   AttestationFormatTPM,
			KeyBackend:          mockBackend,
			Storage:             storage,
		}

		auth, err := NewAuthenticator(config)
		require.NoError(t, err)
		defer func() { _ = auth.Close() }()

		authData := []byte("mock-auth-data")
		clientDataHash := make([]byte, 32)

		fmt, attStmt := auth.buildAttestationStatement(authData, clientDataHash)
		require.Equal(t, AttestationFormatTPM, fmt)
		require.Equal(t, COSEAlgES256, attStmt["alg"])
		require.Equal(t, []byte("tpm-signature"), attStmt["sig"])
		require.Equal(t, []byte("tpm-certinfo-and-pubarea"), attStmt["certInfo"])

		x5c, ok := attStmt["x5c"].([][]byte)
		require.True(t, ok)
		require.Len(t, x5c, 1)
		require.Equal(t, []byte("aik-cert"), x5c[0])
	})

	t.Run("attestation fallback when backend does not support attestation", func(t *testing.T) {
		storage := NewMemoryStorage()
		mockBackend := &mockNonAttestingKeyBackend{}

		config := &Config{
			AAGUID:              DefaultAAGUID,
			SupportedAlgorithms: []int{COSEAlgES256},
			MaxCredentials:      100,
			PINMinLength:        4,
			PINMaxRetries:       8,
			AttestationFormat:   AttestationFormatPacked,
			KeyBackend:          mockBackend,
			Storage:             storage,
		}

		auth, err := NewAuthenticator(config)
		require.NoError(t, err)
		defer func() { _ = auth.Close() }()

		authData := []byte("mock-auth-data")
		clientDataHash := make([]byte, 32)

		fmt, attStmt := auth.buildAttestationStatement(authData, clientDataHash)
		require.Equal(t, AttestationFormatNone, fmt)
		require.Empty(t, attStmt)
	})

	t.Run("attestation fallback when GetAttestationStatement fails", func(t *testing.T) {
		storage := NewMemoryStorage()
		mockBackend := &mockAttestingKeyBackend{
			attestationErr: errors.New("attestation failed"),
		}

		config := &Config{
			AAGUID:              DefaultAAGUID,
			SupportedAlgorithms: []int{COSEAlgES256},
			MaxCredentials:      100,
			PINMinLength:        4,
			PINMaxRetries:       8,
			AttestationFormat:   AttestationFormatPacked,
			KeyBackend:          mockBackend,
			Storage:             storage,
		}

		auth, err := NewAuthenticator(config)
		require.NoError(t, err)
		defer func() { _ = auth.Close() }()

		authData := []byte("mock-auth-data")
		clientDataHash := make([]byte, 32)

		fmt, attStmt := auth.buildAttestationStatement(authData, clientDataHash)
		require.Equal(t, AttestationFormatNone, fmt)
		require.Empty(t, attStmt)
	})

	t.Run("unknown format falls back to none", func(t *testing.T) {
		storage := NewMemoryStorage()
		mockBackend := &mockAttestingKeyBackend{
			attestationStmt: &keybackend.FIDO2AttestationStatement{
				Format:    "unknown-format",
				Algorithm: COSEAlgES256,
				Signature: []byte("sig"),
			},
		}

		config := &Config{
			AAGUID:              DefaultAAGUID,
			SupportedAlgorithms: []int{COSEAlgES256},
			MaxCredentials:      100,
			PINMinLength:        4,
			PINMaxRetries:       8,
			AttestationFormat:   "unknown-format",
			KeyBackend:          mockBackend,
			Storage:             storage,
		}

		auth, err := NewAuthenticator(config)
		require.NoError(t, err)
		defer func() { _ = auth.Close() }()

		authData := []byte("mock-auth-data")
		clientDataHash := make([]byte, 32)

		fmt, attStmt := auth.buildAttestationStatement(authData, clientDataHash)
		require.Equal(t, AttestationFormatNone, fmt)
		require.Empty(t, attStmt)
	})

	t.Run("attestation fallback when no key backend configured", func(t *testing.T) {
		storage := NewMemoryStorage()

		config := &Config{
			AAGUID:              DefaultAAGUID,
			SupportedAlgorithms: []int{COSEAlgES256},
			MaxCredentials:      100,
			PINMinLength:        4,
			PINMaxRetries:       8,
			AttestationFormat:   AttestationFormatPacked,
			KeyBackend:          nil, // No backend
			Storage:             storage,
		}

		auth, err := NewAuthenticator(config)
		require.NoError(t, err)
		defer func() { _ = auth.Close() }()

		authData := []byte("mock-auth-data")
		clientDataHash := make([]byte, 32)

		fmt, attStmt := auth.buildAttestationStatement(authData, clientDataHash)
		require.Equal(t, AttestationFormatNone, fmt)
		require.Empty(t, attStmt)
	})
}

func TestMakeCredential_WithPackedAttestation(t *testing.T) {
	storage := NewMemoryStorage()
	mockBackend := &mockAttestingKeyBackend{
		attestationStmt: &keybackend.FIDO2AttestationStatement{
			Format:    AttestationFormatPacked,
			Algorithm: COSEAlgES256,
			Signature: []byte("packed-attestation-signature"),
			CertificateChain: []*x509.Certificate{
				{Raw: []byte("attestation-cert")},
			},
		},
	}

	config := &Config{
		AAGUID:                 DefaultAAGUID,
		SupportedAlgorithms:    []int{COSEAlgES256},
		MaxCredentials:         100,
		MaxResidentCredentials: 25,
		PINMinLength:           4,
		PINMaxRetries:          8,
		AttestationFormat:      AttestationFormatPacked,
		KeyBackend:             mockBackend,
		Storage:                storage,
	}

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	defer func() { _ = auth.Close() }()

	clientDataHash := make([]byte, ClientDataHashSize)
	rp := RelyingParty{ID: "example.com", Name: "Example"}
	user := User{ID: []byte("user-123"), Name: "test@example.com"}
	pubKeyCredParams := []PublicKeyCredentialParam{{Type: "public-key", Alg: COSEAlgES256}}

	resp, err := auth.MakeCredential(clientDataHash, rp, user, pubKeyCredParams, nil)
	require.NoError(t, err)
	require.NotNil(t, resp)

	require.Equal(t, AttestationFormatPacked, resp.Fmt)
	require.NotEmpty(t, resp.AuthData)

	// Verify attestation statement contains expected fields
	require.Equal(t, COSEAlgES256, resp.AttStmt["alg"])
	require.Equal(t, []byte("packed-attestation-signature"), resp.AttStmt["sig"])

	x5c, ok := resp.AttStmt["x5c"].([][]byte)
	require.True(t, ok)
	require.Len(t, x5c, 1)
}

func TestMakeCredential_WithTPMAttestation(t *testing.T) {
	storage := NewMemoryStorage()
	mockBackend := &mockAttestingKeyBackend{
		backendType: types.BackendTypeTPM2,
		attestationStmt: &keybackend.FIDO2AttestationStatement{
			Format:    AttestationFormatTPM,
			Algorithm: COSEAlgES256,
			Signature: []byte("tpm-attestation-signature"),
			TPMData:   []byte("tpm-certinfo-data"),
			CertificateChain: []*x509.Certificate{
				{Raw: []byte("aik-certificate")},
			},
		},
	}

	config := &Config{
		AAGUID:                 DefaultAAGUID,
		SupportedAlgorithms:    []int{COSEAlgES256},
		MaxCredentials:         100,
		MaxResidentCredentials: 25,
		PINMinLength:           4,
		PINMaxRetries:          8,
		AttestationFormat:      AttestationFormatTPM,
		KeyBackend:             mockBackend,
		Storage:                storage,
	}

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	defer func() { _ = auth.Close() }()

	clientDataHash := make([]byte, ClientDataHashSize)
	rp := RelyingParty{ID: "example.com", Name: "Example"}
	user := User{ID: []byte("user-123"), Name: "test@example.com"}
	pubKeyCredParams := []PublicKeyCredentialParam{{Type: "public-key", Alg: COSEAlgES256}}

	resp, err := auth.MakeCredential(clientDataHash, rp, user, pubKeyCredParams, nil)
	require.NoError(t, err)
	require.NotNil(t, resp)

	require.Equal(t, AttestationFormatTPM, resp.Fmt)
	require.NotEmpty(t, resp.AuthData)

	// Verify TPM attestation statement contains expected fields
	require.Equal(t, COSEAlgES256, resp.AttStmt["alg"])
	require.Equal(t, []byte("tpm-attestation-signature"), resp.AttStmt["sig"])
	require.Equal(t, []byte("tpm-certinfo-data"), resp.AttStmt["certInfo"])

	x5c, ok := resp.AttStmt["x5c"].([][]byte)
	require.True(t, ok)
	require.Len(t, x5c, 1)
}

func TestMakeCredential_AttestationFallbackToNone(t *testing.T) {
	storage := NewMemoryStorage()
	mockBackend := &mockNonAttestingKeyBackend{}

	config := &Config{
		AAGUID:                 DefaultAAGUID,
		SupportedAlgorithms:    []int{COSEAlgES256},
		MaxCredentials:         100,
		MaxResidentCredentials: 25,
		PINMinLength:           4,
		PINMaxRetries:          8,
		AttestationFormat:      AttestationFormatPacked, // Requested but not supported
		KeyBackend:             mockBackend,
		Storage:                storage,
	}

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	defer func() { _ = auth.Close() }()

	clientDataHash := make([]byte, ClientDataHashSize)
	rp := RelyingParty{ID: "example.com", Name: "Example"}
	user := User{ID: []byte("user-123"), Name: "test@example.com"}
	pubKeyCredParams := []PublicKeyCredentialParam{{Type: "public-key", Alg: COSEAlgES256}}

	resp, err := auth.MakeCredential(clientDataHash, rp, user, pubKeyCredParams, nil)
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Should fall back to "none" since backend doesn't support attestation
	require.Equal(t, AttestationFormatNone, resp.Fmt)
	require.Empty(t, resp.AttStmt)
}

// Additional tests for improved coverage

func TestGenerateCredentialKeyPair_EdDSA(t *testing.T) {
	// Test EdDSA key generation
	auth := createMakeCredentialTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	credentialID := make([]byte, 32)
	_, err := rand.Read(credentialID)
	require.NoError(t, err)

	privateKeyBytes, publicKeyCOSE, backendID, err := auth.generateCredentialKeyPair(COSEAlgEdDSA, credentialID)
	require.NoError(t, err)
	require.NotNil(t, privateKeyBytes)
	require.NotNil(t, publicKeyCOSE)
	require.Equal(t, types.BackendTypeSoftware, backendID)

	// Verify the public key can be decoded
	pubKey, alg, err := DecodeCOSEPublicKey(publicKeyCOSE)
	require.NoError(t, err)
	require.Equal(t, COSEAlgEdDSA, alg)

	// Verify it's an Ed25519 key
	_, ok := pubKey.(ed25519.PublicKey)
	require.True(t, ok, "public key should be Ed25519")
}

func TestParseAssertionPrivateKey_Ed25519(t *testing.T) {
	// Generate an Ed25519 key
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Encode to PKCS#8
	edKeyBytes, err := x509.MarshalPKCS8PrivateKey(edPriv)
	require.NoError(t, err)

	// Test parsing Ed25519 key
	parsed, err := parseAssertionPrivateKey(edKeyBytes)
	require.NoError(t, err)

	_, ok := parsed.(ed25519.PrivateKey)
	require.True(t, ok, "Parsed key should be Ed25519")
}

func TestMakeCredential_HMACSecretNotRequested(t *testing.T) {
	auth := createMakeCredentialTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	clientDataHash := make([]byte, ClientDataHashSize)
	rp := RelyingParty{ID: "example.com"}
	user := User{ID: []byte("user"), Name: "user"}
	pubKeyCredParams := []PublicKeyCredentialParam{{Type: "public-key", Alg: COSEAlgES256}}

	// Request with hmac-secret explicitly set to false
	opts := &MakeCredentialOptions{
		Extensions: map[string]interface{}{
			"hmac-secret": false,
		},
	}

	resp, err := auth.MakeCredential(clientDataHash, rp, user, pubKeyCredParams, opts)
	require.NoError(t, err)

	authData, err := ParseAuthData(resp.AuthData)
	require.NoError(t, err)

	cred, err := auth.storage.Load(authData.CredentialID)
	require.NoError(t, err)
	require.Empty(t, cred.HMACSecretKey, "HMAC secret key should not be generated when not requested")
}

func TestShouldGenerateHMACSecret(t *testing.T) {
	t.Run("hmac-secret enabled and requested", func(t *testing.T) {
		auth := createMakeCredentialTestAuthenticator(t)
		defer func() { _ = auth.Close() }()

		extensions := map[string]interface{}{
			"hmac-secret": true,
		}
		result := auth.shouldGenerateHMACSecret(extensions)
		require.True(t, result)
	})

	t.Run("hmac-secret enabled but not requested", func(t *testing.T) {
		auth := createMakeCredentialTestAuthenticator(t)
		defer func() { _ = auth.Close() }()

		extensions := map[string]interface{}{}
		result := auth.shouldGenerateHMACSecret(extensions)
		require.False(t, result)
	})

	t.Run("hmac-secret requested but set to false", func(t *testing.T) {
		auth := createMakeCredentialTestAuthenticator(t)
		defer func() { _ = auth.Close() }()

		extensions := map[string]interface{}{
			"hmac-secret": false,
		}
		result := auth.shouldGenerateHMACSecret(extensions)
		require.False(t, result)
	})

	t.Run("hmac-secret disabled in config", func(t *testing.T) {
		storage := NewMemoryStorage()
		config := DefaultConfig()
		config.Storage = storage
		config.EnableHMACSecret = false

		auth, err := NewAuthenticator(config)
		require.NoError(t, err)
		defer func() { _ = auth.Close() }()

		extensions := map[string]interface{}{
			"hmac-secret": true,
		}
		result := auth.shouldGenerateHMACSecret(extensions)
		require.False(t, result)
	})

	t.Run("hmac-secret not a bool", func(t *testing.T) {
		auth := createMakeCredentialTestAuthenticator(t)
		defer func() { _ = auth.Close() }()

		extensions := map[string]interface{}{
			"hmac-secret": "true", // String instead of bool
		}
		result := auth.shouldGenerateHMACSecret(extensions)
		require.False(t, result)
	})
}

func TestMakeCredential_WithRequireUserPresence(t *testing.T) {
	storage := NewMemoryStorage()
	config := DefaultConfig()
	config.Storage = storage
	config.RequireUserPresence = true

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	defer func() { _ = auth.Close() }()

	clientDataHash := make([]byte, ClientDataHashSize)
	rp := RelyingParty{ID: "example.com"}
	user := User{ID: []byte("user"), Name: "user"}
	pubKeyCredParams := []PublicKeyCredentialParam{{Type: "public-key", Alg: COSEAlgES256}}

	// Should succeed even with RequireUserPresence set (auto UP handler)
	resp, err := auth.MakeCredential(clientDataHash, rp, user, pubKeyCredParams, nil)
	require.NoError(t, err)
	require.NotNil(t, resp)

	authData, err := ParseAuthData(resp.AuthData)
	require.NoError(t, err)
	require.True(t, authData.UserPresent())
}

func TestCredProtectExtension_IntValue(t *testing.T) {
	auth := createMakeCredentialTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	// Test with int type instead of uint8 (as CBOR might decode)
	extensions := map[string]interface{}{
		"credProtect": int(2),
	}
	outputs := auth.processMakeCredentialExtensions(extensions, false)
	require.Equal(t, CredProtectUserVerificationOptionalWithList, outputs["credProtect"])
}

func TestCredProtectExtension_InvalidType(t *testing.T) {
	auth := createMakeCredentialTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	// Test with invalid type
	extensions := map[string]interface{}{
		"credProtect": "not-an-int",
	}
	outputs := auth.processMakeCredentialExtensions(extensions, false)
	_, exists := outputs["credProtect"]
	require.False(t, exists)
}

// denyingUPHandler is a UserPresenceHandler that always denies requests.
type denyingUPHandler struct{}

func (h *denyingUPHandler) RequestUserPresence(_ context.Context, _ *UserPresenceRequest) (*UserPresenceResult, error) {
	return &UserPresenceResult{Approved: false}, nil
}

func (h *denyingUPHandler) RequestUserVerification(_ context.Context, _ *UserVerificationRequest) (*UserVerificationResult, error) {
	return &UserVerificationResult{Verified: false}, nil
}

// errorUPHandler is a UserPresenceHandler that returns an error.
type errorUPHandler struct {
	err error
}

func (h *errorUPHandler) RequestUserPresence(_ context.Context, _ *UserPresenceRequest) (*UserPresenceResult, error) {
	return nil, h.err
}

func (h *errorUPHandler) RequestUserVerification(_ context.Context, _ *UserVerificationRequest) (*UserVerificationResult, error) {
	return nil, h.err
}

func TestHandleMakeCredential_UserPresenceDenied(t *testing.T) {
	t.Parallel()

	storage := NewMemoryStorage()
	config := DefaultConfig()
	config.Storage = storage
	config.UserPresenceHandler = &denyingUPHandler{}

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	defer func() { _ = auth.Close() }()

	clientDataHash := make([]byte, ClientDataHashSize)
	rp := RelyingParty{ID: "example.com"}
	user := User{ID: []byte("user"), Name: "user"}
	pubKeyCredParams := []PublicKeyCredentialParam{{Type: "public-key", Alg: COSEAlgES256}}

	_, err = auth.MakeCredential(clientDataHash, rp, user, pubKeyCredParams, nil)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrUserPresenceRequired)
}

func TestHandleMakeCredential_UserPresenceError(t *testing.T) {
	t.Parallel()

	storage := NewMemoryStorage()
	config := DefaultConfig()
	config.Storage = storage
	config.UserPresenceHandler = &errorUPHandler{err: ErrUserPresenceTimeout}

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	defer func() { _ = auth.Close() }()

	clientDataHash := make([]byte, ClientDataHashSize)
	rp := RelyingParty{ID: "example.com"}
	user := User{ID: []byte("user"), Name: "user"}
	pubKeyCredParams := []PublicKeyCredentialParam{{Type: "public-key", Alg: COSEAlgES256}}

	_, err = auth.MakeCredential(clientDataHash, rp, user, pubKeyCredParams, nil)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrUserPresenceTimeout)
}

// failingKeyGenBackend is a key backend that fails key generation.
type failingKeyGenBackend struct {
	genErr    error
	exportErr error
}

func (b *failingKeyGenBackend) Type() types.BackendType {
	return types.BackendTypeSoftware
}

func (b *failingKeyGenBackend) Capabilities() keybackend.FIDO2KeyCapabilities {
	return keybackend.FIDO2KeyCapabilities{
		SupportedAlgorithms: []int{COSEAlgES256},
		SupportsExport:      true,
		SupportsImport:      true,
	}
}

func (b *failingKeyGenBackend) GenerateCredentialKey(_ int, _ []byte) (keybackend.KeyHandle, []byte, error) {
	if b.genErr != nil {
		return nil, nil, b.genErr
	}
	return &mockKeyHandle{credID: []byte("test"), alg: COSEAlgES256}, []byte("cose-key"), nil
}

func (b *failingKeyGenBackend) Sign(_ keybackend.KeyHandle, _ int, _ []byte) ([]byte, error) {
	return []byte("sig"), nil
}

func (b *failingKeyGenBackend) LoadKey(credentialID []byte, algorithm int) (keybackend.KeyHandle, error) {
	return &mockKeyHandle{credID: credentialID, alg: algorithm}, nil
}

func (b *failingKeyGenBackend) DeleteKey(_ keybackend.KeyHandle) error {
	return nil
}

func (b *failingKeyGenBackend) ExportPrivateKey(_ keybackend.KeyHandle) ([]byte, error) {
	if b.exportErr != nil {
		return nil, b.exportErr
	}
	return []byte("private-key"), nil
}

func (b *failingKeyGenBackend) ImportPrivateKey(credentialID []byte, algorithm int, _ []byte) (keybackend.KeyHandle, error) {
	return &mockKeyHandle{credID: credentialID, alg: algorithm}, nil
}

func (b *failingKeyGenBackend) Close() error {
	return nil
}

func TestHandleMakeCredential_KeyGenerationFailure(t *testing.T) {
	t.Parallel()

	storage := NewMemoryStorage()
	config := DefaultConfig()
	config.Storage = storage
	config.KeyBackend = &failingKeyGenBackend{genErr: errors.New("key generation failed")}

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	defer func() { _ = auth.Close() }()

	clientDataHash := make([]byte, ClientDataHashSize)
	rp := RelyingParty{ID: "example.com"}
	user := User{ID: []byte("user"), Name: "user"}
	pubKeyCredParams := []PublicKeyCredentialParam{{Type: "public-key", Alg: COSEAlgES256}}

	_, err = auth.MakeCredential(clientDataHash, rp, user, pubKeyCredParams, nil)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrCryptoError)
}

func TestHandleMakeCredential_KeyExportFailure(t *testing.T) {
	t.Parallel()

	storage := NewMemoryStorage()
	config := DefaultConfig()
	config.Storage = storage
	config.KeyBackend = &failingKeyGenBackend{exportErr: errors.New("export failed")}

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	defer func() { _ = auth.Close() }()

	clientDataHash := make([]byte, ClientDataHashSize)
	rp := RelyingParty{ID: "example.com"}
	user := User{ID: []byte("user"), Name: "user"}
	pubKeyCredParams := []PublicKeyCredentialParam{{Type: "public-key", Alg: COSEAlgES256}}

	_, err = auth.MakeCredential(clientDataHash, rp, user, pubKeyCredParams, nil)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrCryptoError)
}

func TestCheckExcludeList_DifferentRPID(t *testing.T) {
	t.Parallel()

	auth := createMakeCredentialTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	clientDataHash := make([]byte, ClientDataHashSize)
	pubKeyCredParams := []PublicKeyCredentialParam{{Type: "public-key", Alg: COSEAlgES256}}

	// Create credential for example.com
	rp1 := RelyingParty{ID: "example.com"}
	user1 := User{ID: []byte("user1"), Name: "user1"}
	resp1, err := auth.MakeCredential(clientDataHash, rp1, user1, pubKeyCredParams, nil)
	require.NoError(t, err)

	authData1, err := ParseAuthData(resp1.AuthData)
	require.NoError(t, err)

	// Try to create credential for different.com with example.com credential in exclude list
	// Should succeed because RP IDs don't match
	rp2 := RelyingParty{ID: "different.com"}
	user2 := User{ID: []byte("user2"), Name: "user2"}
	opts := &MakeCredentialOptions{
		ExcludeList: []CredentialDescriptor{
			{Type: "public-key", ID: authData1.CredentialID},
		},
	}

	resp2, err := auth.MakeCredential(clientDataHash, rp2, user2, pubKeyCredParams, opts)
	require.NoError(t, err)
	require.NotNil(t, resp2)
}

func TestHandleMakeCredential_PINAuthWithRequireUserPresence(t *testing.T) {
	t.Parallel()

	storage := NewMemoryStorage()
	config := DefaultConfig()
	config.Storage = storage
	config.RequireUserPresence = true
	config.EnablePIN = true

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	defer func() { _ = auth.Close() }()

	// Set up valid PIN protocol state
	pinToken := make([]byte, 32)
	for i := range pinToken {
		pinToken[i] = byte(i)
	}
	auth.pinState.protocol = &pinProtocolState{
		pinUvAuthToken:   pinToken,
		tokenPermissions: PINPermissionMakeCredential,
	}

	clientDataHash := make([]byte, ClientDataHashSize)

	// Compute valid pinUvAuthParam
	mac := hmac.New(sha256.New, pinToken)
	mac.Write(clientDataHash)
	pinUvAuthParam := mac.Sum(nil)[:16]

	rp := RelyingParty{ID: "example.com"}
	user := User{ID: []byte("user"), Name: "user"}
	pubKeyCredParams := []PublicKeyCredentialParam{{Type: "public-key", Alg: COSEAlgES256}}

	opts := &MakeCredentialOptions{
		PINUVAuthParam:    pinUvAuthParam,
		PINUVAuthProtocol: 1,
	}

	// Should still succeed - PIN auth is valid, UP is auto-granted
	resp, err := auth.MakeCredential(clientDataHash, rp, user, pubKeyCredParams, opts)
	require.NoError(t, err)
	require.NotNil(t, resp)

	authData, err := ParseAuthData(resp.AuthData)
	require.NoError(t, err)
	require.True(t, authData.UserPresent())
	require.True(t, authData.UserVerified())
}

func TestHandleMakeCredential_CBORWithAllOptions(t *testing.T) {
	t.Parallel()

	auth := createMakeCredentialTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	clientDataHash := make([]byte, ClientDataHashSize)

	reqMap := map[int]interface{}{
		makeCredentialKeyClientDataHash: clientDataHash,
		makeCredentialKeyRP: map[string]interface{}{
			"id":   "example.com",
			"name": "Example Corp",
			"icon": "https://example.com/icon.png",
		},
		makeCredentialKeyUser: map[string]interface{}{
			"id":          []byte("user-full"),
			"name":        "full@example.com",
			"displayName": "Full User",
			"icon":        "https://example.com/user.png",
		},
		makeCredentialKeyPubKeyCredParams: []interface{}{
			map[string]interface{}{"type": "public-key", "alg": COSEAlgES256},
		},
		makeCredentialKeyExtensions: map[string]interface{}{
			"hmac-secret": true,
			"credProtect": uint8(CredProtectUserVerificationOptionalWithList),
		},
		makeCredentialKeyOptions: map[string]interface{}{
			"rk": true,
		},
		makeCredentialKeyPINUVAuthParam:        []byte{},
		makeCredentialKeyPINUVAuthProtocol:     uint8(0),
		makeCredentialKeyEnterpriseAttestation: uint8(0),
	}

	reqData, err := cbor.Marshal(reqMap)
	require.NoError(t, err)

	respData, err := auth.HandleMakeCredential(reqData)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), respData[0])

	var respMap map[int]interface{}
	err = cbor.Unmarshal(respData[1:], &respMap)
	require.NoError(t, err)

	authDataBytes := respMap[makeCredentialResponseKeyAuthData].([]byte)
	authData, err := ParseAuthData(authDataBytes)
	require.NoError(t, err)

	// Verify credential was stored with correct properties
	cred, err := auth.storage.Load(authData.CredentialID)
	require.NoError(t, err)
	require.True(t, cred.Discoverable)
	require.NotEmpty(t, cred.HMACSecretKey)
	require.Equal(t, CredProtectUserVerificationOptionalWithList, cred.CredProtect)
}

func TestHandleMakeCredential_NonPublicKeyType(t *testing.T) {
	t.Parallel()

	auth := createMakeCredentialTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	clientDataHash := make([]byte, ClientDataHashSize)

	// All params have non-"public-key" type, should result in no supported algorithm
	reqMap := map[int]interface{}{
		makeCredentialKeyClientDataHash: clientDataHash,
		makeCredentialKeyRP: map[string]interface{}{
			"id": "example.com",
		},
		makeCredentialKeyUser: map[string]interface{}{
			"id": []byte("user"),
		},
		makeCredentialKeyPubKeyCredParams: []interface{}{
			map[string]interface{}{"type": "invalid-type", "alg": COSEAlgES256},
		},
	}

	reqData, err := cbor.Marshal(reqMap)
	require.NoError(t, err)

	_, err = auth.HandleMakeCredential(reqData)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrNoSupportedAlgorithm)
}

func TestConvertMakeCredentialStringKeyMap(t *testing.T) {
	t.Parallel()

	input := map[interface{}]interface{}{
		"key1": "value1",
		"key2": 42,
		123:    "non-string-key-ignored",
	}

	result := convertMakeCredentialStringKeyMap(input)

	require.Equal(t, "value1", result["key1"])
	require.Equal(t, 42, result["key2"])
	_, exists := result["123"]
	require.False(t, exists)
}

func TestValidateMakeCredentialRequest_EmptyPubKeyCredParams(t *testing.T) {
	t.Parallel()

	auth := createMakeCredentialTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	req := &MakeCredentialRequest{
		ClientDataHash:   make([]byte, ClientDataHashSize),
		RP:               RelyingParty{ID: "example.com"},
		User:             User{ID: []byte("user")},
		PubKeyCredParams: []PublicKeyCredentialParam{}, // Empty
	}

	err := auth.validateMakeCredentialRequest(req)
	require.ErrorIs(t, err, ErrMissingPubKeyCredParams)
}

func TestHandleMakeCredential_ES384Algorithm(t *testing.T) {
	t.Parallel()

	auth := createMakeCredentialTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	clientDataHash := make([]byte, ClientDataHashSize)
	rp := RelyingParty{ID: "example.com"}
	user := User{ID: []byte("user"), Name: "user"}
	pubKeyCredParams := []PublicKeyCredentialParam{{Type: "public-key", Alg: COSEAlgES384}}

	resp, err := auth.MakeCredential(clientDataHash, rp, user, pubKeyCredParams, nil)
	require.NoError(t, err)
	require.NotNil(t, resp)

	authData, err := ParseAuthData(resp.AuthData)
	require.NoError(t, err)

	pubKey, alg, err := DecodeCOSEPublicKey(authData.PublicKey)
	require.NoError(t, err)
	require.Equal(t, COSEAlgES384, alg)
	require.NotNil(t, pubKey)
}

func TestHandleMakeCredential_ExcludeListWithNonexistentCredential(t *testing.T) {
	t.Parallel()

	auth := createMakeCredentialTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	clientDataHash := make([]byte, ClientDataHashSize)
	rp := RelyingParty{ID: "example.com"}
	user := User{ID: []byte("user"), Name: "user"}
	pubKeyCredParams := []PublicKeyCredentialParam{{Type: "public-key", Alg: COSEAlgES256}}

	// Include a credential ID that doesn't exist in exclude list
	opts := &MakeCredentialOptions{
		ExcludeList: []CredentialDescriptor{
			{Type: "public-key", ID: []byte("nonexistent-credential-id")},
		},
	}

	// Should succeed because the credential doesn't exist
	resp, err := auth.MakeCredential(clientDataHash, rp, user, pubKeyCredParams, opts)
	require.NoError(t, err)
	require.NotNil(t, resp)
}

func TestHandleMakeCredential_WithLogger(t *testing.T) {
	t.Parallel()

	storage := NewMemoryStorage()
	config := DefaultConfig()
	config.Storage = storage
	config.Logger = slog.Default()

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	defer func() { _ = auth.Close() }()

	clientDataHash := make([]byte, ClientDataHashSize)
	rp := RelyingParty{ID: "example.com", Name: "Example"}
	user := User{ID: []byte("user"), Name: "user@example.com"}
	pubKeyCredParams := []PublicKeyCredentialParam{{Type: "public-key", Alg: COSEAlgES256}}

	resp, err := auth.MakeCredential(clientDataHash, rp, user, pubKeyCredParams, nil)
	require.NoError(t, err)
	require.NotNil(t, resp)
}

func TestHandleMakeCredential_WithLoggerAndPINAuth(t *testing.T) {
	t.Parallel()

	storage := NewMemoryStorage()
	config := DefaultConfig()
	config.Storage = storage
	config.Logger = slog.Default()
	config.EnablePIN = true

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	defer func() { _ = auth.Close() }()

	// Set up valid PIN protocol state
	pinToken := make([]byte, 32)
	for i := range pinToken {
		pinToken[i] = byte(i)
	}
	auth.pinState.protocol = &pinProtocolState{
		pinUvAuthToken:   pinToken,
		tokenPermissions: PINPermissionMakeCredential,
	}

	clientDataHash := make([]byte, ClientDataHashSize)
	mac := hmac.New(sha256.New, pinToken)
	mac.Write(clientDataHash)
	pinUvAuthParam := mac.Sum(nil)[:16]

	rp := RelyingParty{ID: "example.com"}
	user := User{ID: []byte("user"), Name: "user"}
	pubKeyCredParams := []PublicKeyCredentialParam{{Type: "public-key", Alg: COSEAlgES256}}

	opts := &MakeCredentialOptions{
		PINUVAuthParam:    pinUvAuthParam,
		PINUVAuthProtocol: 1,
	}

	resp, err := auth.MakeCredential(clientDataHash, rp, user, pubKeyCredParams, opts)
	require.NoError(t, err)
	require.NotNil(t, resp)
}

func TestHandleMakeCredential_WithLoggerPINRequired(t *testing.T) {
	t.Parallel()

	storage := NewMemoryStorage()
	state := NewAuthenticatorState()
	state.AAGUID = DefaultAAGUID
	state.PINSet = true
	err := storage.SaveState(state)
	require.NoError(t, err)

	config := DefaultConfig()
	config.Storage = storage
	config.Logger = slog.Default()
	config.EnablePIN = true

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	defer func() { _ = auth.Close() }()

	clientDataHash := make([]byte, ClientDataHashSize)
	rp := RelyingParty{ID: "example.com"}
	user := User{ID: []byte("user"), Name: "user"}
	pubKeyCredParams := []PublicKeyCredentialParam{{Type: "public-key", Alg: COSEAlgES256}}

	_, err = auth.MakeCredential(clientDataHash, rp, user, pubKeyCredParams, nil)
	require.ErrorIs(t, err, ErrPINRequired)
}

func TestHandleMakeCredential_WithLoggerInvalidPINAuth(t *testing.T) {
	t.Parallel()

	storage := NewMemoryStorage()
	config := DefaultConfig()
	config.Storage = storage
	config.Logger = slog.Default()
	config.EnablePIN = true

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	defer func() { _ = auth.Close() }()

	// Set up PIN protocol state with known token
	pinToken := make([]byte, 32)
	for i := range pinToken {
		pinToken[i] = byte(i)
	}
	auth.pinState.protocol = &pinProtocolState{
		pinUvAuthToken:   pinToken,
		tokenPermissions: PINPermissionMakeCredential,
	}

	clientDataHash := make([]byte, ClientDataHashSize)
	rp := RelyingParty{ID: "example.com"}
	user := User{ID: []byte("user"), Name: "user"}
	pubKeyCredParams := []PublicKeyCredentialParam{{Type: "public-key", Alg: COSEAlgES256}}

	// Use wrong pinUvAuthParam
	opts := &MakeCredentialOptions{
		PINUVAuthParam:    []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
		PINUVAuthProtocol: 1,
	}

	_, err = auth.MakeCredential(clientDataHash, rp, user, pubKeyCredParams, opts)
	require.ErrorIs(t, err, ErrPINAuthInvalid)
}

func TestHandleMakeCredential_WithLoggerResponseBuilt(t *testing.T) {
	t.Parallel()

	storage := NewMemoryStorage()
	config := DefaultConfig()
	config.Storage = storage
	config.Logger = slog.Default()

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	defer func() { _ = auth.Close() }()

	// Build CBOR request
	clientDataHash := make([]byte, ClientDataHashSize)
	reqMap := map[int]interface{}{
		makeCredentialKeyClientDataHash: clientDataHash,
		makeCredentialKeyRP: map[string]interface{}{
			"id":   "example.com",
			"name": "Example",
		},
		makeCredentialKeyUser: map[string]interface{}{
			"id":   []byte("user"),
			"name": "user@example.com",
		},
		makeCredentialKeyPubKeyCredParams: []interface{}{
			map[string]interface{}{"type": "public-key", "alg": COSEAlgES256},
		},
	}

	reqData, err := cbor.Marshal(reqMap)
	require.NoError(t, err)

	// Use HandleMakeCredential directly to cover the logger path at the end
	respData, err := auth.HandleMakeCredential(reqData)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), respData[0])
}

func TestHandleMakeCredential_WithLoggerAndUPRequired(t *testing.T) {
	t.Parallel()

	storage := NewMemoryStorage()
	config := DefaultConfig()
	config.Storage = storage
	config.Logger = slog.Default()
	config.RequireUserPresence = true

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	defer func() { _ = auth.Close() }()

	clientDataHash := make([]byte, ClientDataHashSize)
	reqMap := map[int]interface{}{
		makeCredentialKeyClientDataHash: clientDataHash,
		makeCredentialKeyRP: map[string]interface{}{
			"id": "example.com",
		},
		makeCredentialKeyUser: map[string]interface{}{
			"id": []byte("user"),
		},
		makeCredentialKeyPubKeyCredParams: []interface{}{
			map[string]interface{}{"type": "public-key", "alg": COSEAlgES256},
		},
	}

	reqData, err := cbor.Marshal(reqMap)
	require.NoError(t, err)

	respData, err := auth.HandleMakeCredential(reqData)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), respData[0])
}

func TestHandleMakeCredential_WithLoggerPINAuthSkipsUP(t *testing.T) {
	t.Parallel()

	storage := NewMemoryStorage()
	config := DefaultConfig()
	config.Storage = storage
	config.Logger = slog.Default()
	config.EnablePIN = true
	config.RequireUserPresence = false

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	defer func() { _ = auth.Close() }()

	// Set up valid PIN protocol state
	pinToken := make([]byte, 32)
	for i := range pinToken {
		pinToken[i] = byte(i)
	}
	auth.pinState.protocol = &pinProtocolState{
		pinUvAuthToken:   pinToken,
		tokenPermissions: PINPermissionMakeCredential,
	}

	clientDataHash := make([]byte, ClientDataHashSize)
	mac := hmac.New(sha256.New, pinToken)
	mac.Write(clientDataHash)
	pinUvAuthParam := mac.Sum(nil)[:16]

	reqMap := map[int]interface{}{
		makeCredentialKeyClientDataHash: clientDataHash,
		makeCredentialKeyRP: map[string]interface{}{
			"id": "example.com",
		},
		makeCredentialKeyUser: map[string]interface{}{
			"id": []byte("user"),
		},
		makeCredentialKeyPubKeyCredParams: []interface{}{
			map[string]interface{}{"type": "public-key", "alg": COSEAlgES256},
		},
		makeCredentialKeyPINUVAuthParam:    pinUvAuthParam,
		makeCredentialKeyPINUVAuthProtocol: uint8(1),
	}

	reqData, err := cbor.Marshal(reqMap)
	require.NoError(t, err)

	// This should skip UP and log "UP implicitly satisfied by PIN verification"
	respData, err := auth.HandleMakeCredential(reqData)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), respData[0])
}

// --- InternalPINHash tests for MakeCredential ---

// TestMakeCredential_InternalPINHash_Success verifies that a trusted in-process caller
// can create a credential by providing the correct InternalPINHash, bypassing the
// CTAP2 clientPin ECDH ceremony. The response must have the UV flag set.
func TestMakeCredential_InternalPINHash_Success(t *testing.T) {
	storage := NewMemoryStorage()
	config := DefaultConfig()
	config.Storage = storage
	config.EnablePIN = true

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	defer func() { _ = auth.Close() }()

	// Set PIN via SyncPINHash (the first 16 bytes of SHA-256 of the raw PIN).
	rawPIN := "123456"
	fullHash := sha256.Sum256([]byte(rawPIN))
	pinHash := fullHash[:PINHashSize]
	auth.SyncPINHash(pinHash)
	require.True(t, auth.IsPINSet(), "PIN should be set")

	// Create credential with InternalPINHash to bypass PIN enforcement.
	clientDataHash := sha256.Sum256([]byte("test client data"))
	rp := RelyingParty{ID: "example.com", Name: "Example Corp"}
	user := User{ID: []byte("user-42"), Name: "bob@example.com", DisplayName: "Bob"}
	pubKeyCredParams := []PublicKeyCredentialParam{
		{Type: "public-key", Alg: COSEAlgES256},
	}

	opts := &MakeCredentialOptions{
		Options: map[string]bool{
			"rk": true,
		},
		InternalPINHash: pinHash,
	}

	resp, err := auth.MakeCredential(clientDataHash[:], rp, user, pubKeyCredParams, opts)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, AttestationFormatNone, resp.Fmt)
	require.NotEmpty(t, resp.AuthData)

	// Parse authData and verify UV flag is set.
	parsedAuthData, err := ParseAuthData(resp.AuthData)
	require.NoError(t, err)
	require.True(t, parsedAuthData.UserPresent(), "UP flag should be set")
	require.True(t, parsedAuthData.UserVerified(), "UV flag should be set when InternalPINHash is valid")
	require.True(t, parsedAuthData.HasAttestedCredentialData(), "AT flag should be set")
	require.NotEmpty(t, parsedAuthData.CredentialID)
	require.NotEmpty(t, parsedAuthData.PublicKey)

	// Verify the credential was actually stored.
	cred, err := auth.storage.Load(parsedAuthData.CredentialID)
	require.NoError(t, err)
	require.Equal(t, rp.ID, cred.RPID)
	require.Equal(t, user.Name, cred.UserName)
}

// TestMakeCredential_InternalPINHash_WrongHash verifies that providing an incorrect
// InternalPINHash returns ErrPINInvalid instead of creating a credential.
func TestMakeCredential_InternalPINHash_WrongHash(t *testing.T) {
	storage := NewMemoryStorage()
	config := DefaultConfig()
	config.Storage = storage
	config.EnablePIN = true

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	defer func() { _ = auth.Close() }()

	// Set the correct PIN hash.
	rawPIN := "123456"
	fullHash := sha256.Sum256([]byte(rawPIN))
	pinHash := fullHash[:PINHashSize]
	auth.SyncPINHash(pinHash)
	require.True(t, auth.IsPINSet())

	// Compute a wrong PIN hash.
	wrongFullHash := sha256.Sum256([]byte("wrong-pin"))
	wrongPINHash := wrongFullHash[:PINHashSize]

	clientDataHash := sha256.Sum256([]byte("test client data"))
	rp := RelyingParty{ID: "example.com", Name: "Example Corp"}
	user := User{ID: []byte("user-42"), Name: "bob@example.com", DisplayName: "Bob"}
	pubKeyCredParams := []PublicKeyCredentialParam{
		{Type: "public-key", Alg: COSEAlgES256},
	}

	opts := &MakeCredentialOptions{
		InternalPINHash: wrongPINHash,
	}

	_, err = auth.MakeCredential(clientDataHash[:], rp, user, pubKeyCredParams, opts)
	require.ErrorIs(t, err, ErrPINInvalid)
}

// --- User intent check tests for MakeCredential ---

// TestMakeCredentialUserIntentCheck_Approved verifies that when EnableUserIntentCheck
// is true, PIN is set, and no pinUvAuthParam is provided, the authenticator calls
// RequestUserPresence before returning ErrPINRequired. When the user approves,
// ErrPINRequired is returned so Chrome proceeds with PIN exchange.
func TestMakeCredentialUserIntentCheck_Approved(t *testing.T) {
	storage := NewMemoryStorage()
	config := DefaultConfig()
	config.Storage = storage
	config.EnablePIN = true
	config.RequireUserPresence = false
	config.EnableUserIntentCheck = true

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	defer func() { _ = auth.Close() }()

	// Set a PIN so that PINSet=true.
	rawPIN := "123456"
	fullHash := sha256.Sum256([]byte(rawPIN))
	pinHash := fullHash[:PINHashSize]
	auth.SyncPINHash(pinHash)
	require.True(t, auth.IsPINSet())

	// Switch to tracking handler that approves
	tracker := &trackingUPHandler{approve: true}
	auth.upHandler = tracker

	// Build CBOR MakeCredential request WITHOUT pinUvAuthParam
	clientDataHash := generateTestClientDataHash()
	makeCredReq := map[int]interface{}{
		makeCredentialKeyClientDataHash: clientDataHash,
		makeCredentialKeyRP:             map[string]interface{}{"id": "example.com", "name": "Example"},
		makeCredentialKeyUser: map[string]interface{}{
			"id":          []byte("user-id-1"),
			"name":        "testuser",
			"displayName": "Test User",
		},
		makeCredentialKeyPubKeyCredParams: []interface{}{
			map[string]interface{}{"type": "public-key", "alg": int64(COSEAlgES256)},
		},
	}
	makeCredReqBytes, err := cbor.Marshal(makeCredReq)
	require.NoError(t, err)

	respBytes, err := auth.ProcessCBOR(CmdMakeCredential, makeCredReqBytes)

	// Assert: UP handler was called (intent check happened)
	require.True(t, tracker.called.Load(), "UP handler should have been called for intent check")

	// Assert: returns ErrPINRequired (user approved, Chrome should do PIN exchange)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrPINRequired)
	require.Equal(t, byte(StatusPINRequired), respBytes[0])
}

// TestMakeCredentialUserIntentCheck_Denied verifies that when EnableUserIntentCheck
// is true and the user denies the presence check, the authenticator returns
// ErrOperationDenied so Chrome falls through to other devices (e.g., YubiKey).
func TestMakeCredentialUserIntentCheck_Denied(t *testing.T) {
	storage := NewMemoryStorage()
	config := DefaultConfig()
	config.Storage = storage
	config.EnablePIN = true
	config.RequireUserPresence = false
	config.EnableUserIntentCheck = true

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	defer func() { _ = auth.Close() }()

	// Set a PIN so that PINSet=true.
	rawPIN := "123456"
	fullHash := sha256.Sum256([]byte(rawPIN))
	pinHash := fullHash[:PINHashSize]
	auth.SyncPINHash(pinHash)
	require.True(t, auth.IsPINSet())

	// Switch to tracking handler that DENIES
	tracker := &trackingUPHandler{approve: false}
	auth.upHandler = tracker

	// Build CBOR MakeCredential request WITHOUT pinUvAuthParam
	clientDataHash := generateTestClientDataHash()
	makeCredReq := map[int]interface{}{
		makeCredentialKeyClientDataHash: clientDataHash,
		makeCredentialKeyRP:             map[string]interface{}{"id": "example.com", "name": "Example"},
		makeCredentialKeyUser: map[string]interface{}{
			"id":          []byte("user-id-1"),
			"name":        "testuser",
			"displayName": "Test User",
		},
		makeCredentialKeyPubKeyCredParams: []interface{}{
			map[string]interface{}{"type": "public-key", "alg": int64(COSEAlgES256)},
		},
	}
	makeCredReqBytes, err := cbor.Marshal(makeCredReq)
	require.NoError(t, err)

	respBytes, err := auth.ProcessCBOR(CmdMakeCredential, makeCredReqBytes)

	// Assert: UP handler was called (intent check happened)
	require.True(t, tracker.called.Load(), "UP handler should have been called for intent check")

	// Assert: returns ErrOperationDenied (user chose different key, e.g., YubiKey)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrOperationDenied)
	require.Equal(t, byte(StatusOperationDenied), respBytes[0])
}

// TestMakeCredentialUserIntentCheck_Disabled verifies that when EnableUserIntentCheck
// is false, the authenticator returns ErrPINRequired directly without calling the
// UP handler for an intent check.
func TestMakeCredentialUserIntentCheck_Disabled(t *testing.T) {
	storage := NewMemoryStorage()
	config := DefaultConfig()
	config.Storage = storage
	config.EnablePIN = true
	config.RequireUserPresence = false
	config.EnableUserIntentCheck = false // Explicitly disabled

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	defer func() { _ = auth.Close() }()

	// Set a PIN so that PINSet=true.
	rawPIN := "123456"
	fullHash := sha256.Sum256([]byte(rawPIN))
	pinHash := fullHash[:PINHashSize]
	auth.SyncPINHash(pinHash)
	require.True(t, auth.IsPINSet())

	// Switch to tracking handler (should NOT be called)
	tracker := &trackingUPHandler{approve: true}
	auth.upHandler = tracker

	// Build CBOR MakeCredential request WITHOUT pinUvAuthParam
	clientDataHash := generateTestClientDataHash()
	makeCredReq := map[int]interface{}{
		makeCredentialKeyClientDataHash: clientDataHash,
		makeCredentialKeyRP:             map[string]interface{}{"id": "example.com", "name": "Example"},
		makeCredentialKeyUser: map[string]interface{}{
			"id":          []byte("user-id-1"),
			"name":        "testuser",
			"displayName": "Test User",
		},
		makeCredentialKeyPubKeyCredParams: []interface{}{
			map[string]interface{}{"type": "public-key", "alg": int64(COSEAlgES256)},
		},
	}
	makeCredReqBytes, err := cbor.Marshal(makeCredReq)
	require.NoError(t, err)

	respBytes, err := auth.ProcessCBOR(CmdMakeCredential, makeCredReqBytes)

	// Assert: UP handler was NOT called (intent check disabled)
	require.False(t, tracker.called.Load(), "UP handler should NOT have been called when intent check disabled")

	// Assert: returns ErrPINRequired directly (legacy behavior)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrPINRequired)
	require.Equal(t, byte(StatusPINRequired), respBytes[0])
}
