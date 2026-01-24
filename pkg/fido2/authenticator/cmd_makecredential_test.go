// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package authenticator

import (
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/fxamacker/cbor/v2"
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

		// Extensions are NOT included in authData to avoid RP parsing issues
		require.False(t, authData.HasExtensions())
	})

	t.Run("with user verification", func(t *testing.T) {
		opts := &MakeCredentialOptions{
			Options: map[string]bool{
				"uv": true,
			},
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

		// Extensions are NOT included in authData to avoid RP parsing issues.
		// The credProtect level is stored on the credential instead.
		require.False(t, authData.HasExtensions())

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
			Options:        map[string]bool{"uv": true},
			PINUVAuthParam: []byte{1, 2, 3},
		}
		result := auth.userVerificationSatisfied(req)
		require.True(t, result)
	})

	t.Run("uv requested software authenticator simulation", func(t *testing.T) {
		req := &MakeCredentialRequest{
			Options: map[string]bool{"uv": true},
		}
		result := auth.userVerificationSatisfied(req)
		require.True(t, result) // Software authenticator simulates UV as satisfied
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
