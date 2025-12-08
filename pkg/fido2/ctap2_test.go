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

package fido2

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAuthenticator(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() { _ = ctapDev.Close() }()

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)
	require.NotNil(t, auth)

	assert.NotNil(t, auth.info)
	assert.NotNil(t, auth.device)
	assert.NotNil(t, auth.config)
}

func TestAuthenticator_GetInfo(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() { _ = ctapDev.Close() }()

	auth := &Authenticator{
		device: ctapDev,
		config: &config,
	}

	info, err := auth.GetInfo()
	require.NoError(t, err)
	require.NotNil(t, info)

	// Verify expected fields from mock
	assert.Contains(t, info.Versions, "FIDO_2_0")
	assert.Contains(t, info.Extensions, "hmac-secret")
	assert.NotNil(t, info.Options)
	assert.True(t, info.Options["rk"])
	assert.True(t, info.Options["up"])
}

func TestAuthenticator_GetInfo_AllFields(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() { _ = ctapDev.Close() }()

	auth := &Authenticator{
		device: ctapDev,
		config: &config,
	}

	info, err := auth.GetInfo()
	require.NoError(t, err)
	require.NotNil(t, info)

	// Check all fields are parsed
	assert.NotEmpty(t, info.Versions)
	assert.NotEmpty(t, info.Extensions)
	assert.NotNil(t, info.AAGUID)
	assert.NotEmpty(t, info.Options)
	assert.Greater(t, info.MaxMsgSize, uint64(0))
	assert.NotEmpty(t, info.PINProtocols)
}

func TestAuthenticator_SupportsExtension(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() { _ = ctapDev.Close() }()

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	// hmac-secret is in mock response
	assert.True(t, auth.SupportsExtension(ExtensionHMACSecret))
	assert.True(t, auth.SupportsHMACSecret())

	// Other extensions not in mock response
	assert.False(t, auth.SupportsExtension("credProtect"))
	assert.False(t, auth.SupportsExtension("unknown-extension"))
}

func TestAuthenticator_MakeCredential(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() { _ = ctapDev.Close() }()

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	req := &MakeCredentialRequest{
		ClientDataHash: CreateClientDataHash([]byte("test challenge")),
		RP: RelyingParty{
			ID:   "example.com",
			Name: "Example Corp",
		},
		User: User{
			ID:          []byte("user123"),
			Name:        "test@example.com",
			DisplayName: "Test User",
		},
		PubKeyCredParams: DefaultPublicKeyCredentialParameters(),
		Extensions: map[string]interface{}{
			ExtensionHMACSecret: true,
		},
		Options: AuthenticatorOptions{
			RK: false,
			UP: true,
		},
	}

	resp, err := auth.MakeCredential(req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, "none", resp.Fmt)
	assert.NotEmpty(t, resp.AuthData)
	assert.NotNil(t, resp.AttStmt)
}

func TestAuthenticator_MakeCredential_WithOptionalFields(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() { _ = ctapDev.Close() }()

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	req := &MakeCredentialRequest{
		ClientDataHash: CreateClientDataHash([]byte("test challenge")),
		RP: RelyingParty{
			ID:   "example.com",
			Name: "Example Corp",
			Icon: "https://example.com/icon.png",
		},
		User: User{
			ID:          []byte("user123"),
			Name:        "test@example.com",
			DisplayName: "Test User",
			Icon:        "https://example.com/user.png",
		},
		PubKeyCredParams: DefaultPublicKeyCredentialParameters(),
		ExcludeList: []PublicKeyCredentialDescriptor{
			{
				Type:       "public-key",
				ID:         make([]byte, 32),
				Transports: []string{"usb"},
			},
		},
		Extensions: map[string]interface{}{
			ExtensionHMACSecret: true,
		},
		Options: AuthenticatorOptions{
			RK: true,
			UV: true,
		},
		PinUVAuthParam:    make([]byte, 16),
		PinUVAuthProtocol: 1,
	}

	resp, err := auth.MakeCredential(req)
	require.NoError(t, err)
	require.NotNil(t, resp)
}

func TestAuthenticator_MakeCredential_InvalidRequest(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() { _ = ctapDev.Close() }()

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	// Missing required fields should still be handled
	req := &MakeCredentialRequest{
		// Incomplete request
	}

	// The mock will respond, but in real scenario this would fail
	_, err = auth.MakeCredential(req)
	// Mock accepts anything, so this won't error
	assert.NoError(t, err)
}

func TestAuthenticator_GetAssertion(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() { _ = ctapDev.Close() }()

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	credID := make([]byte, 32)
	salt := make([]byte, 32)

	req := &GetAssertionRequest{
		RPID:           "example.com",
		ClientDataHash: CreateClientDataHash([]byte("test challenge")),
		AllowList: []PublicKeyCredentialDescriptor{
			{
				Type: "public-key",
				ID:   credID,
			},
		},
		Extensions: map[string]interface{}{
			ExtensionHMACSecret: map[string]interface{}{
				"salt1": salt,
			},
		},
		Options: AuthenticatorOptions{
			UP: true,
		},
	}

	resp, err := auth.GetAssertion(req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.NotEmpty(t, resp.AuthData)
	assert.NotEmpty(t, resp.Signature)
	assert.Equal(t, "public-key", resp.Credential.Type)
}

func TestAuthenticator_GetAssertion_WithAllowListTransports(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() { _ = ctapDev.Close() }()

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	req := &GetAssertionRequest{
		RPID:           "example.com",
		ClientDataHash: CreateClientDataHash([]byte("test challenge")),
		AllowList: []PublicKeyCredentialDescriptor{
			{
				Type:       "public-key",
				ID:         make([]byte, 32),
				Transports: []string{"usb", "nfc"},
			},
		},
		Options: AuthenticatorOptions{
			UP: true,
			UV: true,
		},
		PinUVAuthParam:    make([]byte, 16),
		PinUVAuthProtocol: 1,
	}

	resp, err := auth.GetAssertion(req)
	require.NoError(t, err)
	require.NotNil(t, resp)
}

func TestAuthenticator_GetAssertion_WithCanoKeyWorkaround(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig
	config.WorkaroundCanoKey = true

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() { _ = ctapDev.Close() }()

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	credID := make([]byte, 32)
	salt := make([]byte, 32)

	req := &GetAssertionRequest{
		RPID:           "example.com",
		ClientDataHash: CreateClientDataHash([]byte("test challenge")),
		AllowList: []PublicKeyCredentialDescriptor{
			{
				Type: "public-key",
				ID:   credID,
			},
		},
		Extensions: map[string]interface{}{
			ExtensionHMACSecret: map[string]interface{}{
				"salt1": salt,
			},
		},
		Options: AuthenticatorOptions{
			UP: true,
		},
	}

	resp, err := auth.GetAssertion(req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.NotEmpty(t, resp.AuthData)
}

func TestAuthenticator_Info(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() { _ = ctapDev.Close() }()

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	info := auth.Info()
	require.NotNil(t, info)

	assert.Contains(t, info.Versions, "FIDO_2_0")
	assert.Contains(t, info.Extensions, "hmac-secret")
}

func TestAuthenticator_DeviceInfo(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	mockDev.manufacturer = "Test Vendor"
	mockDev.product = "Test Key"

	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() { _ = ctapDev.Close() }()

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	devInfo := auth.DeviceInfo()
	assert.Equal(t, "/dev/hidraw0", devInfo.Path)
	assert.Equal(t, "Test Vendor", devInfo.Manufacturer)
	assert.Equal(t, "Test Key", devInfo.Product)
	assert.Equal(t, "usb", devInfo.Transport)
}

func TestAuthenticator_Close(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	err = auth.Close()
	assert.NoError(t, err)
}

func TestCOSEAlgorithmConstants(t *testing.T) {
	// Verify COSE algorithm identifiers
	assert.Equal(t, -7, COSEAlgES256)
	assert.Equal(t, -35, COSEAlgES384)
	assert.Equal(t, -36, COSEAlgES512)
	assert.Equal(t, -257, COSEAlgRS256)
	assert.Equal(t, -8, COSEAlgEdDSA)
}

func TestExtensionConstants(t *testing.T) {
	// Verify extension identifiers
	assert.Equal(t, "hmac-secret", ExtensionHMACSecret)
	assert.Equal(t, "credProtect", ExtensionCredProtect)
	assert.Equal(t, "credBlob", ExtensionCredBlob)
	assert.Equal(t, "largeBlobKey", ExtensionLargeBlobKey)
	assert.Equal(t, "minPinLength", ExtensionMinPINLength)
}

func TestCTAP2CommandConstants(t *testing.T) {
	// Verify CTAP2 command codes
	assert.Equal(t, 0x01, CmdMakeCredential)
	assert.Equal(t, 0x02, CmdGetAssertion)
	assert.Equal(t, 0x04, CmdGetInfo)
	assert.Equal(t, 0x06, CmdClientPIN)
	assert.Equal(t, 0x07, CmdReset)
	assert.Equal(t, 0x08, CmdGetNextAssertion)
}

func TestNewAuthenticator_GetInfoError(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() { _ = ctapDev.Close() }()

	// Create a response that will cause GetInfo to fail
	errorResp := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(errorResp[0:4], ctapDev.cid)
	errorResp[4] = CTAPHID_CBOR
	binary.BigEndian.PutUint16(errorResp[5:7], 1)
	errorResp[7] = StatusInvalidCommand

	mockDev.Reset()
	mockDev.SetResponse(errorResp)

	auth, err := NewAuthenticator(ctapDev, &config)
	assert.Error(t, err)
	assert.Nil(t, auth)
	assert.Contains(t, err.Error(), "failed to get authenticator info")
}

func TestAuthenticator_SupportsExtension_NoInfo(t *testing.T) {
	auth := &Authenticator{
		info: nil,
	}

	result := auth.SupportsExtension("hmac-secret")
	assert.False(t, result)
}

func TestAuthenticator_MakeCredential_WithoutExtensions(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() { _ = ctapDev.Close() }()

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	req := &MakeCredentialRequest{
		ClientDataHash:   CreateClientDataHash([]byte("test")),
		RP:               RelyingParty{ID: "example.com", Name: "Example"},
		User:             User{ID: []byte("user"), Name: "test", DisplayName: "Test"},
		PubKeyCredParams: DefaultPublicKeyCredentialParameters(),
		Options: AuthenticatorOptions{
			RK: false,
			UV: false,
		},
	}

	resp, err := auth.MakeCredential(req)
	require.NoError(t, err)
	require.NotNil(t, resp)
}

func TestAuthenticator_MakeCredential_WithoutOptions(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() { _ = ctapDev.Close() }()

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	req := &MakeCredentialRequest{
		ClientDataHash:   CreateClientDataHash([]byte("test")),
		RP:               RelyingParty{ID: "example.com", Name: "Example"},
		User:             User{ID: []byte("user"), Name: "test", DisplayName: "Test"},
		PubKeyCredParams: DefaultPublicKeyCredentialParameters(),
		// No options - both RK and UV will be false
	}

	resp, err := auth.MakeCredential(req)
	require.NoError(t, err)
	require.NotNil(t, resp)
}

func TestAuthenticator_GetAssertion_WithoutAllowList(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() { _ = ctapDev.Close() }()

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	req := &GetAssertionRequest{
		RPID:           "example.com",
		ClientDataHash: CreateClientDataHash([]byte("test")),
		Options: AuthenticatorOptions{
			UP: true,
		},
	}

	resp, err := auth.GetAssertion(req)
	require.NoError(t, err)
	require.NotNil(t, resp)
}

func TestAuthenticator_GetAssertion_WithoutOptions(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() { _ = ctapDev.Close() }()

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	req := &GetAssertionRequest{
		RPID:           "example.com",
		ClientDataHash: CreateClientDataHash([]byte("test")),
		// No options - both UP and UV will be false
	}

	resp, err := auth.GetAssertion(req)
	require.NoError(t, err)
	require.NotNil(t, resp)
}

func TestCreateClientDataHash_EdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		challenge []byte
	}{
		{
			name:      "empty challenge",
			challenge: []byte{},
		},
		{
			name:      "single byte",
			challenge: []byte{0x42},
		},
		{
			name:      "large challenge",
			challenge: make([]byte, 1024),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := CreateClientDataHash(tt.challenge)
			assert.Equal(t, 32, len(hash))
		})
	}
}

func TestDefaultPublicKeyCredentialParameters_Coverage(t *testing.T) {
	params := DefaultPublicKeyCredentialParameters()

	require.NotEmpty(t, params)
	assert.GreaterOrEqual(t, len(params), 3)

	// Verify all parameters have correct type
	for _, param := range params {
		assert.Equal(t, "public-key", param.Type)
		assert.NotEqual(t, 0, param.Alg)
	}
}

func TestAuthenticator_MakeCredential_ResponseParsing(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() { _ = ctapDev.Close() }()

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	req := &MakeCredentialRequest{
		ClientDataHash:   CreateClientDataHash([]byte("test")),
		RP:               RelyingParty{ID: "example.com", Name: "Example"},
		User:             User{ID: []byte("user"), Name: "test", DisplayName: "Test"},
		PubKeyCredParams: DefaultPublicKeyCredentialParameters(),
	}

	resp, err := auth.MakeCredential(req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Check all fields are initialized
	assert.NotEmpty(t, resp.Fmt)
	assert.NotEmpty(t, resp.AuthData)
	assert.NotNil(t, resp.AttStmt)
}

func TestAuthenticator_GetAssertion_ResponseParsing(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() { _ = ctapDev.Close() }()

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	req := &GetAssertionRequest{
		RPID:           "example.com",
		ClientDataHash: CreateClientDataHash([]byte("test")),
	}

	resp, err := auth.GetAssertion(req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Check required fields
	assert.NotEmpty(t, resp.AuthData)
	assert.NotEmpty(t, resp.Signature)
}

func TestAuthenticator_MakeCredential_OptionsHandling(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() { _ = ctapDev.Close() }()

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	tests := []struct {
		name    string
		options AuthenticatorOptions
	}{
		{
			name:    "no options",
			options: AuthenticatorOptions{RK: false, UV: false},
		},
		{
			name:    "RK only",
			options: AuthenticatorOptions{RK: true, UV: false},
		},
		{
			name:    "UV only",
			options: AuthenticatorOptions{RK: false, UV: true},
		},
		{
			name:    "both RK and UV",
			options: AuthenticatorOptions{RK: true, UV: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &MakeCredentialRequest{
				ClientDataHash:   CreateClientDataHash([]byte("test")),
				RP:               RelyingParty{ID: "example.com", Name: "Example"},
				User:             User{ID: []byte("user"), Name: "test", DisplayName: "Test"},
				PubKeyCredParams: DefaultPublicKeyCredentialParameters(),
				Options:          tt.options,
			}

			resp, err := auth.MakeCredential(req)
			require.NoError(t, err)
			require.NotNil(t, resp)
		})
	}
}

func TestAuthenticator_GetAssertion_OptionsHandling(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() { _ = ctapDev.Close() }()

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	tests := []struct {
		name    string
		options AuthenticatorOptions
	}{
		{
			name:    "no options",
			options: AuthenticatorOptions{UP: false, UV: false},
		},
		{
			name:    "UP only",
			options: AuthenticatorOptions{UP: true, UV: false},
		},
		{
			name:    "UV only",
			options: AuthenticatorOptions{UP: false, UV: true},
		},
		{
			name:    "both UP and UV",
			options: AuthenticatorOptions{UP: true, UV: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &GetAssertionRequest{
				RPID:           "example.com",
				ClientDataHash: CreateClientDataHash([]byte("test")),
				Options:        tt.options,
			}

			resp, err := auth.GetAssertion(req)
			require.NoError(t, err)
			require.NotNil(t, resp)
		})
	}
}

func TestAuthenticator_GetInfo_CBORError(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() { _ = ctapDev.Close() }()

	// Create invalid CBOR response
	badResp := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(badResp[0:4], ctapDev.cid)
	badResp[4] = CTAPHID_CBOR
	binary.BigEndian.PutUint16(badResp[5:7], 5)
	badResp[7] = StatusOK
	// Invalid CBOR data
	badResp[8] = 0xFF
	badResp[9] = 0xFF

	mockDev.Reset()
	mockDev.SetResponse(badResp)

	auth := &Authenticator{
		device: ctapDev,
		config: &config,
	}

	info, err := auth.GetInfo()
	assert.Error(t, err)
	assert.Nil(t, info)
	assert.Contains(t, err.Error(), "failed to decode")
}

func TestAuthenticator_MakeCredential_CBORError(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() { _ = ctapDev.Close() }()

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	// Create invalid CBOR response
	badResp := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(badResp[0:4], ctapDev.cid)
	badResp[4] = CTAPHID_CBOR
	binary.BigEndian.PutUint16(badResp[5:7], 5)
	badResp[7] = StatusOK
	// Invalid CBOR data
	badResp[8] = 0xFF
	badResp[9] = 0xFF

	mockDev.Reset()
	mockDev.SetResponse(badResp)

	req := &MakeCredentialRequest{
		ClientDataHash:   CreateClientDataHash([]byte("test")),
		RP:               RelyingParty{ID: "example.com", Name: "Example"},
		User:             User{ID: []byte("user"), Name: "test", DisplayName: "Test"},
		PubKeyCredParams: DefaultPublicKeyCredentialParameters(),
	}

	resp, err := auth.MakeCredential(req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "failed to decode")
}

func TestAuthenticator_GetAssertion_CBORError(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() { _ = ctapDev.Close() }()

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	// Create invalid CBOR response
	badResp := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(badResp[0:4], ctapDev.cid)
	badResp[4] = CTAPHID_CBOR
	binary.BigEndian.PutUint16(badResp[5:7], 5)
	badResp[7] = StatusOK
	// Invalid CBOR data
	badResp[8] = 0xFF
	badResp[9] = 0xFF

	mockDev.Reset()
	mockDev.SetResponse(badResp)

	req := &GetAssertionRequest{
		RPID:           "example.com",
		ClientDataHash: CreateClientDataHash([]byte("test")),
	}

	resp, err := auth.GetAssertion(req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "failed to decode")
}

func TestAuthenticator_GetInfo_PartialFields(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() { _ = ctapDev.Close() }()

	auth := &Authenticator{
		device: ctapDev,
		config: &config,
	}

	// The mock provides a full response, we're just verifying parsing works
	info, err := auth.GetInfo()
	require.NoError(t, err)
	require.NotNil(t, info)

	// Verify various field types are handled
	assert.NotNil(t, info.Versions)
	assert.NotNil(t, info.Extensions)
	assert.NotNil(t, info.Options)
}

func TestAuthenticator_GetAssertion_WithExtensions(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() { _ = ctapDev.Close() }()

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	req := &GetAssertionRequest{
		RPID:           "example.com",
		ClientDataHash: CreateClientDataHash([]byte("test")),
		Extensions: map[string]interface{}{
			"credProtect": 2,
		},
	}

	resp, err := auth.GetAssertion(req)
	require.NoError(t, err)
	require.NotNil(t, resp)
}

func TestAuthenticator_MakeCredential_WithExcludeList(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() { _ = ctapDev.Close() }()

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	req := &MakeCredentialRequest{
		ClientDataHash:   CreateClientDataHash([]byte("test")),
		RP:               RelyingParty{ID: "example.com", Name: "Example"},
		User:             User{ID: []byte("user"), Name: "test", DisplayName: "Test"},
		PubKeyCredParams: DefaultPublicKeyCredentialParameters(),
		ExcludeList: []PublicKeyCredentialDescriptor{
			{Type: "public-key", ID: make([]byte, 16)},
			{Type: "public-key", ID: make([]byte, 32), Transports: []string{"usb"}},
		},
	}

	resp, err := auth.MakeCredential(req)
	require.NoError(t, err)
	require.NotNil(t, resp)
}
