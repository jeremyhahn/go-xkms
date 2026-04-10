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

//go:build integration && linux

package fido2

// chrome_ctap21_test.go tests Chrome CTAP2.1 protocol compliance at the
// HID transport level. This validates the authenticator's wire protocol
// (the upper-most abstraction for the authenticator package per CLAUDE.md)
// rather than CLI commands since Chrome communicates via raw CTAP2 over HID.

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/hkdf"
)

// COSE key labels (used for constructing outgoing maps, not for looking up
// decoded CBOR maps where keys are interface{}).
const (
	coseKeyLabelKty = 1
	coseKeyLabelAlg = 3
	coseKeyLabelCrv = -1
	coseKeyLabelX   = -2
	coseKeyLabelY   = -3
)

// coseMapGet retrieves a value from a CBOR-decoded COSE key map by integer label.
// CBOR decoders produce interface{} keys (int64 for negative, uint64 for positive),
// so we must try both representations.
func coseMapGet(m map[interface{}]interface{}, key int) (interface{}, bool) {
	// Try int64 (CBOR decoders use this for negative integers)
	if v, ok := m[int64(key)]; ok {
		return v, true
	}
	// Try uint64 (CBOR decoders may use this for positive integers)
	if key >= 0 {
		if v, ok := m[uint64(key)]; ok {
			return v, true
		}
	}
	// Try int (Go native)
	if v, ok := m[key]; ok {
		return v, true
	}
	return nil, false
}

// COSE key types and algorithms.
const (
	coseKeyTypeEC2       = 2
	coseAlgECDHESHKDF256 = -25
	coseCurveP256        = 1
)

// ClientPIN request/response keys.
const (
	clientPINKeyPinUvAuthProtocol = 0x01
	clientPINKeySubCommand        = 0x02
	clientPINKeyKeyAgreement      = 0x03
	clientPINKeyPinUvAuthParam    = 0x04
	clientPINKeyNewPinEnc         = 0x05
	clientPINKeyPinHashEnc        = 0x06
	clientPINKeyPermissions       = 0x09
	clientPINKeyPermissionsRPID   = 0x0A
)

// ClientPIN response keys.
const (
	clientPINResponseKeyKeyAgreement   = 0x01
	clientPINResponseKeyPinUvAuthToken = 0x02
)

// PIN permissions.
const (
	pinPermissionMakeCredential = 0x01
	pinPermissionGetAssertion   = 0x02
)

// Protocol constants.
const (
	pinProtocol2       = 2
	aesBlockSize       = 16
	encryptedPINMinLen = 64
	pinHashSize        = 16
)

// hkdfDeriveKey derives a 32-byte key from IKM using HKDF-SHA-256 with the given info string.
func hkdfDeriveKey(ikm []byte, info string) ([]byte, error) {
	salt := make([]byte, 32)
	hkdfReader := hkdf.New(sha256.New, ikm, salt, []byte(info))
	out := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, out); err != nil {
		return nil, err
	}
	return out, nil
}

// TestChromeCTAP21Flow tests the full Chrome CTAP2.1 authentication sequence.
// Chrome requires FIDO_2_1_PRE, pinUvAuthToken option, and permission-based
// PIN tokens for CTAP2.1 authenticators.
func TestChromeCTAP21Flow(t *testing.T) {
	skipIfNoUHID(t)

	cfg := DefaultTestConfig()
	cfg.EnablePIN = true
	// Don't set PIN yet - we'll set it via CTAP2 protocol

	td := NewTestDevice(t, cfg)
	require.NoError(t, td.Start(context.Background()))
	defer td.Stop()

	// =========================================================================
	// Step 1: GetInfo - Verify CTAP2.1 compliance fields
	// =========================================================================
	t.Log("=== Step 1: GetInfo - Verify CTAP2.1 compliance ===")

	resp, err := td.SendCBOR(cmdGetInfo, nil)
	require.NoError(t, err)
	require.Equal(t, byte(statusOK), resp[0], "GetInfo should succeed")

	var info map[int]interface{}
	err = cbor.Unmarshal(resp[1:], &info)
	require.NoError(t, err)

	// Check versions: must include FIDO_2_0, FIDO_2_1_PRE, FIDO_2_1
	versions, ok := info[0x01].([]interface{})
	require.True(t, ok, "versions must be present")
	versionStrings := make([]string, 0, len(versions))
	for _, v := range versions {
		if s, ok := v.(string); ok {
			versionStrings = append(versionStrings, s)
		}
	}
	assert.Contains(t, versionStrings, "FIDO_2_0", "Must include FIDO_2_0")
	assert.Contains(t, versionStrings, "FIDO_2_1_PRE", "Must include FIDO_2_1_PRE for Chrome")
	assert.Contains(t, versionStrings, "FIDO_2_1", "Must include FIDO_2_1")

	// Check options: must include pinUvAuthToken, clientPin, rk, credMgmt
	options, ok := info[0x04].(map[interface{}]interface{})
	require.True(t, ok, "options must be present")
	assert.Equal(t, true, options["pinUvAuthToken"], "pinUvAuthToken must be true")
	_, hasClientPin := options["clientPin"]
	assert.True(t, hasClientPin, "clientPin must be present")
	assert.Equal(t, true, options["rk"], "rk must be true")
	assert.Equal(t, true, options["credMgmt"], "credMgmt must be true")

	// Check pinUvAuthProtocols: V2 must be first
	protocols, ok := info[0x06].([]interface{})
	require.True(t, ok, "pinUvAuthProtocols must be present")
	require.GreaterOrEqual(t, len(protocols), 1)
	firstProto, ok := protocols[0].(uint64)
	require.True(t, ok, "protocol should be uint64")
	assert.Equal(t, uint64(2), firstProto, "V2 must be first (preferred by Chrome)")

	// Check transports, algorithms, maxMsgSize
	_, ok = info[0x09].([]interface{})
	assert.True(t, ok, "transports must be present")
	_, ok = info[0x0A].([]interface{})
	assert.True(t, ok, "algorithms must be present")
	_, ok = info[0x05].(uint64)
	assert.True(t, ok, "maxMsgSize must be present")

	t.Logf("GetInfo CTAP2.1 compliance: versions=%v, pinUvAuthToken=%v",
		versionStrings, options["pinUvAuthToken"])

	// =========================================================================
	// Step 2: ClientPIN GetKeyAgreement - Get authenticator's ECDH public key
	// =========================================================================
	t.Log("=== Step 2: ClientPIN GetKeyAgreement ===")

	keyAgreementReq := map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: pinProtocol2,
		clientPINKeySubCommand:        pinSubCmdGetKeyAgreement,
	}
	reqBytes, err := cbor.Marshal(keyAgreementReq)
	require.NoError(t, err)

	resp, err = td.SendCBOR(cmdClientPIN, reqBytes)
	require.NoError(t, err)
	require.Equal(t, byte(statusOK), resp[0], "GetKeyAgreement should succeed")

	var keyAgreementResp map[int]interface{}
	err = cbor.Unmarshal(resp[1:], &keyAgreementResp)
	require.NoError(t, err)

	// Parse authenticator's COSE public key
	authKeyRaw, ok := keyAgreementResp[clientPINResponseKeyKeyAgreement]
	require.True(t, ok, "Response must contain keyAgreement")

	authKeyMap, ok := authKeyRaw.(map[interface{}]interface{})
	require.True(t, ok, "keyAgreement must be a map")

	authXRaw, ok := coseMapGet(authKeyMap, coseKeyLabelX)
	require.True(t, ok, "keyAgreement must have X coordinate")
	authXBytes, ok := authXRaw.([]byte)
	require.True(t, ok, "X coordinate must be []byte")
	require.Len(t, authXBytes, 32, "X coordinate must be 32 bytes")

	authYRaw, ok := coseMapGet(authKeyMap, coseKeyLabelY)
	require.True(t, ok, "keyAgreement must have Y coordinate")
	authYBytes, ok := authYRaw.([]byte)
	require.True(t, ok, "Y coordinate must be []byte")
	require.Len(t, authYBytes, 32, "Y coordinate must be 32 bytes")

	// =========================================================================
	// Step 3: ClientPIN SetPIN (V2 protocol) - Set initial PIN
	// =========================================================================
	t.Log("=== Step 3: ClientPIN SetPIN (V2 protocol) ===")

	// Generate platform ECDH key pair
	platformPrivKey, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)

	platPubBytes := platformPrivKey.PublicKey().Bytes()
	platXBytes := platPubBytes[1:33]
	platYBytes := platPubBytes[33:65]

	// Build platform COSE key for the request
	platformCOSEMap := map[int]interface{}{
		coseKeyLabelKty: coseKeyTypeEC2,
		coseKeyLabelAlg: coseAlgECDHESHKDF256,
		coseKeyLabelCrv: coseCurveP256,
		coseKeyLabelX:   platXBytes,
		coseKeyLabelY:   platYBytes,
	}

	// Compute ECDH shared secret with authenticator's public key
	authPubBytes := make([]byte, 65)
	authPubBytes[0] = 0x04
	copy(authPubBytes[1:33], authXBytes)
	copy(authPubBytes[33:65], authYBytes)

	authPubKey, err := ecdh.P256().NewPublicKey(authPubBytes)
	require.NoError(t, err)

	rawSecret, err := platformPrivKey.ECDH(authPubKey)
	require.NoError(t, err)

	// V2: Derive separate hmacKey and aesKey via HKDF
	hmacKey, err := hkdfDeriveKey(rawSecret, "CTAP2 HMAC key")
	require.NoError(t, err)
	aesKey, err := hkdfDeriveKey(rawSecret, "CTAP2 AES key")
	require.NoError(t, err)

	// Encrypt new PIN (pad to 64 bytes, encrypt with random IV)
	pin := "123456"
	paddedPIN := make([]byte, encryptedPINMinLen)
	copy(paddedPIN, []byte(pin))

	iv := make([]byte, aesBlockSize)
	_, err = rand.Read(iv)
	require.NoError(t, err)

	block, err := aes.NewCipher(aesKey)
	require.NoError(t, err)
	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(paddedPIN))
	mode.CryptBlocks(ciphertext, paddedPIN)
	encryptedPIN := append(iv, ciphertext...)

	// Full 32-byte HMAC auth param
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(encryptedPIN)
	authParam := mac.Sum(nil)

	setPINReq := map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: pinProtocol2,
		clientPINKeySubCommand:        pinSubCmdSetPIN,
		clientPINKeyKeyAgreement:      platformCOSEMap,
		clientPINKeyPinUvAuthParam:    authParam,
		clientPINKeyNewPinEnc:         encryptedPIN,
	}

	reqBytes, err = cbor.Marshal(setPINReq)
	require.NoError(t, err)

	resp, err = td.SendCBOR(cmdClientPIN, reqBytes)
	require.NoError(t, err)
	require.Equal(t, byte(statusOK), resp[0], "SetPIN V2 should succeed")
	t.Log("PIN set successfully via V2 protocol")

	// =========================================================================
	// Step 4: ClientPIN GetPinUvAuthToken with permissions (V2)
	// =========================================================================
	t.Log("=== Step 4: ClientPIN GetPinUvAuthToken with mc permission ===")

	// Need fresh key agreement since ECDH state resets after SetPIN
	keyAgreementReq = map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: pinProtocol2,
		clientPINKeySubCommand:        pinSubCmdGetKeyAgreement,
	}
	reqBytes, err = cbor.Marshal(keyAgreementReq)
	require.NoError(t, err)

	resp, err = td.SendCBOR(cmdClientPIN, reqBytes)
	require.NoError(t, err)
	require.Equal(t, byte(statusOK), resp[0])

	err = cbor.Unmarshal(resp[1:], &keyAgreementResp)
	require.NoError(t, err)

	authKeyRaw = keyAgreementResp[clientPINResponseKeyKeyAgreement]
	authKeyMap = authKeyRaw.(map[interface{}]interface{})
	authXRaw, _ = coseMapGet(authKeyMap, coseKeyLabelX)
	authXBytes = authXRaw.([]byte)
	authYRaw, _ = coseMapGet(authKeyMap, coseKeyLabelY)
	authYBytes = authYRaw.([]byte)

	// Generate new platform key for this exchange
	platformPrivKey, err = ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)

	platPubBytes = platformPrivKey.PublicKey().Bytes()
	platXBytes = platPubBytes[1:33]
	platYBytes = platPubBytes[33:65]

	platformCOSEMap = map[int]interface{}{
		coseKeyLabelKty: coseKeyTypeEC2,
		coseKeyLabelAlg: coseAlgECDHESHKDF256,
		coseKeyLabelCrv: coseCurveP256,
		coseKeyLabelX:   platXBytes,
		coseKeyLabelY:   platYBytes,
	}

	authPubBytes = make([]byte, 65)
	authPubBytes[0] = 0x04
	copy(authPubBytes[1:33], authXBytes)
	copy(authPubBytes[33:65], authYBytes)

	authPubKey, err = ecdh.P256().NewPublicKey(authPubBytes)
	require.NoError(t, err)

	rawSecret, err = platformPrivKey.ECDH(authPubKey)
	require.NoError(t, err)

	hmacKey, err = hkdfDeriveKey(rawSecret, "CTAP2 HMAC key")
	require.NoError(t, err)
	aesKey, err = hkdfDeriveKey(rawSecret, "CTAP2 AES key")
	require.NoError(t, err)

	// Encrypt PIN hash for authentication
	pinHash := sha256.Sum256([]byte(pin))
	iv = make([]byte, aesBlockSize)
	_, err = rand.Read(iv)
	require.NoError(t, err)

	block, err = aes.NewCipher(aesKey)
	require.NoError(t, err)
	mode = cipher.NewCBCEncrypter(block, iv)
	pinHashEnc := make([]byte, pinHashSize)
	mode.CryptBlocks(pinHashEnc, pinHash[:pinHashSize])
	pinHashEncWithIV := append(iv, pinHashEnc...)

	rpID := "chrome-ctap21-test.example.com"
	permissions := pinPermissionMakeCredential | pinPermissionGetAssertion

	getPinTokenReq := map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: pinProtocol2,
		clientPINKeySubCommand:        pinSubCmdGetPINUvAuthTokenUsingPinWithPermissions,
		clientPINKeyKeyAgreement:      platformCOSEMap,
		clientPINKeyPinHashEnc:        pinHashEncWithIV,
		clientPINKeyPermissions:       permissions,
		clientPINKeyPermissionsRPID:   rpID,
	}

	reqBytes, err = cbor.Marshal(getPinTokenReq)
	require.NoError(t, err)

	resp, err = td.SendCBOR(cmdClientPIN, reqBytes)
	require.NoError(t, err)
	require.Equal(t, byte(statusOK), resp[0],
		"GetPinUvAuthTokenUsingPinWithPermissions should succeed")

	var tokenResp map[int]interface{}
	err = cbor.Unmarshal(resp[1:], &tokenResp)
	require.NoError(t, err)

	encryptedToken, ok := tokenResp[clientPINResponseKeyPinUvAuthToken].([]byte)
	require.True(t, ok, "Response must contain pinUvAuthToken")
	require.Greater(t, len(encryptedToken), aesBlockSize,
		"V2 encrypted token must have IV prefix")

	// Decrypt the PIN token
	tokenIV := encryptedToken[:aesBlockSize]
	tokenCiphertext := encryptedToken[aesBlockSize:]

	block, err = aes.NewCipher(aesKey)
	require.NoError(t, err)
	decMode := cipher.NewCBCDecrypter(block, tokenIV)
	pinToken := make([]byte, len(tokenCiphertext))
	decMode.CryptBlocks(pinToken, tokenCiphertext)
	// Token is 32 bytes (PINTokenSize)
	pinToken = pinToken[:32]

	t.Logf("Got pinUvAuthToken via V2 permissions (token len=%d)", len(pinToken))

	// =========================================================================
	// Step 5: MakeCredential with pinUvAuthToken
	// =========================================================================
	t.Log("=== Step 5: MakeCredential with pinUvAuthToken ===")

	clientDataHash := make([]byte, 32)
	_, err = rand.Read(clientDataHash)
	require.NoError(t, err)

	userID := []byte("chrome-ctap21-user")

	mcReqMap := map[int]interface{}{
		1: clientDataHash,
		2: map[string]interface{}{"id": rpID, "name": "Chrome CTAP2.1 Test"},
		3: map[string]interface{}{
			"id":          userID,
			"name":        "chromeuser@example.com",
			"displayName": "Chrome User",
		},
		4: []interface{}{
			map[string]interface{}{"type": "public-key", "alg": -7}, // ES256
		},
		7: map[string]interface{}{"rk": true},
	}

	// Compute pinUvAuthParam: HMAC-SHA-256(pinToken, clientDataHash)
	mac = hmac.New(sha256.New, pinToken)
	mac.Write(clientDataHash)
	mcPinAuth := mac.Sum(nil) // Full 32 bytes for V2

	// Add PIN auth parameters
	mcReqMap[8] = mcPinAuth    // pinUvAuthParam
	mcReqMap[9] = pinProtocol2 // pinUvAuthProtocol

	mcReqBytes, err := cbor.Marshal(mcReqMap)
	require.NoError(t, err)

	resp, err = td.SendCBOR(cmdMakeCredential, mcReqBytes)
	require.NoError(t, err)
	require.Equal(t, byte(statusOK), resp[0],
		"MakeCredential with pinUvAuthToken should succeed (status=0x%02X)", resp[0])

	// Parse MakeCredential response
	var mcResp map[int]interface{}
	err = cbor.Unmarshal(resp[1:], &mcResp)
	require.NoError(t, err)

	authData, ok := mcResp[2].([]byte)
	require.True(t, ok, "Response must contain authData")
	require.True(t, len(authData) >= 55, "authData too short")

	// Verify UV flag is set (bit 2 = 0x04) since we used PIN
	flags := authData[32]
	assert.True(t, flags&0x04 != 0, "UV flag should be set when PIN auth is used")
	assert.True(t, flags&0x01 != 0, "UP flag should be set")

	// Extract credential ID from authData
	offset := 37 + 16 // rpIdHash(32) + flags(1) + signCount(4) + aaguid(16)
	credIDLen := int(authData[offset])<<8 | int(authData[offset+1])
	offset += 2
	credentialID := make([]byte, credIDLen)
	copy(credentialID, authData[offset:offset+credIDLen])
	offset += credIDLen
	publicKeyCOSE := authData[offset:]

	t.Logf("MakeCredential succeeded: credID=%x (len=%d), UV=%v",
		credentialID[:8], len(credentialID), flags&0x04 != 0)

	// =========================================================================
	// Step 6: GetAssertion with pinUvAuthToken
	// =========================================================================
	t.Log("=== Step 6: GetAssertion with pinUvAuthToken ===")

	gaClientDataHash := make([]byte, 32)
	_, err = rand.Read(gaClientDataHash)
	require.NoError(t, err)

	gaReqMap := map[int]interface{}{
		1: rpID,
		2: gaClientDataHash,
		3: []interface{}{
			map[string]interface{}{
				"type": "public-key",
				"id":   credentialID,
			},
		},
	}

	// Compute pinUvAuthParam for GetAssertion
	mac = hmac.New(sha256.New, pinToken)
	mac.Write(gaClientDataHash)
	gaPinAuth := mac.Sum(nil) // Full 32 bytes for V2

	gaReqMap[6] = gaPinAuth    // pinUvAuthParam
	gaReqMap[7] = pinProtocol2 // pinUvAuthProtocol

	gaReqBytes, err := cbor.Marshal(gaReqMap)
	require.NoError(t, err)

	resp, err = td.SendCBOR(cmdGetAssertion, gaReqBytes)
	require.NoError(t, err)
	require.Equal(t, byte(statusOK), resp[0],
		"GetAssertion with pinUvAuthToken should succeed (status=0x%02X)", resp[0])

	// Parse GetAssertion response
	var gaResp map[int]interface{}
	err = cbor.Unmarshal(resp[1:], &gaResp)
	require.NoError(t, err)

	gaAuthData, ok := gaResp[2].([]byte)
	require.True(t, ok, "Response must contain authData")
	signature, ok := gaResp[3].([]byte)
	require.True(t, ok, "Response must contain signature")

	// Verify UV flag is set in assertion
	gaFlags := gaAuthData[32]
	assert.True(t, gaFlags&0x04 != 0, "UV flag should be set in assertion")
	assert.True(t, gaFlags&0x01 != 0, "UP flag should be set in assertion")

	// Verify signature
	valid, err := VerifySignature(publicKeyCOSE, gaAuthData, gaClientDataHash, signature)
	require.NoError(t, err)
	require.True(t, valid, "Assertion signature must verify")

	t.Log("=== Chrome CTAP2.1 full flow completed successfully ===")
}
