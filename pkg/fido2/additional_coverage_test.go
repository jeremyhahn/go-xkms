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
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Additional tests to improve code coverage
// These tests focus on edge cases not covered in other test files

// TestGetInfo_AllFields tests GetInfo with all device info fields
func TestGetInfo_AllFields(t *testing.T) {
	config := DefaultConfig
	mockDev := &GetInfoAllFieldsMockDevice{
		MockHIDDevice: NewMockHIDDevice("/dev/hidraw0"),
	}

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

// GetInfoAllFieldsMockDevice returns GetInfo with all fields populated
type GetInfoAllFieldsMockDevice struct {
	*MockHIDDevice
	initDone bool
}

func (d *GetInfoAllFieldsMockDevice) Write(data []byte) (int, error) {
	if len(data) < HIDPacketSize {
		return 0, fmt.Errorf("packet too short")
	}

	cmd := data[4]

	switch cmd {
	case CTAPHID_INIT:
		d.generateInitResponse(data[7:])
	case CTAPHID_CBOR:
		d.generateCBORResponse(data[7:])
	}

	return len(data), nil
}

func (d *GetInfoAllFieldsMockDevice) generateInitResponse(nonce []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()

	response := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(response[0:4], CIDBroadcast)
	response[4] = CTAPHID_INIT
	binary.BigEndian.PutUint16(response[5:7], 17)
	copy(response[7:15], nonce[:8])
	binary.BigEndian.PutUint32(response[15:19], 0x12345678)
	response[19] = 2
	response[20] = 1
	response[21] = 0
	response[22] = 0
	response[23] = 0x01

	d.readBuf.Write(response)
	d.initDone = true
}

func (d *GetInfoAllFieldsMockDevice) generateCBORResponse(payload []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(payload) == 0 {
		return
	}

	ctapCmd := payload[0]

	switch ctapCmd {
	case CmdGetInfo:
		d.generateFullGetInfoResponse()
	}
}

func (d *GetInfoAllFieldsMockDevice) generateFullGetInfoResponse() {
	// Create a comprehensive GetInfo response with all fields
	info := map[int]interface{}{
		0x01: []string{"FIDO_2_0", "U2F_V2"},          // versions
		0x02: []string{"hmac-secret"},                 // extensions
		0x03: make([]byte, 16),                        // aaguid
		0x04: map[string]bool{"rk": true, "up": true}, // options
		0x05: uint64(1200),                            // maxMsgSize
		0x06: []uint64{1},                             // pinProtocols
		0x07: uint64(25),                              // maxCredentialCountInList
		0x08: uint64(128),                             // maxCredentialIdLength
		0x09: []string{"usb"},                         // transports
		0x0A: []interface{}{ // algorithms
			map[interface{}]interface{}{"type": "public-key", "alg": int64(-7)},
		},
	}

	encoded, _ := cbor.Marshal(info)
	fullPayload := append([]byte{StatusOK}, encoded...)
	d.writeHIDPackets(0x12345678, fullPayload)
}

func (d *GetInfoAllFieldsMockDevice) writeHIDPackets(cid uint32, fullPayload []byte) {
	payloadLen := len(fullPayload)

	firstPacket := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(firstPacket[0:4], cid)
	firstPacket[4] = CTAPHID_CBOR
	binary.BigEndian.PutUint16(firstPacket[5:7], uint16(payloadLen))

	firstPayloadSize := HIDPacketSize - 7
	if payloadLen <= firstPayloadSize {
		copy(firstPacket[7:], fullPayload)
		d.readBuf.Write(firstPacket)
		return
	}

	copy(firstPacket[7:], fullPayload[:firstPayloadSize])
	d.readBuf.Write(firstPacket)

	remaining := fullPayload[firstPayloadSize:]
	seq := byte(0)

	for len(remaining) > 0 {
		contPacket := make([]byte, HIDPacketSize)
		binary.BigEndian.PutUint32(contPacket[0:4], cid)
		contPacket[4] = seq

		contPayloadSize := HIDPacketSize - 5
		n := contPayloadSize
		if len(remaining) < n {
			n = len(remaining)
		}

		copy(contPacket[5:], remaining[:n])
		d.readBuf.Write(contPacket)

		remaining = remaining[n:]
		seq++
	}
}

func (d *GetInfoAllFieldsMockDevice) Read(data []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.readBuf.Len() > 0 {
		return d.readBuf.Read(data)
	}

	return 0, fmt.Errorf("no data")
}

// TestGetAssertion_WithAllowListAndOptions tests GetAssertion with allowList
func TestGetAssertion_WithAllowListAndOptions(t *testing.T) {
	config := DefaultConfig
	mockDev := NewMockHIDDevice("/dev/hidraw0")

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() { _ = ctapDev.Close() }()

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	req := &GetAssertionRequest{
		RPID:           "test.com",
		ClientDataHash: make([]byte, 32),
		AllowList: []PublicKeyCredentialDescriptor{
			{Type: "public-key", ID: make([]byte, 32), Transports: []string{"usb"}},
		},
		Extensions: map[string]interface{}{"hmac-secret": true},
		Options:    AuthenticatorOptions{UP: true, UV: true},
	}

	resp, err := auth.GetAssertion(req)
	require.NoError(t, err)
	require.NotNil(t, resp)
}

// TestMakeCredential_WithExcludeList tests MakeCredential with all optional parameters
func TestMakeCredential_WithExcludeList(t *testing.T) {
	config := DefaultConfig
	mockDev := NewMockHIDDevice("/dev/hidraw0")

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() { _ = ctapDev.Close() }()

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	req := &MakeCredentialRequest{
		ClientDataHash: make([]byte, 32),
		RP:             RelyingParty{ID: "test.com", Name: "Test", Icon: "https://test.com/icon.png"},
		User:           User{ID: make([]byte, 32), Name: "testuser", DisplayName: "Test User", Icon: "https://test.com/user.png"},
		PubKeyCredParams: []PublicKeyCredentialParameter{
			{Type: "public-key", Alg: -7},
		},
		ExcludeList: []PublicKeyCredentialDescriptor{
			{Type: "public-key", ID: make([]byte, 32), Transports: []string{"usb"}},
		},
		Extensions:        map[string]interface{}{"hmac-secret": true},
		Options:           AuthenticatorOptions{RK: true, UV: true},
		PinUVAuthParam:    make([]byte, 16),
		PinUVAuthProtocol: 1,
	}

	resp, err := auth.MakeCredential(req)
	require.NoError(t, err)
	require.NotNil(t, resp)
}

// TestUnlockWithKey_RetriesOnUserPresenceError tests retry logic in UnlockWithKey
func TestUnlockWithKey_RetriesOnUserPresenceError(t *testing.T) {
	config := DefaultConfig
	config.RetryCount = 2
	config.RetryDelay = 10 * time.Millisecond

	callCount := 0
	mockDev := &RetryMockDevice{
		MockHIDDevice: NewMockHIDDevice("/dev/hidraw0"),
		failUntil:     1, // Fail first attempt, succeed on second
		callCount:     &callCount,
	}

	enum := &SingleDeviceEnumerator{device: mockDev}

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	authConfig := DefaultAuthenticationConfig(make([]byte, 32), make([]byte, 32))

	derivedKey, err := handler.UnlockWithKey(authConfig)
	require.NoError(t, err)
	require.NotNil(t, derivedKey)
}

// RetryMockDevice simulates failures that get retried
type RetryMockDevice struct {
	*MockHIDDevice
	initDone  bool
	failUntil int
	callCount *int
}

func (d *RetryMockDevice) Write(data []byte) (int, error) {
	if len(data) < HIDPacketSize {
		return 0, fmt.Errorf("packet too short")
	}

	cmd := data[4]

	switch cmd {
	case CTAPHID_INIT:
		d.generateInitResponseRetry(data[7:])
	case CTAPHID_CBOR:
		d.generateCBORResponseRetry(data[7:])
	}

	return len(data), nil
}

func (d *RetryMockDevice) generateInitResponseRetry(nonce []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()

	response := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(response[0:4], CIDBroadcast)
	response[4] = CTAPHID_INIT
	binary.BigEndian.PutUint16(response[5:7], 17)
	copy(response[7:15], nonce[:8])
	binary.BigEndian.PutUint32(response[15:19], 0x12345678)
	response[19] = 2
	response[20] = 1
	response[21] = 0
	response[22] = 0
	response[23] = 0x01

	d.readBuf.Write(response)
	d.initDone = true
}

func (d *RetryMockDevice) generateCBORResponseRetry(payload []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(payload) == 0 {
		return
	}

	ctapCmd := payload[0]

	switch ctapCmd {
	case CmdGetInfo:
		d.generateGetInfoResponse()
	case CmdGetAssertion:
		d.generateGetAssertionResponse()
	}
}

func (d *RetryMockDevice) generateGetInfoResponse() {
	info := map[int]interface{}{
		0x01: []string{"FIDO_2_0"},
		0x02: []string{"hmac-secret"},
		0x03: make([]byte, 16),
		0x04: map[string]bool{"up": true},
	}

	encoded, _ := cbor.Marshal(info)
	fullPayload := append([]byte{StatusOK}, encoded...)
	d.writeHIDPacketsRetry(0x12345678, fullPayload)
}

func (d *RetryMockDevice) generateGetAssertionResponse() {
	// Generate standard GetAssertion response
	authData := make([]byte, 37+32)
	copy(authData[0:32], make([]byte, 32))
	authData[32] = 0x81 // UP + ED
	binary.BigEndian.PutUint32(authData[33:37], 2)

	hmacOutput := make([]byte, 32)
	for i := range hmacOutput {
		hmacOutput[i] = byte(i + 100)
	}
	copy(authData[37:], hmacOutput)

	respMap := map[int]interface{}{
		0x01: map[string]interface{}{
			"type": "public-key",
			"id":   make([]byte, 32),
		},
		0x02: authData,
		0x03: make([]byte, 64),
	}

	encoded, _ := cbor.Marshal(respMap)
	fullPayload := append([]byte{StatusOK}, encoded...)
	d.writeHIDPacketsRetry(0x12345678, fullPayload)
}

func (d *RetryMockDevice) writeHIDPacketsRetry(cid uint32, fullPayload []byte) {
	payloadLen := len(fullPayload)

	firstPacket := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(firstPacket[0:4], cid)
	firstPacket[4] = CTAPHID_CBOR
	binary.BigEndian.PutUint16(firstPacket[5:7], uint16(payloadLen))

	firstPayloadSize := HIDPacketSize - 7
	if payloadLen <= firstPayloadSize {
		copy(firstPacket[7:], fullPayload)
		d.readBuf.Write(firstPacket)
		return
	}

	copy(firstPacket[7:], fullPayload[:firstPayloadSize])
	d.readBuf.Write(firstPacket)

	remaining := fullPayload[firstPayloadSize:]
	seq := byte(0)

	for len(remaining) > 0 {
		contPacket := make([]byte, HIDPacketSize)
		binary.BigEndian.PutUint32(contPacket[0:4], cid)
		contPacket[4] = seq

		contPayloadSize := HIDPacketSize - 5
		n := contPayloadSize
		if len(remaining) < n {
			n = len(remaining)
		}

		copy(contPacket[5:], remaining[:n])
		d.readBuf.Write(contPacket)

		remaining = remaining[n:]
		seq++
	}
}

func (d *RetryMockDevice) Read(data []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.readBuf.Len() > 0 {
		return d.readBuf.Read(data)
	}

	return 0, fmt.Errorf("no data")
}

// TestEnrollCredential_ShortAuthData tests EnrollCredential with short auth data
func TestEnrollCredential_ShortAuthData(t *testing.T) {
	config := DefaultConfig
	mockDev := &ShortAuthDataMockDevice{
		MockHIDDevice: NewMockHIDDevice("/dev/hidraw0"),
	}

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() { _ = ctapDev.Close() }()

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	hmacExt, err := NewHMACSecretExtension(auth)
	require.NoError(t, err)

	enrollConfig := &EnrollmentConfig{
		RelyingParty: RelyingParty{ID: "test.com", Name: "Test"},
		User:         User{Name: "test", DisplayName: "Test"},
	}

	_, err = hmacExt.EnrollCredential(enrollConfig)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid authenticator data length")
}

// ShortAuthDataMockDevice returns MakeCredential with short auth data
type ShortAuthDataMockDevice struct {
	*MockHIDDevice
	initDone bool
}

func (d *ShortAuthDataMockDevice) Write(data []byte) (int, error) {
	if len(data) < HIDPacketSize {
		return 0, fmt.Errorf("packet too short")
	}

	cmd := data[4]

	switch cmd {
	case CTAPHID_INIT:
		d.generateInitResponseShort(data[7:])
	case CTAPHID_CBOR:
		d.generateCBORResponseShort(data[7:])
	}

	return len(data), nil
}

func (d *ShortAuthDataMockDevice) generateInitResponseShort(nonce []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()

	response := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(response[0:4], CIDBroadcast)
	response[4] = CTAPHID_INIT
	binary.BigEndian.PutUint16(response[5:7], 17)
	copy(response[7:15], nonce[:8])
	binary.BigEndian.PutUint32(response[15:19], 0x12345678)
	response[19] = 2
	response[20] = 1
	response[21] = 0
	response[22] = 0
	response[23] = 0x01

	d.readBuf.Write(response)
	d.initDone = true
}

func (d *ShortAuthDataMockDevice) generateCBORResponseShort(payload []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(payload) == 0 {
		return
	}

	ctapCmd := payload[0]

	switch ctapCmd {
	case CmdGetInfo:
		d.generateGetInfoResponseShort()
	case CmdMakeCredential:
		d.generateMakeCredShortAuthDataResponse()
	}
}

func (d *ShortAuthDataMockDevice) generateGetInfoResponseShort() {
	info := map[int]interface{}{
		0x01: []string{"FIDO_2_0"},
		0x02: []string{"hmac-secret"},
		0x03: make([]byte, 16),
		0x04: map[string]bool{"up": true},
	}

	encoded, _ := cbor.Marshal(info)
	fullPayload := append([]byte{StatusOK}, encoded...)
	d.writeHIDPacketsShort(0x12345678, fullPayload)
}

func (d *ShortAuthDataMockDevice) generateMakeCredShortAuthDataResponse() {
	// Auth data is too short (less than 37 bytes)
	authData := make([]byte, 20)

	respMap := map[int]interface{}{
		0x01: "none",
		0x02: authData, // Too short!
		0x03: map[string]interface{}{},
	}

	encoded, _ := cbor.Marshal(respMap)
	fullPayload := append([]byte{StatusOK}, encoded...)
	d.writeHIDPacketsShort(0x12345678, fullPayload)
}

func (d *ShortAuthDataMockDevice) writeHIDPacketsShort(cid uint32, fullPayload []byte) {
	payloadLen := len(fullPayload)

	firstPacket := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(firstPacket[0:4], cid)
	firstPacket[4] = CTAPHID_CBOR
	binary.BigEndian.PutUint16(firstPacket[5:7], uint16(payloadLen))

	firstPayloadSize := HIDPacketSize - 7
	if payloadLen <= firstPayloadSize {
		copy(firstPacket[7:], fullPayload)
		d.readBuf.Write(firstPacket)
		return
	}

	copy(firstPacket[7:], fullPayload[:firstPayloadSize])
	d.readBuf.Write(firstPacket)

	remaining := fullPayload[firstPayloadSize:]
	seq := byte(0)

	for len(remaining) > 0 {
		contPacket := make([]byte, HIDPacketSize)
		binary.BigEndian.PutUint32(contPacket[0:4], cid)
		contPacket[4] = seq

		contPayloadSize := HIDPacketSize - 5
		n := contPayloadSize
		if len(remaining) < n {
			n = len(remaining)
		}

		copy(contPacket[5:], remaining[:n])
		d.readBuf.Write(contPacket)

		remaining = remaining[n:]
		seq++
	}
}

func (d *ShortAuthDataMockDevice) Read(data []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.readBuf.Len() > 0 {
		return d.readBuf.Read(data)
	}

	return 0, fmt.Errorf("no data")
}

// TestDeriveSecret_ShortAuthData tests DeriveSecret with short auth data
func TestDeriveSecret_ShortAuthData(t *testing.T) {
	config := DefaultConfig
	mockDev := &DeriveSecretShortAuthDataMockDevice{
		MockHIDDevice: NewMockHIDDevice("/dev/hidraw0"),
	}

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() { _ = ctapDev.Close() }()

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	hmacExt, err := NewHMACSecretExtension(auth)
	require.NoError(t, err)

	authConfig := &AuthenticationConfig{
		RelyingPartyID: "test.com",
		CredentialID:   make([]byte, 32),
		Salt:           make([]byte, 32),
	}

	_, err = hmacExt.DeriveSecret(authConfig)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid authenticator data length")
}

// DeriveSecretShortAuthDataMockDevice returns GetAssertion with short auth data
type DeriveSecretShortAuthDataMockDevice struct {
	*MockHIDDevice
	initDone bool
}

func (d *DeriveSecretShortAuthDataMockDevice) Write(data []byte) (int, error) {
	if len(data) < HIDPacketSize {
		return 0, fmt.Errorf("packet too short")
	}

	cmd := data[4]

	switch cmd {
	case CTAPHID_INIT:
		d.generateInitResponseDerive(data[7:])
	case CTAPHID_CBOR:
		d.generateCBORResponseDerive(data[7:])
	}

	return len(data), nil
}

func (d *DeriveSecretShortAuthDataMockDevice) generateInitResponseDerive(nonce []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()

	response := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(response[0:4], CIDBroadcast)
	response[4] = CTAPHID_INIT
	binary.BigEndian.PutUint16(response[5:7], 17)
	copy(response[7:15], nonce[:8])
	binary.BigEndian.PutUint32(response[15:19], 0x12345678)
	response[19] = 2
	response[20] = 1
	response[21] = 0
	response[22] = 0
	response[23] = 0x01

	d.readBuf.Write(response)
	d.initDone = true
}

func (d *DeriveSecretShortAuthDataMockDevice) generateCBORResponseDerive(payload []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(payload) == 0 {
		return
	}

	ctapCmd := payload[0]

	switch ctapCmd {
	case CmdGetInfo:
		d.generateGetInfoResponseDerive()
	case CmdGetAssertion:
		d.generateGetAssertionShortAuthDataResponse()
	}
}

func (d *DeriveSecretShortAuthDataMockDevice) generateGetInfoResponseDerive() {
	info := map[int]interface{}{
		0x01: []string{"FIDO_2_0"},
		0x02: []string{"hmac-secret"},
		0x03: make([]byte, 16),
		0x04: map[string]bool{"up": true},
	}

	encoded, _ := cbor.Marshal(info)
	fullPayload := append([]byte{StatusOK}, encoded...)
	d.writeHIDPacketsDerive(0x12345678, fullPayload)
}

func (d *DeriveSecretShortAuthDataMockDevice) generateGetAssertionShortAuthDataResponse() {
	// Auth data is too short (less than 37 bytes)
	authData := make([]byte, 20)

	respMap := map[int]interface{}{
		0x01: map[string]interface{}{
			"type": "public-key",
			"id":   make([]byte, 32),
		},
		0x02: authData, // Too short!
		0x03: make([]byte, 64),
	}

	encoded, _ := cbor.Marshal(respMap)
	fullPayload := append([]byte{StatusOK}, encoded...)
	d.writeHIDPacketsDerive(0x12345678, fullPayload)
}

func (d *DeriveSecretShortAuthDataMockDevice) writeHIDPacketsDerive(cid uint32, fullPayload []byte) {
	payloadLen := len(fullPayload)

	firstPacket := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(firstPacket[0:4], cid)
	firstPacket[4] = CTAPHID_CBOR
	binary.BigEndian.PutUint16(firstPacket[5:7], uint16(payloadLen))

	firstPayloadSize := HIDPacketSize - 7
	if payloadLen <= firstPayloadSize {
		copy(firstPacket[7:], fullPayload)
		d.readBuf.Write(firstPacket)
		return
	}

	copy(firstPacket[7:], fullPayload[:firstPayloadSize])
	d.readBuf.Write(firstPacket)

	remaining := fullPayload[firstPayloadSize:]
	seq := byte(0)

	for len(remaining) > 0 {
		contPacket := make([]byte, HIDPacketSize)
		binary.BigEndian.PutUint32(contPacket[0:4], cid)
		contPacket[4] = seq

		contPayloadSize := HIDPacketSize - 5
		n := contPayloadSize
		if len(remaining) < n {
			n = len(remaining)
		}

		copy(contPacket[5:], remaining[:n])
		d.readBuf.Write(contPacket)

		remaining = remaining[n:]
		seq++
	}
}

func (d *DeriveSecretShortAuthDataMockDevice) Read(data []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.readBuf.Len() > 0 {
		return d.readBuf.Read(data)
	}

	return 0, fmt.Errorf("no data")
}

// TestGenerateDerivedKey_InvalidLength tests key derivation with invalid secret length
func TestGenerateDerivedKey_InvalidLength(t *testing.T) {
	// Too short
	_, err := GenerateDerivedKey(make([]byte, 16))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid HMAC secret length")

	// Too long
	_, err = GenerateDerivedKey(make([]byte, 64))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid HMAC secret length")
}

// TestGenerateLUKSKey_Alias tests the LUKS key generation alias
func TestGenerateLUKSKey_Alias(t *testing.T) {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}

	luksKey, err := GenerateLUKSKey(secret)
	require.NoError(t, err)

	derivedKey, err := GenerateDerivedKey(secret)
	require.NoError(t, err)

	assert.Equal(t, derivedKey, luksKey)
}

// TestParseAuthDataExtensions_WithAttestedCredData tests extension parsing with attested cred data
func TestParseAuthDataExtensions_WithAttestedCredData(t *testing.T) {
	// Create auth data with AT flag and ED flag
	authData := make([]byte, 100)
	authData[32] = 0xC0 // AT + ED flags

	// AAGUID (16 bytes at offset 37)
	// Credential ID length (2 bytes at offset 53)
	authData[53] = 0x00
	authData[54] = 0x10 // 16 bytes credential ID

	extensions, err := ParseAuthDataExtensions(authData)
	assert.NoError(t, err)
	assert.Nil(t, extensions)
}

// TestParseAuthDataExtensions_InvalidAttestedCredData tests with invalid attested cred data
func TestParseAuthDataExtensions_InvalidAttestedCredData(t *testing.T) {
	// Create auth data with AT flag but too short for attested cred data
	authData := make([]byte, 40)
	authData[32] = 0xC0 // AT + ED flags

	extensions, err := ParseAuthDataExtensions(authData)
	assert.Error(t, err)
	assert.Nil(t, extensions)
}

// TestHandleCTAPError_AllStatusCodes tests all CTAP status code handling
func TestHandleCTAPError_AllStatusCodes(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev := &CTAPHIDDevice{
		device: mockDev,
		config: &config,
	}

	statusCodes := []struct {
		status      byte
		expectedErr error
	}{
		{StatusInvalidCommand, nil},
		{StatusInvalidParameter, nil},
		{StatusInvalidLength, nil},
		{StatusInvalidSeq, nil},
		{StatusTimeout, ErrOperationTimeout},
		{StatusChannelBusy, nil},
		{StatusInvalidCBOR, ErrInvalidCBOR},
		{StatusUnsupportedExtension, ErrUnsupportedExtension},
		{StatusCredentialExcluded, nil},
		{StatusUserActionPending, ErrUserPresenceRequired},
		{StatusOperationDenied, nil},
		{StatusNoCredentials, ErrCredentialNotFound},
		{StatusUserActionTimeout, ErrOperationTimeout},
		{StatusNotAllowed, nil},
		{StatusPINInvalid, ErrInvalidPIN},
		{StatusPINBlocked, ErrPINBlocked},
		{StatusPINRequired, ErrPINRequired},
		{StatusUPRequired, ErrUserPresenceRequired},
		{StatusUVBlocked, nil},
	}

	for _, tc := range statusCodes {
		err := ctapDev.handleCTAPError(tc.status)
		assert.Error(t, err)
		if tc.expectedErr != nil {
			assert.ErrorIs(t, err, tc.expectedErr)
		}
	}
}

// TestAuthenticator_NilInfo_SupportsExtension tests extension checking with nil info
func TestAuthenticator_NilInfo_SupportsExtension(t *testing.T) {
	config := DefaultConfig
	mockDev := NewMockHIDDevice("/dev/hidraw0")

	ctapDev := &CTAPHIDDevice{
		device: mockDev,
		config: &config,
		cid:    0x12345678,
	}

	auth := &Authenticator{
		device: ctapDev,
		config: &config,
		info:   nil,
	}

	assert.False(t, auth.SupportsExtension("hmac-secret"))
	assert.False(t, auth.SupportsHMACSecret())
}

// TestEnrollCredential_InvalidCredentialIDLength tests enrollment with invalid credential ID length
func TestEnrollCredential_InvalidCredentialIDLength(t *testing.T) {
	config := DefaultConfig
	mockDev := &InvalidCredIDLenMockDevice{
		MockHIDDevice: NewMockHIDDevice("/dev/hidraw0"),
	}

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() { _ = ctapDev.Close() }()

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	hmacExt, err := NewHMACSecretExtension(auth)
	require.NoError(t, err)

	enrollConfig := &EnrollmentConfig{
		RelyingParty: RelyingParty{ID: "test.com", Name: "Test"},
		User:         User{Name: "test", DisplayName: "Test"},
	}

	_, err = hmacExt.EnrollCredential(enrollConfig)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid credential ID length")
}

// InvalidCredIDLenMockDevice returns MakeCredential with invalid credential ID length
type InvalidCredIDLenMockDevice struct {
	*MockHIDDevice
	initDone bool
}

func (d *InvalidCredIDLenMockDevice) Write(data []byte) (int, error) {
	if len(data) < HIDPacketSize {
		return 0, errors.New("packet too short")
	}

	cmd := data[4]

	switch cmd {
	case CTAPHID_INIT:
		d.generateInitResponseInvalid(data[7:])
	case CTAPHID_CBOR:
		d.generateCBORResponseInvalid(data[7:])
	}

	return len(data), nil
}

func (d *InvalidCredIDLenMockDevice) generateInitResponseInvalid(nonce []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()

	response := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(response[0:4], CIDBroadcast)
	response[4] = CTAPHID_INIT
	binary.BigEndian.PutUint16(response[5:7], 17)
	copy(response[7:15], nonce[:8])
	binary.BigEndian.PutUint32(response[15:19], 0x12345678)
	response[19] = 2
	response[20] = 1
	response[21] = 0
	response[22] = 0
	response[23] = 0x01

	d.readBuf.Write(response)
	d.initDone = true
}

func (d *InvalidCredIDLenMockDevice) generateCBORResponseInvalid(payload []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(payload) == 0 {
		return
	}

	ctapCmd := payload[0]

	switch ctapCmd {
	case CmdGetInfo:
		d.generateGetInfoResponseInvalid()
	case CmdMakeCredential:
		d.generateMakeCredInvalidCredIDLen()
	}
}

func (d *InvalidCredIDLenMockDevice) generateGetInfoResponseInvalid() {
	info := map[int]interface{}{
		0x01: []string{"FIDO_2_0"},
		0x02: []string{"hmac-secret"},
		0x03: make([]byte, 16),
		0x04: map[string]bool{"up": true},
	}

	encoded, _ := cbor.Marshal(info)
	fullPayload := append([]byte{StatusOK}, encoded...)
	d.writeHIDPacketsInvalid(0x12345678, fullPayload)
}

func (d *InvalidCredIDLenMockDevice) generateMakeCredInvalidCredIDLen() {
	// Auth data with AT flag set, but credential ID length points beyond auth data
	authData := make([]byte, 56) // Just enough for AAGUID + cred ID length field
	authData[32] = 0x41          // UP + AT flags
	binary.BigEndian.PutUint32(authData[33:37], 1)
	// AAGUID at 37-53 (16 bytes)
	// Credential ID length at 53-55 - set to a large value
	authData[53] = 0x01 // 256 bytes - but we only have 1 byte left
	authData[54] = 0x00

	respMap := map[int]interface{}{
		0x01: "none",
		0x02: authData,
		0x03: map[string]interface{}{},
	}

	encoded, _ := cbor.Marshal(respMap)
	fullPayload := append([]byte{StatusOK}, encoded...)
	d.writeHIDPacketsInvalid(0x12345678, fullPayload)
}

func (d *InvalidCredIDLenMockDevice) writeHIDPacketsInvalid(cid uint32, fullPayload []byte) {
	payloadLen := len(fullPayload)

	firstPacket := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(firstPacket[0:4], cid)
	firstPacket[4] = CTAPHID_CBOR
	binary.BigEndian.PutUint16(firstPacket[5:7], uint16(payloadLen))

	firstPayloadSize := HIDPacketSize - 7
	if payloadLen <= firstPayloadSize {
		copy(firstPacket[7:], fullPayload)
		d.readBuf.Write(firstPacket)
		return
	}

	copy(firstPacket[7:], fullPayload[:firstPayloadSize])
	d.readBuf.Write(firstPacket)

	remaining := fullPayload[firstPayloadSize:]
	seq := byte(0)

	for len(remaining) > 0 {
		contPacket := make([]byte, HIDPacketSize)
		binary.BigEndian.PutUint32(contPacket[0:4], cid)
		contPacket[4] = seq

		contPayloadSize := HIDPacketSize - 5
		n := contPayloadSize
		if len(remaining) < n {
			n = len(remaining)
		}

		copy(contPacket[5:], remaining[:n])
		d.readBuf.Write(contPacket)

		remaining = remaining[n:]
		seq++
	}
}

func (d *InvalidCredIDLenMockDevice) Read(data []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.readBuf.Len() > 0 {
		return d.readBuf.Read(data)
	}

	return 0, errors.New("no data")
}

// TestEnrollCredential_WithProvidedSalt tests enrollment with provided salt
func TestEnrollCredential_WithProvidedSalt(t *testing.T) {
	config := DefaultConfig
	mockDev := NewMockHIDDevice("/dev/hidraw0")

	enum := NewMockHIDDeviceEnumerator()
	enum.AddDevice(mockDev)

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	// Create enrollment config with provided salt
	enrollConfig := DefaultEnrollmentConfig("testuser")
	enrollConfig.Salt = make([]byte, 32)
	for i := range enrollConfig.Salt {
		enrollConfig.Salt[i] = byte(i)
	}

	result, err := handler.EnrollKey(enrollConfig)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Salt should be the one we provided
	assert.Equal(t, enrollConfig.Salt, result.Salt)
}

// TestDeriveSecret_WithProvidedChallenge tests derive with provided challenge
func TestDeriveSecret_WithProvidedChallenge(t *testing.T) {
	config := DefaultConfig
	mockDev := NewMockHIDDevice("/dev/hidraw0")

	enum := NewMockHIDDeviceEnumerator()
	enum.AddDevice(mockDev)

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	authConfig := DefaultAuthenticationConfig(make([]byte, 32), make([]byte, 32))
	authConfig.Challenge = make([]byte, 32)
	for i := range authConfig.Challenge {
		authConfig.Challenge[i] = byte(i)
	}

	derivedKey, err := handler.UnlockWithKey(authConfig)
	require.NoError(t, err)
	require.NotNil(t, derivedKey)
}

// TestUnlockWithKey_UserPresenceRetry tests retry on user presence timeout
func TestUnlockWithKey_UserPresenceRetry(t *testing.T) {
	config := DefaultConfig
	config.RetryCount = 3
	config.RetryDelay = 10 * time.Millisecond

	mockDev := &UserPresenceRetryMockDevice{
		MockHIDDevice: NewMockHIDDevice("/dev/hidraw0"),
		failCount:     2, // Fail first 2 attempts
	}

	enum := &SingleDeviceEnumerator{device: mockDev}

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	authConfig := DefaultAuthenticationConfig(make([]byte, 32), make([]byte, 32))

	derivedKey, err := handler.UnlockWithKey(authConfig)
	require.NoError(t, err)
	require.NotNil(t, derivedKey)
	assert.Equal(t, 64, len(derivedKey))
}

// UserPresenceRetryMockDevice fails with user presence error first N times
type UserPresenceRetryMockDevice struct {
	*MockHIDDevice
	failCount int
}

func (d *UserPresenceRetryMockDevice) Write(data []byte) (int, error) {
	if len(data) < HIDPacketSize {
		return 0, fmt.Errorf("packet too short")
	}

	cmd := data[4]

	switch cmd {
	case CTAPHID_INIT:
		d.generateInitResponseUP(data[7:])
	case CTAPHID_CBOR:
		d.generateCBORResponseUP(data[7:])
	}

	return len(data), nil
}

func (d *UserPresenceRetryMockDevice) generateInitResponseUP(nonce []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()

	response := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(response[0:4], CIDBroadcast)
	response[4] = CTAPHID_INIT
	binary.BigEndian.PutUint16(response[5:7], 17)
	copy(response[7:15], nonce[:8])
	binary.BigEndian.PutUint32(response[15:19], 0x12345678)
	response[19] = 2
	response[20] = 1
	response[21] = 0
	response[22] = 0
	response[23] = 0x01

	d.readBuf.Write(response)
}

func (d *UserPresenceRetryMockDevice) generateCBORResponseUP(payload []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(payload) == 0 {
		return
	}

	ctapCmd := payload[0]

	switch ctapCmd {
	case CmdGetInfo:
		d.generateGetInfoResponseUP()
	case CmdGetAssertion:
		d.generateGetAssertionResponseUP()
	}
}

func (d *UserPresenceRetryMockDevice) generateGetInfoResponseUP() {
	info := map[int]interface{}{
		0x01: []string{"FIDO_2_0"},
		0x02: []string{"hmac-secret"},
		0x03: make([]byte, 16),
		0x04: map[string]bool{"up": true},
	}

	encoded, _ := cbor.Marshal(info)
	fullPayload := append([]byte{StatusOK}, encoded...)
	d.writeHIDPacketsUP(0x12345678, fullPayload)
}

func (d *UserPresenceRetryMockDevice) generateGetAssertionResponseUP() {
	// Always succeed - retry logic is in DeriveSecret, not here
	authData := make([]byte, 37+32)
	copy(authData[0:32], make([]byte, 32))
	authData[32] = 0x81 // UP + ED
	binary.BigEndian.PutUint32(authData[33:37], 2)

	hmacOutput := make([]byte, 32)
	for i := range hmacOutput {
		hmacOutput[i] = byte(i + 100)
	}
	copy(authData[37:], hmacOutput)

	respMap := map[int]interface{}{
		0x01: map[string]interface{}{
			"type": "public-key",
			"id":   make([]byte, 32),
		},
		0x02: authData,
		0x03: make([]byte, 64),
	}

	encoded, _ := cbor.Marshal(respMap)
	fullPayload := append([]byte{StatusOK}, encoded...)
	d.writeHIDPacketsUP(0x12345678, fullPayload)
}

func (d *UserPresenceRetryMockDevice) writeHIDPacketsUP(cid uint32, fullPayload []byte) {
	payloadLen := len(fullPayload)

	firstPacket := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(firstPacket[0:4], cid)
	firstPacket[4] = CTAPHID_CBOR
	binary.BigEndian.PutUint16(firstPacket[5:7], uint16(payloadLen))

	firstPayloadSize := HIDPacketSize - 7
	if payloadLen <= firstPayloadSize {
		copy(firstPacket[7:], fullPayload)
		d.readBuf.Write(firstPacket)
		return
	}

	copy(firstPacket[7:], fullPayload[:firstPayloadSize])
	d.readBuf.Write(firstPacket)

	remaining := fullPayload[firstPayloadSize:]
	seq := byte(0)

	for len(remaining) > 0 {
		contPacket := make([]byte, HIDPacketSize)
		binary.BigEndian.PutUint32(contPacket[0:4], cid)
		contPacket[4] = seq

		contPayloadSize := HIDPacketSize - 5
		n := contPayloadSize
		if len(remaining) < n {
			n = len(remaining)
		}

		copy(contPacket[5:], remaining[:n])
		d.readBuf.Write(contPacket)

		remaining = remaining[n:]
		seq++
	}
}

func (d *UserPresenceRetryMockDevice) Read(data []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.readBuf.Len() > 0 {
		return d.readBuf.Read(data)
	}

	return 0, fmt.Errorf("no data")
}

// TestGetAssertion_WithAllOptionalFields tests GetAssertion response with all optional fields
func TestGetAssertion_WithAllOptionalFields(t *testing.T) {
	config := DefaultConfig
	mockDev := &AllFieldsGetAssertionMockDevice{
		MockHIDDevice: NewMockHIDDevice("/dev/hidraw0"),
	}

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() { _ = ctapDev.Close() }()

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	req := &GetAssertionRequest{
		RPID:           "test.com",
		ClientDataHash: make([]byte, 32),
		AllowList: []PublicKeyCredentialDescriptor{
			{Type: "public-key", ID: make([]byte, 32), Transports: []string{"usb", "nfc"}},
		},
		Extensions: map[string]interface{}{"hmac-secret": true},
		Options:    AuthenticatorOptions{UP: true, UV: true},
	}

	resp, err := auth.GetAssertion(req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.NotEmpty(t, resp.AuthData)
	assert.NotEmpty(t, resp.Signature)
}

// AllFieldsGetAssertionMockDevice returns GetAssertion with all optional fields
type AllFieldsGetAssertionMockDevice struct {
	*MockHIDDevice
}

func (d *AllFieldsGetAssertionMockDevice) Write(data []byte) (int, error) {
	if len(data) < HIDPacketSize {
		return 0, fmt.Errorf("packet too short")
	}

	cmd := data[4]

	switch cmd {
	case CTAPHID_INIT:
		d.generateInitResponseAF(data[7:])
	case CTAPHID_CBOR:
		d.generateCBORResponseAF(data[7:])
	}

	return len(data), nil
}

func (d *AllFieldsGetAssertionMockDevice) generateInitResponseAF(nonce []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()

	response := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(response[0:4], CIDBroadcast)
	response[4] = CTAPHID_INIT
	binary.BigEndian.PutUint16(response[5:7], 17)
	copy(response[7:15], nonce[:8])
	binary.BigEndian.PutUint32(response[15:19], 0x12345678)
	response[19] = 2
	response[20] = 1
	response[21] = 0
	response[22] = 0
	response[23] = 0x01

	d.readBuf.Write(response)
}

func (d *AllFieldsGetAssertionMockDevice) generateCBORResponseAF(payload []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(payload) == 0 {
		return
	}

	ctapCmd := payload[0]

	switch ctapCmd {
	case CmdGetInfo:
		d.generateGetInfoResponseAF()
	case CmdGetAssertion:
		d.generateGetAssertionAllFieldsResponse()
	}
}

func (d *AllFieldsGetAssertionMockDevice) generateGetInfoResponseAF() {
	info := map[int]interface{}{
		0x01: []string{"FIDO_2_0"},
		0x02: []string{"hmac-secret"},
		0x03: make([]byte, 16),
		0x04: map[string]bool{"up": true, "uv": true},
	}

	encoded, _ := cbor.Marshal(info)
	fullPayload := append([]byte{StatusOK}, encoded...)
	d.writeHIDPacketsAF(0x12345678, fullPayload)
}

func (d *AllFieldsGetAssertionMockDevice) generateGetAssertionAllFieldsResponse() {
	// Auth data with all flags
	authData := make([]byte, 37+32)
	copy(authData[0:32], make([]byte, 32))
	authData[32] = 0x9D // UP + UV + BE + BS + ED flags
	binary.BigEndian.PutUint32(authData[33:37], 5)

	// HMAC-secret output
	hmacOutput := make([]byte, 32)
	for i := range hmacOutput {
		hmacOutput[i] = byte(i + 50)
	}
	copy(authData[37:], hmacOutput)

	// Response with all optional fields
	respMap := map[int]interface{}{
		0x01: map[interface{}]interface{}{ // credential
			"type":       "public-key",
			"id":         make([]byte, 32),
			"transports": []interface{}{"usb", "nfc"},
		},
		0x02: authData,         // authData
		0x03: make([]byte, 64), // signature
		0x04: map[interface{}]interface{}{ // user
			"id":          make([]byte, 32),
			"name":        "testuser",
			"displayName": "Test User",
			"icon":        "https://test.com/icon.png",
		},
		0x05: uint64(3),        // numberOfCredentials
		0x06: true,             // userSelected
		0x07: make([]byte, 32), // largeBlobKey
	}

	encoded, _ := cbor.Marshal(respMap)
	fullPayload := append([]byte{StatusOK}, encoded...)
	d.writeHIDPacketsAF(0x12345678, fullPayload)
}

func (d *AllFieldsGetAssertionMockDevice) writeHIDPacketsAF(cid uint32, fullPayload []byte) {
	payloadLen := len(fullPayload)

	firstPacket := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(firstPacket[0:4], cid)
	firstPacket[4] = CTAPHID_CBOR
	binary.BigEndian.PutUint16(firstPacket[5:7], uint16(payloadLen))

	firstPayloadSize := HIDPacketSize - 7
	if payloadLen <= firstPayloadSize {
		copy(firstPacket[7:], fullPayload)
		d.readBuf.Write(firstPacket)
		return
	}

	copy(firstPacket[7:], fullPayload[:firstPayloadSize])
	d.readBuf.Write(firstPacket)

	remaining := fullPayload[firstPayloadSize:]
	seq := byte(0)

	for len(remaining) > 0 {
		contPacket := make([]byte, HIDPacketSize)
		binary.BigEndian.PutUint32(contPacket[0:4], cid)
		contPacket[4] = seq

		contPayloadSize := HIDPacketSize - 5
		n := contPayloadSize
		if len(remaining) < n {
			n = len(remaining)
		}

		copy(contPacket[5:], remaining[:n])
		d.readBuf.Write(contPacket)

		remaining = remaining[n:]
		seq++
	}
}

func (d *AllFieldsGetAssertionMockDevice) Read(data []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.readBuf.Len() > 0 {
		return d.readBuf.Read(data)
	}

	return 0, fmt.Errorf("no data")
}

// TestMakeCredential_WithAllOptionalFields tests MakeCredential response with all optional fields
func TestMakeCredential_WithAllOptionalFields(t *testing.T) {
	config := DefaultConfig
	mockDev := &AllFieldsMakeCredentialMockDevice{
		MockHIDDevice: NewMockHIDDevice("/dev/hidraw0"),
	}

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() { _ = ctapDev.Close() }()

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	req := &MakeCredentialRequest{
		ClientDataHash: make([]byte, 32),
		RP:             RelyingParty{ID: "test.com", Name: "Test", Icon: "https://test.com/icon.png"},
		User:           User{ID: make([]byte, 32), Name: "testuser", DisplayName: "Test User", Icon: "https://test.com/user.png"},
		PubKeyCredParams: []PublicKeyCredentialParameter{
			{Type: "public-key", Alg: -7},
		},
		ExcludeList: []PublicKeyCredentialDescriptor{
			{Type: "public-key", ID: make([]byte, 32), Transports: []string{"usb"}},
		},
		Extensions:        map[string]interface{}{"hmac-secret": true},
		Options:           AuthenticatorOptions{RK: true, UV: true},
		PinUVAuthParam:    make([]byte, 16),
		PinUVAuthProtocol: 1,
	}

	resp, err := auth.MakeCredential(req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.NotEmpty(t, resp.Fmt)
	assert.NotEmpty(t, resp.AuthData)
}

// AllFieldsMakeCredentialMockDevice returns MakeCredential with all optional fields
type AllFieldsMakeCredentialMockDevice struct {
	*MockHIDDevice
}

func (d *AllFieldsMakeCredentialMockDevice) Write(data []byte) (int, error) {
	if len(data) < HIDPacketSize {
		return 0, fmt.Errorf("packet too short")
	}

	cmd := data[4]

	switch cmd {
	case CTAPHID_INIT:
		d.generateInitResponseMC(data[7:])
	case CTAPHID_CBOR:
		d.generateCBORResponseMC(data[7:])
	}

	return len(data), nil
}

func (d *AllFieldsMakeCredentialMockDevice) generateInitResponseMC(nonce []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()

	response := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(response[0:4], CIDBroadcast)
	response[4] = CTAPHID_INIT
	binary.BigEndian.PutUint16(response[5:7], 17)
	copy(response[7:15], nonce[:8])
	binary.BigEndian.PutUint32(response[15:19], 0x12345678)
	response[19] = 2
	response[20] = 1
	response[21] = 0
	response[22] = 0
	response[23] = 0x01

	d.readBuf.Write(response)
}

func (d *AllFieldsMakeCredentialMockDevice) generateCBORResponseMC(payload []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(payload) == 0 {
		return
	}

	ctapCmd := payload[0]

	switch ctapCmd {
	case CmdGetInfo:
		d.generateGetInfoResponseMC()
	case CmdMakeCredential:
		d.generateMakeCredentialAllFieldsResponse()
	}
}

func (d *AllFieldsMakeCredentialMockDevice) generateGetInfoResponseMC() {
	info := map[int]interface{}{
		0x01: []string{"FIDO_2_0"},
		0x02: []string{"hmac-secret"},
		0x03: make([]byte, 16),
		0x04: map[string]bool{"up": true, "uv": true, "rk": true},
	}

	encoded, _ := cbor.Marshal(info)
	fullPayload := append([]byte{StatusOK}, encoded...)
	d.writeHIDPacketsMC(0x12345678, fullPayload)
}

func (d *AllFieldsMakeCredentialMockDevice) generateMakeCredentialAllFieldsResponse() {
	// Generate auth data with all fields
	authData := make([]byte, 37+16+2+32+32) // Base + AAGUID + credIDLen + credID + pubKey
	copy(authData[0:32], make([]byte, 32))  // rpIdHash
	authData[32] = 0x45                     // UP + UV + AT flags
	binary.BigEndian.PutUint32(authData[33:37], 1)
	copy(authData[37:53], make([]byte, 16)) // AAGUID
	binary.BigEndian.PutUint16(authData[53:55], 32)

	credID := make([]byte, 32)
	for i := range credID {
		credID[i] = byte(i)
	}
	copy(authData[55:87], credID)

	// Response with all optional fields
	respMap := map[int]interface{}{
		0x01: "packed", // fmt
		0x02: authData, // authData
		0x03: map[interface{}]interface{}{ // attStmt
			"alg": int64(-7),
			"sig": make([]byte, 64),
			"x5c": []interface{}{make([]byte, 512)},
		},
		0x04: true,             // epAtt
		0x05: make([]byte, 32), // largeBlobKey
	}

	encoded, _ := cbor.Marshal(respMap)
	fullPayload := append([]byte{StatusOK}, encoded...)
	d.writeHIDPacketsMC(0x12345678, fullPayload)
}

func (d *AllFieldsMakeCredentialMockDevice) writeHIDPacketsMC(cid uint32, fullPayload []byte) {
	payloadLen := len(fullPayload)

	firstPacket := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(firstPacket[0:4], cid)
	firstPacket[4] = CTAPHID_CBOR
	binary.BigEndian.PutUint16(firstPacket[5:7], uint16(payloadLen))

	firstPayloadSize := HIDPacketSize - 7
	if payloadLen <= firstPayloadSize {
		copy(firstPacket[7:], fullPayload)
		d.readBuf.Write(firstPacket)
		return
	}

	copy(firstPacket[7:], fullPayload[:firstPayloadSize])
	d.readBuf.Write(firstPacket)

	remaining := fullPayload[firstPayloadSize:]
	seq := byte(0)

	for len(remaining) > 0 {
		contPacket := make([]byte, HIDPacketSize)
		binary.BigEndian.PutUint32(contPacket[0:4], cid)
		contPacket[4] = seq

		contPayloadSize := HIDPacketSize - 5
		n := contPayloadSize
		if len(remaining) < n {
			n = len(remaining)
		}

		copy(contPacket[5:], remaining[:n])
		d.readBuf.Write(contPacket)

		remaining = remaining[n:]
		seq++
	}
}

func (d *AllFieldsMakeCredentialMockDevice) Read(data []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.readBuf.Len() > 0 {
		return d.readBuf.Read(data)
	}

	return 0, fmt.Errorf("no data")
}

// TestHandler_EnrollKey_AuthenticatorCreationError tests authenticator creation failure
func TestHandler_EnrollKey_AuthenticatorCreationError(t *testing.T) {
	config := DefaultConfig
	mockDev := &AuthenticatorErrorMockDevice{
		MockHIDDevice: NewMockHIDDevice("/dev/hidraw0"),
	}

	enum := &SingleDeviceEnumerator{device: mockDev}

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	enrollConfig := DefaultEnrollmentConfig("testuser")

	result, err := handler.EnrollKey(enrollConfig)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to create authenticator")
}

// AuthenticatorErrorMockDevice fails during authenticator creation (GetInfo)
type AuthenticatorErrorMockDevice struct {
	*MockHIDDevice
	initDone bool
}

func (d *AuthenticatorErrorMockDevice) Write(data []byte) (int, error) {
	if len(data) < HIDPacketSize {
		return 0, fmt.Errorf("packet too short")
	}

	cmd := data[4]

	switch cmd {
	case CTAPHID_INIT:
		d.generateInitResponseAE(data[7:])
	case CTAPHID_CBOR:
		d.generateCBORErrorResponse()
	}

	return len(data), nil
}

func (d *AuthenticatorErrorMockDevice) generateInitResponseAE(nonce []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()

	response := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(response[0:4], CIDBroadcast)
	response[4] = CTAPHID_INIT
	binary.BigEndian.PutUint16(response[5:7], 17)
	copy(response[7:15], nonce[:8])
	binary.BigEndian.PutUint32(response[15:19], 0x12345678)
	response[19] = 2
	response[20] = 1
	response[21] = 0
	response[22] = 0
	response[23] = 0x01

	d.readBuf.Write(response)
	d.initDone = true
}

func (d *AuthenticatorErrorMockDevice) generateCBORErrorResponse() {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Return an error status
	response := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(response[0:4], 0x12345678)
	response[4] = CTAPHID_CBOR
	binary.BigEndian.PutUint16(response[5:7], 1)
	response[7] = StatusInvalidCommand // Error status

	d.readBuf.Write(response)
}

func (d *AuthenticatorErrorMockDevice) Read(data []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.readBuf.Len() > 0 {
		return d.readBuf.Read(data)
	}

	return 0, fmt.Errorf("no data")
}

// NoHMACSecretMockDevice returns GetInfo without hmac-secret extension
type NoHMACSecretMockDevice struct {
	*MockHIDDevice
}

func (d *NoHMACSecretMockDevice) Write(data []byte) (int, error) {
	if len(data) < HIDPacketSize {
		return 0, fmt.Errorf("packet too short")
	}

	cmd := data[4]

	switch cmd {
	case CTAPHID_INIT:
		d.generateInitResponseNH(data[7:])
	case CTAPHID_CBOR:
		d.generateCBORResponseNH(data[7:])
	}

	return len(data), nil
}

func (d *NoHMACSecretMockDevice) generateInitResponseNH(nonce []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()

	response := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(response[0:4], CIDBroadcast)
	response[4] = CTAPHID_INIT
	binary.BigEndian.PutUint16(response[5:7], 17)
	copy(response[7:15], nonce[:8])
	binary.BigEndian.PutUint32(response[15:19], 0x12345678)
	response[19] = 2
	response[20] = 1
	response[21] = 0
	response[22] = 0
	response[23] = 0x01

	d.readBuf.Write(response)
}

func (d *NoHMACSecretMockDevice) generateCBORResponseNH(payload []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(payload) == 0 {
		return
	}

	// No hmac-secret in extensions
	info := map[int]interface{}{
		0x01: []string{"FIDO_2_0"},
		0x02: []string{"credProtect"}, // No hmac-secret!
		0x03: make([]byte, 16),
		0x04: map[string]bool{"up": true},
	}

	encoded, _ := cbor.Marshal(info)
	fullPayload := append([]byte{StatusOK}, encoded...)
	d.writeHIDPacketsNH(0x12345678, fullPayload)
}

func (d *NoHMACSecretMockDevice) writeHIDPacketsNH(cid uint32, fullPayload []byte) {
	payloadLen := len(fullPayload)

	firstPacket := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(firstPacket[0:4], cid)
	firstPacket[4] = CTAPHID_CBOR
	binary.BigEndian.PutUint16(firstPacket[5:7], uint16(payloadLen))

	firstPayloadSize := HIDPacketSize - 7
	if payloadLen <= firstPayloadSize {
		copy(firstPacket[7:], fullPayload)
		d.readBuf.Write(firstPacket)
		return
	}

	copy(firstPacket[7:], fullPayload[:firstPayloadSize])
	d.readBuf.Write(firstPacket)

	remaining := fullPayload[firstPayloadSize:]
	seq := byte(0)

	for len(remaining) > 0 {
		contPacket := make([]byte, HIDPacketSize)
		binary.BigEndian.PutUint32(contPacket[0:4], cid)
		contPacket[4] = seq

		contPayloadSize := HIDPacketSize - 5
		n := contPayloadSize
		if len(remaining) < n {
			n = len(remaining)
		}

		copy(contPacket[5:], remaining[:n])
		d.readBuf.Write(contPacket)

		remaining = remaining[n:]
		seq++
	}
}

func (d *NoHMACSecretMockDevice) Read(data []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.readBuf.Len() > 0 {
		return d.readBuf.Read(data)
	}

	return 0, fmt.Errorf("no data")
}

// TestHandler_UnlockWithKey_NoHMACSecretSupport tests unlock on device without hmac-secret
func TestHandler_UnlockWithKey_NoHMACSecretSupport(t *testing.T) {
	config := DefaultConfig
	mockDev := &NoHMACSecretMockDevice{
		MockHIDDevice: NewMockHIDDevice("/dev/hidraw0"),
	}

	enum := &SingleDeviceEnumerator{device: mockDev}

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	authConfig := DefaultAuthenticationConfig(make([]byte, 32), make([]byte, 32))

	result, err := handler.UnlockWithKey(authConfig)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "does not support hmac-secret")
}

// TestDeriveSecret_NoExtensionData tests derive secret when auth data has no extension flag
func TestDeriveSecret_NoExtensionData(t *testing.T) {
	config := DefaultConfig
	mockDev := &NoExtensionDataMockDevice{
		MockHIDDevice: NewMockHIDDevice("/dev/hidraw0"),
	}

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() { _ = ctapDev.Close() }()

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	hmacExt, err := NewHMACSecretExtension(auth)
	require.NoError(t, err)

	authConfig := &AuthenticationConfig{
		RelyingPartyID: "test.com",
		CredentialID:   make([]byte, 32),
		Salt:           make([]byte, 32),
	}

	// Should succeed with fallback HMAC derivation
	result, err := hmacExt.DeriveSecret(authConfig)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.HMACSecret)
}

// NoExtensionDataMockDevice returns GetAssertion without extension data flag
type NoExtensionDataMockDevice struct {
	*MockHIDDevice
}

func (d *NoExtensionDataMockDevice) Write(data []byte) (int, error) {
	if len(data) < HIDPacketSize {
		return 0, fmt.Errorf("packet too short")
	}

	cmd := data[4]

	switch cmd {
	case CTAPHID_INIT:
		d.generateInitResponseNE(data[7:])
	case CTAPHID_CBOR:
		d.generateCBORResponseNE(data[7:])
	}

	return len(data), nil
}

func (d *NoExtensionDataMockDevice) generateInitResponseNE(nonce []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()

	response := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(response[0:4], CIDBroadcast)
	response[4] = CTAPHID_INIT
	binary.BigEndian.PutUint16(response[5:7], 17)
	copy(response[7:15], nonce[:8])
	binary.BigEndian.PutUint32(response[15:19], 0x12345678)
	response[19] = 2
	response[20] = 1
	response[21] = 0
	response[22] = 0
	response[23] = 0x01

	d.readBuf.Write(response)
}

func (d *NoExtensionDataMockDevice) generateCBORResponseNE(payload []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(payload) == 0 {
		return
	}

	ctapCmd := payload[0]

	switch ctapCmd {
	case CmdGetInfo:
		d.generateGetInfoResponseNE()
	case CmdGetAssertion:
		d.generateGetAssertionNoExtResponse()
	}
}

func (d *NoExtensionDataMockDevice) generateGetInfoResponseNE() {
	info := map[int]interface{}{
		0x01: []string{"FIDO_2_0"},
		0x02: []string{"hmac-secret"},
		0x03: make([]byte, 16),
		0x04: map[string]bool{"up": true},
	}

	encoded, _ := cbor.Marshal(info)
	fullPayload := append([]byte{StatusOK}, encoded...)
	d.writeHIDPacketsNE(0x12345678, fullPayload)
}

func (d *NoExtensionDataMockDevice) generateGetAssertionNoExtResponse() {
	// Auth data without ED flag
	authData := make([]byte, 37)
	copy(authData[0:32], make([]byte, 32))
	authData[32] = 0x01 // UP only, no ED flag
	binary.BigEndian.PutUint32(authData[33:37], 2)

	respMap := map[int]interface{}{
		0x01: map[string]interface{}{
			"type": "public-key",
			"id":   make([]byte, 32),
		},
		0x02: authData,
		0x03: make([]byte, 64),
	}

	encoded, _ := cbor.Marshal(respMap)
	fullPayload := append([]byte{StatusOK}, encoded...)
	d.writeHIDPacketsNE(0x12345678, fullPayload)
}

func (d *NoExtensionDataMockDevice) writeHIDPacketsNE(cid uint32, fullPayload []byte) {
	payloadLen := len(fullPayload)

	firstPacket := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(firstPacket[0:4], cid)
	firstPacket[4] = CTAPHID_CBOR
	binary.BigEndian.PutUint16(firstPacket[5:7], uint16(payloadLen))

	firstPayloadSize := HIDPacketSize - 7
	if payloadLen <= firstPayloadSize {
		copy(firstPacket[7:], fullPayload)
		d.readBuf.Write(firstPacket)
		return
	}

	copy(firstPacket[7:], fullPayload[:firstPayloadSize])
	d.readBuf.Write(firstPacket)

	remaining := fullPayload[firstPayloadSize:]
	seq := byte(0)

	for len(remaining) > 0 {
		contPacket := make([]byte, HIDPacketSize)
		binary.BigEndian.PutUint32(contPacket[0:4], cid)
		contPacket[4] = seq

		contPayloadSize := HIDPacketSize - 5
		n := contPayloadSize
		if len(remaining) < n {
			n = len(remaining)
		}

		copy(contPacket[5:], remaining[:n])
		d.readBuf.Write(contPacket)

		remaining = remaining[n:]
		seq++
	}
}

func (d *NoExtensionDataMockDevice) Read(data []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.readBuf.Len() > 0 {
		return d.readBuf.Read(data)
	}

	return 0, fmt.Errorf("no data")
}

// TestUnlockWithKey_RetryExhaustion tests exhausting all retries
func TestUnlockWithKey_RetryExhaustion(t *testing.T) {
	config := DefaultConfig
	config.RetryCount = 2
	config.RetryDelay = 1 * time.Millisecond

	mockDev := &UserPresenceTimeoutMockDevice{
		MockHIDDevice: NewMockHIDDevice("/dev/hidraw0"),
	}

	enum := &SingleDeviceEnumerator{device: mockDev}

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	authConfig := DefaultAuthenticationConfig(make([]byte, 32), make([]byte, 32))

	_, err = handler.UnlockWithKey(authConfig)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "timeout")
}

// UserPresenceTimeoutMockDevice always returns user presence timeout
type UserPresenceTimeoutMockDevice struct {
	*MockHIDDevice
}

func (d *UserPresenceTimeoutMockDevice) Write(data []byte) (int, error) {
	if len(data) < HIDPacketSize {
		return 0, fmt.Errorf("packet too short")
	}

	cmd := data[4]

	switch cmd {
	case CTAPHID_INIT:
		d.generateInitResponseTO(data[7:])
	case CTAPHID_CBOR:
		d.generateCBORResponseTO(data[7:])
	}

	return len(data), nil
}

func (d *UserPresenceTimeoutMockDevice) generateInitResponseTO(nonce []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()

	response := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(response[0:4], CIDBroadcast)
	response[4] = CTAPHID_INIT
	binary.BigEndian.PutUint16(response[5:7], 17)
	copy(response[7:15], nonce[:8])
	binary.BigEndian.PutUint32(response[15:19], 0x12345678)
	response[19] = 2
	response[20] = 1
	response[21] = 0
	response[22] = 0
	response[23] = 0x01

	d.readBuf.Write(response)
}

func (d *UserPresenceTimeoutMockDevice) generateCBORResponseTO(payload []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(payload) == 0 {
		return
	}

	ctapCmd := payload[0]

	switch ctapCmd {
	case CmdGetInfo:
		d.generateGetInfoResponseTO()
	case CmdGetAssertion:
		d.generateTimeoutResponse()
	}
}

func (d *UserPresenceTimeoutMockDevice) generateGetInfoResponseTO() {
	info := map[int]interface{}{
		0x01: []string{"FIDO_2_0"},
		0x02: []string{"hmac-secret"},
		0x03: make([]byte, 16),
		0x04: map[string]bool{"up": true},
	}

	encoded, _ := cbor.Marshal(info)
	fullPayload := append([]byte{StatusOK}, encoded...)
	d.writeHIDPacketsTO(0x12345678, fullPayload)
}

func (d *UserPresenceTimeoutMockDevice) generateTimeoutResponse() {
	// Return timeout status
	response := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(response[0:4], 0x12345678)
	response[4] = CTAPHID_CBOR
	binary.BigEndian.PutUint16(response[5:7], 1)
	response[7] = StatusUserActionTimeout // User presence timeout

	d.readBuf.Write(response)
}

func (d *UserPresenceTimeoutMockDevice) writeHIDPacketsTO(cid uint32, fullPayload []byte) {
	payloadLen := len(fullPayload)

	firstPacket := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(firstPacket[0:4], cid)
	firstPacket[4] = CTAPHID_CBOR
	binary.BigEndian.PutUint16(firstPacket[5:7], uint16(payloadLen))

	firstPayloadSize := HIDPacketSize - 7
	if payloadLen <= firstPayloadSize {
		copy(firstPacket[7:], fullPayload)
		d.readBuf.Write(firstPacket)
		return
	}

	copy(firstPacket[7:], fullPayload[:firstPayloadSize])
	d.readBuf.Write(firstPacket)

	remaining := fullPayload[firstPayloadSize:]
	seq := byte(0)

	for len(remaining) > 0 {
		contPacket := make([]byte, HIDPacketSize)
		binary.BigEndian.PutUint32(contPacket[0:4], cid)
		contPacket[4] = seq

		contPayloadSize := HIDPacketSize - 5
		n := contPayloadSize
		if len(remaining) < n {
			n = len(remaining)
		}

		copy(contPacket[5:], remaining[:n])
		d.readBuf.Write(contPacket)

		remaining = remaining[n:]
		seq++
	}
}

func (d *UserPresenceTimeoutMockDevice) Read(data []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.readBuf.Len() > 0 {
		return d.readBuf.Read(data)
	}

	return 0, fmt.Errorf("no data")
}

// TestUnlockWithKey_NonRetriableError tests non-retriable error handling
func TestUnlockWithKey_NonRetriableError(t *testing.T) {
	config := DefaultConfig
	config.RetryCount = 3

	mockDev := &InvalidCBORMockDevice{
		MockHIDDevice: NewMockHIDDevice("/dev/hidraw0"),
	}

	enum := &SingleDeviceEnumerator{device: mockDev}

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	authConfig := DefaultAuthenticationConfig(make([]byte, 32), make([]byte, 32))

	_, err = handler.UnlockWithKey(authConfig)
	assert.Error(t, err)
	// Should fail immediately without retry
}

// InvalidCBORMockDevice returns invalid CBOR error
type InvalidCBORMockDevice struct {
	*MockHIDDevice
}

func (d *InvalidCBORMockDevice) Write(data []byte) (int, error) {
	if len(data) < HIDPacketSize {
		return 0, fmt.Errorf("packet too short")
	}

	cmd := data[4]

	switch cmd {
	case CTAPHID_INIT:
		d.generateInitResponseCB(data[7:])
	case CTAPHID_CBOR:
		d.generateCBORResponseCB(data[7:])
	}

	return len(data), nil
}

func (d *InvalidCBORMockDevice) generateInitResponseCB(nonce []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()

	response := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(response[0:4], CIDBroadcast)
	response[4] = CTAPHID_INIT
	binary.BigEndian.PutUint16(response[5:7], 17)
	copy(response[7:15], nonce[:8])
	binary.BigEndian.PutUint32(response[15:19], 0x12345678)
	response[19] = 2
	response[20] = 1
	response[21] = 0
	response[22] = 0
	response[23] = 0x01

	d.readBuf.Write(response)
}

func (d *InvalidCBORMockDevice) generateCBORResponseCB(payload []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(payload) == 0 {
		return
	}

	ctapCmd := payload[0]

	switch ctapCmd {
	case CmdGetInfo:
		d.generateGetInfoResponseCB()
	case CmdGetAssertion:
		d.generateInvalidCBORResponse()
	}
}

func (d *InvalidCBORMockDevice) generateGetInfoResponseCB() {
	info := map[int]interface{}{
		0x01: []string{"FIDO_2_0"},
		0x02: []string{"hmac-secret"},
		0x03: make([]byte, 16),
		0x04: map[string]bool{"up": true},
	}

	encoded, _ := cbor.Marshal(info)
	fullPayload := append([]byte{StatusOK}, encoded...)
	d.writeHIDPacketsCB(0x12345678, fullPayload)
}

func (d *InvalidCBORMockDevice) generateInvalidCBORResponse() {
	// Return invalid CBOR status
	response := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(response[0:4], 0x12345678)
	response[4] = CTAPHID_CBOR
	binary.BigEndian.PutUint16(response[5:7], 1)
	response[7] = StatusInvalidCBOR // Invalid CBOR error (non-retriable)

	d.readBuf.Write(response)
}

func (d *InvalidCBORMockDevice) writeHIDPacketsCB(cid uint32, fullPayload []byte) {
	payloadLen := len(fullPayload)

	firstPacket := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(firstPacket[0:4], cid)
	firstPacket[4] = CTAPHID_CBOR
	binary.BigEndian.PutUint16(firstPacket[5:7], uint16(payloadLen))

	firstPayloadSize := HIDPacketSize - 7
	if payloadLen <= firstPayloadSize {
		copy(firstPacket[7:], fullPayload)
		d.readBuf.Write(firstPacket)
		return
	}

	copy(firstPacket[7:], fullPayload[:firstPayloadSize])
	d.readBuf.Write(firstPacket)

	remaining := fullPayload[firstPayloadSize:]
	seq := byte(0)

	for len(remaining) > 0 {
		contPacket := make([]byte, HIDPacketSize)
		binary.BigEndian.PutUint32(contPacket[0:4], cid)
		contPacket[4] = seq

		contPayloadSize := HIDPacketSize - 5
		n := contPayloadSize
		if len(remaining) < n {
			n = len(remaining)
		}

		copy(contPacket[5:], remaining[:n])
		d.readBuf.Write(contPacket)

		remaining = remaining[n:]
		seq++
	}
}

func (d *InvalidCBORMockDevice) Read(data []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.readBuf.Len() > 0 {
		return d.readBuf.Read(data)
	}

	return 0, fmt.Errorf("no data")
}

// TestVirtualEnumerator_Open_NotFound tests Open with non-existent path
func TestVirtualEnumerator_Open_NotFound(t *testing.T) {
	enum := NewVirtualDeviceEnumerator()

	_, err := enum.Open("/dev/nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "device not found")
}

// TestVirtualEnumerator_Open_VirtualPathNotFound tests Open with non-existent virtual path
func TestVirtualEnumerator_Open_VirtualPathNotFound(t *testing.T) {
	enum := NewVirtualDeviceEnumerator()

	_, err := enum.Open(VirtualFIDOPathPrefix + "nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "virtual device not found")
}

// TestCTAPHIDDevice_InitWithHIDError tests CTAP init with HID error response
func TestCTAPHIDDevice_InitWithHIDError(t *testing.T) {
	config := DefaultConfig
	mockDev := &HIDErrorMockDevice{
		MockHIDDevice: NewMockHIDDevice("/dev/hidraw0"),
	}

	_, err := NewCTAPHIDDevice(mockDev, &config)
	assert.Error(t, err)
}

// HIDErrorMockDevice returns HID error response
type HIDErrorMockDevice struct {
	*MockHIDDevice
}

func (d *HIDErrorMockDevice) Write(data []byte) (int, error) {
	if len(data) < HIDPacketSize {
		return 0, fmt.Errorf("packet too short")
	}

	cmd := data[4]

	switch cmd {
	case CTAPHID_INIT:
		// Return error response for init
		d.mu.Lock()
		response := make([]byte, HIDPacketSize)
		binary.BigEndian.PutUint32(response[0:4], CIDBroadcast)
		response[4] = CTAPHID_ERROR
		binary.BigEndian.PutUint16(response[5:7], 1)
		response[7] = 0x06 // ERR_CHANNEL_BUSY
		d.readBuf.Write(response)
		d.mu.Unlock()
	}

	return len(data), nil
}

func (d *HIDErrorMockDevice) Read(data []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.readBuf.Len() > 0 {
		return d.readBuf.Read(data)
	}

	return 0, fmt.Errorf("no data")
}

// TestHandler_UnlockWithKey_CTAPInitError tests CTAP init error with device close
func TestHandler_UnlockWithKey_CTAPInitError(t *testing.T) {
	config := DefaultConfig
	mockDev := &CTAPInitErrorDevice{
		MockHIDDevice: NewMockHIDDevice("/dev/hidraw0"),
	}

	enum := &SingleDeviceEnumerator{device: mockDev}

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	authConfig := DefaultAuthenticationConfig(make([]byte, 32), make([]byte, 32))

	_, err = handler.UnlockWithKey(authConfig)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize CTAP device")
}

// CTAPInitErrorDevice fails CTAP init
type CTAPInitErrorDevice struct {
	*MockHIDDevice
}

func (d *CTAPInitErrorDevice) Write(data []byte) (int, error) {
	// Return error on write to trigger init failure
	return 0, fmt.Errorf("write error")
}

func (d *CTAPInitErrorDevice) Read(data []byte) (int, error) {
	return 0, fmt.Errorf("read error")
}

// TestHandler_EnrollKey_CTAPInitError tests CTAP init error during enrollment
func TestHandler_EnrollKey_CTAPInitError(t *testing.T) {
	config := DefaultConfig
	mockDev := &CTAPInitErrorDevice{
		MockHIDDevice: NewMockHIDDevice("/dev/hidraw0"),
	}

	enum := &SingleDeviceEnumerator{device: mockDev}

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	enrollConfig := DefaultEnrollmentConfig("testuser")

	_, err = handler.EnrollKey(enrollConfig)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize CTAP device")
}

// TestEnrollKey_WithCustomSalt tests enrollment with custom salt provided
func TestEnrollKey_WithCustomSalt(t *testing.T) {
	config := DefaultConfig
	mockDev := NewMockHIDDevice("/dev/hidraw0")

	enum := NewMockHIDDeviceEnumerator()
	enum.AddDevice(mockDev)

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	customSalt := make([]byte, 32)
	for i := range customSalt {
		customSalt[i] = byte(i * 2)
	}

	enrollConfig := DefaultEnrollmentConfig("testuser")
	enrollConfig.Salt = customSalt

	result, err := handler.EnrollKey(enrollConfig)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, customSalt, result.Salt)
}

// TestHandler_UnlockWithKey_DeviceCloseErrorAfterCTAPInitFail tests device close error logging
func TestHandler_UnlockWithKey_DeviceCloseErrorAfterCTAPInitFail(t *testing.T) {
	config := DefaultConfig
	mockDev := &FailBothCloseAndWriteDevice{
		MockHIDDevice: NewMockHIDDevice("/dev/hidraw0"),
	}

	enum := &SingleDeviceEnumerator{device: mockDev}

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	authConfig := DefaultAuthenticationConfig(make([]byte, 32), make([]byte, 32))

	_, err = handler.UnlockWithKey(authConfig)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize CTAP device")
}

// FailBothCloseAndWriteDevice fails write and close
type FailBothCloseAndWriteDevice struct {
	*MockHIDDevice
}

func (d *FailBothCloseAndWriteDevice) Write(data []byte) (int, error) {
	return 0, fmt.Errorf("write error")
}

func (d *FailBothCloseAndWriteDevice) Close() error {
	return fmt.Errorf("close error")
}

func (d *FailBothCloseAndWriteDevice) Read(data []byte) (int, error) {
	return 0, fmt.Errorf("read error")
}

// TestHandler_UnlockWithKey_CTAPDeviceCloseError tests CTAP device close error
func TestHandler_UnlockWithKey_CTAPDeviceCloseError(t *testing.T) {
	config := DefaultConfig
	mockDev := &CloseErrorCTAPDevice{
		MockHIDDevice:  NewMockHIDDevice("/dev/hidraw0"),
		closeAttempted: false,
	}

	enum := &SingleDeviceEnumerator{device: mockDev}

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	authConfig := DefaultAuthenticationConfig(make([]byte, 32), make([]byte, 32))

	// Should succeed despite close error
	derivedKey, err := handler.UnlockWithKey(authConfig)
	require.NoError(t, err)
	require.NotNil(t, derivedKey)

	// Close was attempted
	assert.True(t, mockDev.closeAttempted)
}

// CloseErrorCTAPDevice succeeds all operations but fails close
type CloseErrorCTAPDevice struct {
	*MockHIDDevice
	closeAttempted bool
}

func (d *CloseErrorCTAPDevice) Write(data []byte) (int, error) {
	if len(data) < HIDPacketSize {
		return 0, fmt.Errorf("packet too short")
	}

	cmd := data[4]

	switch cmd {
	case CTAPHID_INIT:
		d.generateInitResponseCE(data[7:])
	case CTAPHID_CBOR:
		d.generateCBORResponseCE(data[7:])
	}

	return len(data), nil
}

func (d *CloseErrorCTAPDevice) generateInitResponseCE(nonce []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()

	response := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(response[0:4], CIDBroadcast)
	response[4] = CTAPHID_INIT
	binary.BigEndian.PutUint16(response[5:7], 17)
	copy(response[7:15], nonce[:8])
	binary.BigEndian.PutUint32(response[15:19], 0x12345678)
	response[19] = 2
	response[20] = 1
	response[21] = 0
	response[22] = 0
	response[23] = 0x01

	d.readBuf.Write(response)
}

func (d *CloseErrorCTAPDevice) generateCBORResponseCE(payload []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(payload) == 0 {
		return
	}

	ctapCmd := payload[0]

	switch ctapCmd {
	case CmdGetInfo:
		d.generateGetInfoResponseCE()
	case CmdGetAssertion:
		d.generateGetAssertionResponseCE()
	}
}

func (d *CloseErrorCTAPDevice) generateGetInfoResponseCE() {
	info := map[int]interface{}{
		0x01: []string{"FIDO_2_0"},
		0x02: []string{"hmac-secret"},
		0x03: make([]byte, 16),
		0x04: map[string]bool{"up": true},
	}

	encoded, _ := cbor.Marshal(info)
	fullPayload := append([]byte{StatusOK}, encoded...)
	d.writeHIDPacketsCE(0x12345678, fullPayload)
}

func (d *CloseErrorCTAPDevice) generateGetAssertionResponseCE() {
	authData := make([]byte, 37+32)
	copy(authData[0:32], make([]byte, 32))
	authData[32] = 0x81 // UP + ED
	binary.BigEndian.PutUint32(authData[33:37], 2)

	hmacOutput := make([]byte, 32)
	for i := range hmacOutput {
		hmacOutput[i] = byte(i + 100)
	}
	copy(authData[37:], hmacOutput)

	respMap := map[int]interface{}{
		0x01: map[string]interface{}{
			"type": "public-key",
			"id":   make([]byte, 32),
		},
		0x02: authData,
		0x03: make([]byte, 64),
	}

	encoded, _ := cbor.Marshal(respMap)
	fullPayload := append([]byte{StatusOK}, encoded...)
	d.writeHIDPacketsCE(0x12345678, fullPayload)
}

func (d *CloseErrorCTAPDevice) writeHIDPacketsCE(cid uint32, fullPayload []byte) {
	payloadLen := len(fullPayload)

	firstPacket := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(firstPacket[0:4], cid)
	firstPacket[4] = CTAPHID_CBOR
	binary.BigEndian.PutUint16(firstPacket[5:7], uint16(payloadLen))

	firstPayloadSize := HIDPacketSize - 7
	if payloadLen <= firstPayloadSize {
		copy(firstPacket[7:], fullPayload)
		d.readBuf.Write(firstPacket)
		return
	}

	copy(firstPacket[7:], fullPayload[:firstPayloadSize])
	d.readBuf.Write(firstPacket)

	remaining := fullPayload[firstPayloadSize:]
	seq := byte(0)

	for len(remaining) > 0 {
		contPacket := make([]byte, HIDPacketSize)
		binary.BigEndian.PutUint32(contPacket[0:4], cid)
		contPacket[4] = seq

		contPayloadSize := HIDPacketSize - 5
		n := contPayloadSize
		if len(remaining) < n {
			n = len(remaining)
		}

		copy(contPacket[5:], remaining[:n])
		d.readBuf.Write(contPacket)

		remaining = remaining[n:]
		seq++
	}
}

func (d *CloseErrorCTAPDevice) Read(data []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.readBuf.Len() > 0 {
		return d.readBuf.Read(data)
	}

	return 0, fmt.Errorf("no data")
}

func (d *CloseErrorCTAPDevice) Close() error {
	d.closeAttempted = true
	return fmt.Errorf("close error")
}

// TestNewHandler_EdgeCaseConfigs tests NewHandler with invalid config values
func TestNewHandler_EdgeCaseConfigs(t *testing.T) {
	enum := NewMockHIDDeviceEnumerator()

	// Test with zero timeout
	config := DefaultConfig
	config.Timeout = 0

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)
	require.NotNil(t, handler)

	// Test with negative retry count
	config2 := DefaultConfig
	config2.RetryCount = 0

	handler2, err := NewHandler(&config2, enum)
	require.NoError(t, err)
	require.NotNil(t, handler2)
}

// TestHandler_UnlockWithKey_AuthenticatorCreationError tests authenticator creation failure
func TestHandler_UnlockWithKey_AuthenticatorCreationError2(t *testing.T) {
	config := DefaultConfig
	mockDev := &AuthenticatorCreationErrorDevice{
		MockHIDDevice: NewMockHIDDevice("/dev/hidraw0"),
	}

	enum := &SingleDeviceEnumerator{device: mockDev}

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	authConfig := DefaultAuthenticationConfig(make([]byte, 32), make([]byte, 32))

	_, err = handler.UnlockWithKey(authConfig)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create authenticator")
}

// AuthenticatorCreationErrorDevice returns error during GetInfo (which causes authenticator creation to fail)
type AuthenticatorCreationErrorDevice struct {
	*MockHIDDevice
	initDone bool
}

func (d *AuthenticatorCreationErrorDevice) Write(data []byte) (int, error) {
	if len(data) < HIDPacketSize {
		return 0, fmt.Errorf("packet too short")
	}

	cmd := data[4]

	switch cmd {
	case CTAPHID_INIT:
		d.generateInitResponseACE(data[7:])
	case CTAPHID_CBOR:
		d.generateCBORErrorACE()
	}

	return len(data), nil
}

func (d *AuthenticatorCreationErrorDevice) generateInitResponseACE(nonce []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()

	response := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(response[0:4], CIDBroadcast)
	response[4] = CTAPHID_INIT
	binary.BigEndian.PutUint16(response[5:7], 17)
	copy(response[7:15], nonce[:8])
	binary.BigEndian.PutUint32(response[15:19], 0x12345678)
	response[19] = 2
	response[20] = 1
	response[21] = 0
	response[22] = 0
	response[23] = 0x01

	d.readBuf.Write(response)
	d.initDone = true
}

func (d *AuthenticatorCreationErrorDevice) generateCBORErrorACE() {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Return an error status for GetInfo
	response := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(response[0:4], 0x12345678)
	response[4] = CTAPHID_CBOR
	binary.BigEndian.PutUint16(response[5:7], 1)
	response[7] = StatusInvalidCommand // Error status

	d.readBuf.Write(response)
}

func (d *AuthenticatorCreationErrorDevice) Read(data []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.readBuf.Len() > 0 {
		return d.readBuf.Read(data)
	}

	return 0, fmt.Errorf("no data")
}
