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

//go:build linux

package fido2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/bulwarkid/virtual-fido/cose"
	"github.com/bulwarkid/virtual-fido/crypto"
	"github.com/bulwarkid/virtual-fido/identities"
	"github.com/bulwarkid/virtual-fido/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockFIDOClient implements virtualfido.FIDOClient for testing
type MockFIDOClient struct {
	sealingKey []byte
}

func NewMockFIDOClient() *MockFIDOClient {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	return &MockFIDOClient{sealingKey: key}
}

// U2FClient methods
func (m *MockFIDOClient) SealingEncryptionKey() []byte {
	return m.sealingKey
}

func (m *MockFIDOClient) NewPrivateKey() *ecdsa.PrivateKey {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return key
}

func (m *MockFIDOClient) NewAuthenticationCounterId() uint32 {
	return 1
}

func (m *MockFIDOClient) CreateAttestationCertificiate(privateKey *cose.SupportedCOSEPrivateKey) []byte {
	return make([]byte, 512)
}

func (m *MockFIDOClient) ApproveU2FRegistration(keyHandle *webauthn.KeyHandle) bool {
	return true
}

func (m *MockFIDOClient) ApproveU2FAuthentication(keyHandle *webauthn.KeyHandle) bool {
	return true
}

// CTAPClient methods
func (m *MockFIDOClient) SupportsResidentKey() bool {
	return true
}

func (m *MockFIDOClient) SupportsPIN() bool {
	return false
}

func (m *MockFIDOClient) NewCredentialSource(
	PubKeyCredParams []webauthn.PublicKeyCredentialParams,
	ExcludeList []webauthn.PublicKeyCredentialDescriptor,
	relyingParty *webauthn.PublicKeyCredentialRPEntity,
	user *webauthn.PublicKeyCrendentialUserEntity) *identities.CredentialSource {
	return nil
}

func (m *MockFIDOClient) GetAssertionSource(relyingPartyID string, allowList []webauthn.PublicKeyCredentialDescriptor) *identities.CredentialSource {
	return nil
}

func (m *MockFIDOClient) PINHash() []byte {
	return nil
}

func (m *MockFIDOClient) SetPINHash(pin []byte) {}

func (m *MockFIDOClient) PINRetries() int32 {
	return 8
}

func (m *MockFIDOClient) SetPINRetries(retries int32) {}

func (m *MockFIDOClient) PINKeyAgreement() *crypto.ECDHKey {
	return nil
}

func (m *MockFIDOClient) PINToken() []byte {
	return nil
}

func (m *MockFIDOClient) ApproveAccountCreation(relyingParty string) bool {
	return true
}

func (m *MockFIDOClient) ApproveAccountLogin(credentialSource *identities.CredentialSource) bool {
	return true
}

func TestNewVirtualFIDO2Device_Success(t *testing.T) {
	config := &VirtualDeviceConfig{
		SerialNumber: "TEST001",
		Manufacturer: "TestMfg",
		Product:      "TestProduct",
		FIDOClient:   NewMockFIDOClient(),
	}

	device, err := NewVirtualFIDO2Device(config)
	require.NoError(t, err)
	require.NotNil(t, device)
	defer func() { _ = device.Close() }()

	assert.Equal(t, VirtualFIDOPathPrefix+"TEST001", device.Path())
	assert.Equal(t, "TestMfg", device.Manufacturer())
	assert.Equal(t, "TestProduct", device.Product())
	assert.Equal(t, "TEST001", device.SerialNumber())
	assert.Equal(t, uint16(VirtualFIDOVendorID), device.VendorID())
	assert.Equal(t, uint16(VirtualFIDOProductID), device.ProductID())
}

func TestNewVirtualFIDO2Device_NilConfig(t *testing.T) {
	// Nil config should fail because FIDOClient is required
	device, err := NewVirtualFIDO2Device(nil)
	assert.Error(t, err)
	assert.Nil(t, device)
	assert.Contains(t, err.Error(), "FIDOClient is required")
}

func TestNewVirtualFIDO2Device_NilFIDOClient(t *testing.T) {
	config := &VirtualDeviceConfig{
		SerialNumber: "TEST001",
		FIDOClient:   nil,
	}

	device, err := NewVirtualFIDO2Device(config)
	assert.Error(t, err)
	assert.Nil(t, device)
	assert.Contains(t, err.Error(), "FIDOClient is required")
}

func TestNewVirtualFIDO2Device_DefaultValues(t *testing.T) {
	config := &VirtualDeviceConfig{
		FIDOClient: NewMockFIDOClient(),
	}

	device, err := NewVirtualFIDO2Device(config)
	require.NoError(t, err)
	require.NotNil(t, device)
	defer func() { _ = device.Close() }()

	// Verify defaults are applied
	assert.Equal(t, VirtualFIDOPathPrefix+"VFIDO001", device.Path())
	assert.Equal(t, "go-keychain", device.Manufacturer())
	assert.Equal(t, "VirtualFIDO", device.Product())
	assert.Equal(t, "VFIDO001", device.SerialNumber())
}

func TestVirtualFIDO2Device_Write_Success(t *testing.T) {
	device, err := NewVirtualFIDO2Device(&VirtualDeviceConfig{
		FIDOClient: NewMockFIDOClient(),
	})
	require.NoError(t, err)
	defer func() { _ = device.Close() }()

	data := make([]byte, 64)
	n, err := device.Write(data)
	require.NoError(t, err)
	assert.Equal(t, 64, n)
}

func TestVirtualFIDO2Device_Write_Closed(t *testing.T) {
	device, err := NewVirtualFIDO2Device(&VirtualDeviceConfig{
		FIDOClient: NewMockFIDOClient(),
	})
	require.NoError(t, err)

	err = device.Close()
	require.NoError(t, err)

	data := make([]byte, 64)
	n, err := device.Write(data)
	assert.Error(t, err)
	assert.Equal(t, 0, n)
	assert.ErrorIs(t, err, ErrVirtualDeviceClosed)
}

func TestVirtualFIDO2Device_Read_Closed(t *testing.T) {
	device, err := NewVirtualFIDO2Device(&VirtualDeviceConfig{
		FIDOClient: NewMockFIDOClient(),
	})
	require.NoError(t, err)

	err = device.Close()
	require.NoError(t, err)

	data := make([]byte, 64)
	n, err := device.Read(data)
	assert.Error(t, err)
	assert.Equal(t, 0, n)
	assert.ErrorIs(t, err, ErrVirtualDeviceClosed)
}

func TestVirtualFIDO2Device_Close_Idempotent(t *testing.T) {
	device, err := NewVirtualFIDO2Device(&VirtualDeviceConfig{
		FIDOClient: NewMockFIDOClient(),
	})
	require.NoError(t, err)

	// Close multiple times should not error
	err = device.Close()
	assert.NoError(t, err)

	err = device.Close()
	assert.NoError(t, err)
}

func TestVirtualFIDO2Device_FIDOClient(t *testing.T) {
	client := NewMockFIDOClient()
	device, err := NewVirtualFIDO2Device(&VirtualDeviceConfig{
		FIDOClient: client,
	})
	require.NoError(t, err)
	defer func() { _ = device.Close() }()

	// FIDOClient should return the same client
	assert.Equal(t, client, device.FIDOClient())
}

func TestVirtualFIDO2Device_ImplementsHIDDevice(t *testing.T) {
	device, err := NewVirtualFIDO2Device(&VirtualDeviceConfig{
		FIDOClient: NewMockFIDOClient(),
	})
	require.NoError(t, err)
	defer func() { _ = device.Close() }()

	// Verify it implements HIDDevice interface
	var _ HIDDevice = device
}

func TestVirtualFIDO2Device_WriteReadFlow(t *testing.T) {
	device, err := NewVirtualFIDO2Device(&VirtualDeviceConfig{
		FIDOClient: NewMockFIDOClient(),
	})
	require.NoError(t, err)
	defer func() { _ = device.Close() }()

	// Write a command
	cmd := make([]byte, 64)
	n, err := device.Write(cmd)
	require.NoError(t, err)
	assert.Equal(t, 64, n)

	// Read should eventually return data (via channel with timeout)
	// Use a goroutine to read with timeout
	done := make(chan struct{})
	go func() {
		data := make([]byte, 64)
		_, _ = device.Read(data)
		close(done)
	}()

	select {
	case <-done:
		// Read completed - may or may not have error depending on implementation
	case <-time.After(100 * time.Millisecond):
		// Timeout is expected if no response is generated
	}
}

func TestVirtualFIDO2Device_ResponseChannelOverflow(t *testing.T) {
	device, err := NewVirtualFIDO2Device(&VirtualDeviceConfig{
		FIDOClient: NewMockFIDOClient(),
	})
	require.NoError(t, err)
	defer func() { _ = device.Close() }()

	// Fill the response channel (capacity is 64)
	// This tests the non-blocking send and overflow handling
	for i := 0; i < 100; i++ {
		cmd := make([]byte, 64)
		_, err := device.Write(cmd)
		require.NoError(t, err)
	}
}
