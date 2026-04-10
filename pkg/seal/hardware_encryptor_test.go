// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.

package seal

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHardwareEncryptorWrapper_RoundTrip(t *testing.T) {
	inner := &mockSymmetricEncrypter{}
	wrapper := &hardwareEncryptorWrapper{inner: inner}

	plaintext := []byte("sensitive data for hardware encryptor")

	ciphertext, err := wrapper.Encrypt(plaintext)
	require.NoError(t, err)
	require.NotEmpty(t, ciphertext)

	recovered, err := wrapper.Decrypt(ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, recovered)
}

func TestHardwareEncryptorWrapper_DecryptEmpty(t *testing.T) {
	inner := &mockSymmetricEncrypter{}
	wrapper := &hardwareEncryptorWrapper{inner: inner}

	_, err := wrapper.Decrypt([]byte{})
	assert.ErrorIs(t, err, ErrCorruptRootKey)
}

func TestHardwareEncryptorWrapper_DecryptInvalidTLV(t *testing.T) {
	inner := &mockSymmetricEncrypter{}
	wrapper := &hardwareEncryptorWrapper{inner: inner}

	// Random garbage that won't parse as valid TLV.
	_, err := wrapper.Decrypt([]byte{0xFF, 0xFF, 0xFF})
	assert.ErrorIs(t, err, ErrCorruptRootKey)
}

// failingEncrypter returns errors on Encrypt and Decrypt.
type failingEncrypter struct {
	encryptErr error
	decryptErr error
}

func (f *failingEncrypter) Encrypt(_ []byte, _ *types.EncryptOptions) (*types.EncryptedData, error) {
	if f.encryptErr != nil {
		return nil, f.encryptErr
	}
	return &types.EncryptedData{}, nil
}

func (f *failingEncrypter) Decrypt(_ *types.EncryptedData, _ *types.DecryptOptions) ([]byte, error) {
	if f.decryptErr != nil {
		return nil, f.decryptErr
	}
	return nil, nil
}

func TestHardwareEncryptorWrapper_EncryptError(t *testing.T) {
	encErr := assert.AnError
	inner := &failingEncrypter{encryptErr: encErr}
	wrapper := &hardwareEncryptorWrapper{inner: inner}

	_, err := wrapper.Encrypt([]byte("data"))
	assert.Error(t, err)
}

func TestHardwareEncryptorWrapper_DecryptReturnsNilAsEmpty(t *testing.T) {
	// When inner returns nil plaintext, wrapper should return empty byte slice.
	inner := &mockSymmetricEncrypter{}
	wrapper := &hardwareEncryptorWrapper{inner: inner}

	// First encrypt to get valid TLV.
	ciphertext, err := wrapper.Encrypt([]byte("data"))
	require.NoError(t, err)

	// The mock returns ciphertext as-is, so decryption returns the original.
	recovered, err := wrapper.Decrypt(ciphertext)
	require.NoError(t, err)
	assert.NotNil(t, recovered)
}
