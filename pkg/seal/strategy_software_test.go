// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.

package seal

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSoftwareStrategy_ID(t *testing.T) {
	s := NewSoftwareStrategy()
	assert.Equal(t, StrategyPassphrase, s.ID())
}

func TestSoftwareStrategy_Available(t *testing.T) {
	s := NewSoftwareStrategy()
	assert.True(t, s.Available())
}

func TestSoftwareStrategy_HardwareBacked(t *testing.T) {
	s := NewSoftwareStrategy()
	assert.False(t, s.HardwareBacked())
}

func TestSoftwareStrategy_SealUnsealRoundTrip(t *testing.T) {
	s := NewSoftwareStrategy()
	ctx := context.Background()
	rootKey := []byte("this-is-a-32-byte-root-key-test!")
	creds, err := CredentialsFor(t.Context(), []byte("my-passphrase"))
	require.NoError(t, err)
	defer creds.Secret.Destroy()

	sealed, err := s.SealRootKey(ctx, rootKey, creds)
	require.NoError(t, err)
	require.NotNil(t, sealed)

	recovered, err := s.UnsealRootKey(ctx, sealed, creds)
	require.NoError(t, err)
	assert.Equal(t, rootKey, recovered)
}

func TestSoftwareStrategy_UnsealWrongPassphrase(t *testing.T) {
	s := NewSoftwareStrategy()
	ctx := context.Background()
	rootKey := []byte("this-is-a-32-byte-root-key-test!")
	creds, err := CredentialsFor(t.Context(), []byte("correct-passphrase"))
	require.NoError(t, err)
	defer creds.Secret.Destroy()

	sealed, err := s.SealRootKey(ctx, rootKey, creds)
	require.NoError(t, err)

	wrongCreds, err := CredentialsFor(t.Context(), []byte("wrong-passphrase"))
	require.NoError(t, err)
	defer wrongCreds.Secret.Destroy()
	_, err = s.UnsealRootKey(ctx, sealed, wrongCreds)
	// The software strategy reports a wrong passphrase as ErrDecryptionFailed,
	// wrapped in go-quicraft's *UnsealError. ErrInvalidCredentials belongs to
	// the hardware path (hardware_encryptor.go).
	assert.ErrorIs(t, err, ErrDecryptionFailed)
}

func TestSoftwareStrategy_BarrierEncryptor(t *testing.T) {
	s := NewSoftwareStrategy()
	enc, err := s.BarrierEncryptor(context.Background(), []byte("key"))
	assert.NoError(t, err)
	assert.Nil(t, enc)
}

func TestSoftwareStrategy_Close(t *testing.T) {
	s := NewSoftwareStrategy()
	err := s.Close()
	assert.NoError(t, err)
}
