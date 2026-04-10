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
	assert.Equal(t, StrategySoftware, s.ID())
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
	creds := Credentials{Secret: "my-passphrase"}

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
	creds := Credentials{Secret: "correct-passphrase"}

	sealed, err := s.SealRootKey(ctx, rootKey, creds)
	require.NoError(t, err)

	wrongCreds := Credentials{Secret: "wrong-passphrase"}
	_, err = s.UnsealRootKey(ctx, sealed, wrongCreds)
	assert.ErrorIs(t, err, ErrInvalidCredentials)
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
