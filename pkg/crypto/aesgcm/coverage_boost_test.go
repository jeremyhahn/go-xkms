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

package aesgcm

import (
	"crypto/rand"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEncryptWithAAD_RandReaderFailure tests that EncryptWithAAD returns an
// error when the random number generator fails.
func TestEncryptWithAAD_RandReaderFailure(t *testing.T) {
	key := make([]byte, KeySize)
	_, err := io.ReadFull(rand.Reader, key)
	require.NoError(t, err)

	// Replace rand.Reader with a failing reader
	origReader := rand.Reader
	rand.Reader = &failingReader{}
	defer func() { rand.Reader = origReader }()

	_, err = EncryptWithAAD(key, []byte("test"), nil)
	assert.Error(t, err, "EncryptWithAAD should fail when random source fails")
}

// TestEncryptWithAAD_RandReaderFailure_WithAAD verifies the error path when
// AAD is provided and the random source fails.
func TestEncryptWithAAD_RandReaderFailure_WithAAD(t *testing.T) {
	key := make([]byte, KeySize)
	_, err := io.ReadFull(rand.Reader, key)
	require.NoError(t, err)

	origReader := rand.Reader
	rand.Reader = &failingReader{}
	defer func() { rand.Reader = origReader }()

	_, err = EncryptWithAAD(key, []byte("payload"), []byte("aad"))
	assert.Error(t, err, "EncryptWithAAD with AAD should fail when random source fails")
}

// failingReader is a reader that always returns an error.
type failingReader struct{}

func (f *failingReader) Read(p []byte) (int, error) {
	return 0, errors.New("rand: simulated failure")
}
