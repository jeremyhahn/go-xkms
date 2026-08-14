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

package module

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// failingReader always fails, standing in for a broken system entropy source.
type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("entropy source unavailable") }

// withFailingEntropy swaps the package entropy source for a failing one for the
// duration of the test, restoring it afterward.
func withFailingEntropy(t *testing.T) {
	t.Helper()
	prev := entropySource
	entropySource = failingReader{}
	t.Cleanup(func() { entropySource = prev })
}

// C24: an entropy-source failure must be RETURNED, not panicked, so an embedded
// Go host gets a clean error instead of a crash.
func TestHashPin_EntropyFailureReturnsError(t *testing.T) {
	withFailingEntropy(t)

	_, err := hashPin("pin")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrEntropyUnavailable)
}

func TestGenerateSerialNumber_EntropyFailureReturnsError(t *testing.T) {
	withFailingEntropy(t)

	_, err := generateSerialNumber()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrEntropyUnavailable)
}

// The token PIN setters propagate the entropy error rather than panicking.
func TestTokenSetPin_EntropyFailurePropagates(t *testing.T) {
	withFailingEntropy(t)

	tok := &Token{}
	assert.ErrorIs(t, tok.SetSOPin("so"), ErrEntropyUnavailable)
	assert.ErrorIs(t, tok.SetUserPin("user"), ErrEntropyUnavailable)
}

// C_InitToken surfaces the entropy failure as CKR_DEVICE_ERROR rather than
// crashing the caller.
func TestInitToken_EntropyFailureIsDeviceError(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	withFailingEntropy(t)
	rv := m.InitToken(0, []byte("so-pin-1234"), "Entropy Token")
	assert.Equal(t, CKR_DEVICE_ERROR, rv,
		"an entropy failure during C_InitToken must be a device error, not a panic")
}
