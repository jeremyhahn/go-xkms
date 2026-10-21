package cmd

import (
	"bytes"
	"encoding/base64"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
)

// errSealTestEncrypt is the failure sealTestBarrier returns when told to.
var errSealTestEncrypt = errors.New("seal test: barrier sealed")

// sealTestBarrier reverses its input so a sealed key is never the
// plaintext, and fails every call when err is set.
type sealTestBarrier struct {
	err error
}

func (b sealTestBarrier) Encrypt(plaintext []byte) ([]byte, error) {
	if b.err != nil {
		return nil, b.err
	}
	out := make([]byte, len(plaintext))
	for i, c := range plaintext {
		out[len(plaintext)-1-i] = c
	}
	return out, nil
}

func (b sealTestBarrier) Decrypt(ciphertext []byte) ([]byte, error) {
	return b.Encrypt(ciphertext)
}

func newSealTestLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, nil))
}

// Without a barrier the key is stored as base64 plaintext and the user is
// warned that it is unprotected.
func TestSealOrWarnLocalNoiseKey_NoBarrierWarns(t *testing.T) {
	var logs bytes.Buffer
	priv := []byte{1, 2, 3, 4}

	stored, err := sealOrWarnLocalNoiseKey(newSealTestLogger(&logs), "phone", nil, priv)

	require.NoError(t, err)
	assert.Equal(t, base64.StdEncoding.EncodeToString(priv), stored)
	assert.Contains(t, logs.String(), "pairing key stored unencrypted")
}

// With a barrier the key is sealed: the stored form carries the sealed
// prefix, round-trips through the barrier, and no warning is logged.
func TestSealOrWarnLocalNoiseKey_BarrierSeals(t *testing.T) {
	var logs bytes.Buffer
	priv := []byte{1, 2, 3, 4}
	barrier := sealTestBarrier{}

	stored, err := sealOrWarnLocalNoiseKey(newSealTestLogger(&logs), "phone", barrier, priv)

	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(stored, pairing.NoiseKeySealedPrefix), "got %q", stored)
	assert.Empty(t, logs.String())

	opened, err := pairing.UnsealLocalNoiseKey(barrier, stored)
	require.NoError(t, err)
	defer opened.Destroy()
	require.NoError(t, opened.WithBytes(func(b []byte) error {
		assert.Equal(t, priv, b)
		return nil
	}))
}

// A barrier that refuses to encrypt yields the typed seal error and no
// stored value, never a plaintext fallback.
func TestSealOrWarnLocalNoiseKey_EncryptFails(t *testing.T) {
	var logs bytes.Buffer

	stored, err := sealOrWarnLocalNoiseKey(newSealTestLogger(&logs), "phone", sealTestBarrier{err: errSealTestEncrypt}, []byte{1})

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDeviceBarrierSealFailed)
	assert.ErrorIs(t, err, errSealTestEncrypt)
	assert.Empty(t, stored)
}
