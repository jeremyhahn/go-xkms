//go:build tpm_simulator

package tpm2

import (
	"crypto/rsa"
	"crypto/x509"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newRSALAKHarness is newLAKHarness with an RSA LAK, the key type the
// RSA branch of createLAKKeyPair serves.
func newRSALAKHarness(t *testing.T) *simHarness {
	t.Helper()
	h := newSimHarness(t, func(c *Config) {
		c.LAK = &LAKConfig{
			CN:                 "lak-rsa-fixture",
			Handle:             0x81010003,
			KeyAlgorithm:       x509.RSA.String(),
			RSAConfig:          &store.RSAConfig{KeySize: 2048},
			Hash:               "SHA-256",
			SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
		}
	})
	pks, err := NewPlatformKeyStore(h.Logger, h.TPM, h.Backend, h.TPM.config,
		filepath.Join(t.TempDir(), "pin-state.json"))
	require.NoError(t, err)
	require.NoError(t, pks.EnrollPlatformSRK("", "lak-rsa-operator-pin"))
	return h
}

// TestCreateLAK_RSA_PersistsRSAKey proves an RSA LAK config yields a
// persisted RSA key whose public half LAK() returns.
func TestCreateLAK_RSA_PersistsRSAKey(t *testing.T) {
	h := newRSALAKHarness(t)

	lakAttrs, err := h.TPM.CreateLAK(nil, h.Backend, false)
	require.NoError(t, err)
	assert.Equal(t, x509.RSA, lakAttrs.KeyAlgorithm)

	pub, err := h.TPM.LAK()
	require.NoError(t, err)
	_, ok := pub.(*rsa.PublicKey)
	assert.True(t, ok, "the configured LAK is RSA, got %T", pub)
}

// TestCreateLAK_InvalidConfig_ReturnsTypedError proves an unparseable LAK
// config is refused before any TPM object is created.
func TestCreateLAK_InvalidConfig_ReturnsTypedError(t *testing.T) {
	h := newLAKHarness(t)
	h.TPM.config.LAK.Hash = "no-such-hash"

	_, err := h.TPM.CreateLAK(nil, h.Backend, false)
	assert.ErrorIs(t, err, ErrLAKConfigFailed)
	_, _, err = h.TPM.ReadHandle(tpm2.TPMHandle(h.TPM.config.LAK.Handle))
	assert.Error(t, err, "nothing may be persisted at the LAK handle")
}

// TestCreateLAK_OverwriteWithNothingPersisted proves overwrite on a TPM with
// no LAK yet skips the eviction instead of failing on the empty handle.
func TestCreateLAK_OverwriteWithNothingPersisted(t *testing.T) {
	h := newLAKHarness(t)

	lakAttrs, err := h.TPM.CreateLAK(nil, h.Backend, true)
	require.NoError(t, err)
	assert.Equal(t, tpm2.TPMHandle(h.TPM.config.LAK.Handle), lakAttrs.TPMAttributes.Handle)
}

// TestCreateLAK_ExistingWithoutOverwrite_Fails proves a second CreateLAK
// without overwrite refuses to clobber the persisted LAK and leaves it in
// place.
func TestCreateLAK_ExistingWithoutOverwrite_Fails(t *testing.T) {
	h := newLAKHarness(t)
	first, err := h.TPM.CreateLAK(nil, h.Backend, false)
	require.NoError(t, err)
	firstPub := first.TPMAttributes.PublicKeyBytes

	_, err = h.TPM.CreateLAK(nil, h.Backend, false)
	require.Error(t, err)

	h.TPM.lakAttrs = nil
	persisted, err := h.TPM.LAKAttributes()
	require.NoError(t, err)
	assert.Equal(t, firstPub, persisted.TPMAttributes.PublicKeyBytes,
		"the original LAK must survive the refused create")
}

// TestLAK_PublicKeyErrors covers LAK() before a LAK exists and with a
// public area that does not parse.
func TestLAK_PublicKeyErrors(t *testing.T) {
	tpm := &TPM2{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}

	_, err := tpm.LAK()
	assert.ErrorIs(t, err, ErrLAKNotInitialized)

	tpm.lakAttrs = &types.KeyAttributes{
		TPMAttributes: &types.TPMAttributes{PublicKeyBytes: []byte("not a PKIX key")},
	}
	_, err = tpm.LAK()
	assert.ErrorIs(t, err, ErrLAKPublicParse)
}
