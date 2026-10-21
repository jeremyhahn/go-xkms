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

package clusterca

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// mustSecret seals s into a *secure.Secret for test fixtures that need a
// KeyProtection.Passphrase. Test-only: production callers resolve the
// passphrase from config via Server.resolveClusterCAKeyPassphrase.
func mustSecret(t *testing.T, s string) *secure.Secret {
	t.Helper()
	sec, err := secure.NewSecret(t.Context(), []byte(s))
	require.NoError(t, err)
	return sec
}

// secretBytes opens sec and returns a copy of its plaintext for test
// assertions. A nil Secret (no passphrase configured) returns nil, matching
// the empty-string behaviour the pre-enclave *KeyProtection.Passphrase had.
func secretBytes(t *testing.T, sec *secure.Secret) []byte {
	t.Helper()
	if sec == nil {
		return nil
	}
	buf, err := sec.Open(t.Context())
	require.NoError(t, err)
	defer buf.Destroy()
	out, err := secure.CopyOut(buf)
	require.NoError(t, err)
	return out
}

// fakeSealer is an AES-256-GCM stand-in for a hardware types.Sealer, letting
// the key-protection logic be exercised without a real TPM. It models the
// invariant that matters here: seal/unseal round-trips, and the sealed blob is
// opaque (the wrapping key never leaves the sealer), exactly as a TPM-sealed
// blob behaves.
type fakeSealer struct {
	key     []byte
	canSeal bool
}

func newFakeSealer() *fakeSealer {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	return &fakeSealer{key: key, canSeal: true}
}

func (f *fakeSealer) CanSeal() bool { return f.canSeal }

func (f *fakeSealer) Seal(_ context.Context, data []byte, _ *types.SealOptions) (*types.SealedData, error) {
	gcm, err := f.aead()
	if err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nil, data, nil)
	return &types.SealedData{Backend: types.BackendTypeTPM2, Ciphertext: ct}, nil
}

func (f *fakeSealer) Unseal(_ context.Context, sealed *types.SealedData, _ *types.UnsealOptions) ([]byte, error) {
	gcm, err := f.aead()
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nil, sealed.Ciphertext, nil)
}

// aead returns an AES-GCM AEAD that generates its own nonce and carries it
// in the ciphertext (NewGCMWithRandomNonce), the only GCM construction a
// fips140=only process may build.
func (f *fakeSealer) aead() (cipher.AEAD, error) {
	block, err := aes.NewCipher(f.key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(block)
}

// ---------------------------------------------------------------------------
// Mode selection
// ---------------------------------------------------------------------------

func TestKeyProtection_AutoSelectsTPMWhenAvailable(t *testing.T) {
	kp := &KeyProtection{
		Mode:       KeyProtectAuto,
		DataDir:    t.TempDir(),
		Passphrase: mustSecret(t, "operator-secret"),
		Sealer:     newFakeSealer(),
	}
	assert.Equal(t, KeyProtectTPM2, kp.effectiveMode())
}

func TestKeyProtection_AutoFallsBackToPassphrase(t *testing.T) {
	kp := &KeyProtection{
		Mode:       KeyProtectAuto,
		DataDir:    t.TempDir(),
		Passphrase: mustSecret(t, "operator-secret"),
		Sealer:     nil,
	}
	assert.Equal(t, KeyProtectPassphrase, kp.effectiveMode())
}

func TestKeyProtection_AutoRefusesWhenNoSecureOption(t *testing.T) {
	kp := &KeyProtection{Mode: KeyProtectAuto, DataDir: t.TempDir()}
	_, _, err := kp.Resolve(context.Background())
	var refuse *ErrNoSecureCAKeyProtection
	require.ErrorAs(t, err, &refuse)
}

func TestKeyProtection_AutoAllowsPlaintextOnlyWhenInsecure(t *testing.T) {
	kp := &KeyProtection{Mode: KeyProtectAuto, DataDir: t.TempDir(), AllowInsecure: true}
	pw, allowPlaintext, err := kp.Resolve(context.Background())
	require.NoError(t, err)
	assert.True(t, allowPlaintext)
	assert.Empty(t, pw.Bytes())
}

// ---------------------------------------------------------------------------
// Passphrase mode
// ---------------------------------------------------------------------------

func TestKeyProtection_Passphrase(t *testing.T) {
	kp := &KeyProtection{Mode: KeyProtectPassphrase, DataDir: t.TempDir(), Passphrase: mustSecret(t, "hunter2")}
	pw, allowPlaintext, err := kp.Resolve(context.Background())
	require.NoError(t, err)
	assert.False(t, allowPlaintext)
	assert.Equal(t, "hunter2", string(pw.Bytes()))
}

// ---------------------------------------------------------------------------
// none mode
// ---------------------------------------------------------------------------

func TestKeyProtection_NoneRequiresInsecure(t *testing.T) {
	kp := &KeyProtection{Mode: KeyProtectNone, DataDir: t.TempDir()}
	_, _, err := kp.Resolve(context.Background())
	var refuse *ErrNoSecureCAKeyProtection
	require.ErrorAs(t, err, &refuse)

	kp.AllowInsecure = true
	pw, allowPlaintext, err := kp.Resolve(context.Background())
	require.NoError(t, err)
	assert.True(t, allowPlaintext)
	assert.Empty(t, pw.Bytes())
}

// ---------------------------------------------------------------------------
// TPM (sealed) mode — first boot seals, restart unseals the SAME password
// ---------------------------------------------------------------------------

func TestKeyProtection_TPM2SealAndRestartUnseal(t *testing.T) {
	dataDir := t.TempDir()
	sealer := newFakeSealer()

	kp := &KeyProtection{Mode: KeyProtectTPM2, DataDir: dataDir, Sealer: sealer}
	pw1, allowPlaintext, err := kp.Resolve(context.Background())
	require.NoError(t, err)
	assert.False(t, allowPlaintext)
	assert.Len(t, pw1.Bytes(), 32)

	// The sealed blob is cached and contains no plaintext of the password.
	blob, err := os.ReadFile(filepath.Join(dataDir, caKeySealFile))
	require.NoError(t, err)
	assert.NotContains(t, string(blob), string(pw1.Bytes()))

	// A fresh KeyProtection over the same DataDir + sealer recovers the SAME
	// password (restart path — unattended, no operator interaction).
	kp2 := &KeyProtection{Mode: KeyProtectTPM2, DataDir: dataDir, Sealer: sealer}
	pw2, _, err := kp2.Resolve(context.Background())
	require.NoError(t, err)
	assert.Equal(t, pw1.Bytes(), pw2.Bytes())
}

func TestKeyProtection_TPM2WithoutSealerFails(t *testing.T) {
	kp := &KeyProtection{Mode: KeyProtectTPM2, DataDir: t.TempDir()}
	_, _, err := kp.Resolve(context.Background())
	var unavailable *ErrSealerUnavailable
	require.ErrorAs(t, err, &unavailable)
}

func TestKeyProtection_TPM2CorruptBlob(t *testing.T) {
	dataDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, caKeySealFile), []byte("{not json"), 0o600))
	kp := &KeyProtection{Mode: KeyProtectTPM2, DataDir: dataDir, Sealer: newFakeSealer()}
	_, _, err := kp.Resolve(context.Background())
	var corrupt *ErrSealBlobCorrupt
	require.ErrorAs(t, err, &corrupt)
}

// TestPasswordFromSecret_NilSecretYieldsNoAuthentication verifies the
// documented contract: a nil *secure.Secret (KeyProtection.Passphrase never
// configured) resolves to a usable, passwordless Password rather than an
// error, mirroring types.NewPasswordFromString("")'s "empty is not a
// failure" behaviour.
func TestPasswordFromSecret_NilSecretYieldsNoAuthentication(t *testing.T) {
	pw, err := passwordFromSecret(t.Context(), nil)
	require.NoError(t, err)
	require.NotNil(t, pw)
	assert.Empty(t, pw.Bytes())
}

// TestPasswordFromSecret_OpensSealedPlaintext verifies the non-nil path
// decrypts the Secret's enclave and carries its exact plaintext into the
// returned Password.
func TestPasswordFromSecret_OpensSealedPlaintext(t *testing.T) {
	sec := mustSecret(t, "s3cr3t-passphrase")
	pw, err := passwordFromSecret(t.Context(), sec)
	require.NoError(t, err)
	assert.Equal(t, []byte("s3cr3t-passphrase"), pw.Bytes())
}

// TestPasswordFromSecret_DestroyedSecretFails verifies that a Secret whose
// enclave has already been released propagates the real Open() failure
// instead of masking it as "no authentication" — silently downgrading a
// destroyed secret to passwordless auth would be a security regression, not
// a convenience.
func TestPasswordFromSecret_DestroyedSecretFails(t *testing.T) {
	sec := mustSecret(t, "will-be-destroyed")
	sec.Destroy()

	_, err := passwordFromSecret(t.Context(), sec)
	require.Error(t, err)
}
