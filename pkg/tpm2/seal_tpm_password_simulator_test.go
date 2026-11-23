//go:build tpm_simulator

package tpm2

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sealDeadline bounds one seal or unseal: a password resolved under the
// seal lock re-enters it and never returns.
const sealDeadline = 60 * time.Second

// withinDeadline runs op on its own goroutine and fails the test when it
// does not finish before sealDeadline.
func withinDeadline(t *testing.T, name string, op func() error) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- op() }()
	select {
	case err := <-done:
		require.NoError(t, err, name)
	case <-time.After(sealDeadline):
		t.Fatalf("%s did not finish within %s: the password was resolved under the seal lock", name, sealDeadline)
	}
}

// TestSealKey_TPMBackedPasswordDoesNotDeadlock seals and unseals a key whose
// password is itself sealed by the same TPM (a PlatformPassword): resolving
// that password unseals through the same TPM and must not wait on the
// operation it authorises.
func TestSealKey_TPMBackedPasswordDoesNotDeadlock(t *testing.T) {
	h := newSimHarness(t, nil)

	source := sealedKeyAttrs(t, h, "tpm-password-source", false, mustPassword(t, []byte("source-pin")))
	source.SealData = types.NewSealData([]byte("tpm-backed-pin"))
	_, err := h.TPM.SealKey(source, h.Backend, true)
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	password := NewPlatformPassword(logger, h.TPM,
		sealedKeyAttrs(t, h, "tpm-password-source", false, mustPassword(t, []byte("source-pin"))),
		h.Backend)
	require.Equal(t, []byte("tpm-backed-pin"), password.Bytes(), "the TPM-backed password must resolve")

	secret := []byte("protected-by-a-tpm-password")
	protected := sealedKeyAttrs(t, h, "tpm-password-protected", false, password)
	protected.SealData = types.NewSealData(secret)
	withinDeadline(t, "SealKey", func() error {
		_, err := h.TPM.SealKey(protected, h.Backend, true)
		return err
	})

	var got []byte
	unsealAttrs := sealedKeyAttrs(t, h, "tpm-password-protected", false, password)
	withinDeadline(t, "UnsealKey", func() error {
		var err error
		got, err = h.TPM.UnsealKey(unsealAttrs, h.Backend)
		return err
	})
	assert.Equal(t, secret, got)

	next := sealedKeyAttrs(t, h, "tpm-password-next", false, mustPassword(t, []byte("next-pin")))
	next.SealData = types.NewSealData([]byte("next-secret"))
	withinDeadline(t, "SealKey after", func() error {
		_, err := h.TPM.SealKey(next, h.Backend, true)
		return err
	})
}

// TestSeal_UnreadablePlatformPasswordReturnsUnavailable seals under a
// TPM-backed password whose secret was never sealed: the seal must fail with
// ErrPlatformPasswordUnavailable and leave no object an empty credential opens.
func TestSeal_UnreadablePlatformPasswordReturnsUnavailable(t *testing.T) {
	h := newSimHarness(t, nil)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	password := NewPlatformPassword(logger, h.TPM,
		sealedKeyAttrs(t, h, "tpm-password-never-sealed", false, mustPassword(t, []byte("source-pin"))),
		h.Backend)

	protected := sealedKeyAttrs(t, h, "tpm-password-unreadable", false, password)
	protected.SealData = types.NewSealData([]byte("must-not-be-sealed"))
	var err error
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, err = h.TPM.SealKey(protected, h.Backend, true)
	}()
	select {
	case <-done:
	case <-time.After(sealDeadline):
		t.Fatalf("SealKey did not finish within %s", sealDeadline)
	}
	require.ErrorIs(t, err, ErrPlatformPasswordUnavailable)
	assert.Same(t, password.(*PlatformPassword), protected.Password, "the caller's password must stay in place")

	empty := sealedKeyAttrs(t, h, "tpm-password-unreadable", false, mustPassword(t, []byte{}))
	_, err = h.TPM.UnsealKey(empty, h.Backend)
	require.Error(t, err, "no sealed object may open with an empty credential")
}
