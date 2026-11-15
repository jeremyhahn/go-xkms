//go:build tpm_simulator

package tpm2

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestSealer_SealUnseal_PlatformPasswordUnavailable pins the verify13 P1 on
// seal.go's lockSeal: a PlatformPassword whose own unseal fails (here its
// sealed object was never created) must surface
// ErrPlatformPasswordUnavailable. It must never become an empty password:
// Seal would then create the object under empty authorization, and Unseal
// would try the object under empty authorization, failing it against the
// TPM's dictionary-attack protection.
func TestSealer_SealUnseal_PlatformPasswordUnavailable(t *testing.T) {
	h := newSimHarness(t, nil)
	ctx := context.Background()

	unavailable := func() types.Password {
		return NewPlatformPassword(h.Logger, h.TPM,
			sealedKeyAttrs(t, h, "platform-password-never-sealed", false, mustPassword(t, []byte("inner-password"))), h.Backend)
	}

	// Seal under the unavailable password refuses and creates nothing.
	_, err := h.TPM.Seal(ctx, []byte("secret"), &types.SealOptions{
		KeyAttributes: sealedKeyAttrs(t, h, "unavailable-seal", false, unavailable()),
	})
	require.ErrorIs(t, err, ErrPlatformPasswordUnavailable)

	// An object sealed under a real password, then opened with the
	// unavailable one: refused before any TPM command under empty auth, so
	// the lockout counter does not move.
	sealed, err := h.TPM.Seal(ctx, []byte("secret"), &types.SealOptions{
		KeyAttributes: sealedKeyAttrs(t, h, "unavailable-unseal", false, mustPassword(t, []byte("object-password"))),
	})
	require.NoError(t, err)

	before, err := lockoutCounter(h.TPM.Transport())
	require.NoError(t, err)
	_, err = h.TPM.Unseal(ctx, sealed, &types.UnsealOptions{
		KeyAttributes: sealedKeyAttrs(t, h, "unavailable-unseal", false, unavailable()),
	})
	require.ErrorIs(t, err, ErrPlatformPasswordUnavailable)
	after, err := lockoutCounter(h.TPM.Transport())
	require.NoError(t, err)
	require.Equal(t, before, after, "a failed platform password must not reach the TPM as empty authorization")
}
