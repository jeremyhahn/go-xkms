// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

//go:build vault

package vault

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"os/exec"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/aead"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/require"
)

// TestWrapKey_AgreesWithArbitraryIVGCMUsable exercises WrapKey's BYOK
// ceremony against whatever this process actually is: Vault's wire format
// mandates the all-zero nonce sealed under an ephemeral, single-use key, an
// interop framing with no substitute AEAD construction, so WrapKey must
// succeed when this process can construct arbitrary-IV GCM and fail closed
// with aead.ErrArbitraryIVGCMUnavailable when it cannot
// (GODEBUG=fips140=only), rather than relaying the runtime's own refusal
// from inside Seal.
func TestWrapKey_AgreesWithArbitraryIVGCMUsable(t *testing.T) {
	b, _ := newVaultTestBackend(t)
	ctx := context.Background()

	keyMaterial := make([]byte, 32)
	_, err := rand.Read(keyMaterial)
	require.NoError(t, err)

	attrs := &types.KeyAttributes{
		CN:                 "wrapkey-fips-gate",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_VAULT,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		Exportable:         true,
	}

	params, err := b.GetImportParameters(ctx, attrs, backend.WrappingAlgorithmVaultTransitBYOK)
	require.NoError(t, err)

	wrapped, err := b.WrapKey(ctx, keyMaterial, params)

	if aead.ArbitraryIVGCMUsable() {
		require.NoError(t, err)
		require.NotEmpty(t, wrapped.WrappedKey)
		return
	}
	require.Nil(t, wrapped)
	require.Error(t, err)
	require.True(t, errors.Is(err, aead.ErrArbitraryIVGCMUnavailable),
		"WrapKey error = %v, want aead.ErrArbitraryIVGCMUnavailable", err)
}

// TestWrapKey_FIPS140Only re-execs the test binary under
// GODEBUG=fips140=only, the one mode where WrapKey must diverge from its
// ordinary behavior, so the fail-closed path in
// TestWrapKey_AgreesWithArbitraryIVGCMUsable is exercised directly rather
// than only when the host happens to already be FIPS 140-only.
func TestWrapKey_FIPS140Only(t *testing.T) {
	if mode := os.Getenv("XKMS_VAULT_FIPS_SUBPROCESS"); mode != "" {
		if aead.ArbitraryIVGCMUsable() {
			t.Fatal("ArbitraryIVGCMUsable() = true under fips140=only")
		}
		TestWrapKey_AgreesWithArbitraryIVGCMUsable(t)
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestWrapKey_FIPS140Only$", "-test.v")
	cmd.Env = append(os.Environ(), "XKMS_VAULT_FIPS_SUBPROCESS=only", "GODEBUG=fips140=only")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("fips140=only subprocess failed: %v\n%s", err, out)
	}
	if !bytes.Contains(out, []byte("PASS")) {
		t.Fatalf("fips140=only subprocess did not pass:\n%s", out)
	}
	if bytes.Contains(out, []byte("panic:")) {
		t.Fatalf("fips140=only subprocess panicked:\n%s", out)
	}
}
