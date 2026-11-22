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

package usb

import (
	"testing"

	enclave "github.com/jeremyhahn/go-enclave"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// TestAdmitPassphraseCopy_ByteAccess pins the go-enclave v0.11.1 contract the
// LUKS passphrase path relies on: the copy is an enclave.ByteAccess (the type
// go-luks2 Format and Unlock take) holding exactly the passphrase, it is a
// frozen Freezer, and it releases on Destroy.
func TestAdmitPassphraseCopy_ByteAccess(t *testing.T) {
	const phrase = "correct horse battery staple"
	buf, err := secure.NewBufferFromBytes([]byte(phrase))
	require.NoError(t, err)
	t.Cleanup(buf.Destroy)

	var pass enclave.ByteAccess
	pass, err = admitPassphraseCopy(buf)
	require.NoError(t, err)
	require.Equal(t, len(phrase), pass.Size())

	equal, err := pass.EqualTo([]byte(phrase))
	require.NoError(t, err)
	require.True(t, equal, "passphrase copy does not hold the passphrase")

	_, isFreezer := pass.(enclave.Freezer)
	require.True(t, isFreezer, "passphrase copy must be freezable (read-only)")

	require.NoError(t, pass.Destroy())
	require.False(t, pass.IsAlive())
}
