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

package services

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	sshclient "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// TestSSHService_ResolveBackend_ExplicitChoiceWins covers the branch where
// the caller names a backend directly: it must win over any registry
// default and the registry must never be consulted.
func TestSSHService_ResolveBackend_ExplicitChoiceWins(t *testing.T) {
	s := NewSSHService(nil)
	assert.Equal(t, "tpm2", s.resolveBackend("tpm2"))
}

// TestSSHService_ResolveBackend_NoRegistryFallsBackToEmpty covers the
// branch where no explicit backend is given and no registry is wired: the
// service must report "no default" rather than panic on a nil registry.
func TestSSHService_ResolveBackend_NoRegistryFallsBackToEmpty(t *testing.T) {
	s := NewSSHService(nil)
	assert.Empty(t, s.resolveBackend(""))
}

// TestSSHService_CtxOrBackground_FallsBackBeforeStartup covers the branch
// taken before the Wails startup hook has run: SetContext was never called,
// so s.ctx is nil and the call must fall back to context.Background()
// rather than return a nil context that would panic downstream callers.
func TestSSHService_CtxOrBackground_FallsBackBeforeStartup(t *testing.T) {
	s := NewSSHService(nil)
	ctx := s.ctxOrBackground()
	require := assert.New(t)
	require.NotNil(ctx)
	require.NoError(ctx.Err())
}

// TestSSHService_CtxOrBackground_UsesWiredContext covers the branch where
// SetContext has already run.
func TestSSHService_CtxOrBackground_UsesWiredContext(t *testing.T) {
	s := NewSSHService(nil)
	wired, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.SetContext(wired)

	assert.Same(t, wired, s.ctxOrBackground())
}

// TestKeyToInfo_NilKeyReturnsNil covers keyToInfo's nil guard, exercised
// when the SDK reports no key for a given lookup.
func TestKeyToInfo_NilKeyReturnsNil(t *testing.T) {
	assert.Nil(t, keyToInfo(nil))
}

// TestKeyToInfo_MapsAllFields covers the mapping branch, including the
// CreatedAt RFC3339 formatting.
func TestKeyToInfo_MapsAllFields(t *testing.T) {
	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	k := &sshclient.Key{
		Name:         "id_ed25519",
		Algorithm:    "ed25519",
		PublicKey:    "ssh-ed25519 AAAA...",
		Fingerprint:  "SHA256:abc",
		Comment:      "test@host",
		Backend:      "tpm2",
		BackendKeyID: "key-1",
		CreatedAt:    created,
	}

	info := keyToInfo(k)
	require := assert.New(t)
	require.NotNil(info)
	require.Equal("id_ed25519", info.Name)
	require.Equal("ed25519", info.Algorithm)
	require.Equal("ssh-ed25519 AAAA...", info.PublicKey)
	require.Equal("SHA256:abc", info.Fingerprint)
	require.Equal("test@host", info.Comment)
	require.Equal("tpm2", info.Backend)
	require.Equal("key-1", info.BackendKeyID)
	require.Equal("2026-01-02T03:04:05Z", info.CreatedAt)
}
