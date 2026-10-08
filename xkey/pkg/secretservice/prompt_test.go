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

package secretservice

import (
	"context"
	"testing"

	"github.com/godbus/dbus/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

func TestPrompt_ResolvesUnlock(t *testing.T) {
	barrier := newTestBarrier(t)
	d := newBusDaemonWithBarrier(t, newMemoryStore(), barrier).Daemon
	require.NoError(t, barrier.Seal())

	auditLog := &recordingAudit{}
	d.SetAuditLogger(auditLog)

	called := false
	d.SetUnlockFunc(func(ctx context.Context) (xkms.SealCredentials, error) {
		called = true
		return testCredentials(t), nil
	})

	collectionPath := d.mapper.CollectionPathFromFolder("")
	_, promptPath, dbusErr := d.Unlock([]dbus.ObjectPath{collectionPath})
	require.Nil(t, dbusErr)
	require.NotEqual(t, dbus.ObjectPath("/"), promptPath)

	p := &promptObject{daemon: d, path: promptPath}
	promptErr := p.Prompt("")
	require.Nil(t, promptErr)
	assert.True(t, called)
	assert.False(t, barrier.IsSealed())

	d.promptsMu.Lock()
	_, stillPending := d.prompts[promptPath]
	d.promptsMu.Unlock()
	assert.False(t, stillPending, "a resolved prompt must be removed from the pending table")

	var sawUnlockSuccess bool
	for _, e := range auditLog.recorded() {
		if e.Operation == "secretservice_unlock" && e.Success {
			sawUnlockSuccess = true
		}
	}
	assert.True(t, sawUnlockSuccess, "a successful prompt-driven unlock must be audited")
}

func TestPrompt_NoUnlockFuncDismisses(t *testing.T) {
	barrier := newTestBarrier(t)
	d := newBusDaemonWithBarrier(t, newMemoryStore(), barrier).Daemon
	require.NoError(t, barrier.Seal())

	collectionPath := d.mapper.CollectionPathFromFolder("")
	_, promptPath, dbusErr := d.Unlock([]dbus.ObjectPath{collectionPath})
	require.Nil(t, dbusErr)

	p := &promptObject{daemon: d, path: promptPath}
	promptErr := p.Prompt("")
	require.Nil(t, promptErr)
	assert.True(t, barrier.IsSealed(), "barrier must remain sealed with no configured unlock function")
}

func TestPrompt_WrongCredentialsDismisses(t *testing.T) {
	barrier := newTestBarrier(t)
	d := newBusDaemonWithBarrier(t, newMemoryStore(), barrier).Daemon
	require.NoError(t, barrier.Seal())

	d.SetUnlockFunc(func(ctx context.Context) (xkms.SealCredentials, error) {
		creds, err := xkms.CredentialsFor(t.Context(), []byte("totally-wrong-password"))
		require.NoError(t, err)
		return creds, nil
	})

	collectionPath := d.mapper.CollectionPathFromFolder("")
	_, promptPath, dbusErr := d.Unlock([]dbus.ObjectPath{collectionPath})
	require.Nil(t, dbusErr)

	p := &promptObject{daemon: d, path: promptPath}
	promptErr := p.Prompt("")
	require.Nil(t, promptErr)
	assert.True(t, barrier.IsSealed(), "a wrong password must never unseal the barrier")
}

func TestPrompt_Dismiss(t *testing.T) {
	barrier := newTestBarrier(t)
	d := newBusDaemonWithBarrier(t, newMemoryStore(), barrier).Daemon
	require.NoError(t, barrier.Seal())

	collectionPath := d.mapper.CollectionPathFromFolder("")
	_, promptPath, dbusErr := d.Unlock([]dbus.ObjectPath{collectionPath})
	require.Nil(t, dbusErr)

	p := &promptObject{daemon: d, path: promptPath}
	dismissErr := p.Dismiss()
	require.Nil(t, dismissErr)
	assert.True(t, barrier.IsSealed())

	// A second resolution attempt on the same prompt must be rejected: the
	// resolved prompt was removed from the pending table by completePrompt,
	// so the lookup itself now fails (ErrPromptAlreadyResolved guards the
	// narrower race where two callers hold the same *PromptInfo
	// concurrently; here the second call arrives after cleanup).
	dismissErr = p.Dismiss()
	require.NotNil(t, dismissErr)
	assert.Contains(t, dismissErr.Error(), ErrPromptNotFound.Error())
}

func TestPrompt_UnknownPath(t *testing.T) {
	d := newBusDaemon(t, newMemoryStore()).Daemon
	p := &promptObject{daemon: d, path: "/no/such/prompt"}

	promptErr := p.Prompt("")
	require.NotNil(t, promptErr)
	assert.Contains(t, promptErr.Error(), ErrPromptNotFound.Error())

	dismissErr := p.Dismiss()
	require.NotNil(t, dismissErr)
	assert.Contains(t, dismissErr.Error(), ErrPromptNotFound.Error())
}
