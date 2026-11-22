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
	"log/slog"
	"testing"

	"github.com/godbus/dbus/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// credentialFreeStrategy stands in for a hardware or auto-unseal factor: it
// ignores the caller's credentials and seals under a fixed secret of its own,
// so the barrier opens with the zero SealCredentials.
type credentialFreeStrategy struct {
	xkms.SealingStrategy
}

func (s credentialFreeStrategy) own(ctx context.Context) xkms.SealCredentials {
	return xkms.MustCredentials(ctx, []byte("hardware-held-secret-12345"))
}

func (s credentialFreeStrategy) SealRootKey(ctx context.Context, key []byte, _ xkms.SealCredentials) (*xkms.SealedRootKey, error) {
	creds := s.own(ctx)
	defer creds.Secret.Destroy()
	return s.SealingStrategy.SealRootKey(ctx, key, creds)
}

func (s credentialFreeStrategy) UnsealRootKey(ctx context.Context, sealed *xkms.SealedRootKey, _ xkms.SealCredentials) ([]byte, error) {
	creds := s.own(ctx)
	defer creds.Secret.Destroy()
	return s.SealingStrategy.UnsealRootKey(ctx, sealed, creds)
}

// zeroCredentials is what CredentialsFor returns for an empty secret: the
// zero SealCredentials, whose Secret is a nil interface.
func zeroCredentials(t *testing.T) xkms.SealCredentials {
	t.Helper()
	creds, err := xkms.CredentialsFor(t.Context(), nil)
	require.NoError(t, err)
	require.Nil(t, creds.Secret, "an empty secret yields the zero credentials")
	return creds
}

func promptUnlock(t *testing.T, d *Daemon) *dbus.Error {
	t.Helper()
	_, promptPath, dbusErr := d.Unlock([]dbus.ObjectPath{d.mapper.CollectionPathFromFolder("")})
	require.Nil(t, dbusErr)
	require.NotEqual(t, dbus.ObjectPath("/"), promptPath)
	p := &promptObject{daemon: d, path: promptPath}
	var promptErr *dbus.Error
	require.NotPanics(t, func() { promptErr = p.Prompt("") })
	return promptErr
}

// TestPrompt_ZeroCredentialUnlockUnseals: an unlock callback for a factor
// that needs no secret returns the zero credentials; the prompt unseals the
// barrier without panicking on the nil Secret.
func TestPrompt_ZeroCredentialUnlockUnseals(t *testing.T) {
	backend := xkms.NewStorageMemory()
	strategy := credentialFreeStrategy{SealingStrategy: xkms.NewSoftwareSealStrategy()}
	barrier, err := xkms.NewBarrier(slog.New(slog.DiscardHandler), backend, xkms.BarrierConfig{
		RootKeyPath:     "barrier/root_key",
		PreferenceOrder: []xkms.StrategyID{strategy.ID()},
	}, strategy)
	require.NoError(t, err)
	require.NoError(t, barrier.Initialize(t.Context(), zeroCredentials(t)))

	d := newBusDaemonWithBarrier(t, newMemoryStore(), barrier).Daemon
	require.NoError(t, barrier.Seal())
	auditLog := &recordingAudit{}
	d.SetAuditLogger(auditLog)
	d.SetUnlockFunc(func(context.Context) (xkms.SealCredentials, error) {
		return zeroCredentials(t), nil
	})

	require.Nil(t, promptUnlock(t, d))
	assert.False(t, barrier.IsSealed())
	var sawSuccess bool
	for _, e := range auditLog.recorded() {
		if e.Operation == "secretservice_unlock" && e.Success {
			sawSuccess = true
		}
	}
	assert.True(t, sawSuccess, "the unlock is audited as a success")
}

// TestPrompt_ZeroCredentialUnsealErrorReported: when the barrier refuses the
// zero credentials, the prompt still completes without panicking and the
// unseal error is reported in the failure audit entry.
func TestPrompt_ZeroCredentialUnsealErrorReported(t *testing.T) {
	barrier := newTestBarrier(t)
	d := newBusDaemonWithBarrier(t, newMemoryStore(), barrier).Daemon
	require.NoError(t, barrier.Seal())
	auditLog := &recordingAudit{}
	d.SetAuditLogger(auditLog)
	d.SetUnlockFunc(func(context.Context) (xkms.SealCredentials, error) {
		return zeroCredentials(t), nil
	})

	require.Nil(t, promptUnlock(t, d))
	assert.True(t, barrier.IsSealed())
	var failure string
	for _, e := range auditLog.recorded() {
		if e.Operation == "secretservice_unlock" && !e.Success {
			failure = e.Error
		}
	}
	assert.NotEmpty(t, failure, "the unseal error is reported in the failure audit entry")
}
