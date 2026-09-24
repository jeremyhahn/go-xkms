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
	"errors"
	"testing"

	"github.com/godbus/dbus/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
)

// errAuditSinkDown is injected by failingAuditLogger to exercise the
// SeveritySecurity write-failure path (go-xkms#688/#765): a failed
// security-event audit write must refuse the operation it would have
// recorded, not let it silently proceed unaudited.
var errAuditSinkDown = errors.New("audit sink unavailable")

// failingAuditLogger always fails to persist, for tests that must observe
// every SeveritySecurity operation in this package fail closed rather than
// succeed unaudited.
type failingAuditLogger struct {
	audit.Logger
}

func (failingAuditLogger) Log(audit.Entry) error { return errAuditSinkDown }

func TestDaemon_Lock_AuditWriteFailureFailsTheCall(t *testing.T) {
	d := newBusDaemon(t, newMemoryStore()).Daemon
	d.SetAuditLogger(failingAuditLogger{})

	_, _, dbusErr := d.Lock(nil)
	require.NotNil(t, dbusErr)
	assert.Contains(t, dbusErr.Error(), errAuditSinkDown.Error())
	assert.True(t, d.barrier.IsSealed(), "Seal already succeeded and stays sealed -- the fail-safe direction -- even though the call reports failure")
}

func TestDaemon_Unlock_AlreadyUnsealed_AuditWriteFailureFailsTheCall(t *testing.T) {
	d := newBusDaemon(t, newMemoryStore()).Daemon
	d.SetAuditLogger(failingAuditLogger{})

	_, _, dbusErr := d.Unlock(nil)
	require.NotNil(t, dbusErr)
	assert.Contains(t, dbusErr.Error(), errAuditSinkDown.Error())
}

// TestPrompt_ResolvesUnlock_AuditWriteFailureReSeals is the regression test
// for this package's most security-sensitive line: a successful Unseal
// whose audit write then fails must not leave the barrier open on an action
// nobody could prove happened (see resolveUnlockPrompt's doc comment).
func TestPrompt_ResolvesUnlock_AuditWriteFailureReSeals(t *testing.T) {
	barrier := newTestBarrier(t)
	d := newBusDaemonWithBarrier(t, newMemoryStore(), barrier).Daemon
	require.NoError(t, barrier.Seal())
	d.SetAuditLogger(failingAuditLogger{})

	d.SetUnlockFunc(func(ctx context.Context) (xkms.SealCredentials, error) {
		return testCredentials(t), nil
	})

	collectionPath := d.mapper.CollectionPathFromFolder("")
	_, promptPath, dbusErr := d.Unlock([]dbus.ObjectPath{collectionPath})
	require.Nil(t, dbusErr, "creating the prompt itself is not a SeveritySecurity write")

	p := &promptObject{daemon: d, path: promptPath}
	promptErr := p.Prompt("")
	require.NotNil(t, promptErr)
	assert.Contains(t, promptErr.Error(), errAuditSinkDown.Error())
	assert.True(t, barrier.IsSealed(), "an unlock that could not be audited must not leave the barrier open")
}

func TestCollection_CreateItem_AuditWriteFailureFailsTheCall(t *testing.T) {
	d := newBusDaemon(t, newMemoryStore()).Daemon
	collectionPath, err := d.exportCollection("Work")
	require.NoError(t, err)
	c := &collectionObject{daemon: d, path: collectionPath, folder: "Work"}

	// Obtain the session before installing the failing logger: OpenSession
	// audits too, and this test's failingAuditLogger fails every write
	// unconditionally (a real Logger only fails the caller for
	// SeveritySecurity ops -- see audit.handleWriteFailure -- but that
	// distinction is applied inside the Logger implementation, not by this
	// package, so a blanket-failing test double would fail OpenSession as
	// well if installed first).
	secret := testSecret(t, d, "s3cret")
	d.SetAuditLogger(failingAuditLogger{})

	_, _, dbusErr := c.CreateItem(map[string]dbus.Variant{
		"org.freedesktop.Secret.Item.Label": dbus.MakeVariant("GitHub"),
	}, secret, false)
	require.NotNil(t, dbusErr)
	assert.Contains(t, dbusErr.Error(), errAuditSinkDown.Error())
}

func TestItem_Delete_AuditWriteFailureFailsTheCall(t *testing.T) {
	store := newMemoryStore()
	d := newBusDaemon(t, store).Daemon
	item := newTestItem(t, d, store, &xkms.StaticPassword{ID: "gh", Name: "GitHub", Password: "s3cret"})
	d.SetAuditLogger(failingAuditLogger{})

	_, dbusErr := item.Delete()
	require.NotNil(t, dbusErr)
	assert.Contains(t, dbusErr.Error(), errAuditSinkDown.Error())
}
