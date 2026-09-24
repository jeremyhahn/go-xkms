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
	"testing"

	"github.com/godbus/dbus/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSessionObject_Close proves Session.Close is reachable as its own
// exported D-Bus object (org.freedesktop.Secret.Session.Close), which is
// what the freedesktop Secret Service spec requires, rather than only
// through the previous non-spec Service.CloseSession entry point.
func TestSessionObject_Close(t *testing.T) {
	d := newBusDaemon(t, newMemoryStore()).Daemon

	_, sessionPath, dbusErr := d.OpenSession(testSender, AlgorithmPlain, dbus.MakeVariant(""))
	require.Nil(t, dbusErr)

	_, ok := d.getSession(sessionPath)
	require.True(t, ok)

	sess := &sessionObject{daemon: d, path: sessionPath}
	closeErr := sess.Close()
	require.Nil(t, closeErr)

	_, ok = d.getSession(sessionPath)
	assert.False(t, ok, "Close must remove the session")
}

func TestSessionObject_Close_UnknownSession(t *testing.T) {
	d := newBusDaemon(t, newMemoryStore()).Daemon

	sess := &sessionObject{daemon: d, path: "/no/such/session"}
	closeErr := sess.Close()
	require.NotNil(t, closeErr)
	assert.Contains(t, closeErr.Error(), ErrSessionNotFound.Error())
}
