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

// TestOpenSession_FIPSRefusesDH proves that under FIPS 140 enforcement,
// OpenSession refuses dh-ietf1024-sha256-aes128-cbc-pkcs7 and offers only
// the plain algorithm over the local session bus (go-xkms#723 scope item 3).
func TestOpenSession_FIPSRefusesDH(t *testing.T) {
	d := newBusDaemon(t, newMemoryStore()).Daemon

	original := fipsMode
	fipsMode = func() bool { return true }
	t.Cleanup(func() { fipsMode = original })

	auditLog := &recordingAudit{}
	d.SetAuditLogger(auditLog)

	keyPair, err := GenerateDHKeyPair()
	require.NoError(t, err)

	_, path, dbusErr := d.OpenSession(testSender, AlgorithmDH, dbus.MakeVariant(PublicKeyToBytes(keyPair.Public)))
	require.NotNil(t, dbusErr)
	assert.Equal(t, dbus.ObjectPath("/"), path)
	assert.Contains(t, dbusErr.Error(), ErrAlgorithmNotFIPSApproved.Error())
	assert.Empty(t, d.sessions, "a FIPS-refused algorithm must not create a session")

	entries := auditLog.recorded()
	require.Len(t, entries, 1)
	assert.False(t, entries[0].Success)
}

// TestOpenSession_FIPSStillAllowsPlain proves the plain algorithm remains
// available under FIPS enforcement -- only dh-ietf1024 is refused.
func TestOpenSession_FIPSStillAllowsPlain(t *testing.T) {
	d := newBusDaemon(t, newMemoryStore()).Daemon

	original := fipsMode
	fipsMode = func() bool { return true }
	t.Cleanup(func() { fipsMode = original })

	_, path, dbusErr := d.OpenSession(testSender, AlgorithmPlain, dbus.MakeVariant(""))
	require.Nil(t, dbusErr)
	assert.NotEqual(t, dbus.ObjectPath("/"), path)
}
