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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestExport_NilConnIsANoOp proves the export/unexport helpers tolerate a
// daemon with no live bus connection (the state used by pure-logic unit
// tests throughout this package) instead of panicking, which lets
// createPrompt/resolveUnlockPrompt's own nil-conn guard be exercised
// end-to-end without a loopback bus in every test.
func TestExport_NilConnIsANoOp(t *testing.T) {
	d, err := NewDaemon(newMemoryStore(), newTestBarrier(t), nil, nil)
	require.NoError(t, err)
	require.Nil(t, d.conn)

	collectionPath, err := d.exportCollection("Work")
	require.NoError(t, err)
	assert.Equal(t, d.mapper.CollectionPathFromFolder("Work"), collectionPath)
	d.unexportCollection(collectionPath, nil)

	itemPath, err := d.exportItem(collectionPath, "abc")
	require.NoError(t, err)
	assert.Equal(t, d.mapper.ItemPathFromPassword(collectionPath, "abc"), itemPath)
	d.unexportItem(itemPath)

	sessionPath := d.mapper.SessionPath("1")
	require.NoError(t, d.exportSession(sessionPath))
	d.unexportSession(sessionPath)
}
