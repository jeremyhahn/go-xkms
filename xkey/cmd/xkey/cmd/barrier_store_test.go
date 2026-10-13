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

package cmd

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/xhome"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpenBarrierBackend_UnresolvableHomeIsError(t *testing.T) {
	dir := isolateBarrier(t)
	writeBarrierRootKey(t, dir, softwareRootKey)
	breakXKeyHome(t)

	backend, err := openBarrierBackend("correct-horse", dir, "", false)
	var resolveErr *xhome.ResolveError
	require.ErrorAs(t, err, &resolveErr)
	assert.Nil(t, backend)
}

func TestOpenBarrierBackend_UninitializedBarrierIsError(t *testing.T) {
	dir := isolateBarrier(t)
	t.Setenv(xhome.EnvHome, t.TempDir())

	backend, err := openBarrierBackend("correct-horse", dir, "", false)
	require.Error(t, err)
	assert.Nil(t, backend)
	assert.False(t, barrierRootKeyExists(dir), "opening must never create a root key")
}
