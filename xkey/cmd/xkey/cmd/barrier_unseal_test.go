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
	"bytes"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/xhome"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// softwareRootKey is a root key envelope naming the software strategy. The
// tests below fail before its sealed blob is ever opened.
var softwareRootKey = []byte(`{"strategy":"software","sealed":"AAAA"}`)

func TestRunBarrierUnseal_UnresolvableHomeIsError(t *testing.T) {
	assertBarrierRunnerReportsUnresolvableHome(t, runBarrierUnseal)
}

func TestRunBarrierUnseal_PasswordReadFailureIsError(t *testing.T) {
	dir := isolateBarrier(t)
	writeBarrierRootKey(t, dir, softwareRootKey)
	pipeBarrier(t)
	restore := setBarrierStdin(errReader{err: errors.New("pipe broke")})
	t.Cleanup(restore)

	out, err := runBarrierCmd(t, runBarrierUnseal)

	var barrierErr *BarrierError
	require.ErrorAs(t, err, &barrierErr)
	assert.Equal(t, "read_password", barrierErr.Operation)
	assert.NotContains(t, out, "Barrier unsealed successfully.")
}

func TestRunBarrierUnsealAuto_RootKeyWithoutStrategyIsError(t *testing.T) {
	dir := isolateBarrier(t)
	writeBarrierRootKey(t, dir, []byte(`{"sealed":"AAAA"}`))

	err := runBarrierUnsealAuto(newBarrierTestCmd(t), dir)
	require.ErrorIs(t, err, ErrServeRootKeyMissingStrategy)

	var barrierErr *BarrierError
	require.ErrorAs(t, err, &barrierErr)
	assert.Equal(t, "read_strategy", barrierErr.Operation)
}

func TestRunBarrierUnsealAuto_UnresolvableHomeIsError(t *testing.T) {
	dir := isolateBarrier(t)
	writeBarrierRootKey(t, dir, softwareRootKey)
	breakXKeyHome(t)

	err := runBarrierUnsealAuto(newBarrierTestCmd(t), dir)

	var resolveErr *xhome.ResolveError
	require.ErrorAs(t, err, &resolveErr)
	var barrierErr *BarrierError
	require.ErrorAs(t, err, &barrierErr)
	assert.Equal(t, "resolve_home", barrierErr.Operation)
}

// newBarrierTestCmd returns a command whose output is discarded into a
// buffer, for runners that take a command and a data directory.
func newBarrierTestCmd(t *testing.T) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{}
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetContext(t.Context())
	return cmd
}
