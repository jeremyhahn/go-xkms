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
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestSecretServiceUnlockFunc_FlagPassword exercises the closure without
// ever reaching its interactive-terminal fallback: a non-empty
// --barrier-password resolves before readBarrierPassword is consulted, so
// this never touches os.Stdin.
func TestSecretServiceUnlockFunc_FlagPassword(t *testing.T) {
	cmd := newSecretServicePasswordTestCmd()
	require.NoError(t, cmd.Flags().Set("barrier-password", "unlock-me"))
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	unlock := secretServiceUnlockFunc(cmd)
	creds, err := unlock(context.Background())
	require.NoError(t, err)
	require.NotNil(t, creds)
	require.Empty(t, buf.String(), "a pre-resolved password must never print an interactive prompt")
}

func TestSecretServiceUnlockFunc_FileReadFailurePropagates(t *testing.T) {
	cmd := newSecretServicePasswordTestCmd()
	require.NoError(t, cmd.Flags().Set("barrier-password-file", filepath.Join(t.TempDir(), "missing.txt")))

	unlock := secretServiceUnlockFunc(cmd)
	_, err := unlock(context.Background())
	require.ErrorIs(t, err, ErrSecretServiceUnlockFailed)
}
