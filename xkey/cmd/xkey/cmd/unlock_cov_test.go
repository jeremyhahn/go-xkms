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
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/ipc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// failingStatusHandler grants the unlock but cannot answer a status query.
type failingStatusHandler struct {
	unlockTestHandler
}

func (h *failingStatusHandler) HandleStatus() (*ipc.Response, error) {
	return nil, errors.New("status backend down")
}

func TestRunUnlock_MissingUnlockResultIsAFailure(t *testing.T) {
	sock := serveUnlockDaemon(t, &unlockTestHandler{statusAction: ipc.ActionUnlocked})

	cmd, out := newUnlockTestCmd(t, sock, "1234")
	err := runUnlock(cmd, nil)

	require.ErrorIs(t, err, ErrUnlockFailed)
	assert.NotContains(t, out.String(), "Unlocked", "a missing answer must not be read as success")
}

func TestRunUnlock_FailedStatusQueryIsAFailure(t *testing.T) {
	sock := serveUnlockDaemon(t, &failingStatusHandler{unlockTestHandler{
		unlockResult: &ipc.UnlockResult{Success: true},
	}})

	cmd, out := newUnlockTestCmd(t, sock, "1234")
	err := runUnlock(cmd, nil)

	require.ErrorIs(t, err, ErrUnlockFailed)
	assert.Contains(t, err.Error(), "status query failed")
	assert.NotContains(t, out.String(), "Unlocked", "an unconfirmed unlock must not print a success line")
}
