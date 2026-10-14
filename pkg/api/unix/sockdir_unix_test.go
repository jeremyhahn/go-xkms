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

//go:build unix

package unix

import (
	"io/fs"
	"os"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeDirInfo is an fs.FileInfo whose Sys value the test chooses.
type fakeDirInfo struct {
	fs.FileInfo
	sys any
}

func (f fakeDirInfo) Sys() any { return f.sys }

// TestCheckSocketDirOwner_RefusesForeignOwner proves a directory owned by
// another uid is refused and one owned by this process is accepted.
func TestCheckSocketDirOwner_RefusesForeignOwner(t *testing.T) {
	foreign := &syscall.Stat_t{Uid: uint32(os.Geteuid()) + 1}

	err := checkSocketDirOwner("/run/xkms", fakeDirInfo{sys: foreign})
	var insecureErr *InsecureSocketDirError
	require.ErrorAs(t, err, &insecureErr)
	assert.Equal(t, "is owned by another user", insecureErr.Reason)

	own := &syscall.Stat_t{Uid: uint32(os.Geteuid())}
	assert.NoError(t, checkSocketDirOwner("/run/xkms", fakeDirInfo{sys: own}))
}

// TestCheckSocketDirOwner_NoOwnerInformation proves a file system that
// reports no ownership leaves the decision to the mode check.
func TestCheckSocketDirOwner_NoOwnerInformation(t *testing.T) {
	assert.NoError(t, checkSocketDirOwner("/run/xkms", fakeDirInfo{sys: nil}))
}
