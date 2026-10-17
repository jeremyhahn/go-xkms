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

	"github.com/jeremyhahn/go-xkms/xkey/pkg/luks"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/xhome"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func TestCreateLockVolume_FallsBackToXKeyHome(t *testing.T) {
	assertVolumeFallsBackToXKeyHome(t, createLockVolume)
}

func TestCreateLockVolume_UnresolvableHomeIsError(t *testing.T) {
	assertVolumeReportsUnresolvableHome(t, createLockVolume)
}

func TestRunLock_RequiresRoot(t *testing.T) {
	withEUID(t, 1000)

	err := runLock(&cobra.Command{Use: "lock"}, nil)
	require.ErrorIs(t, err, luks.ErrPermissionDenied)
}

func TestRunLock_UnresolvableHomeIsError(t *testing.T) {
	withEUID(t, 0)
	useXKeyHomeFallback(t)
	breakXKeyHome(t)

	err := runLock(&cobra.Command{Use: "lock"}, nil)
	var resolveErr *xhome.ResolveError
	require.ErrorAs(t, err, &resolveErr)
}
