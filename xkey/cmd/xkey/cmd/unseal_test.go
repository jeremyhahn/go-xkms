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
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadUnsealPassphrase_ReadFailureIsUnsealError(t *testing.T) {
	closeStdin(t)

	got, err := readUnsealPassphrase(io.Discard)
	require.ErrorIs(t, err, os.ErrClosed)

	var unsealErr *UnsealError
	require.ErrorAs(t, err, &unsealErr)
	assert.Equal(t, "read_passphrase", unsealErr.Operation)
	assert.Empty(t, got)
}

func TestCreateUnsealVolume_FallsBackToXKeyHome(t *testing.T) {
	assertVolumeFallsBackToXKeyHome(t, createUnsealVolume)
}

func TestCreateUnsealVolume_UnresolvableHomeIsError(t *testing.T) {
	assertVolumeReportsUnresolvableHome(t, createUnsealVolume)
}
