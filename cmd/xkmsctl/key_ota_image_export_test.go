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

package main

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
)

func TestKeyOTAImageExportCmd_Registered(t *testing.T) {
	sub, _, err := keyOTAImageCmd.Find([]string{"export"})
	require.NoError(t, err)
	assert.Equal(t, "export", sub.Name())
}

// TestKeyOTAImageExportCmd checks that export prints the key id, the board
// id, the current version and the raw public key of a board's OTA image key.
func TestKeyOTAImageExportCmd(t *testing.T) {
	mock := &mockOTAImageClient{}
	out, _, code := runOTAImageCmd(t, mock, keyOTAImageExportCmd, []string{"cm4"}, nil)
	assert.Equal(t, -1, code)
	assert.Contains(t, out, "ota-image-cm4")
	assert.Contains(t, out, "Board ID: cm4")
	assert.Contains(t, out, "Version: 2")
	assert.Contains(t, out, hex.EncodeToString(bytes.Repeat([]byte{0xab}, 64)))
	assert.Equal(t, &client.OTAImageKeyRequest{Backend: "software", BoardID: "cm4"}, mock.keyReq)
}

// TestKeyOTAImageExportCmd_NotFound checks that export fails for a board
// that has no OTA image key.
func TestKeyOTAImageExportCmd_NotFound(t *testing.T) {
	out, stderr, code := runOTAImageCmd(t, &mockOTAImageClient{}, keyOTAImageExportCmd, []string{otaMissingBoard}, nil)
	assert.Equal(t, 1, code)
	assert.Contains(t, stderr, ErrExportOTAImagePublicKeyFailed.Error())
	assert.Contains(t, stderr, errOTANoKey.Error())
	assert.Empty(t, out)
}
