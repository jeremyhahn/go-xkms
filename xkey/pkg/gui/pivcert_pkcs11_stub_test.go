// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

//go:build !pkcs11

package gui

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// TestApp_RegisterPKCS11PIVStore_NotAvailable verifies the non-pkcs11 build
// registers no on-token PIV storage and logs the typed reason, without the
// PINs it was handed.
func TestApp_RegisterPKCS11PIVStore_NotAvailable(t *testing.T) {
	logs := &logBuffer{}
	app := &App{log: slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))}

	app.registerPKCS11PIVStore("softhsm", &xkms.PKCS11Connection{}, "so-pin", "user-pin")

	require.True(t, logs.Contains("PKCS#11 PIV cert storage not available"))
	assert.True(t, logs.Contains(xkms.ErrPIVPKCS11NotAvailable.Error()))
	assert.False(t, logs.Contains("registered PKCS#11 PIV cert storage"))
	assert.False(t, logs.Contains("so-pin"), "a PIN must never reach the log")
}
