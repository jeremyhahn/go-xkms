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

//go:build pkcs11

package xkms

import (
	"testing"

	"github.com/stretchr/testify/require"

	pkcs11backend "github.com/jeremyhahn/go-xkms/pkg/backend/pkcs11"
)

// TestReexport_PKCS11SessionPoolLogin pins the session-pool login sentinel,
// so xkey matches it with errors.Is through sdk/go.
func TestReexport_PKCS11SessionPoolLogin(t *testing.T) {
	require.Same(t, pkcs11backend.ErrSessionPoolLogin, ErrPKCS11SessionPoolLogin)
}
