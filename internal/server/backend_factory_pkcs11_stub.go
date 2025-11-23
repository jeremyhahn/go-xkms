// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build !pkcs11

package server

import (
	"fmt"

	"github.com/jeremyhahn/go-keychain/pkg/types"
)

func createPKCS11Backend(config BackendConfig) (types.Backend, error) {
	return nil, fmt.Errorf("PKCS11 backend not compiled in (use -tags pkcs11)")
}
