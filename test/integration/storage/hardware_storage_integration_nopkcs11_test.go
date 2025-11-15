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

//go:build integration && tpm2 && !pkcs11

package storage_test

import (
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/storage/hardware"
)

// tryInitSoftHSM is a stub that returns nil when PKCS11 support is not compiled in.
func tryInitSoftHSM(t *testing.T) hardware.HardwareCertStorage {
	return nil
}
