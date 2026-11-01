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

package tpm2

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
)

// TestRSADecrypt_NilKeyAttributes tests error handling for nil key
// attributes before any TPM command.
func TestRSADecrypt_NilKeyAttributes(t *testing.T) {
	tpm := &TPM2{}
	_, err := tpm.RSADecrypt(nil, nil, []byte{1})
	if err != store.ErrInvalidKeyAttributes {
		t.Errorf("expected ErrInvalidKeyAttributes, got %v", err)
	}
}
