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

package xkms

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestErrSealedDataAuthentication_ReExport proves the SDK sentinel is the
// library's own, so an SDK consumer's errors.Is matches what every Sealer
// returns, and does not match an unrelated sentinel.
func TestErrSealedDataAuthentication_ReExport(t *testing.T) {
	sealerErr := types.SealedDataAuthenticationError("aead open", errors.New("cipher: message authentication failed"))
	if !errors.Is(sealerErr, ErrSealedDataAuthentication) {
		t.Fatal("a Sealer's authentication failure must match the SDK sentinel")
	}
	if errors.Is(ErrInvalidKeyStore, ErrSealedDataAuthentication) {
		t.Fatal("the SDK sentinel must not match an unrelated error")
	}
}
