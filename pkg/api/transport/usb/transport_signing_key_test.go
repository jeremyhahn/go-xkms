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

package usb

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jeremyhahn/go-xkms/pkg/testutil/signingkeytest"
)

// TestSigningKey_NotSupported proves no signing-key method is served over
// USB.
func TestSigningKey_NotSupported(t *testing.T) {
	calls := signingkeytest.Calls(context.Background(), &Transport{})
	assert.Len(t, calls, 7, "every method of transport.SigningKeyService")
	for name, call := range calls {
		t.Run(name, func(t *testing.T) { assert.ErrorIs(t, call(), ErrNotSupported) })
	}
}
