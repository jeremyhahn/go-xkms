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

	"github.com/jeremyhahn/go-xkms/pkg/testutil/oidccredentialtest"
)

// TestOIDCCredential_NotSupported proves every OIDC credential method
// refuses with ErrNotSupported, whatever its request: the paired phone holds
// no server-side credentials.
func TestOIDCCredential_NotSupported(t *testing.T) {
	calls := oidccredentialtest.Calls(context.Background(), &Transport{})
	assert.Len(t, calls, 9, "every method of transport.OIDCCredentialService")
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			assert.ErrorIs(t, call(), ErrNotSupported)
		})
	}
}
