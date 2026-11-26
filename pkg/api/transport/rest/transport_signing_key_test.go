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

package rest

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jeremyhahn/go-xkms/pkg/api/rest/wire"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/signingkeytest"
)

// TestSigningKey_RefusesANilRequest proves a connected transport hands its
// calls to the wire client, which refuses a nil request.
func TestSigningKey_RefusesANilRequest(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	_, err := tr.ResolveSigningKey(context.Background(), nil)
	assert.ErrorIs(t, err, wire.ErrNilRequest)
	assert.ErrorIs(t, tr.DeleteSigningKeyBinding(context.Background(), nil), wire.ErrNilRequest)
	_, err = tr.SetSigningKeyBinding(context.Background(), nil)
	assert.ErrorIs(t, err, wire.ErrNilRequest)
	_, err = tr.GetSigningKeyBinding(context.Background(), nil)
	assert.ErrorIs(t, err, wire.ErrNilRequest)
	_, err = tr.SignCoRIM(context.Background(), nil)
	assert.ErrorIs(t, err, wire.ErrNilRequest)
}

// TestSigningKey_NotConnected proves every signing-key method refuses
// before the transport is connected.
func TestSigningKey_NotConnected(t *testing.T) {
	for name, call := range signingkeytest.Calls(context.Background(), &Transport{}) {
		t.Run(name, func(t *testing.T) { assert.ErrorIs(t, call(), ErrNotConnected) })
	}
}
