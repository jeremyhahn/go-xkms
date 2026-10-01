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

package xkms

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// TestServicer_PKCS11State_RefusesPathsAStoreWouldResolve covers the token
// labels and keys a path-normalizing store (file storage) would resolve out of
// the token's namespace.
func TestServicer_PKCS11State_RefusesPathsAStoreWouldResolve(t *testing.T) {
	svc := newPKCS11StateService(t)
	ctx := context.Background()

	for _, token := range []string{".", ".."} {
		_, err := svc.PKCS11StateGet(ctx, &transport.PKCS11StateGetRequest{Token: token, Key: "k"})
		assert.ErrorIs(t, err, ErrPKCS11StateTokenDotSegment, "token %q", token)
		assert.True(t, IsPKCS11StateRequestError(err))
	}

	for _, key := range []string{"../other/k", "pkcs11/../x", "a//b", "/abs", "./k", "a/."} {
		_, err := svc.PKCS11StatePut(ctx, &transport.PKCS11StatePutRequest{Token: "tok0", Key: key, Value: []byte("v")})
		assert.ErrorIs(t, err, ErrPKCS11StateKeyPath, "key %q", key)
		assert.True(t, IsPKCS11StateRequestError(err))
	}

	_, err := svc.PKCS11StateList(ctx, &transport.PKCS11StateListRequest{Token: "tok0", Prefix: "pkcs11/../"})
	assert.ErrorIs(t, err, ErrPKCS11StateKeyPath)

	// The module's own hierarchical keys and list prefixes are accepted.
	_, err = svc.PKCS11StatePut(ctx, &transport.PKCS11StatePutRequest{Token: "tok0", Key: "pkcs11/objects/1", Value: []byte("v")})
	require.NoError(t, err)
	resp, err := svc.PKCS11StateList(ctx, &transport.PKCS11StateListRequest{Token: "tok0", Prefix: "pkcs11/objects/"})
	require.NoError(t, err)
	assert.Equal(t, []string{"pkcs11/objects/1"}, resp.Keys)
}
