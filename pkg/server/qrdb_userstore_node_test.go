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

package server

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"

	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// TestQRDBUserStore_EmbeddedNodeAnswersAnonymousLookup proves the admin
// plane's certificate lookup reaches the embedded node's user service. The
// node's auth chain refuses an anonymous client call, so a lookup made through
// the client would fail authentication; through the user service an unbound
// thumbprint is answered with qrdb's typed not-found, in the tenant the
// caller's certificate names.
func TestQRDBUserStore_EmbeddedNodeAnswersAnonymousLookup(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	server, err := New(qrdbBarrierConfig(t))
	require.NoError(t, err)
	defer func() { require.NoError(t, server.Shutdown()) }()

	store := server.QRDBUserStore()
	require.NotNil(t, store)
	for _, tenantID := range []string{qrdbsdk.SystemTenantID, "tenant-a"} {
		ctx := qrdbsdk.ContextWithTenant(context.Background(), tenantID)
		_, err := store.GetByCertFingerprint(ctx, "unbound-thumbprint")
		var notFound *qrdbsdk.UserNotFoundError
		assert.ErrorAs(t, err, &notFound, "tenant %q: the lookup must be answered, not refused", tenantID)
	}
}

// TestNodeCertUsers_NodeNotBooted proves a lookup against a node that has not
// published its user service fails with ErrQRDBNodeNotServing.
func TestNodeCertUsers_NodeNotBooted(t *testing.T) {
	users := nodeCertUsers{node: &qrdbnode.Node{}}
	_, err := users.UserByCertThumbprint(context.Background(), "thumb")
	assert.ErrorIs(t, err, ErrQRDBNodeNotServing)
}
