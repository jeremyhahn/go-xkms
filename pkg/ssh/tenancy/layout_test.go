// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package tenancy

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// newLayoutClient returns the tenancy client and the shared storage it
// writes, so a test can inspect the raw storage keys.
func newLayoutClient(t *testing.T) (sdkssh.Client, storage.Backend) {
	t.Helper()
	backend, err := storage.NewMemoryBackend()
	require.NoError(t, err)
	c, err := New(Options{Storage: backend, Permissions: serviceGrants})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, c.Close()) })
	return c, backend
}

// TestPartitions_ScopeLayout pins the storage layout every transport's
// writes land in: "{tenant}/ssh/shared|users/{subject}|services/{owner}/..."
// with the platform partition rooted at "system/".
func TestPartitions_ScopeLayout(t *testing.T) {
	c, backend := newLayoutClient(t)
	line, _ := publicLine(t)

	generate(t, c, aliceA, "user", "alice", "laptop")
	generate(t, c, aliceA, "tenant", tenantA, "deploy")
	generate(t, c, aliceA, "service", "ci", "runner")
	generate(t, c, platform, "user", "root", "admin")
	generate(t, c, platform, "tenant", qrdbsdk.SystemTenantID, "sys-shared")
	generate(t, c, platform, "tenant", tenantB, "platform-made")
	require.NoError(t, c.KnownHosts().Add(as(aliceA), sdkssh.AddKnownHostRequest{Scope: "user", Owner: "alice", Host: "web.example.com", PublicKey: line}))
	require.NoError(t, c.AuthorizedKeys().Add(as(adminB), sdkssh.AddAuthorizedKeyRequest{Scope: "tenant", Owner: tenantB, Name: "ops", Line: line}))

	got, err := backend.List(context.Background(), "")
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{
		"tenant-a/ssh/users/alice/keys/laptop",
		"tenant-a/ssh/shared/keys/deploy",
		"tenant-a/ssh/services/ci/keys/runner",
		"system/ssh/users/root/keys/admin",
		"system/ssh/shared/keys/sys-shared",
		"tenant-b/ssh/shared/keys/platform-made",
		"tenant-a/ssh/users/alice/known_hosts/web.example.com",
		"tenant-b/ssh/shared/authorized_keys/ops",
	}, got)
}

// TestPartitions_SameSubjectInTwoTenants proves equal subjects in two
// tenants address distinct records: each lands under its own tenant root and
// deleting one leaves the other.
func TestPartitions_SameSubjectInTwoTenants(t *testing.T) {
	c, backend := newLayoutClient(t)
	generate(t, c, aliceA, "user", "alice", "laptop")
	generate(t, c, aliceB, "user", "alice", "laptop")

	got, err := backend.List(context.Background(), "")
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{
		"tenant-a/ssh/users/alice/keys/laptop",
		"tenant-b/ssh/users/alice/keys/laptop",
	}, got)

	require.NoError(t, c.Keys().Delete(as(aliceA), sdkssh.DeleteKeyRequest{Scope: "user", Owner: "alice", Name: "laptop"}))
	got, err = backend.List(context.Background(), "")
	require.NoError(t, err)
	assert.Equal(t, []string{"tenant-b/ssh/users/alice/keys/laptop"}, got)
}
