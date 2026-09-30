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
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/scope"
	pkgauthorized "github.com/jeremyhahn/go-xkms/pkg/ssh/authorized"
	sshbackend "github.com/jeremyhahn/go-xkms/pkg/ssh/backend"
	pkgkeys "github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	pkgknownhosts "github.com/jeremyhahn/go-xkms/pkg/ssh/known_hosts"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

const (
	tenantA = "tenant-a"
	tenantB = "tenant-b"
)

var (
	aliceA   = &auth.Identity{Subject: "alice", TenantID: tenantA}
	bobA     = &auth.Identity{Subject: "bob", TenantID: tenantA}
	adminB   = &auth.Identity{Subject: "b-admin", TenantID: tenantB}
	aliceB   = &auth.Identity{Subject: "alice", TenantID: tenantB}
	platform = &auth.Identity{Subject: "root", TenantID: qrdbsdk.SystemTenantID}
)

func as(id *auth.Identity) context.Context {
	return auth.WithIdentity(context.Background(), id)
}

// grants is a PermissionChecker holding ssh:service for the listed
// "<tenant>/<subject>" principals and nothing else.
type grants map[string]bool

// errNotGranted is grants' refusal.
var errNotGranted = errors.New("tenancy test: permission not granted")

// AuthorizeCaller implements PermissionChecker.
func (g grants) AuthorizeCaller(ctx context.Context, resource, action string) error {
	id := auth.GetIdentity(ctx)
	if id != nil && resource == auth.ResourceSSH && action == auth.ActionService && g[id.TenantID+"/"+id.Subject] {
		return nil
	}
	return errNotGranted
}

// serviceGrants holds ssh:service for alice of tenant A and tenant B's admin.
var serviceGrants = grants{tenantA + "/alice": true, tenantB + "/b-admin": true}

// newTestClient returns the tenancy client over empty in-memory storage and,
// when withBackend is set, a software crypto backend named "software".
func newTestClient(t *testing.T, withBackend bool) (sdkssh.Client, types.KeyProvider) {
	t.Helper()
	backend, err := storage.NewMemoryBackend()
	require.NoError(t, err)
	opts := Options{Storage: backend, Permissions: serviceGrants}
	var kp types.KeyProvider
	if withBackend {
		kp, err = software.NewBackend(&software.Config{KeyStorage: storage.New()})
		require.NoError(t, err)
		opts.Resolver = sshbackend.ResolverFunc(func(_ context.Context, id string) (types.KeyProvider, error) {
			if id != "software" {
				return nil, &sshbackend.BackendNotFoundError{BackendID: id}
			}
			return kp, nil
		})
	}
	client, err := New(opts)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, client.Close()) })
	return client, kp
}

func publicLine(t *testing.T) (string, gossh.PublicKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := gossh.NewSignerFromKey(priv)
	require.NoError(t, err)
	return strings.TrimSpace(string(gossh.MarshalAuthorizedKey(signer.PublicKey()))), signer.PublicKey()
}

func generate(t *testing.T, c sdkssh.Client, id *auth.Identity, scope, owner, name string) *sdkssh.Key {
	t.Helper()
	key, err := c.Keys().Generate(as(id), sdkssh.GenerateRequest{Scope: scope, Owner: owner, Name: name, Algorithm: "ed25519"})
	require.NoError(t, err)
	return key
}

// requireRefusedAsMissing proves err is an *OwnerBindingError whose rendered
// text is exactly miss's.
func requireRefusedAsMissing(t *testing.T, err, miss error) {
	t.Helper()
	require.Error(t, miss, "control: the genuine miss must fail")
	require.Error(t, err)
	var refusal *OwnerBindingError
	require.True(t, errors.As(err, &refusal), "expected *OwnerBindingError, got %T", err)
	assert.Equal(t, miss.Error(), err.Error(), "the refusal must render as the genuine miss")
}

func TestNew_RequiresStorage(t *testing.T) {
	_, err := New(Options{})
	var nilErr *NilInputError
	require.True(t, errors.As(err, &nilErr))
	assert.Equal(t, "Storage", nilErr.Field)
	assert.Equal(t, "ssh/tenancy: nil input: Storage", err.Error())
}

func TestClose_Idempotent(t *testing.T) {
	backend, err := storage.NewMemoryBackend()
	require.NoError(t, err)
	c, err := New(Options{Storage: backend})
	require.NoError(t, err)
	require.NoError(t, c.Close())
	require.NoError(t, c.Close())
}

// TestKeys_OwnerBinding walks every key operation across the owner matrix.
func TestKeys_OwnerBinding(t *testing.T) {
	c, _ := newTestClient(t, false)
	empty, _ := newTestClient(t, false)
	generate(t, c, adminB, "tenant", tenantB, "b-key")
	generate(t, c, bobA, "user", "bob", "bob-key")
	generate(t, c, aliceB, "user", "alice", "alice-b-key")
	generate(t, c, adminB, "service", "b-admin", "svc-key")

	refs := map[string]sdkssh.GetKeyRequest{
		"tenant": {Scope: "tenant", Owner: tenantB, Name: "b-key"},
		"user":   {Scope: "user", Owner: "bob", Name: "bob-key"},
	}
	for name, ref := range refs {
		t.Run(name, func(t *testing.T) {
			ctx := as(aliceA)
			_, err := c.Keys().Get(ctx, ref)
			_, miss := empty.Keys().Get(ctx, ref)
			requireRefusedAsMissing(t, err, miss)

			_, err = c.Keys().ExportPublic(ctx, sdkssh.ExportRequest(ref))
			_, miss = empty.Keys().ExportPublic(ctx, sdkssh.ExportRequest(ref))
			requireRefusedAsMissing(t, err, miss)

			_, err = c.Keys().Signer(ctx, ref)
			_, miss = empty.Keys().Signer(ctx, ref)
			requireRefusedAsMissing(t, err, miss)

			err = c.Keys().Delete(ctx, sdkssh.DeleteKeyRequest(ref))
			miss = empty.Keys().Delete(ctx, sdkssh.DeleteKeyRequest(ref))
			requireRefusedAsMissing(t, err, miss)

			_, err = c.Keys().Generate(ctx, sdkssh.GenerateRequest{Scope: ref.Scope, Owner: ref.Owner, Name: "planted", Algorithm: "ed25519"})
			var notFound *pkgkeys.KeyNotFoundError
			require.True(t, errors.As(err, &notFound), "a refused generate is the key's not-found, got %v", err)

			_, err = c.Keys().Import(ctx, sdkssh.ImportRequest{Scope: ref.Scope, Owner: ref.Owner, Name: "planted", PEM: []byte("unused")}, nil)
			require.True(t, errors.As(err, &notFound), "a refused import is the key's not-found, got %v", err)
		})
	}

	// The alice of tenant B shares the attacker's subject, so user/alice is
	// alice's own address -- but in her own tenant's partition, where
	// alice-b-key is genuinely absent, and a key she creates there under the
	// same name is hers, not a replacement of tenant B's.
	t.Run("same subject other tenant", func(t *testing.T) {
		ref := sdkssh.GetKeyRequest{Scope: "user", Owner: "alice", Name: "alice-b-key"}
		_, err := c.Keys().Get(as(aliceA), ref)
		_, miss := empty.Keys().Get(as(aliceA), ref)
		require.Error(t, err)
		assert.Equal(t, miss.Error(), err.Error())
		_, err = c.Keys().Signer(as(aliceA), ref)
		require.Error(t, err)

		mine := generate(t, c, aliceA, "user", "alice", "alice-b-key")
		theirs, err := c.Keys().Get(as(aliceB), ref)
		require.NoError(t, err)
		assert.NotEqual(t, theirs.Fingerprint, mine.Fingerprint, "tenant B's key was replaced")
		require.NoError(t, c.Keys().Delete(as(aliceA), sdkssh.DeleteKeyRequest(ref)))
	})

	// Nothing was deleted or planted.
	for id, owner := range map[*auth.Identity][2]string{adminB: {"tenant", tenantB}, bobA: {"user", "bob"}, aliceB: {"user", "alice"}} {
		keys, err := c.Keys().List(as(id), sdkssh.ListKeysRequest{Scope: owner[0], Owner: owner[1]})
		require.NoError(t, err)
		require.Len(t, keys, 1, "%s's keys changed", id.Subject)
	}
}

// TestKeys_ServiceScope proves a service-scoped key is reachable only with
// the explicit ssh:service permission, only in the caller's own tenant, and
// not at all when no permission checker is wired.
func TestKeys_ServiceScope(t *testing.T) {
	c, _ := newTestClient(t, false)
	empty, _ := newTestClient(t, false)
	theirs := generate(t, c, adminB, "service", "ci", "deploy")
	ref := sdkssh.GetKeyRequest{Scope: "service", Owner: "ci", Name: "deploy"}

	// Without ssh:service, bob is refused as if the key were missing, and
	// cannot plant one.
	_, err := c.Keys().Generate(as(bobA), sdkssh.GenerateRequest{Scope: "service", Owner: "ci", Name: "deploy", Algorithm: "ed25519"})
	var refusal *OwnerBindingError
	require.ErrorAs(t, err, &refusal)
	var serviceErr *scope.ServiceScopeError
	require.ErrorAs(t, refusal.Cause, &serviceErr, "the cause names the missing permission")

	// Alice holds ssh:service in tenant A: she creates and reads tenant A's
	// service keys for any workload...
	mine := generate(t, c, aliceA, "service", "ci", "deploy")
	got, err := c.Keys().Get(as(aliceA), ref)
	require.NoError(t, err)
	assert.Equal(t, mine.Fingerprint, got.Fingerprint)
	assert.NotEqual(t, theirs.Fingerprint, mine.Fingerprint, "tenant B's service key must be unreachable from tenant A")

	// ...and bob, in the same tenant, still reaches none of them.
	_, err = c.Keys().Get(as(bobA), ref)
	_, miss := empty.Keys().Get(as(bobA), ref)
	requireRefusedAsMissing(t, err, miss)
	listed, err := c.Keys().List(as(bobA), sdkssh.ListKeysRequest{})
	require.NoError(t, err)
	assert.Empty(t, listed, "bob's listing must omit service keys")
	listed, err = c.Keys().List(as(aliceA), sdkssh.ListKeysRequest{Scope: "service"})
	require.NoError(t, err)
	require.Len(t, listed, 1)

	// Tenant B's key is untouched.
	got, err = c.Keys().Get(as(adminB), ref)
	require.NoError(t, err)
	assert.Equal(t, theirs.Fingerprint, got.Fingerprint)

	// With no permission checker the scope is closed, even to alice.
	backend, err := storage.NewMemoryBackend()
	require.NoError(t, err)
	closed, err := New(Options{Storage: backend})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, closed.Close()) })
	_, err = closed.Keys().Generate(as(aliceA), sdkssh.GenerateRequest{Scope: "service", Owner: "ci", Name: "deploy", Algorithm: "ed25519"})
	require.ErrorAs(t, err, &refusal)
}

// TestKeys_PlatformCannotReachPersonalKeys proves a user's personal keys stay
// private even from a platform caller: the platform reaches tenants' shared
// keys, never another user's.
func TestKeys_PlatformCannotReachPersonalKeys(t *testing.T) {
	c, _ := newTestClient(t, false)
	empty, _ := newTestClient(t, false)
	generate(t, c, bobA, "user", "bob", "bob-key")
	ref := sdkssh.GetKeyRequest{Scope: "user", Owner: "bob", Name: "bob-key"}

	_, err := c.Keys().Get(as(platform), ref)
	_, miss := empty.Keys().Get(as(platform), ref)
	requireRefusedAsMissing(t, err, miss)
	var refusal *OwnerBindingError
	require.ErrorAs(t, err, &refusal)
	var crossUser *scope.CrossUserError
	require.ErrorAs(t, refusal.Cause, &crossUser)

	err = c.Keys().Delete(as(platform), sdkssh.DeleteKeyRequest(ref))
	require.Error(t, err)
	_, err = c.Keys().Get(as(bobA), ref)
	require.NoError(t, err, "bob's key must survive the platform's refused delete")

	// The platform's own personal keys are its own.
	generate(t, c, platform, "user", "root", "root-key")
	_, err = c.Keys().Get(as(platform), sdkssh.GetKeyRequest{Scope: "user", Owner: "root", Name: "root-key"})
	require.NoError(t, err)
}

// TestKeys_OwnersAndPlatform is the positive control.
func TestKeys_OwnersAndPlatform(t *testing.T) {
	c, _ := newTestClient(t, false)
	generate(t, c, aliceA, "tenant", tenantA, "a-key")
	generate(t, c, aliceA, "user", "alice", "alice-key")
	generate(t, c, aliceA, "service", "alice", "alice-svc")
	generate(t, c, aliceB, "user", "alice", "alice-b-key")
	generate(t, c, platform, "tenant", tenantB, "platform-made")

	// Alice sees exactly her three; the alice of tenant B exactly hers.
	keys, err := c.Keys().List(as(aliceA), sdkssh.ListKeysRequest{})
	require.NoError(t, err)
	names := make([]string, 0, len(keys))
	for _, k := range keys {
		names = append(names, k.Name)
	}
	assert.ElementsMatch(t, []string{"a-key", "alice-key", "alice-svc"}, names)

	keys, err = c.Keys().List(as(aliceB), sdkssh.ListKeysRequest{Scope: "user", Owner: "alice"})
	require.NoError(t, err)
	require.Len(t, keys, 1)
	assert.Equal(t, "alice-b-key", keys[0].Name)

	// The key the platform made for tenant B lives in B's partition.
	_, err = c.Keys().Get(as(adminB), sdkssh.GetKeyRequest{Scope: "tenant", Owner: tenantB, Name: "platform-made"})
	require.NoError(t, err)
	keys, err = c.Keys().List(as(platform), sdkssh.ListKeysRequest{Scope: "tenant", Owner: tenantB})
	require.NoError(t, err)
	require.Len(t, keys, 1)

	// The platform's own partition holds none of the tenants' keys.
	keys, err = c.Keys().List(as(platform), sdkssh.ListKeysRequest{})
	require.NoError(t, err)
	assert.Empty(t, keys)

	// A nil identity is the platform too.
	_, err = c.Keys().Get(context.Background(), sdkssh.GetKeyRequest{Scope: "tenant", Owner: tenantA, Name: "a-key"})
	require.NoError(t, err)

	signer, err := c.Keys().Signer(as(aliceA), sdkssh.GetKeyRequest{Scope: "user", Owner: "alice", Name: "alice-key"})
	require.NoError(t, err)
	_, err = signer.Sign(rand.Reader, []byte("payload"))
	require.NoError(t, err)
	_, err = c.Keys().ExportPublic(as(aliceA), sdkssh.ExportRequest{Scope: "user", Owner: "alice", Name: "alice-key"})
	require.NoError(t, err)
	require.NoError(t, c.Keys().Delete(as(aliceA), sdkssh.DeleteKeyRequest{Scope: "user", Owner: "alice", Name: "alice-key"}))

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	block, err := gossh.MarshalPrivateKey(priv, "")
	require.NoError(t, err)
	imported, err := c.Keys().Import(as(aliceA), sdkssh.ImportRequest{Scope: "user", Owner: "alice", Name: "imported", PEM: pem.EncodeToMemory(block)}, nil)
	require.NoError(t, err)
	assert.Equal(t, "imported", imported.Name)
}

// TestPlatform_SystemAndInvalidTenantOwners proves the platform reaches the
// platform partition for the system tenant, and that an owner no tenant can
// have is answered as missing and never written.
func TestPlatform_SystemAndInvalidTenantOwners(t *testing.T) {
	c, _ := newTestClient(t, false)
	empty, _ := newTestClient(t, false)
	generate(t, c, platform, "tenant", qrdbsdk.SystemTenantID, "sys-key")
	keys, err := c.Keys().List(as(platform), sdkssh.ListKeysRequest{})
	require.NoError(t, err)
	require.Len(t, keys, 1)

	ref := sdkssh.GetKeyRequest{Scope: "tenant", Owner: "bad:tenant", Name: "k"}
	_, err = c.Keys().Get(as(platform), ref)
	_, miss := empty.Keys().Get(as(aliceA), ref)
	requireRefusedAsMissing(t, err, miss)

	_, err = c.Keys().Generate(as(platform), sdkssh.GenerateRequest{Scope: "tenant", Owner: "bad:tenant", Name: "k", Algorithm: "ed25519"})
	var refusal *OwnerBindingError
	require.True(t, errors.As(err, &refusal))

	keys, err = c.Keys().List(as(platform), sdkssh.ListKeysRequest{Scope: "tenant", Owner: "bad:tenant"})
	require.NoError(t, err)
	assert.Empty(t, keys)
}

// TestInvalidScope proves an unknown scope is the SDK's own bad-request
// answer for every caller and every operation family.
func TestInvalidScope(t *testing.T) {
	c, _ := newTestClient(t, false)
	var scopeErr *sdkssh.InvalidScopeError
	_, err := c.Keys().Get(as(aliceA), sdkssh.GetKeyRequest{Scope: "galaxy", Owner: tenantA, Name: "k"})
	require.True(t, errors.As(err, &scopeErr))
	_, err = c.Keys().Generate(as(aliceA), sdkssh.GenerateRequest{Scope: "galaxy", Owner: tenantA, Name: "k", Algorithm: "ed25519"})
	require.True(t, errors.As(err, &scopeErr))
	_, err = c.Keys().List(as(aliceA), sdkssh.ListKeysRequest{Scope: "galaxy"})
	require.True(t, errors.As(err, &scopeErr))
	_, err = c.KnownHosts().List(as(platform), sdkssh.ListKnownHostsRequest{Scope: "galaxy"})
	require.True(t, errors.As(err, &scopeErr))
	_, err = c.AuthorizedKeys().List(as(platform), sdkssh.ListAuthorizedKeysRequest{Scope: "galaxy"})
	require.True(t, errors.As(err, &scopeErr))

	cb := c.KnownHosts().Callback(as(aliceA), "galaxy", tenantA)
	_, pub := publicLine(t)
	require.True(t, errors.As(cb("h.example.com", &net.TCPAddr{}, pub), &scopeErr))
}

// TestCallerTenantInvariant proves a tenant-scoped identity whose tenant
// cannot root a partition is an internal failure, never a success.
func TestCallerTenantInvariant(t *testing.T) {
	c, _ := newTestClient(t, false)
	broken := &auth.Identity{Subject: "eve", TenantID: "a/b"}
	_, err := c.Keys().Generate(as(broken), sdkssh.GenerateRequest{Scope: "tenant", Owner: "a/b", Name: "k", Algorithm: "ed25519"})
	var tenantErr *CallerTenantError
	require.True(t, errors.As(err, &tenantErr))
	assert.Equal(t, "a/b", tenantErr.TenantID)
	assert.Contains(t, err.Error(), "ssh/tenancy: caller tenant a/b")
	require.NotNil(t, errors.Unwrap(err))

	_, err = c.Keys().List(as(broken), sdkssh.ListKeysRequest{})
	require.True(t, errors.As(err, &tenantErr))
}

// TestKnownHosts_OwnerBinding covers every pin operation.
func TestKnownHosts_OwnerBinding(t *testing.T) {
	c, _ := newTestClient(t, false)
	empty, _ := newTestClient(t, false)
	line, pub := publicLine(t)
	require.NoError(t, c.KnownHosts().Add(as(adminB), sdkssh.AddKnownHostRequest{Scope: "tenant", Owner: tenantB, Host: "b.example.com", PublicKey: line}))

	ctx := as(aliceA)
	rm := sdkssh.RemoveKnownHostRequest{Scope: "tenant", Owner: tenantB, Host: "b.example.com"}
	requireRefusedAsMissing(t, c.KnownHosts().Remove(ctx, rm), empty.KnownHosts().Remove(ctx, rm))
	requireRefusedAsMissing(t,
		c.KnownHosts().Verify(ctx, "tenant", tenantB, "b.example.com", pub),
		empty.KnownHosts().Verify(ctx, "tenant", tenantB, "b.example.com", pub))

	cb := c.KnownHosts().Callback(ctx, "tenant", tenantB)
	missCb := empty.KnownHosts().Callback(ctx, "tenant", tenantB)
	requireRefusedAsMissing(t, cb("b.example.com:22", &net.TCPAddr{}, pub), missCb("b.example.com:22", &net.TCPAddr{}, pub))

	err := c.KnownHosts().Add(ctx, sdkssh.AddKnownHostRequest{Scope: "tenant", Owner: tenantB, Host: "planted.example.com", PublicKey: line})
	var notFound *pkgknownhosts.NotFoundError
	require.True(t, errors.As(err, &notFound), "a refused add is the pin's not-found, got %v", err)

	pins, err := c.KnownHosts().List(ctx, sdkssh.ListKnownHostsRequest{})
	require.NoError(t, err)
	assert.Empty(t, pins)
	pins, err = c.KnownHosts().List(as(adminB), sdkssh.ListKnownHostsRequest{})
	require.NoError(t, err)
	require.Len(t, pins, 1, "tenant B's pins changed")

	// The owner verifies, and its callback admits the pinned key.
	require.NoError(t, c.KnownHosts().Verify(as(adminB), "tenant", tenantB, "b.example.com", pub))
	require.NoError(t, c.KnownHosts().Callback(as(adminB), "tenant", tenantB)("b.example.com:22", &net.TCPAddr{}, pub))
	require.NoError(t, c.KnownHosts().Remove(as(adminB), rm))
}

// TestAuthorizedKeys_OwnerBinding covers every authorized_keys operation.
func TestAuthorizedKeys_OwnerBinding(t *testing.T) {
	c, _ := newTestClient(t, false)
	empty, _ := newTestClient(t, false)
	line, pub := publicLine(t)
	require.NoError(t, c.AuthorizedKeys().Add(as(bobA), sdkssh.AddAuthorizedKeyRequest{Scope: "user", Owner: "bob", Name: "bob-entry", Line: line}))

	ctx := as(aliceA)
	_, err := c.AuthorizedKeys().Get(ctx, "user", "bob", "bob-entry")
	_, miss := empty.AuthorizedKeys().Get(ctx, "user", "bob", "bob-entry")
	requireRefusedAsMissing(t, err, miss)
	_, err = c.AuthorizedKeys().Verify(ctx, "user", "bob", pub)
	_, miss = empty.AuthorizedKeys().Verify(ctx, "user", "bob", pub)
	requireRefusedAsMissing(t, err, miss)
	requireRefusedAsMissing(t,
		c.AuthorizedKeys().Remove(ctx, "user", "bob", "bob-entry"),
		empty.AuthorizedKeys().Remove(ctx, "user", "bob", "bob-entry"))

	err = c.AuthorizedKeys().Add(ctx, sdkssh.AddAuthorizedKeyRequest{Scope: "user", Owner: "bob", Name: "planted", Line: line})
	var notFound *pkgauthorized.NotFoundError
	require.True(t, errors.As(err, &notFound), "a refused add is the entry's not-found, got %v", err)

	entries, err := c.AuthorizedKeys().List(ctx, sdkssh.ListAuthorizedKeysRequest{Scope: "user", Owner: "bob"})
	require.NoError(t, err)
	assert.Empty(t, entries)
	entries, err = c.AuthorizedKeys().List(as(bobA), sdkssh.ListAuthorizedKeysRequest{})
	require.NoError(t, err)
	require.Len(t, entries, 1, "bob's entries changed")

	// Emit addresses no asset and answers every caller.
	out, err := c.AuthorizedKeys().Emit(ctx, sdkssh.EmitRequest{PublicKey: line, Comment: "c"})
	require.NoError(t, err)
	assert.Contains(t, out, "c")
	_, err = c.AuthorizedKeys().Emit(ctx, sdkssh.EmitRequest{PublicKey: "not a key"})
	require.Error(t, err)

	// The owner reaches its entry.
	_, err = c.AuthorizedKeys().Get(as(bobA), "user", "bob", "bob-entry")
	require.NoError(t, err)
	_, err = c.AuthorizedKeys().Verify(as(bobA), "user", "bob", pub)
	require.NoError(t, err)
	require.NoError(t, c.AuthorizedKeys().Remove(as(bobA), "user", "bob", "bob-entry"))
}

// TestSession_Refusals proves a session never authenticates with a foreign
// key or verifies against foreign pins. Every refusal is decided before any
// network dial.
func TestSession_Refusals(t *testing.T) {
	c, _ := newTestClient(t, false)
	generate(t, c, bobA, "user", "bob", "bob-key")
	generate(t, c, adminB, "tenant", tenantB, "b-key")

	cases := map[string]struct {
		id  *auth.Identity
		req sdkssh.SessionDialRequest
	}{
		"foreign key": {aliceA, sdkssh.SessionDialRequest{KeyScope: "user", KeyOwner: "bob", KeyName: "bob-key", Host: "h.example.com", User: "u"}},
		"foreign pins": {bobA, sdkssh.SessionDialRequest{KeyScope: "user", KeyOwner: "bob", KeyName: "bob-key",
			HostKeyScope: "tenant", HostKeyOwner: tenantB, Host: "h.example.com", User: "u"}},
		"platform across partitions": {platform, sdkssh.SessionDialRequest{KeyScope: "tenant", KeyOwner: tenantB, KeyName: "b-key",
			HostKeyScope: "user", HostKeyOwner: "root", Host: "h.example.com", User: "u"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := c.Session().Dial(as(tc.id), tc.req)
			var refusal *OwnerBindingError
			require.True(t, errors.As(err, &refusal), "expected a refusal, got %v", err)
			var notFound *pkgkeys.KeyNotFoundError
			assert.True(t, errors.As(err, &notFound))
		})
	}

	var scopeErr *sdkssh.InvalidScopeError
	_, err := c.Session().Dial(as(aliceA), sdkssh.SessionDialRequest{KeyScope: "galaxy"})
	require.True(t, errors.As(err, &scopeErr))
	_, err = c.Session().Dial(as(bobA), sdkssh.SessionDialRequest{KeyScope: "user", KeyOwner: "bob", HostKeyScope: "galaxy"})
	require.True(t, errors.As(err, &scopeErr))
}

// TestConsole_Refusals proves a console never opens with a foreign key.
func TestConsole_Refusals(t *testing.T) {
	c, _ := newTestClient(t, false)
	generate(t, c, bobA, "user", "bob", "bob-key")

	_, err := c.Console(as(aliceA), sdkssh.ConsoleConnectRequest{KeyScope: "user", KeyOwner: "bob", KeyName: "bob-key", Host: "h.example.com", User: "u"}, sdkssh.ConsoleConfig{})
	var refusal *OwnerBindingError
	require.True(t, errors.As(err, &refusal), "expected a refusal, got %v", err)
	assert.Equal(t, "console", refusal.Op)
	assert.Equal(t, tenantA, refusal.CallerTenantID)
	assert.Equal(t, "alice", refusal.CallerSubject)

	var scopeErr *sdkssh.InvalidScopeError
	_, err = c.Console(as(aliceA), sdkssh.ConsoleConnectRequest{KeyScope: "galaxy"}, sdkssh.ConsoleConfig{})
	require.True(t, errors.As(err, &scopeErr))
}

// TestBackendKeys_NamespacedPerTenant proves two tenants whose SSH keys
// share an address -- the same subject, scope and name -- get distinct
// backend keys, each signing with its own material.
func TestBackendKeys_NamespacedPerTenant(t *testing.T) {
	c, kp := newTestClient(t, true)
	req := sdkssh.GenerateRequest{Scope: "user", Owner: "alice", Name: "hw", Algorithm: "ecdsa-p256", Backend: "software"}
	keyA, err := c.Keys().Generate(as(aliceA), req)
	require.NoError(t, err)
	keyB, err := c.Keys().Generate(as(aliceB), req)
	require.NoError(t, err)
	assert.NotEqual(t, keyA.Fingerprint, keyB.Fingerprint, "each tenant must mint its own backend key")
	assert.Equal(t, keyA.BackendKeyID, keyB.BackendKeyID, "the addresses collide; only the tenant namespace separates them")

	for id, key := range map[*auth.Identity]*sdkssh.Key{aliceA: keyA, aliceB: keyB} {
		signer, err := c.Keys().Signer(as(id), sdkssh.GetKeyRequest{Scope: "user", Owner: "alice", Name: "hw"})
		require.NoError(t, err)
		sig, err := signer.Sign(rand.Reader, []byte("payload"))
		require.NoError(t, err)
		pub, _, _, _, err := gossh.ParseAuthorizedKey([]byte(key.PublicKey))
		require.NoError(t, err)
		require.NoError(t, pub.Verify([]byte("payload"), sig), "%s signed with another tenant's key", id.TenantID)
	}

	all, err := kp.ListKeys(context.Background())
	require.NoError(t, err)
	tenants := map[string]bool{}
	for _, attrs := range all {
		tenants[attrs.TenantID] = true
	}
	assert.True(t, tenants[tenantA] && tenants[tenantB], "backend keys must carry their tenant, got %v", tenants)

	// A platform backend key carries no tenant.
	_, err = c.Keys().Generate(as(platform), sdkssh.GenerateRequest{Scope: "user", Owner: "root", Name: "hw", Algorithm: "ed25519", Backend: "software"})
	require.NoError(t, err)

	// Deleting tenant A's key leaves tenant B's signer working.
	require.NoError(t, c.Keys().Delete(as(aliceA), sdkssh.DeleteKeyRequest{Scope: "user", Owner: "alice", Name: "hw"}))
	_, err = c.Keys().Signer(as(aliceB), sdkssh.GetKeyRequest{Scope: "user", Owner: "alice", Name: "hw"})
	require.NoError(t, err)
}

// TestBackendKeys_DistinctAddressesDoNotCollide is the end-to-end regression
// for go-xkms#1238: "user/a-b/c" and "user/a/b-c" are two distinct SSH key
// addresses (owner="a-b" name="c" vs. owner="a" name="b-c"), and each must
// generate, sign and round-trip through Get as its own key on the real
// software backend -- not silently alias the other's backend CN. Both
// addresses are generated by two platform principals whose subjects are the
// two owners, since scope=user binds every caller -- the platform included --
// to its own subject; both live in the platform partition, which drives both
// addresses through one backend namespace.
func TestBackendKeys_DistinctAddressesDoNotCollide(t *testing.T) {
	c, kp := newTestClient(t, true)
	platformAB := &auth.Identity{Subject: "a-b", TenantID: qrdbsdk.SystemTenantID}
	platformA := &auth.Identity{Subject: "a", TenantID: qrdbsdk.SystemTenantID}
	ctx := context.Background()

	key1, err := c.Keys().Generate(as(platformAB), sdkssh.GenerateRequest{
		Scope: "user", Owner: "a-b", Name: "c", Algorithm: "ed25519", Backend: "software",
	})
	require.NoError(t, err)
	key2, err := c.Keys().Generate(as(platformA), sdkssh.GenerateRequest{
		Scope: "user", Owner: "a", Name: "b-c", Algorithm: "ed25519", Backend: "software",
	})
	require.NoError(t, err)

	require.NotEqual(t, key1.BackendKeyID, key2.BackendKeyID,
		"user/a-b/c and user/a/b-c must not share a backend key")
	require.NotEqual(t, key1.Fingerprint, key2.Fingerprint)

	all, err := kp.ListKeys(ctx)
	require.NoError(t, err)
	require.Len(t, all, 2, "each address must own its own backend key")

	// Each address's Signer produces a signature that verifies only under
	// its own address's public key -- proving the two are genuinely
	// distinct keys, not one key answering for both addresses.
	signer1, err := c.Keys().Signer(as(platformAB), sdkssh.GetKeyRequest{Scope: "user", Owner: "a-b", Name: "c"})
	require.NoError(t, err)
	signer2, err := c.Keys().Signer(as(platformA), sdkssh.GetKeyRequest{Scope: "user", Owner: "a", Name: "b-c"})
	require.NoError(t, err)

	msg := []byte("go-xkms#1238")
	sig1, err := signer1.Sign(rand.Reader, msg)
	require.NoError(t, err)
	sig2, err := signer2.Sign(rand.Reader, msg)
	require.NoError(t, err)

	pub1, _, _, _, err := gossh.ParseAuthorizedKey([]byte(key1.PublicKey))
	require.NoError(t, err)
	pub2, _, _, _, err := gossh.ParseAuthorizedKey([]byte(key2.PublicKey))
	require.NoError(t, err)

	require.NoError(t, pub1.Verify(msg, sig1))
	require.NoError(t, pub2.Verify(msg, sig2))
	require.Error(t, pub1.Verify(msg, sig2), "user/a-b/c's key must not accept user/a/b-c's signature")
	require.Error(t, pub2.Verify(msg, sig1), "user/a/b-c's key must not accept user/a-b/c's signature")

	// Get round-trips each address back to its own metadata and public key.
	got1, err := c.Keys().Get(as(platformAB), sdkssh.GetKeyRequest{Scope: "user", Owner: "a-b", Name: "c"})
	require.NoError(t, err)
	assert.Equal(t, key1.PublicKey, got1.PublicKey)
	assert.Equal(t, key1.BackendKeyID, got1.BackendKeyID)

	got2, err := c.Keys().Get(as(platformA), sdkssh.GetKeyRequest{Scope: "user", Owner: "a", Name: "b-c"})
	require.NoError(t, err)
	assert.Equal(t, key2.PublicKey, got2.PublicKey)
	assert.Equal(t, key2.BackendKeyID, got2.BackendKeyID)
}

// TestBackendKeys_UnknownBackend proves a tenant partition reports an
// unknown backend as the resolver does.
func TestBackendKeys_UnknownBackend(t *testing.T) {
	c, _ := newTestClient(t, true)
	_, err := c.Keys().Generate(as(aliceA), sdkssh.GenerateRequest{Scope: "user", Owner: "alice", Name: "hw", Algorithm: "ed25519", Backend: "nope"})
	var notFound *sshbackend.BackendNotFoundError
	require.True(t, errors.As(err, &notFound), "got %v", err)
}

// TestTenantResolver_NilProvider proves a resolver answering no provider is
// the backend-not-found error, never a nil provider.
func TestTenantResolver_NilProvider(t *testing.T) {
	backend, err := storage.NewMemoryBackend()
	require.NoError(t, err)
	c := &client{storage: backend, resolver: sshbackend.ResolverFunc(func(context.Context, string) (types.KeyProvider, error) {
		return nil, nil
	})}
	_, err = c.tenantResolver(tenantA).ResolveKeyProvider(context.Background(), "hw")
	var notFound *sshbackend.BackendNotFoundError
	require.True(t, errors.As(err, &notFound))
	assert.Equal(t, "hw", notFound.BackendID)
}

func TestErrors(t *testing.T) {
	miss := &pkgkeys.KeyNotFoundError{ID: "user/bob/k"}
	refusal := &OwnerBindingError{Op: "keys.get", Scope: "user", Owner: "bob", Err: miss}
	assert.Equal(t, miss.Error(), refusal.Error())
	assert.Same(t, miss, errors.Unwrap(refusal))

	empty := &EmptyPartitionError{Op: "keys.generate"}
	assert.Equal(t, "ssh/tenancy: the empty partition answered keys.generate: it must hold nothing", empty.Error())

	// A nil genuine miss -- the empty partition answering -- is still a
	// refusal, carrying the invariant failure.
	err := newOwnerBindingError(context.Background(), "keys.generate", "user", "bob", nil, nil)
	var partitionErr *EmptyPartitionError
	require.True(t, errors.As(err, &partitionErr))
	var binding *OwnerBindingError
	require.True(t, errors.As(err, &binding))
	assert.Empty(t, binding.CallerTenantID, "a nil identity carries no caller detail")
}
