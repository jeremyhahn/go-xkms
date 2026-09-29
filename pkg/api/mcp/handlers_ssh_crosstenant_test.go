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

package mcp

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/tenancy"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// ===========================================================================
// SSH owner binding over MCP (go-xkms#1230).
//
// Tenant A's alice addresses SSH assets owned by tenant B, by bob (her own
// tenant), and by the alice of tenant B, who shares her subject. Every
// ssh.* method must answer exactly as it does for a missing asset and leave
// the asset in place; no listing may return one; no write may land under a
// foreign owner.
// ===========================================================================

const (
	mcpSSHTenantA = "tenant-a"
	mcpSSHTenantB = "tenant-b"
)

var (
	mcpSSHAliceA   = &auth.Identity{Subject: "alice", TenantID: mcpSSHTenantA}
	mcpSSHBobA     = &auth.Identity{Subject: "bob", TenantID: mcpSSHTenantA}
	mcpSSHAdminB   = &auth.Identity{Subject: "b-admin", TenantID: mcpSSHTenantB}
	mcpSSHAliceB   = &auth.Identity{Subject: "alice", TenantID: mcpSSHTenantB}
	mcpSSHPlatform = &auth.Identity{Subject: "root", TenantID: qrdbsdk.SystemTenantID}
)

func mcpSSHAs(id *auth.Identity) context.Context {
	return auth.WithIdentity(context.Background(), id)
}

// newMCPSSHTenancyServer returns an MCP server over the SSH client xkmsd
// wires into every transport, on empty in-memory storage.
func newMCPSSHTenancyServer(t *testing.T) (*Server, sdkssh.Client) {
	t.Helper()
	svc := setupTestXKMS(t)
	t.Cleanup(cleanupXKMS)

	backend, err := storage.NewMemoryBackend()
	require.NoError(t, err)
	client, err := tenancy.New(tenancy.Options{Storage: backend})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, client.Close()) })

	server, err := NewServer(&Config{
		XKMSService:   svc,
		Authenticator: auth.NewNoOpAuthenticator(),
		SSHClient:     client,
	})
	require.NoError(t, err)
	return server, client
}

func mcpSSHPublicLine(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := gossh.NewSignerFromKey(priv)
	require.NoError(t, err)
	return strings.TrimSpace(string(gossh.MarshalAuthorizedKey(signer.PublicKey())))
}

// seedMCPSSHOwners stores each asset through its rightful owner.
func seedMCPSSHOwners(t *testing.T, s *Server) {
	t.Helper()
	gen := func(id *auth.Identity, scope, owner, name string) {
		_, err := s.handleSSHKeysGenerate(mcpSSHAs(id), sshRequest(t, "ssh.keys.generate",
			sdkssh.GenerateRequest{Scope: scope, Owner: owner, Name: name, Algorithm: "ed25519"}))
		require.NoError(t, err, "seeding %s/%s/%s", scope, owner, name)
	}
	gen(mcpSSHAdminB, "tenant", mcpSSHTenantB, "b-key")
	gen(mcpSSHBobA, "user", "bob", "bob-key")
	gen(mcpSSHAliceB, "user", "alice", "alice-b-key")

	_, err := s.handleSSHAuthorizedKeysAdd(mcpSSHAs(mcpSSHAdminB), sshRequest(t, "ssh.authorizedKeys.add",
		sdkssh.AddAuthorizedKeyRequest{Scope: "tenant", Owner: mcpSSHTenantB, Name: "b-entry", Line: mcpSSHPublicLine(t)}))
	require.NoError(t, err)
	_, err = s.handleSSHKnownHostsAdd(mcpSSHAs(mcpSSHAdminB), sshRequest(t, "ssh.knownHosts.add",
		sdkssh.AddKnownHostRequest{Scope: "tenant", Owner: mcpSSHTenantB, Host: "b.example.com", PublicKey: mcpSSHPublicLine(t)}))
	require.NoError(t, err)
}

// mcpSSHCode returns the JSON-RPC code err carries.
func mcpSSHCode(t *testing.T, err error) int {
	t.Helper()
	var keyErr *KeyOpError
	require.True(t, errors.As(err, &keyErr), "expected *KeyOpError, got %T (%v)", err, err)
	return keyErr.Code
}

// TestSSHMCP_CrossOwnerReadsAnswerAsMissing proves each by-name method
// refuses another owner's asset with the error a missing asset gets.
func TestSSHMCP_CrossOwnerReadsAnswerAsMissing(t *testing.T) {
	type call struct {
		method string
		params interface{}
		fn     func(*Server) func(context.Context, *JSONRPCRequest) (interface{}, error)
	}
	getKey := func(s *Server) func(context.Context, *JSONRPCRequest) (interface{}, error) { return s.handleSSHKeysGet }
	export := func(s *Server) func(context.Context, *JSONRPCRequest) (interface{}, error) {
		return s.handleSSHKeysExport
	}
	sign := func(s *Server) func(context.Context, *JSONRPCRequest) (interface{}, error) {
		return s.handleSSHKeysSign
	}
	del := func(s *Server) func(context.Context, *JSONRPCRequest) (interface{}, error) {
		return s.handleSSHKeysDelete
	}

	attacks := map[string]call{}
	for label, ref := range map[string]sdkssh.GetKeyRequest{
		"tenant":                    {Scope: "tenant", Owner: mcpSSHTenantB, Name: "b-key"},
		"user":                      {Scope: "user", Owner: "bob", Name: "bob-key"},
		"same subject other tenant": {Scope: "user", Owner: "alice", Name: "alice-b-key"},
	} {
		attacks[label+" get key"] = call{"ssh.keys.get", ref, getKey}
		attacks[label+" export public"] = call{"ssh.keys.export", ref, export}
		attacks[label+" sign"] = call{"ssh.keys.sign", SSHSignParams{Scope: ref.Scope, Owner: ref.Owner, Name: ref.Name, Digest: []byte("payload")}, sign}
		attacks[label+" delete key"] = call{"ssh.keys.delete", ref, del}
	}
	attacks["tenant get authorized"] = call{"ssh.authorizedKeys.get",
		SSHAuthorizedKeysGetParams{Scope: "tenant", Owner: mcpSSHTenantB, Name: "b-entry"},
		func(s *Server) func(context.Context, *JSONRPCRequest) (interface{}, error) {
			return s.handleSSHAuthorizedKeysGet
		}}
	attacks["tenant remove authorized"] = call{"ssh.authorizedKeys.remove",
		SSHAuthorizedKeysRemoveParams{Scope: "tenant", Owner: mcpSSHTenantB, Name: "b-entry"},
		func(s *Server) func(context.Context, *JSONRPCRequest) (interface{}, error) {
			return s.handleSSHAuthorizedKeysRemove
		}}
	attacks["tenant remove known host"] = call{"ssh.knownHosts.remove",
		sdkssh.RemoveKnownHostRequest{Scope: "tenant", Owner: mcpSSHTenantB, Host: "b.example.com"},
		func(s *Server) func(context.Context, *JSONRPCRequest) (interface{}, error) {
			return s.handleSSHKnownHostsRemove
		}}

	for name, tc := range attacks {
		t.Run(name, func(t *testing.T) {
			seeded, seededClient := newMCPSSHTenancyServer(t)
			seedMCPSSHOwners(t, seeded)
			empty, _ := newMCPSSHTenancyServer(t)

			_, gotErr := tc.fn(seeded)(mcpSSHAs(mcpSSHAliceA), sshRequest(t, tc.method, tc.params))
			_, missErr := tc.fn(empty)(mcpSSHAs(mcpSSHAliceA), sshRequest(t, tc.method, tc.params))
			require.Error(t, missErr, "control: the empty deployment must refuse")
			require.Error(t, gotErr, "another owner's asset must be refused")

			assert.Equal(t, sdkssh.JSONRPCCodeNotFound, mcpSSHCode(t, missErr))
			assert.Equal(t, mcpSSHCode(t, missErr), mcpSSHCode(t, gotErr), "another owner's asset must answer as a missing one")
			assert.Equal(t, missErr.Error(), gotErr.Error(), "the refusal must carry the genuine-miss message")
			requireMCPSSHOwnersIntact(t, seededClient)
		})
	}
}

// TestSSHMCP_CrossOwnerListsHideForeignAssets proves no listing returns an
// asset alice does not own.
func TestSSHMCP_CrossOwnerListsHideForeignAssets(t *testing.T) {
	s, _ := newMCPSSHTenancyServer(t)
	seedMCPSSHOwners(t, s)
	ctx := mcpSSHAs(mcpSSHAliceA)

	for _, req := range []sdkssh.ListKeysRequest{
		{Scope: "tenant", Owner: mcpSSHTenantB},
		{Scope: "user", Owner: "bob"},
		{Scope: "user", Owner: "alice"},
		{},
	} {
		got, err := s.handleSSHKeysList(ctx, sshRequest(t, "ssh.keys.list", req))
		require.NoError(t, err)
		assert.Empty(t, got.(SSHKeyListResult).Items, "keys listed for %+v", req)
	}
	for _, req := range []sdkssh.ListAuthorizedKeysRequest{{Scope: "tenant", Owner: mcpSSHTenantB}, {}} {
		got, err := s.handleSSHAuthorizedKeysList(ctx, sshRequest(t, "ssh.authorizedKeys.list", req))
		require.NoError(t, err)
		assert.Empty(t, got.(SSHAuthorizedListResult).Items, "authorized entries listed for %+v", req)
	}
	for _, req := range []sdkssh.ListKnownHostsRequest{{Scope: "tenant", Owner: mcpSSHTenantB}, {}} {
		got, err := s.handleSSHKnownHostsList(ctx, sshRequest(t, "ssh.knownHosts.list", req))
		require.NoError(t, err)
		assert.Empty(t, got.(SSHPinListResult).Items, "pins listed for %+v", req)
	}
}

// TestSSHMCP_CrossOwnerWritesRefused proves alice cannot plant a key, an
// authorized entry or a pin under another owner.
func TestSSHMCP_CrossOwnerWritesRefused(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	block, err := gossh.MarshalPrivateKey(priv, "")
	require.NoError(t, err)
	privPEM := pem.EncodeToMemory(block)

	attacks := map[string]func(*Server) error{
		"generate tenant": func(s *Server) error {
			_, err := s.handleSSHKeysGenerate(mcpSSHAs(mcpSSHAliceA), sshRequest(t, "ssh.keys.generate",
				sdkssh.GenerateRequest{Scope: "tenant", Owner: mcpSSHTenantB, Name: "planted", Algorithm: "ed25519"}))
			return err
		},
		"generate user": func(s *Server) error {
			_, err := s.handleSSHKeysGenerate(mcpSSHAs(mcpSSHAliceA), sshRequest(t, "ssh.keys.generate",
				sdkssh.GenerateRequest{Scope: "user", Owner: "bob", Name: "planted", Algorithm: "ed25519"}))
			return err
		},
		"import tenant": func(s *Server) error {
			_, err := s.handleSSHKeysImport(mcpSSHAs(mcpSSHAliceA), sshRequest(t, "ssh.keys.import",
				SSHImportParams{Scope: "tenant", Owner: mcpSSHTenantB, Name: "planted", PEM: privPEM}))
			return err
		},
		"add authorized tenant": func(s *Server) error {
			_, err := s.handleSSHAuthorizedKeysAdd(mcpSSHAs(mcpSSHAliceA), sshRequest(t, "ssh.authorizedKeys.add",
				sdkssh.AddAuthorizedKeyRequest{Scope: "tenant", Owner: mcpSSHTenantB, Name: "planted", Line: mcpSSHPublicLine(t)}))
			return err
		},
		"add authorized user": func(s *Server) error {
			_, err := s.handleSSHAuthorizedKeysAdd(mcpSSHAs(mcpSSHAliceA), sshRequest(t, "ssh.authorizedKeys.add",
				sdkssh.AddAuthorizedKeyRequest{Scope: "user", Owner: "bob", Name: "planted", Line: mcpSSHPublicLine(t)}))
			return err
		},
		"add known host tenant": func(s *Server) error {
			_, err := s.handleSSHKnownHostsAdd(mcpSSHAs(mcpSSHAliceA), sshRequest(t, "ssh.knownHosts.add",
				sdkssh.AddKnownHostRequest{Scope: "tenant", Owner: mcpSSHTenantB, Host: "planted.example.com", PublicKey: mcpSSHPublicLine(t)}))
			return err
		},
	}
	for name, attack := range attacks {
		t.Run(name, func(t *testing.T) {
			s, client := newMCPSSHTenancyServer(t)
			err := attack(s)
			require.Error(t, err)
			assert.Equal(t, sdkssh.JSONRPCCodeNotFound, mcpSSHCode(t, err))
			for _, owner := range []*auth.Identity{mcpSSHAdminB, mcpSSHBobA} {
				keys, err := client.Keys().List(mcpSSHAs(owner), sdkssh.ListKeysRequest{})
				require.NoError(t, err)
				assert.Empty(t, keys)
				entries, err := client.AuthorizedKeys().List(mcpSSHAs(owner), sdkssh.ListAuthorizedKeysRequest{})
				require.NoError(t, err)
				assert.Empty(t, entries)
				pins, err := client.KnownHosts().List(mcpSSHAs(owner), sdkssh.ListKnownHostsRequest{})
				require.NoError(t, err)
				assert.Empty(t, pins)
			}
		})
	}
}

// TestSSHMCP_OwnersKeepAccess is the positive control.
func TestSSHMCP_OwnersKeepAccess(t *testing.T) {
	s, _ := newMCPSSHTenancyServer(t)
	seedMCPSSHOwners(t, s)

	_, err := s.handleSSHKeysSign(mcpSSHAs(mcpSSHAdminB), sshRequest(t, "ssh.keys.sign",
		SSHSignParams{Scope: "tenant", Owner: mcpSSHTenantB, Name: "b-key", Digest: []byte("payload")}))
	require.NoError(t, err, "tenant B signs with its own key")
	_, err = s.handleSSHKeysSign(mcpSSHAs(mcpSSHBobA), sshRequest(t, "ssh.keys.sign",
		SSHSignParams{Scope: "user", Owner: "bob", Name: "bob-key", Digest: []byte("payload")}))
	require.NoError(t, err, "bob signs with his own key")
	_, err = s.handleSSHKeysGet(mcpSSHAs(mcpSSHPlatform), sshRequest(t, "ssh.keys.get",
		sdkssh.GetKeyRequest{Scope: "tenant", Owner: mcpSSHTenantB, Name: "b-key"}))
	require.NoError(t, err, "a platform identity reaches tenant B's key")

	_, err = s.handleSSHKeysGenerate(mcpSSHAs(mcpSSHAliceA), sshRequest(t, "ssh.keys.generate",
		sdkssh.GenerateRequest{Scope: "user", Owner: "alice", Name: "alice-a-key", Algorithm: "ed25519"}))
	require.NoError(t, err, "alice creates her own key")
	got, err := s.handleSSHKeysList(mcpSSHAs(mcpSSHAliceA), sshRequest(t, "ssh.keys.list", sdkssh.ListKeysRequest{}))
	require.NoError(t, err)
	items := got.(SSHKeyListResult).Items
	require.Len(t, items, 1, "alice sees her key and only her key")
	assert.Equal(t, "alice-a-key", items[0].Name)
}

func requireMCPSSHOwnersIntact(t *testing.T, client sdkssh.Client) {
	t.Helper()
	_, err := client.Keys().Get(mcpSSHAs(mcpSSHAdminB), sdkssh.GetKeyRequest{Scope: "tenant", Owner: mcpSSHTenantB, Name: "b-key"})
	require.NoError(t, err, "tenant B lost its key")
	_, err = client.Keys().Get(mcpSSHAs(mcpSSHBobA), sdkssh.GetKeyRequest{Scope: "user", Owner: "bob", Name: "bob-key"})
	require.NoError(t, err, "bob lost his key")
	_, err = client.Keys().Get(mcpSSHAs(mcpSSHAliceB), sdkssh.GetKeyRequest{Scope: "user", Owner: "alice", Name: "alice-b-key"})
	require.NoError(t, err, "alice of tenant B lost her key")
	_, err = client.AuthorizedKeys().Get(mcpSSHAs(mcpSSHAdminB), "tenant", mcpSSHTenantB, "b-entry")
	require.NoError(t, err, "tenant B lost its authorized entry")
	pins, err := client.KnownHosts().List(mcpSSHAs(mcpSSHAdminB), sdkssh.ListKnownHostsRequest{Scope: "tenant", Owner: mcpSSHTenantB})
	require.NoError(t, err)
	require.Len(t, pins, 1, "tenant B lost its known-hosts pin")
}
