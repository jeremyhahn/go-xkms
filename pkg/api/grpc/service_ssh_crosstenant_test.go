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

package grpc

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/tenancy"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// ===========================================================================
// SSH owner binding over gRPC (go-xkms#1230).
//
// Tenant A's alice addresses SSH assets owned by tenant B, by bob (her own
// tenant), and by the alice of tenant B, who shares her subject. Every RPC
// must answer exactly as it does for a missing asset and leave the asset in
// place; no listing may return one; no write may land under a foreign owner.
// ===========================================================================

const (
	grpcSSHTenantA = "tenant-a"
	grpcSSHTenantB = "tenant-b"
)

var (
	grpcSSHAliceA   = &auth.Identity{Subject: "alice", TenantID: grpcSSHTenantA}
	grpcSSHBobA     = &auth.Identity{Subject: "bob", TenantID: grpcSSHTenantA}
	grpcSSHAdminB   = &auth.Identity{Subject: "b-admin", TenantID: grpcSSHTenantB}
	grpcSSHAliceB   = &auth.Identity{Subject: "alice", TenantID: grpcSSHTenantB}
	grpcSSHPlatform = &auth.Identity{Subject: "root", TenantID: qrdbsdk.SystemTenantID}
)

func grpcSSHAs(id *auth.Identity) context.Context {
	return auth.WithIdentity(context.Background(), id)
}

// newGRPCSSHTenancyService returns a Service over the SSH client xkmsd wires
// into every transport, over an empty in-memory DAO factory, with no
// authorizer so the owner binding is the only check under test.
func newGRPCSSHTenancyService(t *testing.T) (*Service, sdkssh.Client) {
	t.Helper()
	client, err := tenancy.New(tenancy.Options{DAOs: testutil.NewMemoryDAOFactory()})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, client.Close()) })
	svc := NewService(nil, nil, nil)
	svc.SetSSHClient(client)
	return svc, client
}

func grpcSSHPublicLine(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := gossh.NewSignerFromKey(priv)
	require.NoError(t, err)
	return strings.TrimSpace(string(gossh.MarshalAuthorizedKey(signer.PublicKey())))
}

func grpcSSHPrivatePEM(t *testing.T) []byte {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	block, err := gossh.MarshalPrivateKey(priv, "")
	require.NoError(t, err)
	return pem.EncodeToMemory(block)
}

// seedGRPCSSHOwners stores each asset through its rightful owner.
func seedGRPCSSHOwners(t *testing.T, svc *Service) {
	t.Helper()
	gen := func(id *auth.Identity, scope, owner, name string) {
		_, err := svc.SSHGenerateKey(grpcSSHAs(id), &pb.SSHGenerateKeyRequest{
			Scope: scope, Owner: owner, Name: name, Algorithm: "ed25519",
		})
		require.NoError(t, err, "seeding %s/%s/%s", scope, owner, name)
	}
	gen(grpcSSHAdminB, "tenant", grpcSSHTenantB, "b-key")
	gen(grpcSSHBobA, "user", "bob", "bob-key")
	gen(grpcSSHAliceB, "user", "alice", "alice-b-key")

	_, err := svc.SSHAddAuthorizedKey(grpcSSHAs(grpcSSHAdminB), &pb.SSHAddAuthorizedKeyRequest{
		Scope: "tenant", Owner: grpcSSHTenantB, Name: "b-entry", Line: grpcSSHPublicLine(t),
	})
	require.NoError(t, err)
	_, err = svc.SSHAddKnownHost(grpcSSHAs(grpcSSHAdminB), &pb.SSHAddKnownHostRequest{
		Scope: "tenant", Owner: grpcSSHTenantB, Host: "b.example.com", PublicKey: grpcSSHPublicLine(t),
	})
	require.NoError(t, err)
}

// TestSSHGRPC_CrossOwnerReadsAnswerAsMissing proves each by-name RPC refuses
// another owner's asset with the status a missing asset gets.
func TestSSHGRPC_CrossOwnerReadsAnswerAsMissing(t *testing.T) {
	tenantKey := &pb.SSHKeyRef{Scope: "tenant", Owner: grpcSSHTenantB, Name: "b-key"}
	bobKey := &pb.SSHKeyRef{Scope: "user", Owner: "bob", Name: "bob-key"}
	sameSubjectKey := &pb.SSHKeyRef{Scope: "user", Owner: "alice", Name: "alice-b-key"}

	attacks := map[string]func(svc *Service) error{}
	for label, ref := range map[string]*pb.SSHKeyRef{"tenant": tenantKey, "user": bobKey, "same subject other tenant": sameSubjectKey} {
		ref := ref
		attacks[label+" get key"] = func(svc *Service) error {
			_, err := svc.SSHGetKey(grpcSSHAs(grpcSSHAliceA), ref)
			return err
		}
		attacks[label+" export public"] = func(svc *Service) error {
			_, err := svc.SSHExportPublic(grpcSSHAs(grpcSSHAliceA), ref)
			return err
		}
		attacks[label+" sign"] = func(svc *Service) error {
			_, err := svc.SSHSign(grpcSSHAs(grpcSSHAliceA), &pb.SSHSignRequest{Key: ref, Digest: []byte("payload")})
			return err
		}
		attacks[label+" delete key"] = func(svc *Service) error {
			_, err := svc.SSHDeleteKey(grpcSSHAs(grpcSSHAliceA), ref)
			return err
		}
	}
	attacks["tenant remove authorized"] = func(svc *Service) error {
		_, err := svc.SSHRemoveAuthorizedKey(grpcSSHAs(grpcSSHAliceA), &pb.SSHAuthorizedKeyRef{Scope: "tenant", Owner: grpcSSHTenantB, Name: "b-entry"})
		return err
	}
	attacks["tenant remove known host"] = func(svc *Service) error {
		_, err := svc.SSHRemoveKnownHost(grpcSSHAs(grpcSSHAliceA), &pb.SSHRemoveKnownHostRequest{Scope: "tenant", Owner: grpcSSHTenantB, Host: "b.example.com"})
		return err
	}

	for name, attack := range attacks {
		t.Run(name, func(t *testing.T) {
			seeded, seededClient := newGRPCSSHTenancyService(t)
			seedGRPCSSHOwners(t, seeded)
			empty, _ := newGRPCSSHTenancyService(t)

			got := status.Convert(attack(seeded))
			miss := status.Convert(attack(empty))

			assert.Equal(t, codes.NotFound, miss.Code(), "control: the empty deployment must answer NotFound")
			assert.Equal(t, miss.Code(), got.Code(), "another owner's asset must answer as a missing one")
			assert.Equal(t, miss.Message(), got.Message(), "the refusal must carry the genuine-miss message")
			requireGRPCSSHOwnersIntact(t, seededClient)
		})
	}
}

// TestSSHGRPC_CrossOwnerListsHideForeignAssets proves no listing returns an
// asset alice does not own.
func TestSSHGRPC_CrossOwnerListsHideForeignAssets(t *testing.T) {
	svc, _ := newGRPCSSHTenancyService(t)
	seedGRPCSSHOwners(t, svc)
	ctx := grpcSSHAs(grpcSSHAliceA)

	for _, req := range []*pb.SSHListKeysRequest{
		{Scope: "tenant", Owner: grpcSSHTenantB},
		{Scope: "user", Owner: "bob"},
		{Scope: "user", Owner: "alice"},
		{},
	} {
		resp, err := svc.SSHListKeys(ctx, req)
		require.NoError(t, err)
		assert.Empty(t, resp.GetKeys(), "keys listed for %v", req)
	}
	for _, req := range []*pb.SSHListAuthorizedKeysRequest{{Scope: "tenant", Owner: grpcSSHTenantB}, {}} {
		resp, err := svc.SSHListAuthorizedKeys(ctx, req)
		require.NoError(t, err)
		assert.Empty(t, resp.GetEntries(), "authorized entries listed for %v", req)
	}
	for _, req := range []*pb.SSHListKnownHostsRequest{{Scope: "tenant", Owner: grpcSSHTenantB}, {}} {
		resp, err := svc.SSHListKnownHosts(ctx, req)
		require.NoError(t, err)
		assert.Empty(t, resp.GetPins(), "pins listed for %v", req)
	}
}

// TestSSHGRPC_CrossOwnerWritesRefused proves alice cannot plant a key, an
// authorized entry or a pin under another owner.
func TestSSHGRPC_CrossOwnerWritesRefused(t *testing.T) {
	attacks := map[string]func(svc *Service) error{
		"generate tenant": func(svc *Service) error {
			_, err := svc.SSHGenerateKey(grpcSSHAs(grpcSSHAliceA), &pb.SSHGenerateKeyRequest{Scope: "tenant", Owner: grpcSSHTenantB, Name: "planted", Algorithm: "ed25519"})
			return err
		},
		"generate user": func(svc *Service) error {
			_, err := svc.SSHGenerateKey(grpcSSHAs(grpcSSHAliceA), &pb.SSHGenerateKeyRequest{Scope: "user", Owner: "bob", Name: "planted", Algorithm: "ed25519"})
			return err
		},
		"import tenant": func(svc *Service) error {
			_, err := svc.SSHImportKey(grpcSSHAs(grpcSSHAliceA), &pb.SSHImportKeyRequest{Scope: "tenant", Owner: grpcSSHTenantB, Name: "planted", Pem: grpcSSHPrivatePEM(t)})
			return err
		},
		"add authorized tenant": func(svc *Service) error {
			_, err := svc.SSHAddAuthorizedKey(grpcSSHAs(grpcSSHAliceA), &pb.SSHAddAuthorizedKeyRequest{Scope: "tenant", Owner: grpcSSHTenantB, Name: "planted", Line: grpcSSHPublicLine(t)})
			return err
		},
		"add authorized user": func(svc *Service) error {
			_, err := svc.SSHAddAuthorizedKey(grpcSSHAs(grpcSSHAliceA), &pb.SSHAddAuthorizedKeyRequest{Scope: "user", Owner: "bob", Name: "planted", Line: grpcSSHPublicLine(t)})
			return err
		},
		"add known host tenant": func(svc *Service) error {
			_, err := svc.SSHAddKnownHost(grpcSSHAs(grpcSSHAliceA), &pb.SSHAddKnownHostRequest{Scope: "tenant", Owner: grpcSSHTenantB, Host: "planted.example.com", PublicKey: grpcSSHPublicLine(t)})
			return err
		},
	}
	for name, attack := range attacks {
		t.Run(name, func(t *testing.T) {
			svc, client := newGRPCSSHTenancyService(t)
			assert.Equal(t, codes.NotFound, status.Code(attack(svc)))
			for _, owner := range []*auth.Identity{grpcSSHAdminB, grpcSSHBobA} {
				keys, err := client.Keys().List(grpcSSHAs(owner), sdkssh.ListKeysRequest{})
				require.NoError(t, err)
				assert.Empty(t, keys)
				entries, err := client.AuthorizedKeys().List(grpcSSHAs(owner), sdkssh.ListAuthorizedKeysRequest{})
				require.NoError(t, err)
				assert.Empty(t, entries)
				pins, err := client.KnownHosts().List(grpcSSHAs(owner), sdkssh.ListKnownHostsRequest{})
				require.NoError(t, err)
				assert.Empty(t, pins)
			}
		})
	}
}

// TestSSHGRPC_OwnersKeepAccess is the positive control.
func TestSSHGRPC_OwnersKeepAccess(t *testing.T) {
	svc, _ := newGRPCSSHTenancyService(t)
	seedGRPCSSHOwners(t, svc)

	_, err := svc.SSHSign(grpcSSHAs(grpcSSHAdminB), &pb.SSHSignRequest{
		Key: &pb.SSHKeyRef{Scope: "tenant", Owner: grpcSSHTenantB, Name: "b-key"}, Digest: []byte("payload"),
	})
	require.NoError(t, err, "tenant B signs with its own key")
	_, err = svc.SSHSign(grpcSSHAs(grpcSSHBobA), &pb.SSHSignRequest{
		Key: &pb.SSHKeyRef{Scope: "user", Owner: "bob", Name: "bob-key"}, Digest: []byte("payload"),
	})
	require.NoError(t, err, "bob signs with his own key")
	_, err = svc.SSHGetKey(grpcSSHAs(grpcSSHPlatform), &pb.SSHKeyRef{Scope: "tenant", Owner: grpcSSHTenantB, Name: "b-key"})
	require.NoError(t, err, "a platform identity reaches tenant B's key")

	_, err = svc.SSHGenerateKey(grpcSSHAs(grpcSSHAliceA), &pb.SSHGenerateKeyRequest{Scope: "user", Owner: "alice", Name: "alice-a-key", Algorithm: "ed25519"})
	require.NoError(t, err, "alice creates her own key")
	resp, err := svc.SSHListKeys(grpcSSHAs(grpcSSHAliceA), &pb.SSHListKeysRequest{})
	require.NoError(t, err)
	require.Len(t, resp.GetKeys(), 1, "alice sees her key and only her key")
	assert.Equal(t, "alice-a-key", resp.GetKeys()[0].GetName())
}

func requireGRPCSSHOwnersIntact(t *testing.T, client sdkssh.Client) {
	t.Helper()
	_, err := client.Keys().Get(grpcSSHAs(grpcSSHAdminB), sdkssh.GetKeyRequest{Scope: "tenant", Owner: grpcSSHTenantB, Name: "b-key"})
	require.NoError(t, err, "tenant B lost its key")
	_, err = client.Keys().Get(grpcSSHAs(grpcSSHBobA), sdkssh.GetKeyRequest{Scope: "user", Owner: "bob", Name: "bob-key"})
	require.NoError(t, err, "bob lost his key")
	_, err = client.Keys().Get(grpcSSHAs(grpcSSHAliceB), sdkssh.GetKeyRequest{Scope: "user", Owner: "alice", Name: "alice-b-key"})
	require.NoError(t, err, "alice of tenant B lost her key")
	_, err = client.AuthorizedKeys().Get(grpcSSHAs(grpcSSHAdminB), "tenant", grpcSSHTenantB, "b-entry")
	require.NoError(t, err, "tenant B lost its authorized entry")
	pins, err := client.KnownHosts().List(grpcSSHAs(grpcSSHAdminB), sdkssh.ListKnownHostsRequest{Scope: "tenant", Owner: grpcSSHTenantB})
	require.NoError(t, err)
	require.Len(t, pins, 1, "tenant B lost its known-hosts pin")
}
