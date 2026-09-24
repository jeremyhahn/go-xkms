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

package mcp

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	gossh "golang.org/x/crypto/ssh"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	pkgknownhosts "github.com/jeremyhahn/go-xkms/pkg/ssh/known_hosts"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// newSSHServer returns an MCP server wired to the embedded SSH client over an
// in-memory storage backend. The embedded client is the real production
// implementation — the handlers under test exercise the same code path an
// xkmsd deployment uses, without a mock in the way.
func newSSHServer(t *testing.T) *Server {
	t.Helper()

	svc := setupTestXKMS(t)
	t.Cleanup(cleanupXKMS)

	backend, err := storage.NewMemoryBackend()
	require.NoError(t, err)

	sshClient, err := sdkssh.NewEmbedded(sdkssh.EmbeddedOptions{Backend: backend})
	require.NoError(t, err)
	t.Cleanup(func() { _ = sshClient.Close() })

	server, err := NewServer(&Config{
		XKMSService:   svc,
		Authenticator: auth.NewNoOpAuthenticator(),
		SSHClient:     sshClient,
	})
	require.NoError(t, err)
	return server
}

// sshRequest builds a JSON-RPC request with the given params object.
func sshRequest(t *testing.T, method string, params interface{}) *JSONRPCRequest {
	t.Helper()

	raw, err := json.Marshal(params)
	require.NoError(t, err)

	return &JSONRPCRequest{JSONRPC: "2.0", Method: method, Params: raw, ID: 1}
}

// generateSSHKey creates a key through the handler under test and returns it.
func generateSSHKey(t *testing.T, s *Server, name string) *sdkssh.Key {
	t.Helper()

	result, err := s.handleSSHKeysGenerate(context.Background(), sshRequest(t, "ssh.keys.generate",
		sdkssh.GenerateRequest{Scope: "user", Owner: "alice", Name: name, Algorithm: "ed25519"}))
	require.NoError(t, err)

	key, ok := result.(*sdkssh.Key)
	require.True(t, ok, "generate must return *sdkssh.Key, got %T", result)
	require.Equal(t, name, key.Name)
	return key
}

// TestSSHKeys_GenerateGetListExportDelete walks a key through its full
// lifecycle over the MCP handlers.
func TestSSHKeys_GenerateGetListExportDelete(t *testing.T) {
	server := newSSHServer(t)
	ctx := context.Background()

	key := generateSSHKey(t, server, "laptop")
	assert.NotEmpty(t, key.PublicKey)

	got, err := server.handleSSHKeysGet(ctx, sshRequest(t, "ssh.keys.get",
		sdkssh.GetKeyRequest{Scope: "user", Owner: "alice", Name: "laptop"}))
	require.NoError(t, err)
	assert.Equal(t, key.Fingerprint, got.(*sdkssh.Key).Fingerprint)

	listed, err := server.handleSSHKeysList(ctx, sshRequest(t, "ssh.keys.list",
		sdkssh.ListKeysRequest{Scope: "user", Owner: "alice"}))
	require.NoError(t, err)
	require.Len(t, listed.(SSHKeyListResult).Items, 1)

	exported, err := server.handleSSHKeysExport(ctx, sshRequest(t, "ssh.keys.export",
		sdkssh.ExportRequest{Scope: "user", Owner: "alice", Name: "laptop"}))
	require.NoError(t, err)
	assert.NotNil(t, exported)

	deleted, err := server.handleSSHKeysDelete(ctx, sshRequest(t, "ssh.keys.delete",
		sdkssh.DeleteKeyRequest{Scope: "user", Owner: "alice", Name: "laptop"}))
	require.NoError(t, err)
	assert.Equal(t, SSHSuccessResult{Success: true}, deleted)

	_, err = server.handleSSHKeysGet(ctx, sshRequest(t, "ssh.keys.get",
		sdkssh.GetKeyRequest{Scope: "user", Owner: "alice", Name: "laptop"}))
	assert.Error(t, err, "deleted key must not be retrievable")
}

// TestSSHKeys_ListWithoutParams proves the list handlers tolerate an omitted
// params object (the documented "list everything" shape).
func TestSSHKeys_ListWithoutParams(t *testing.T) {
	server := newSSHServer(t)
	ctx := context.Background()

	generateSSHKey(t, server, "laptop")

	result, err := server.handleSSHKeysList(ctx, &JSONRPCRequest{JSONRPC: "2.0", Method: "ssh.keys.list", ID: 1})
	require.NoError(t, err)
	assert.Len(t, result.(SSHKeyListResult).Items, 1)
}

// TestSSHKeys_Sign proves ssh.keys.sign produces a signature that verifies
// against the key's public half.
func TestSSHKeys_Sign(t *testing.T) {
	server := newSSHServer(t)
	ctx := context.Background()

	key := generateSSHKey(t, server, "signing-key")

	digest := sha256.Sum256([]byte("payload"))
	result, err := server.handleSSHKeysSign(ctx, sshRequest(t, "ssh.keys.sign",
		SSHSignParams{Scope: "user", Owner: "alice", Name: "signing-key", Digest: digest[:]}))
	require.NoError(t, err)

	sig := result.(SSHSignResult)
	require.NotEmpty(t, sig.Blob)

	pub, _, _, _, err := gossh.ParseAuthorizedKey([]byte(key.PublicKey))
	require.NoError(t, err)
	require.NoError(t, pub.Verify(digest[:], &gossh.Signature{
		Format: sig.Format,
		Blob:   sig.Blob,
		Rest:   sig.Rest,
	}))
}

// TestSSHKeys_SignRejectsEmptyDigest proves the handler refuses to sign
// nothing rather than passing an empty digest to the enclave signer.
func TestSSHKeys_SignRejectsEmptyDigest(t *testing.T) {
	server := newSSHServer(t)

	_, err := server.handleSSHKeysSign(context.Background(), sshRequest(t, "ssh.keys.sign",
		SSHSignParams{Scope: "user", Owner: "alice", Name: "signing-key"}))

	require.Error(t, err)
	var invalid *SSHInvalidParamsError
	require.ErrorAs(t, err, &invalid)
	assert.Contains(t, err.Error(), "digest is required")
}

// TestSSHKeys_SignUnknownKey proves a signer lookup failure surfaces as an
// error instead of a nil-signer panic.
func TestSSHKeys_SignUnknownKey(t *testing.T) {
	server := newSSHServer(t)

	digest := sha256.Sum256([]byte("payload"))
	_, err := server.handleSSHKeysSign(context.Background(), sshRequest(t, "ssh.keys.sign",
		SSHSignParams{Scope: "user", Owner: "alice", Name: "absent", Digest: digest[:]}))

	assert.Error(t, err)
}

// TestSSHKeys_Import round-trips an OpenSSH private key through
// ssh.keys.import, both unencrypted and passphrase-protected.
func TestSSHKeys_Import(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	plainPEM, err := gossh.MarshalPrivateKey(priv, "")
	require.NoError(t, err)

	t.Run("without passphrase", func(t *testing.T) {
		server := newSSHServer(t)

		result, err := server.handleSSHKeysImport(context.Background(), sshRequest(t, "ssh.keys.import",
			SSHImportParams{Scope: "user", Owner: "alice", Name: "imported", PEM: pem.EncodeToMemory(plainPEM)}))

		require.NoError(t, err)
		assert.Equal(t, "imported", result.(*sdkssh.Key).Name)
	})

	t.Run("with passphrase", func(t *testing.T) {
		server := newSSHServer(t)

		encrypted, err := gossh.MarshalPrivateKeyWithPassphrase(priv, "", []byte("hunter2"))
		require.NoError(t, err)

		result, err := server.handleSSHKeysImport(context.Background(), sshRequest(t, "ssh.keys.import",
			SSHImportParams{
				Scope:      "user",
				Owner:      "alice",
				Name:       "imported-enc",
				PEM:        pem.EncodeToMemory(encrypted),
				Passphrase: []byte("hunter2"),
			}))

		require.NoError(t, err)
		assert.Equal(t, "imported-enc", result.(*sdkssh.Key).Name)
	})

	t.Run("wrong passphrase", func(t *testing.T) {
		server := newSSHServer(t)

		encrypted, err := gossh.MarshalPrivateKeyWithPassphrase(priv, "", []byte("hunter2"))
		require.NoError(t, err)

		_, err = server.handleSSHKeysImport(context.Background(), sshRequest(t, "ssh.keys.import",
			SSHImportParams{
				Scope:      "user",
				Owner:      "alice",
				Name:       "imported-bad",
				PEM:        pem.EncodeToMemory(encrypted),
				Passphrase: []byte("wrong"),
			}))

		assert.Error(t, err)
	})
}

// randomHostKey generates an ed25519 keypair and returns its
// authorized_keys-format line together with its OpenSSH SHA256 fingerprint,
// for tests that need a real host key rather than a synthetic fingerprint
// string (the known_hosts store requires the full key on every pin).
func randomHostKey(t *testing.T) (line, fingerprint string) {
	t.Helper()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	sshPub, err := gossh.NewPublicKey(pub)
	require.NoError(t, err)

	line = strings.TrimRight(string(gossh.MarshalAuthorizedKey(sshPub)), "\n")
	return line, gossh.FingerprintSHA256(sshPub)
}

// TestSSHKnownHosts_AddListVerifyRemove exercises the host-key pin surface,
// including the MITM-indicating host-key mismatch. The verify request now
// carries the presented public key rather than a caller-claimed
// fingerprint, so a "spoofed fingerprint" attack is structurally
// impossible: only the actual key bytes are compared, via known_hosts.Verify.
func TestSSHKnownHosts_AddListVerifyRemove(t *testing.T) {
	server := newSSHServer(t)
	ctx := context.Background()

	line, fingerprint := randomHostKey(t)
	otherLine, otherFingerprint := randomHostKey(t)

	added, err := server.handleSSHKnownHostsAdd(ctx, sshRequest(t, "ssh.knownHosts.add",
		sdkssh.AddKnownHostRequest{
			Scope: "user", Owner: "alice",
			Host: "git.example.com", PublicKey: line, Fingerprint: fingerprint, Algorithm: "ssh-ed25519",
		}))
	require.NoError(t, err)
	assert.Equal(t, SSHSuccessResult{Success: true}, added)

	listed, err := server.handleSSHKnownHostsList(ctx, sshRequest(t, "ssh.knownHosts.list",
		sdkssh.ListKnownHostsRequest{Scope: "user", Owner: "alice"}))
	require.NoError(t, err)
	require.Len(t, listed.(SSHPinListResult).Items, 1)

	// A matching key passes.
	ok, err := server.handleSSHKnownHostsVerify(ctx, sshRequest(t, "ssh.knownHosts.verify",
		SSHKnownHostsVerifyParams{Scope: "user", Owner: "alice", Host: "git.example.com", PublicKey: line}))
	require.NoError(t, err)
	assert.Equal(t, SSHSuccessResult{Success: true}, ok)

	// A different key presented for the same host must fail: the compare is
	// on the actual key bytes known_hosts.Verify receives, not a claim the
	// caller ships alongside them.
	_, err = server.handleSSHKnownHostsVerify(ctx, sshRequest(t, "ssh.knownHosts.verify",
		SSHKnownHostsVerifyParams{Scope: "user", Owner: "alice", Host: "git.example.com", PublicKey: otherLine}))
	var mismatch *pkgknownhosts.MismatchError
	require.ErrorAs(t, err, &mismatch, "a changed host key must be reported as a mismatch, not a generic failure")
	assert.Equal(t, fingerprint, mismatch.Expected)
	assert.Equal(t, otherFingerprint, mismatch.Received)

	// An unknown host is reported as unknown.
	_, err = server.handleSSHKnownHostsVerify(ctx, sshRequest(t, "ssh.knownHosts.verify",
		SSHKnownHostsVerifyParams{Scope: "user", Owner: "alice", Host: "other.example.com", PublicKey: line}))
	var notFound *pkgknownhosts.NotFoundError
	require.ErrorAs(t, err, &notFound)
	assert.Equal(t, "other.example.com", notFound.Host)

	removed, err := server.handleSSHKnownHostsRemove(ctx, sshRequest(t, "ssh.knownHosts.remove",
		sdkssh.RemoveKnownHostRequest{Scope: "user", Owner: "alice", Host: "git.example.com"}))
	require.NoError(t, err)
	assert.Equal(t, SSHSuccessResult{Success: true}, removed)

	listed, err = server.handleSSHKnownHostsList(ctx, &JSONRPCRequest{JSONRPC: "2.0", Method: "ssh.knownHosts.list", ID: 1})
	require.NoError(t, err)
	assert.Empty(t, listed.(SSHPinListResult).Items)
}

// TestSSHKnownHosts_VerifyMismatchReportsConflictCode proves a host-key
// mismatch -- the MITM-indicating condition the issue calls out by name --
// carries JSONRPCCodeMismatch, not the ErrCodeInternalError every SSH store
// error used to collapse into before every handler routed through
// mapSSHError (#769).
func TestSSHKnownHosts_VerifyMismatchReportsConflictCode(t *testing.T) {
	server := newSSHServer(t)
	ctx := context.Background()

	line, _ := randomHostKey(t)
	otherLine, _ := randomHostKey(t)
	_, err := server.handleSSHKnownHostsAdd(ctx, sshRequest(t, "ssh.knownHosts.add",
		sdkssh.AddKnownHostRequest{Scope: "user", Owner: "alice", Host: "git.example.com", PublicKey: line}))
	require.NoError(t, err)

	_, err = server.handleSSHKnownHostsVerify(ctx, sshRequest(t, "ssh.knownHosts.verify",
		SSHKnownHostsVerifyParams{Scope: "user", Owner: "alice", Host: "git.example.com", PublicKey: otherLine}))
	var opErr *KeyOpError
	require.ErrorAs(t, err, &opErr)
	assert.Equal(t, sdkssh.JSONRPCCodeMismatch, opErr.Code)
	var mismatch *pkgknownhosts.MismatchError
	require.ErrorAs(t, err, &mismatch)
}

// TestSSHKnownHosts_VerifyMissingPinReportsNotFoundCode proves a missing
// pin carries JSONRPCCodeNotFound, matching the code the keys and
// authorized_keys stores report for the same class of failure.
func TestSSHKnownHosts_VerifyMissingPinReportsNotFoundCode(t *testing.T) {
	server := newSSHServer(t)

	line, _ := randomHostKey(t)
	_, err := server.handleSSHKnownHostsVerify(context.Background(), sshRequest(t, "ssh.knownHosts.verify",
		SSHKnownHostsVerifyParams{Scope: "user", Owner: "alice", Host: "ghost.example.com", PublicKey: line}))
	var opErr *KeyOpError
	require.ErrorAs(t, err, &opErr)
	assert.Equal(t, sdkssh.JSONRPCCodeNotFound, opErr.Code)
}

// TestSSHKnownHosts_AddDuplicateReportsConflictCode proves re-pinning an
// existing host reports JSONRPCCodeDuplicate.
func TestSSHKnownHosts_AddDuplicateReportsConflictCode(t *testing.T) {
	server := newSSHServer(t)
	ctx := context.Background()

	line, _ := randomHostKey(t)
	req := sdkssh.AddKnownHostRequest{Scope: "user", Owner: "alice", Host: "git.example.com", PublicKey: line}
	_, err := server.handleSSHKnownHostsAdd(ctx, sshRequest(t, "ssh.knownHosts.add", req))
	require.NoError(t, err)

	_, err = server.handleSSHKnownHostsAdd(ctx, sshRequest(t, "ssh.knownHosts.add", req))
	var opErr *KeyOpError
	require.ErrorAs(t, err, &opErr)
	assert.Equal(t, sdkssh.JSONRPCCodeDuplicate, opErr.Code)
}

// TestSSHKeys_GetMissingReportsNotFoundCode proves *pkgkeys.KeyNotFoundError
// -- the case the issue names explicitly ("keys-store errors fall through to
// Internal") -- carries JSONRPCCodeNotFound.
func TestSSHKeys_GetMissingReportsNotFoundCode(t *testing.T) {
	server := newSSHServer(t)

	_, err := server.handleSSHKeysGet(context.Background(), sshRequest(t, "ssh.keys.get",
		sdkssh.GetKeyRequest{Scope: "user", Owner: "alice", Name: "ghost"}))
	var opErr *KeyOpError
	require.ErrorAs(t, err, &opErr)
	assert.Equal(t, sdkssh.JSONRPCCodeNotFound, opErr.Code)
}

// TestMapSSHError_UnknownErrorStaysInternal proves an error mapSSHError's
// table does not recognize reports ErrCodeInternalError rather than being
// misclassified as one of the specific NotFound/Duplicate/Mismatch/
// InvalidParams codes -- a caller must never be told a genuinely internal
// failure is a missing resource or a bad request. The underlying error
// stays reachable via Unwrap for server-side logging (mirroring
// mapKeyOpError's identical fallback in errors_keyops.go); wire-level
// redaction for codes.Internal is enforced at the gRPC transport (see
// pkg/api/grpc's sshStatus and TestSSHStatus_UnknownErrorStaysInternal
// WithoutLeakingDetail), the one transport that currently serializes an SSH
// error onto the wire in production.
func TestMapSSHError_UnknownErrorStaysInternal(t *testing.T) {
	opaque := errors.New("open /var/lib/xkms/data/secret-envelope.json: permission denied")

	mapped := mapSSHError(opaque)
	var opErr *KeyOpError
	require.ErrorAs(t, mapped, &opErr)
	assert.Equal(t, ErrCodeInternalError, opErr.Code)
	assert.Same(t, opaque, opErr.Err)
}

// TestSSHKnownHosts_VerifyRequiredFields proves both required fields are
// validated before the store is touched.
func TestSSHKnownHosts_VerifyRequiredFields(t *testing.T) {
	server := newSSHServer(t)

	_, err := server.handleSSHKnownHostsVerify(context.Background(), sshRequest(t, "ssh.knownHosts.verify",
		SSHKnownHostsVerifyParams{PublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA=="}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "host is required")

	_, err = server.handleSSHKnownHostsVerify(context.Background(), sshRequest(t, "ssh.knownHosts.verify",
		SSHKnownHostsVerifyParams{Host: "git.example.com"}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "public_key is required")
}

// TestSSHKnownHosts_VerifyMalformedKey proves an unparsable authorized_keys
// line is rejected with a typed error before the store is touched.
func TestSSHKnownHosts_VerifyMalformedKey(t *testing.T) {
	server := newSSHServer(t)

	_, err := server.handleSSHKnownHostsVerify(context.Background(), sshRequest(t, "ssh.knownHosts.verify",
		SSHKnownHostsVerifyParams{Scope: "user", Owner: "alice", Host: "git.example.com", PublicKey: "not-a-valid-key"}))

	var invalid *sdkssh.InvalidPublicKeyError
	require.ErrorAs(t, err, &invalid)
	assert.Equal(t, "git.example.com", invalid.Host)
}

// TestSSHAuthorizedKeys_Lifecycle exercises the authorized_keys surface end to
// end: emit a line, store it, read it back, verify by fingerprint, remove it.
func TestSSHAuthorizedKeys_Lifecycle(t *testing.T) {
	server := newSSHServer(t)
	ctx := context.Background()

	key := generateSSHKey(t, server, "deploy")

	emitted, err := server.handleSSHAuthorizedKeysEmit(ctx, sshRequest(t, "ssh.authorizedKeys.emit",
		sdkssh.EmitRequest{PublicKey: key.PublicKey, Comment: "deploy@ci"}))
	require.NoError(t, err)
	line := emitted.(SSHEmitResult).Line
	require.NotEmpty(t, line)

	added, err := server.handleSSHAuthorizedKeysAdd(ctx, sshRequest(t, "ssh.authorizedKeys.add",
		sdkssh.AddAuthorizedKeyRequest{Scope: "user", Owner: "alice", Name: "deploy", Line: line}))
	require.NoError(t, err)
	assert.Equal(t, SSHSuccessResult{Success: true}, added)

	got, err := server.handleSSHAuthorizedKeysGet(ctx, sshRequest(t, "ssh.authorizedKeys.get",
		SSHAuthorizedKeysGetParams{Scope: "user", Owner: "alice", Name: "deploy"}))
	require.NoError(t, err)
	assert.Equal(t, "deploy", got.(*sdkssh.AuthorizedEntry).Name)

	listed, err := server.handleSSHAuthorizedKeysList(ctx, sshRequest(t, "ssh.authorizedKeys.list",
		sdkssh.ListAuthorizedKeysRequest{Scope: "user", Owner: "alice"}))
	require.NoError(t, err)
	require.Len(t, listed.(SSHAuthorizedListResult).Items, 1)

	// The verify result is sourced from List, whose entries carry the stored
	// line (the identity-bearing field) rather than the per-entry name.
	verified, err := server.handleSSHAuthorizedKeysVerify(ctx, sshRequest(t, "ssh.authorizedKeys.verify",
		SSHAuthorizedKeysVerifyParams{Scope: "user", Owner: "alice", Fingerprint: key.Fingerprint}))
	require.NoError(t, err)
	assert.Contains(t, verified.(*sdkssh.AuthorizedEntry).Line, key.PublicKey)

	_, err = server.handleSSHAuthorizedKeysVerify(ctx, sshRequest(t, "ssh.authorizedKeys.verify",
		SSHAuthorizedKeysVerifyParams{Scope: "user", Owner: "alice", Fingerprint: "SHA256:sjpqhDnA3eVRWJPnyQweMjO4YW5jRHDyDcSSi882Cbw"}))
	var notFound *SSHNotFoundError
	require.ErrorAs(t, err, &notFound)
	assert.Equal(t, "authorized_key", notFound.Resource)

	removed, err := server.handleSSHAuthorizedKeysRemove(ctx, sshRequest(t, "ssh.authorizedKeys.remove",
		SSHAuthorizedKeysRemoveParams{Scope: "user", Owner: "alice", Name: "deploy"}))
	require.NoError(t, err)
	assert.Equal(t, SSHSuccessResult{Success: true}, removed)

	listed, err = server.handleSSHAuthorizedKeysList(ctx, &JSONRPCRequest{JSONRPC: "2.0", Method: "ssh.authorizedKeys.list", ID: 1})
	require.NoError(t, err)
	assert.Empty(t, listed.(SSHAuthorizedListResult).Items)
}

// TestSSHAuthorizedKeys_VerifyRequiresFingerprint proves the verify handler
// validates its only mandatory field.
func TestSSHAuthorizedKeys_VerifyRequiresFingerprint(t *testing.T) {
	server := newSSHServer(t)

	_, err := server.handleSSHAuthorizedKeysVerify(context.Background(), sshRequest(t, "ssh.authorizedKeys.verify",
		SSHAuthorizedKeysVerifyParams{Scope: "user", Owner: "alice"}))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "fingerprint is required")
}

// TestSSHAuthorizedKeys_AddRejectsMalformedLine proves a line that is not a
// valid authorized_keys entry is refused at the door instead of being stored
// and silently skipped by every later verification.
func TestSSHAuthorizedKeys_AddRejectsMalformedLine(t *testing.T) {
	server := newSSHServer(t)

	_, err := server.handleSSHAuthorizedKeysAdd(context.Background(), sshRequest(t, "ssh.authorizedKeys.add",
		sdkssh.AddAuthorizedKeyRequest{Scope: "user", Owner: "alice", Name: "broken", Line: "not-an-ssh-key"}))

	assert.Error(t, err)
}

// TestSSHAuthorizedKeys_VerifyNoEntries proves verification against an empty
// store reports not-found rather than succeeding vacuously.
func TestSSHAuthorizedKeys_VerifyNoEntries(t *testing.T) {
	server := newSSHServer(t)

	_, err := server.handleSSHAuthorizedKeysVerify(context.Background(), sshRequest(t, "ssh.authorizedKeys.verify",
		SSHAuthorizedKeysVerifyParams{Scope: "user", Owner: "alice", Fingerprint: "SHA256:hXOPj5p/GwS1MpxZDry55CWSXG0JhAicQ6Ai3k8ZwoE"}))

	var notFound *SSHNotFoundError
	require.ErrorAs(t, err, &notFound)
}

// TestSSH_InvalidParams proves every SSH handler that decodes a params object
// rejects malformed JSON with a typed SSHInvalidParamsError instead of
// operating on a zero-valued request.
func TestSSH_InvalidParams(t *testing.T) {
	server := newSSHServer(t)
	ctx := context.Background()

	handlers := map[string]func(context.Context, *JSONRPCRequest) (interface{}, error){
		"ssh.keys.generate":         server.handleSSHKeysGenerate,
		"ssh.keys.import":           server.handleSSHKeysImport,
		"ssh.keys.get":              server.handleSSHKeysGet,
		"ssh.keys.delete":           server.handleSSHKeysDelete,
		"ssh.keys.export":           server.handleSSHKeysExport,
		"ssh.keys.sign":             server.handleSSHKeysSign,
		"ssh.knownHosts.add":        server.handleSSHKnownHostsAdd,
		"ssh.knownHosts.remove":     server.handleSSHKnownHostsRemove,
		"ssh.knownHosts.verify":     server.handleSSHKnownHostsVerify,
		"ssh.authorizedKeys.add":    server.handleSSHAuthorizedKeysAdd,
		"ssh.authorizedKeys.get":    server.handleSSHAuthorizedKeysGet,
		"ssh.authorizedKeys.remove": server.handleSSHAuthorizedKeysRemove,
		"ssh.authorizedKeys.emit":   server.handleSSHAuthorizedKeysEmit,
		"ssh.authorizedKeys.verify": server.handleSSHAuthorizedKeysVerify,
	}

	for method, handler := range handlers {
		t.Run(method, func(t *testing.T) {
			_, err := handler(ctx, &JSONRPCRequest{
				JSONRPC: "2.0",
				Method:  method,
				Params:  json.RawMessage(`"not-an-object"`),
				ID:      1,
			})

			require.Error(t, err)
			var invalid *SSHInvalidParamsError
			assert.ErrorAs(t, err, &invalid, "%s must report a typed invalid-params error", method)
		})
	}
}

// TestSSH_NotConfigured proves every SSH method reports ErrSSHNotConfigured
// when the server was built without an SSH client, rather than panicking on a
// nil sub-client.
func TestSSH_NotConfigured(t *testing.T) {
	server := createTestServer(t)
	ctx := context.Background()

	methods := []string{
		"ssh.keys.generate", "ssh.keys.import", "ssh.keys.list", "ssh.keys.get",
		"ssh.keys.delete", "ssh.keys.export", "ssh.keys.sign",
		"ssh.knownHosts.add", "ssh.knownHosts.list", "ssh.knownHosts.remove", "ssh.knownHosts.verify",
		"ssh.authorizedKeys.add", "ssh.authorizedKeys.get", "ssh.authorizedKeys.list",
		"ssh.authorizedKeys.remove", "ssh.authorizedKeys.emit", "ssh.authorizedKeys.verify",
	}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			handler, ok := rpcMethodHandlers[method]
			require.True(t, ok, "method %s is not registered", method)

			_, err := handler(server, ctx, &JSONRPCRequest{
				JSONRPC: "2.0", Method: method, Params: json.RawMessage(`{}`), ID: 1,
			})

			assert.ErrorIs(t, err, ErrSSHNotConfigured)
		})
	}
}

// TestSSHErrors_Messages pins the typed SSH error strings, including the
// zero-value shapes the handlers can produce.
func TestSSHErrors_Messages(t *testing.T) {
	assert.Equal(t, "mcp/ssh: invalid params", (&SSHInvalidParamsError{}).Error())

	wrapped := &SSHInvalidParamsError{Err: ErrSSHNotConfigured}
	assert.Contains(t, wrapped.Error(), "mcp/ssh: invalid params: ")
	assert.ErrorIs(t, wrapped, ErrSSHNotConfigured, "Unwrap must expose the cause")

	assert.Equal(t, "mcp/ssh: known_host not found: h", (&SSHNotFoundError{Resource: "known_host", Host: "h"}).Error())
	assert.Equal(t, "mcp/ssh: authorized_key not found", (&SSHNotFoundError{Resource: "authorized_key"}).Error())
}

// TestSSHStaticPassphraseProvider proves the provider hands back a secure
// buffer holding exactly the configured bytes.
func TestSSHStaticPassphraseProvider(t *testing.T) {
	provider := &sshStaticPassphraseProvider{data: []byte("hunter2")}

	buf, err := provider.Passphrase(context.Background(), "any-key")
	require.NoError(t, err)
	require.NotNil(t, buf)
	defer buf.Destroy()

	assert.Equal(t, []byte("hunter2"), buf.Bytes())
}
