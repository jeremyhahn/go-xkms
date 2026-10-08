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

package ssh_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	pkgknownhosts "github.com/jeremyhahn/go-xkms/pkg/ssh/known_hosts"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// mcpTestSignParams / mcpTestSignResult / mcpTestKnownHostVerifyParams
// mirror the unexported wire structs the SDK's MCP client marshals for
// ssh.keys.sign / ssh.knownHosts.verify (see mcp.go's mcpSignParams,
// mcpSignResult, mcpKnownHostVerifyParams) — the JSON tags must match
// exactly since this file decodes what that client sends.
type mcpTestSignParams struct {
	Scope  string `json:"scope"`
	Owner  string `json:"owner"`
	Name   string `json:"name"`
	Digest []byte `json:"digest"`
}

type mcpTestSignResult struct {
	Format string `json:"format"`
	Blob   []byte `json:"blob"`
	Rest   []byte `json:"rest,omitempty"`
}

type mcpTestKnownHostVerifyParams struct {
	Scope     string `json:"scope"`
	Owner     string `json:"owner"`
	Host      string `json:"host"`
	PublicKey string `json:"public_key"`
}

// newMCPSSHFixture wires a fakeMCPServer's ssh.keys.* / ssh.knownHosts.*
// methods to a real embedded sdkssh.Client so Session.Dial exercises
// genuine cryptographic signing and host-key verification — the same
// property the REST and gRPC fixtures give by fronting a real production
// handler. pkg/api/mcp.Server requires a full xkms.XKMSService and
// Authenticator to construct, far more than the SSH RPCs need, so this
// wires the same embedded client the production ssh.* dispatch forwards
// to (see pkg/api/mcp/handlers_ssh.go) directly onto the fake's handler
// table instead of standing up the whole daemon.
func newMCPSSHFixture(t *testing.T) sdkssh.Client {
	t.Helper()
	backend, err := storage.NewMemoryBackend()
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	embedded, err := sdkssh.NewEmbedded(sdkssh.EmbeddedOptions{Backend: backend})
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	t.Cleanup(func() { _ = embedded.Close() })

	srv := newFakeMCPServer(t)
	ctx := context.Background()

	srv.handle("ssh.keys.generate", func(params json.RawMessage) (interface{}, string, qrdbsdk.MCPCode) {
		var req sdkssh.GenerateRequest
		if err := json.Unmarshal(params, &req); err != nil {
			return nil, err.Error(), qrdbsdk.MCPCodeInvalidArgument
		}
		key, err := embedded.Keys().Generate(ctx, req)
		if err != nil {
			return nil, err.Error(), qrdbsdk.MCPCodeInternal
		}
		return key, "", qrdbsdk.MCPCodeOK
	})

	srv.handle("ssh.keys.export", func(params json.RawMessage) (interface{}, string, qrdbsdk.MCPCode) {
		var req sdkssh.ExportRequest
		if err := json.Unmarshal(params, &req); err != nil {
			return nil, err.Error(), qrdbsdk.MCPCodeInvalidArgument
		}
		pub, err := embedded.Keys().ExportPublic(ctx, req)
		if err != nil {
			return nil, err.Error(), qrdbsdk.MCPCodeInternal
		}
		return pub, "", qrdbsdk.MCPCodeOK
	})

	srv.handle("ssh.keys.sign", func(params json.RawMessage) (interface{}, string, qrdbsdk.MCPCode) {
		var req mcpTestSignParams
		if err := json.Unmarshal(params, &req); err != nil {
			return nil, err.Error(), qrdbsdk.MCPCodeInvalidArgument
		}
		signer, err := embedded.Keys().Signer(ctx, sdkssh.GetKeyRequest{
			Scope: req.Scope, Owner: req.Owner, Name: req.Name,
		})
		if err != nil {
			return nil, err.Error(), qrdbsdk.MCPCodeInternal
		}
		sig, err := signer.Sign(rand.Reader, req.Digest)
		if err != nil {
			return nil, err.Error(), qrdbsdk.MCPCodeInternal
		}
		return mcpTestSignResult{Format: sig.Format, Blob: sig.Blob, Rest: sig.Rest}, "", qrdbsdk.MCPCodeOK
	})

	srv.handle("ssh.keys.delete", func(params json.RawMessage) (interface{}, string, qrdbsdk.MCPCode) {
		var req sdkssh.DeleteKeyRequest
		if err := json.Unmarshal(params, &req); err != nil {
			return nil, err.Error(), qrdbsdk.MCPCodeInvalidArgument
		}
		if err := embedded.Keys().Delete(ctx, req); err != nil {
			return nil, err.Error(), qrdbsdk.MCPCodeInternal
		}
		return struct{}{}, "", qrdbsdk.MCPCodeOK
	})

	srv.handle("ssh.knownHosts.add", func(params json.RawMessage) (interface{}, string, qrdbsdk.MCPCode) {
		var req sdkssh.AddKnownHostRequest
		if err := json.Unmarshal(params, &req); err != nil {
			return nil, err.Error(), qrdbsdk.MCPCodeInvalidArgument
		}
		if err := embedded.KnownHosts().Add(ctx, req); err != nil {
			return nil, err.Error(), qrdbsdk.MCPCodeInternal
		}
		return struct{}{}, "", qrdbsdk.MCPCodeOK
	})

	srv.handle("ssh.knownHosts.verify", func(params json.RawMessage) (interface{}, string, qrdbsdk.MCPCode) {
		var req mcpTestKnownHostVerifyParams
		if err := json.Unmarshal(params, &req); err != nil {
			return nil, err.Error(), qrdbsdk.MCPCodeInvalidArgument
		}
		pub, _, _, _, perr := gossh.ParseAuthorizedKey([]byte(req.PublicKey))
		if perr != nil {
			return nil, perr.Error(), qrdbsdk.MCPCodeInvalidArgument
		}
		if err := embedded.KnownHosts().Verify(ctx, req.Scope, req.Owner, req.Host, pub); err != nil {
			// Mirror pkg/api/mcp's real mapSSHError classification so this
			// fixture exercises the same qrdbsdk.MCPCode the production dispatch
			// sends for each condition: an unpinned host is NotFound, a
			// pinned-but-different key is FailedPrecondition (Mismatch).
			var mismatchErr *pkgknownhosts.MismatchError
			if errors.As(err, &mismatchErr) {
				return nil, err.Error(), qrdbsdk.MCPCodeFailedPrecondition
			}
			return nil, err.Error(), qrdbsdk.MCPCodeNotFound
		}
		return struct{}{}, "", qrdbsdk.MCPCodeOK
	})

	return newMCPFixture(t, srv)
}

// TestMCPSessionDial_Success dials the MCP client's Session sub-client
// against a real in-process SSH server, authenticating through the
// forward-signing proxy served over JSON-RPC. Session.Dial needs no
// bidirectional stream from MCP itself: it uses MCP only for the sign and
// verify RPCs, then dials the target directly from this process.
func TestMCPSessionDial_Success(t *testing.T) {
	client := newMCPSSHFixture(t)
	target := newTargetSSHServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	genned, err := client.Keys().Generate(ctx, sdkssh.GenerateRequest{
		Scope: "user", Owner: "alice", Name: "ssh", Algorithm: "ed25519",
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	host, port := target.hostPort()
	if err := client.KnownHosts().Add(ctx, sdkssh.AddKnownHostRequest{
		Scope: "user", Owner: "alice", Host: host,
		PublicKey: authorizedKeyLine(target.signer.PublicKey()),
	}); err != nil {
		t.Fatalf("KnownHosts.Add: %v", err)
	}

	sess, err := client.Session().Dial(ctx, sdkssh.SessionDialRequest{
		KeyScope: "user", KeyOwner: "alice", KeyName: genned.Name,
		Host: host, Port: port, User: "testuser", TimeoutSeconds: 5,
	})
	if err != nil {
		t.Fatalf("Session.Dial: %v", err)
	}
	defer func() { _ = sess.Close() }()

	stdout, _, err := sess.Run(ctx, "echo hello")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(string(stdout), "echo hello") {
		t.Fatalf("unexpected stdout: %q", stdout)
	}
}

// TestMCPSessionDial_UnknownHostRefused asserts host-key verification
// fails closed for an unpinned host. The MCP client's KnownHostsClient.Verify
// maps every server-side verify failure to a *ProtocolError (see mcp.go's
// call()), so — unlike REST/gRPC — this cannot distinguish "unknown host"
// from "mismatched host" by type; it is still always a typed error, never
// a silent accept.
func TestMCPSessionDial_UnknownHostRefused(t *testing.T) {
	client := newMCPSSHFixture(t)
	target := newTargetSSHServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	genned, err := client.Keys().Generate(ctx, sdkssh.GenerateRequest{
		Scope: "user", Owner: "alice", Name: "ssh", Algorithm: "ed25519",
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	host, port := target.hostPort()

	_, err = client.Session().Dial(ctx, sdkssh.SessionDialRequest{
		KeyScope: "user", KeyOwner: "alice", KeyName: genned.Name,
		Host: host, Port: port, User: "testuser", TimeoutSeconds: 5,
	})
	if err == nil {
		t.Fatal("expected dial to fail for an unpinned host")
	}
	var protoErr *sdkssh.ProtocolError
	if !errors.As(err, &protoErr) {
		t.Fatalf("expected *ProtocolError in the chain, got %T: %v", err, err)
	}
}

// TestMCPSessionDial_HostKeyMismatchRefused asserts a pin for the wrong
// host key refuses the connection.
func TestMCPSessionDial_HostKeyMismatchRefused(t *testing.T) {
	client := newMCPSSHFixture(t)
	target := newTargetSSHServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	genned, err := client.Keys().Generate(ctx, sdkssh.GenerateRequest{
		Scope: "user", Owner: "alice", Name: "ssh", Algorithm: "ed25519",
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	host, port := target.hostPort()
	if err := client.KnownHosts().Add(ctx, sdkssh.AddKnownHostRequest{
		Scope: "user", Owner: "alice", Host: host,
		PublicKey: decoyHostKeyLine(t),
	}); err != nil {
		t.Fatalf("KnownHosts.Add: %v", err)
	}

	_, err = client.Session().Dial(ctx, sdkssh.SessionDialRequest{
		KeyScope: "user", KeyOwner: "alice", KeyName: genned.Name,
		Host: host, Port: port, User: "testuser", TimeoutSeconds: 5,
	})
	if err == nil {
		t.Fatal("expected dial to fail for a mismatched host key")
	}
	var protoErr *sdkssh.ProtocolError
	if !errors.As(err, &protoErr) {
		t.Fatalf("expected *ProtocolError in the chain, got %T: %v", err, err)
	}
}

// TestMCPSessionDial_SignerErrorPropagates deletes the authentication key
// before dialing so resolving the remote-signer proxy fails; the failure
// must reach the caller rather than being swallowed.
func TestMCPSessionDial_SignerErrorPropagates(t *testing.T) {
	client := newMCPSSHFixture(t)
	target := newTargetSSHServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	genned, err := client.Keys().Generate(ctx, sdkssh.GenerateRequest{
		Scope: "user", Owner: "alice", Name: "ssh", Algorithm: "ed25519",
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	host, port := target.hostPort()
	if err := client.KnownHosts().Add(ctx, sdkssh.AddKnownHostRequest{
		Scope: "user", Owner: "alice", Host: host,
		PublicKey: authorizedKeyLine(target.signer.PublicKey()),
	}); err != nil {
		t.Fatalf("KnownHosts.Add: %v", err)
	}
	if err := client.Keys().Delete(ctx, sdkssh.DeleteKeyRequest{
		Scope: "user", Owner: "alice", Name: genned.Name,
	}); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err = client.Session().Dial(ctx, sdkssh.SessionDialRequest{
		KeyScope: "user", KeyOwner: "alice", KeyName: genned.Name,
		Host: host, Port: port, User: "testuser", TimeoutSeconds: 5,
	})
	if err == nil {
		t.Fatal("expected dial to fail when the signing key no longer exists")
	}
	var protoErr *sdkssh.ProtocolError
	if !errors.As(err, &protoErr) {
		t.Fatalf("expected *ProtocolError in the chain, got %T: %v", err, err)
	}
	if !strings.Contains(protoErr.Error(), "key not found") {
		t.Fatalf("expected the underlying key-not-found failure to propagate, got: %v", protoErr)
	}
}
