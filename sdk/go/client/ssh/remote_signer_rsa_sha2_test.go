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
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// TestRemoteSigner_RSAKeyAuthenticatesToRSASHA2OnlyServer proves that a
// server-held RSA key reached through the REST, gRPC and MCP remote signers
// signs with rsa-sha2-256/512 on request and so authenticates to an SSH
// target that refuses legacy ssh-rsa (SHA-1) signatures (Codex round 5 on
// #2360).
func TestRemoteSigner_RSAKeyAuthenticatesToRSASHA2OnlyServer(t *testing.T) {
	fixtures := map[string]func(t *testing.T) sdkssh.Client{
		"rest": func(t *testing.T) sdkssh.Client {
			_, client, cleanup := newRESTFixture(t)
			t.Cleanup(cleanup)
			return client
		},
		"grpc": newGRPCSSHFixture,
		"mcp":  newMCPSSHFixture,
	}
	for _, name := range []string{"rest", "grpc", "mcp"} {
		newClient := fixtures[name]
		t.Run(name, func(t *testing.T) {
			client := newClient(t)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			if _, err := client.Keys().Generate(ctx, sdkssh.GenerateRequest{
				Scope: "user", Owner: "alice", Name: "rsa", Algorithm: "rsa",
			}); err != nil {
				t.Fatalf("Generate: %v", err)
			}
			signer, err := client.Keys().Signer(ctx, sdkssh.GetKeyRequest{
				Scope: "user", Owner: "alice", Name: "rsa",
			})
			if err != nil {
				t.Fatalf("Signer: %v", err)
			}
			algSigner, ok := signer.(gossh.AlgorithmSigner)
			if !ok {
				t.Fatalf("remote signer %T does not implement ssh.AlgorithmSigner", signer)
			}

			data := []byte("rsa-sha2 remote signer")
			sig, err := algSigner.SignWithAlgorithm(rand.Reader, data, gossh.KeyAlgoRSASHA512)
			if err != nil {
				t.Fatalf("SignWithAlgorithm: %v", err)
			}
			if sig.Format != gossh.KeyAlgoRSASHA512 {
				t.Fatalf("signature format = %q, want %q", sig.Format, gossh.KeyAlgoRSASHA512)
			}
			if err := signer.PublicKey().Verify(data, sig); err != nil {
				t.Fatalf("Verify: %v", err)
			}

			addr, hostPub := startRSASHA2OnlyServer(t, signer.PublicKey())
			conn, err := gossh.Dial("tcp", addr, &gossh.ClientConfig{
				User:            "u",
				Auth:            []gossh.AuthMethod{gossh.PublicKeys(signer)},
				HostKeyCallback: gossh.FixedHostKey(hostPub),
				Timeout:         10 * time.Second,
			})
			if err != nil {
				t.Fatalf("Dial RSA-SHA2-only server: %v", err)
			}
			_ = conn.Close()
		})
	}
}

// startRSASHA2OnlyServer runs an in-process SSH server on 127.0.0.1:0 that
// accepts only the given public key and only rsa-sha2-256/512 signatures.
// It returns the listen address and the server's host public key.
func startRSASHA2OnlyServer(t *testing.T, allowed gossh.PublicKey) (string, gossh.PublicKey) {
	t.Helper()
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	hostSigner, err := gossh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatalf("NewSignerFromKey: %v", err)
	}
	cfg := &gossh.ServerConfig{
		PublicKeyAuthAlgorithms: []string{gossh.KeyAlgoRSASHA256, gossh.KeyAlgoRSASHA512},
		PublicKeyCallback: func(_ gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
			if string(key.Marshal()) == string(allowed.Marshal()) {
				return &gossh.Permissions{}, nil
			}
			return nil, errors.New("public key not allowed")
		},
	}
	cfg.AddHostKey(hostSigner)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			nc, err := lis.Accept()
			if err != nil {
				return
			}
			go func(nc net.Conn) {
				defer func() { _ = nc.Close() }()
				sconn, chans, reqs, err := gossh.NewServerConn(nc, cfg)
				if err != nil {
					return
				}
				defer func() { _ = sconn.Close() }()
				go gossh.DiscardRequests(reqs)
				for ch := range chans {
					_ = ch.Reject(gossh.Prohibited, "no channels")
				}
			}(nc)
		}
	}()
	t.Cleanup(func() {
		_ = lis.Close()
		<-done
	})
	return lis.Addr().String(), hostSigner.PublicKey()
}
