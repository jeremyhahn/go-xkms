package handlers_ssh_test

import (
	"bytes"
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

// errUnknownClientKey is returned by the test server for a key it was not
// told to accept.
var errUnknownClientKey = errors.New("unknown client key")

// plainSigner hides the ssh.AlgorithmSigner methods of the signer it wraps,
// leaving only Sign, which signs RSA keys with ssh-rsa (SHA-1).
type plainSigner struct{ gossh.Signer }

// authenticate runs one public-key handshake of signer against an in-process
// SSH server that accepts only rsa-sha2-256 and rsa-sha2-512 (the OpenSSH
// 8.8+ default) and returns the client's and the server's handshake errors.
func authenticate(t *testing.T, signer gossh.Signer) (clientErr, serverErr error) {
	t.Helper()
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("host key: %v", err)
	}
	hostSigner, err := gossh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatalf("host signer: %v", err)
	}
	want := signer.PublicKey().Marshal()
	cfg := &gossh.ServerConfig{
		PublicKeyAuthAlgorithms: []string{gossh.KeyAlgoRSASHA256, gossh.KeyAlgoRSASHA512},
		PublicKeyCallback: func(_ gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
			if !bytes.Equal(key.Marshal(), want) {
				return nil, errUnknownClientKey
			}
			return nil, nil
		},
	}
	cfg.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	served := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			served <- err
			return
		}
		defer conn.Close()
		sconn, chans, reqs, err := gossh.NewServerConn(conn, cfg)
		served <- err
		if err != nil {
			return
		}
		go gossh.DiscardRequests(reqs)
		go func() {
			for ch := range chans {
				_ = ch.Reject(gossh.Prohibited, "no channels")
			}
		}()
		_ = sconn.Wait()
	}()

	client, clientErr := gossh.Dial("tcp", ln.Addr().String(), &gossh.ClientConfig{
		User:            "alice",
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(signer)},
		HostKeyCallback: gossh.FixedHostKey(hostSigner.PublicKey()),
		Timeout:         5 * time.Second,
	})
	if clientErr == nil {
		defer client.Close()
	}
	select {
	case serverErr = <-served:
	case <-time.After(10 * time.Second):
		t.Fatal("server handshake did not finish")
	}
	return clientErr, serverErr
}

// TestRemoteSigner_RSAAuthenticatesWithSHA2 is the verification of #1755: an
// RSA key held by the server, used through the REST remote signer,
// authenticates to an SSH server that refuses ssh-rsa (SHA-1), because the
// signer carries the rsa-sha2-* algorithm to the server (RFC 8332 §3).
func TestRemoteSigner_RSAAuthenticatesWithSHA2(t *testing.T) {
	srv, embedded, cleanup := newSSHTestServer(t)
	defer cleanup()
	ctx := context.Background()

	if _, err := embedded.Keys().Generate(ctx, sdkssh.GenerateRequest{
		Scope: "user", Owner: "alice", Name: "rsa-key", Algorithm: "rsa", RSABits: 2048,
	}); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	client, err := sdkssh.NewREST(sdkssh.RESTOptions{BaseURL: srv.URL})
	if err != nil {
		t.Fatalf("NewREST: %v", err)
	}
	defer client.Close()
	signer, err := client.Keys().Signer(ctx, sdkssh.GetKeyRequest{Scope: "user", Owner: "alice", Name: "rsa-key"})
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}
	if _, ok := signer.(gossh.AlgorithmSigner); !ok {
		t.Fatalf("remote signer %T does not implement ssh.AlgorithmSigner", signer)
	}

	clientErr, serverErr := authenticate(t, signer)
	if clientErr != nil || serverErr != nil {
		t.Fatalf("authentication failed: client=%v server=%v", clientErr, serverErr)
	}

	// The control: the same remote key signing only through Sign offers
	// ssh-rsa, which this server refuses. Without it, the success above
	// would not show that the server's restriction was in force.
	clientErr, serverErr = authenticate(t, plainSigner{signer})
	if clientErr == nil || serverErr == nil {
		t.Fatalf("ssh-rsa authentication succeeded against a SHA-2-only server: client=%v server=%v", clientErr, serverErr)
	}
}
