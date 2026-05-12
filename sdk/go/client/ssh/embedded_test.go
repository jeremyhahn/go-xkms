// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// newClient returns a fresh embedded Client backed by an in-memory
// storage.Backend.
func newClient(t *testing.T) sdkssh.Client {
	t.Helper()
	backend, err := storage.NewMemoryBackend()
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	client, err := sdkssh.NewEmbedded(sdkssh.EmbeddedOptions{Backend: backend})
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Logf("client close: %v", err)
		}
	})
	return client
}

// TestNewEmbedded_NilBackend rejects a nil backend with NilInputError.
func TestNewEmbedded_NilBackend(t *testing.T) {
	_, err := sdkssh.NewEmbedded(sdkssh.EmbeddedOptions{})
	var nie *sdkssh.NilInputError
	if !errors.As(err, &nie) {
		t.Fatalf("expected NilInputError, got %T: %v", err, err)
	}
}

// TestKeys_GenerateListGetDelete covers the key-management happy path.
func TestKeys_GenerateListGetDelete(t *testing.T) {
	client := newClient(t)
	ctx := context.Background()
	keys := client.Keys()

	gen, err := keys.Generate(ctx, sdkssh.GenerateRequest{
		Scope:     "user",
		Owner:     "alice",
		Name:      "laptop",
		Algorithm: "ed25519",
		Comment:   "alice@workstation",
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if gen.Fingerprint == "" {
		t.Fatal("expected fingerprint")
	}
	if gen.Scope != "user" || gen.Owner != "alice" || gen.Name != "laptop" {
		t.Fatalf("unexpected metadata: %+v", gen)
	}

	list, err := keys.List(ctx, sdkssh.ListKeysRequest{Scope: "user", Owner: "alice"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 key, got %d", len(list))
	}

	got, err := keys.Get(ctx, sdkssh.GetKeyRequest{Scope: "user", Owner: "alice", Name: "laptop"})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Fingerprint != gen.Fingerprint {
		t.Fatalf("fingerprint mismatch")
	}

	pub, err := keys.ExportPublic(ctx, sdkssh.ExportRequest{Scope: "user", Owner: "alice", Name: "laptop"})
	if err != nil {
		t.Fatalf("ExportPublic: %v", err)
	}
	if pub.Fingerprint != gen.Fingerprint {
		t.Fatalf("public fingerprint mismatch")
	}

	if err := keys.Delete(ctx, sdkssh.DeleteKeyRequest{Scope: "user", Owner: "alice", Name: "laptop"}); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

// TestKeys_SignAndVerify uses Signer() to produce a signature and
// verifies it against the exported public key. Exercises the enclave
// re-open path on every Sign call.
func TestKeys_SignAndVerify(t *testing.T) {
	client := newClient(t)
	ctx := context.Background()
	keys := client.Keys()

	_, err := keys.Generate(ctx, sdkssh.GenerateRequest{
		Scope:     "user",
		Owner:     "alice",
		Name:      "laptop",
		Algorithm: "ed25519",
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	signer, err := keys.Signer(ctx, sdkssh.GetKeyRequest{Scope: "user", Owner: "alice", Name: "laptop"})
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}
	msg := []byte("the quick brown fox")
	sig, err := signer.Sign(rand.Reader, msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := signer.PublicKey().Verify(msg, sig); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// TestKeys_ImportUnencrypted accepts a plain PEM.
func TestKeys_ImportUnencrypted(t *testing.T) {
	client := newClient(t)
	ctx := context.Background()
	keys := client.Keys()

	// Produce an unencrypted ed25519 PEM.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	block, err := gossh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("MarshalPrivateKey: %v", err)
	}
	pemBytes := pem.EncodeToMemory(block)

	got, err := keys.Import(ctx, sdkssh.ImportRequest{
		Scope: "user",
		Owner: "alice",
		Name:  "imported",
		PEM:   pemBytes,
	}, nil)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if got.Algorithm != "ed25519" {
		t.Fatalf("unexpected algorithm: %s", got.Algorithm)
	}
}

// TestKeys_ImportEncryptedRoundtrip supplies a passphrase via
// CallbackProvider and confirms the provider is consulted.
func TestKeys_ImportEncryptedRoundtrip(t *testing.T) {
	client := newClient(t)
	ctx := context.Background()
	keys := client.Keys()

	// Encrypt an ecdsa-p256 key with a passphrase.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa: %v", err)
	}
	pass := []byte("hunter2")
	block, err := gossh.MarshalPrivateKeyWithPassphrase(priv, "encrypted", pass)
	if err != nil {
		t.Fatalf("MarshalPrivateKeyWithPassphrase: %v", err)
	}
	pemBytes := pem.EncodeToMemory(block)

	var invocations atomic.Int32
	provider := secure.NewCallbackProvider(func(_ context.Context, _ string) ([]byte, error) {
		invocations.Add(1)
		out := make([]byte, len(pass))
		copy(out, pass)
		return out, nil
	})

	got, err := keys.Import(ctx, sdkssh.ImportRequest{
		Scope: "user",
		Owner: "alice",
		Name:  "enc",
		PEM:   pemBytes,
	}, provider)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if invocations.Load() != 1 {
		t.Fatalf("expected provider to be called once, got %d", invocations.Load())
	}
	if got.Algorithm != "ecdsa-p256" {
		t.Fatalf("unexpected algorithm: %s", got.Algorithm)
	}
}

// TestKeys_InvalidScope surfaces InvalidScopeError for bad input.
func TestKeys_InvalidScope(t *testing.T) {
	client := newClient(t)
	ctx := context.Background()
	keys := client.Keys()
	_, err := keys.Generate(ctx, sdkssh.GenerateRequest{
		Scope:     "bogus",
		Owner:     "alice",
		Name:      "x",
		Algorithm: "ed25519",
	})
	var se *sdkssh.InvalidScopeError
	if !errors.As(err, &se) {
		t.Fatalf("expected InvalidScopeError, got %T: %v", err, err)
	}
}

// TestKeys_InvalidAlgorithm surfaces InvalidAlgorithmError.
func TestKeys_InvalidAlgorithm(t *testing.T) {
	client := newClient(t)
	ctx := context.Background()
	keys := client.Keys()
	_, err := keys.Generate(ctx, sdkssh.GenerateRequest{
		Scope:     "user",
		Owner:     "alice",
		Name:      "x",
		Algorithm: "blowfish",
	})
	var ae *sdkssh.InvalidAlgorithmError
	if !errors.As(err, &ae) {
		t.Fatalf("expected InvalidAlgorithmError, got %T: %v", err, err)
	}
}

// TestKnownHosts_AddListRemoveVerify exercises the pin sub-client.
func TestKnownHosts_AddListRemoveVerify(t *testing.T) {
	client := newClient(t)
	ctx := context.Background()
	hosts := client.KnownHosts()

	// Generate an SSH public key to pin.
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	sshPub, err := gossh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	fp := gossh.FingerprintSHA256(sshPub)

	if err := hosts.Add(ctx, sdkssh.AddKnownHostRequest{
		Scope:       "user",
		Owner:       "alice",
		Host:        "bastion.example.com",
		Fingerprint: fp,
		Algorithm:   sshPub.Type(),
	}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	list, err := hosts.List(ctx, sdkssh.ListKnownHostsRequest{Scope: "user", Owner: "alice"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 pin, got %d", len(list))
	}

	if err := hosts.Verify(ctx, "user", "alice", "bastion.example.com", sshPub); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if err := hosts.Remove(ctx, sdkssh.RemoveKnownHostRequest{
		Scope: "user", Owner: "alice", Host: "bastion.example.com",
	}); err != nil {
		t.Fatalf("Remove: %v", err)
	}
}

// TestAuthorizedKeys_EmitAddVerify wires Emit + Add + Verify.
func TestAuthorizedKeys_EmitAddVerify(t *testing.T) {
	client := newClient(t)
	ctx := context.Background()

	// Generate a key through Keys to get a public line via Emit's
	// input path.
	keys := client.Keys()
	genned, err := keys.Generate(ctx, sdkssh.GenerateRequest{
		Scope:     "user",
		Owner:     "alice",
		Name:      "forauth",
		Algorithm: "ed25519",
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	auth := client.AuthorizedKeys()
	line, err := auth.Emit(ctx, sdkssh.EmitRequest{
		PublicKey: genned.PublicKey,
		Options:   []string{"no-pty"},
		Comment:   "alice@forauth",
	})
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if err := auth.Add(ctx, sdkssh.AddAuthorizedKeyRequest{
		Scope: "user", Owner: "alice", Name: "forauth", Line: line,
	}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// Verify the pinned authorized entry matches the key's public half.
	pub, _, _, _, perr := gossh.ParseAuthorizedKey([]byte(genned.PublicKey))
	if perr != nil {
		t.Fatalf("ParseAuthorizedKey: %v", perr)
	}
	got, err := auth.Verify(ctx, "user", "alice", pub)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil entry")
	}
}

// TestSession_RejectsMissingKnownHost asserts the session sub-client
// refuses to dial without a pinned host.
func TestSession_RejectsMissingKnownHost(t *testing.T) {
	client := newClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	keys := client.Keys()
	_, err := keys.Generate(ctx, sdkssh.GenerateRequest{
		Scope:     "user",
		Owner:     "alice",
		Name:      "ssh",
		Algorithm: "ed25519",
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	_, err = client.Session().Dial(ctx, sdkssh.SessionDialRequest{
		KeyScope: "user", KeyOwner: "alice", KeyName: "ssh",
		Host: "127.0.0.1", Port: 1, User: "testuser",
		TimeoutSeconds: 1,
	})
	if err == nil {
		t.Fatal("expected dial to fail without pin")
	}
}
