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
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	sshbackend "github.com/jeremyhahn/go-xkms/pkg/ssh/backend"
	pkgkeys "github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// TestEmbeddedKeysClient_Signer_KeyNotFound pins the store-lookup error
// path: a nonexistent key surfaces the store's own KeyNotFoundError rather
// than being masked.
func TestEmbeddedKeysClient_Signer_KeyNotFound(t *testing.T) {
	client := newClient(t)
	_, err := client.Keys().Signer(context.Background(), sdkssh.GetKeyRequest{
		Scope: "user", Owner: "alice", Name: "does-not-exist",
	})
	var nf *pkgkeys.KeyNotFoundError
	if !errors.As(err, &nf) {
		t.Fatalf("expected *pkgkeys.KeyNotFoundError, got %T: %v", err, err)
	}
}

// TestEmbeddedKeysClient_Signer_BackendUnavailable pins that a
// backend-backed key resolved through a *different* embedded client over
// the SAME shared Stores — one constructed with no BackendProvider —
// fails with *BackendUnavailableError instead of a nil-pointer panic or a
// silent fallback to a software signer. This is the realistic shape of the
// gap: the key's backend reference persists in storage independent of
// which process (or process configuration) later opens it.
func TestEmbeddedKeysClient_Signer_BackendUnavailable(t *testing.T) {
	ctx := context.Background()
	stores := newStores(t)

	kp, err := software.NewBackend(&software.Config{KeyStorage: storage.New()})
	if err != nil {
		t.Fatalf("software.NewBackend: %v", err)
	}
	provider, err := sshbackend.New(sshbackend.ResolverFunc(func(_ context.Context, _ string) (types.KeyProvider, error) {
		return kp, nil
	}))
	if err != nil {
		t.Fatalf("sshbackend.New: %v", err)
	}

	writer, err := sdkssh.NewEmbedded(sdkssh.EmbeddedOptions{Stores: stores, BackendProvider: provider})
	if err != nil {
		t.Fatalf("NewEmbedded (writer): %v", err)
	}
	defer writer.Close()

	if _, err := writer.Keys().Generate(ctx, sdkssh.GenerateRequest{
		Scope: "user", Owner: "alice", Name: "hw-key", Algorithm: "ecdsa-p256", Backend: "software",
	}); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	reader, err := sdkssh.NewEmbedded(sdkssh.EmbeddedOptions{Stores: stores})
	if err != nil {
		t.Fatalf("NewEmbedded (reader): %v", err)
	}
	defer reader.Close()

	_, err = reader.Keys().Signer(ctx, sdkssh.GetKeyRequest{Scope: "user", Owner: "alice", Name: "hw-key"})
	var bue *sdkssh.BackendUnavailableError
	if !errors.As(err, &bue) {
		t.Fatalf("expected *BackendUnavailableError, got %T: %v", err, err)
	}
	if bue.Backend != "software" {
		t.Fatalf("Backend = %q, want %q", bue.Backend, "software")
	}
}

// TestEmbeddedKeysClient_Signer_BackendResolutionFails pins the path
// distinct from BackendUnavailable: the client DOES have a BackendProvider,
// but that provider fails to resolve a working crypto.Signer for the key's
// backend (e.g. the backend process is unreachable). Signer must surface
// that failure rather than silently returning a signer that later fails to
// sign.
func TestEmbeddedKeysClient_Signer_BackendResolutionFails(t *testing.T) {
	ctx := context.Background()
	stores := newStores(t)

	kp, err := software.NewBackend(&software.Config{KeyStorage: storage.New()})
	if err != nil {
		t.Fatalf("software.NewBackend: %v", err)
	}
	workingProvider, err := sshbackend.New(sshbackend.ResolverFunc(func(_ context.Context, _ string) (types.KeyProvider, error) {
		return kp, nil
	}))
	if err != nil {
		t.Fatalf("sshbackend.New (working): %v", err)
	}

	writer, err := sdkssh.NewEmbedded(sdkssh.EmbeddedOptions{Stores: stores, BackendProvider: workingProvider})
	if err != nil {
		t.Fatalf("NewEmbedded (writer): %v", err)
	}
	defer writer.Close()

	if _, err := writer.Keys().Generate(ctx, sdkssh.GenerateRequest{
		Scope: "user", Owner: "alice", Name: "hw-key", Algorithm: "ecdsa-p256", Backend: "software",
	}); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	resolveErr := errors.New("backend process unreachable")
	brokenProvider, err := sshbackend.New(sshbackend.ResolverFunc(func(_ context.Context, _ string) (types.KeyProvider, error) {
		return nil, resolveErr
	}))
	if err != nil {
		t.Fatalf("sshbackend.New (broken): %v", err)
	}
	reader, err := sdkssh.NewEmbedded(sdkssh.EmbeddedOptions{Stores: stores, BackendProvider: brokenProvider})
	if err != nil {
		t.Fatalf("NewEmbedded (reader): %v", err)
	}
	defer reader.Close()

	_, err = reader.Keys().Signer(ctx, sdkssh.GetKeyRequest{Scope: "user", Owner: "alice", Name: "hw-key"})
	if err == nil {
		t.Fatal("expected an error when the backend provider cannot resolve a signer")
	}
	if !errors.Is(err, resolveErr) {
		t.Fatalf("expected the resolver's failure to be reachable via errors.Is, got %v", err)
	}
}
