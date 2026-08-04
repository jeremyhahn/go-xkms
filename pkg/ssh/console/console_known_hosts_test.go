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

package console

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/known_hosts"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// TestNoopHostKeyStore_ListAndRemove exercises the trivial List/Remove
// interface members of noopHostKeyStore directly — Add/Get are already
// exercised indirectly via KnownHostsSkipStore Dial tests.
func TestNoopHostKeyStore_ListAndRemove(t *testing.T) {
	store := noopHostKeyStore{}
	list, err := store.List(context.Background(), scope.User, "tester")
	if err != nil || list != nil {
		t.Fatalf("expected (nil, nil) from List, got (%v, %v)", list, err)
	}
	err = store.Remove(context.Background(), scope.User, "tester", "ghost.example.com")
	var nf *known_hosts.NotFoundError
	if !errors.As(err, &nf) {
		t.Fatalf("expected NotFoundError from Remove, got %T: %v", err, err)
	}
}

// writeKnownHostsFile writes a single known_hosts line for (host, pub) to a
// fresh file under t.TempDir() and returns its path.
func writeKnownHostsFile(t *testing.T, host string, pub ssh.PublicKey) string {
	t.Helper()
	line, err := known_hosts.Emit(known_hosts.PinFromPublicKey(host, scope.User, "tester", pub, known_hosts.SourceManual))
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	path := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(path, []byte(line+"\n"), 0o600); err != nil {
		t.Fatalf("write known_hosts file: %v", err)
	}
	return path
}

// TestDial_KnownHostsExtraFiles_Known covers the "known via external file"
// branch: a host key present in a KnownHostsExtraFiles entry is treated as
// known without ever consulting HostKeyConfirm, and the pin is self-healed
// into the (empty) store.
func TestDial_KnownHostsExtraFiles_Known(t *testing.T) {
	srv := startEchoSSHServer(t)
	store, err := known_hosts.NewBackendStore(storage.New())
	if err != nil {
		t.Fatalf("known_hosts store: %v", err)
	}
	extFile := writeKnownHostsFile(t, srv.host, srv.hostPub)

	confirmCalled := false
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := Dial(ctx, DialRequest{
		Host:                 srv.host,
		Port:                 srv.port,
		User:                 "tester",
		Signer:               clientSigner(t),
		KnownHosts:           store,
		HostKeyScope:         scope.User,
		HostKeyOwner:         "tester",
		KnownHostsExtraFiles: []string{extFile},
		HostKeyConfirm: func(context.Context, string, ssh.PublicKey) (bool, error) {
			confirmCalled = true
			return true, nil
		},
	}, Config{})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	if confirmCalled {
		t.Fatal("HostKeyConfirm must not be consulted when an extra file already knows the host")
	}
	if _, gerr := store.Get(context.Background(), scope.User, "tester", srv.host); gerr != nil {
		t.Fatalf("expected the external-file match to self-heal a pin into the store: %v", gerr)
	}
}

// TestDial_KnownHostsExtraFiles_Mismatch covers the hard-fail branch: a
// DIFFERENT key for the host in an extra file rejects the connection
// without ever consulting HostKeyConfirm — TOFU never overrides a
// conflicting pin, external-file or store.
func TestDial_KnownHostsExtraFiles_Mismatch(t *testing.T) {
	srv := startEchoSSHServer(t)
	store, err := known_hosts.NewBackendStore(storage.New())
	if err != nil {
		t.Fatalf("known_hosts store: %v", err)
	}
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	otherSigner, _ := ssh.NewSignerFromKey(otherPriv)
	extFile := writeKnownHostsFile(t, srv.host, otherSigner.PublicKey())

	confirmCalled := false
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = Dial(ctx, DialRequest{
		Host:                 srv.host,
		Port:                 srv.port,
		User:                 "tester",
		Signer:               clientSigner(t),
		KnownHosts:           store,
		HostKeyScope:         scope.User,
		HostKeyOwner:         "tester",
		KnownHostsExtraFiles: []string{extFile},
		HostKeyConfirm: func(context.Context, string, ssh.PublicKey) (bool, error) {
			confirmCalled = true
			return true, nil
		},
	}, Config{})
	var mm *known_hosts.MismatchError
	if !errors.As(err, &mm) {
		t.Fatalf("expected MismatchError, got %T: %v", err, err)
	}
	if confirmCalled {
		t.Fatal("HostKeyConfirm must not be consulted on an extra-file mismatch")
	}
}

// TestDial_HostKeyConfirm_FreshAcceptMirrorsIntoExtraFiles covers the
// opposite direction: a genuinely new host accepted via HostKeyConfirm (no
// extra file knows it yet) gets mirrored (best-effort) into every configured
// KnownHostsExtraFiles entry, in addition to being pinned in the store.
func TestDial_HostKeyConfirm_FreshAcceptMirrorsIntoExtraFiles(t *testing.T) {
	srv := startEchoSSHServer(t)
	store, err := known_hosts.NewBackendStore(storage.New())
	if err != nil {
		t.Fatalf("known_hosts store: %v", err)
	}
	extFile := filepath.Join(t.TempDir(), "known_hosts") // does not exist yet

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := Dial(ctx, DialRequest{
		Host:                 srv.host,
		Port:                 srv.port,
		User:                 "tester",
		Signer:               clientSigner(t),
		KnownHosts:           store,
		HostKeyScope:         scope.User,
		HostKeyOwner:         "tester",
		KnownHostsExtraFiles: []string{extFile},
		HostKeyConfirm: func(context.Context, string, ssh.PublicKey) (bool, error) {
			return true, nil
		},
	}, Config{})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	if _, gerr := store.Get(context.Background(), scope.User, "tester", srv.host); gerr != nil {
		t.Fatalf("expected the accepted host to be pinned in the store: %v", gerr)
	}
	pub, found, lerr := known_hosts.LookupFile(extFile, srv.host)
	if lerr != nil {
		t.Fatalf("LookupFile: %v", lerr)
	}
	if !found {
		t.Fatal("expected the accepted host to be mirrored into the extra file")
	}
	if ssh.FingerprintSHA256(pub) != ssh.FingerprintSHA256(srv.hostPub) {
		t.Fatal("mirrored key does not match the accepted host key")
	}
}

// TestDial_KnownHostsSkipStore_NeverConsultsOrWritesStore covers the
// "system"-only policy: the real store is neither read nor written, even
// though a HostKeyConfirm accepts every connection.
func TestDial_KnownHostsSkipStore_NeverConsultsOrWritesStore(t *testing.T) {
	srv := startEchoSSHServer(t)
	// Pin a DIFFERENT key in the real store — if Dial consulted it, this
	// would surface as a mismatch instead of reaching HostKeyConfirm.
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	otherSigner, _ := ssh.NewSignerFromKey(otherPriv)
	store := pinnedHosts(t, srv.host, otherSigner.PublicKey())

	confirmCalled := false
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := Dial(ctx, DialRequest{
		Host:                srv.host,
		Port:                srv.port,
		User:                "tester",
		Signer:              clientSigner(t),
		KnownHosts:          store,
		HostKeyScope:        scope.User,
		HostKeyOwner:        "tester",
		KnownHostsSkipStore: true,
		HostKeyConfirm: func(context.Context, string, ssh.PublicKey) (bool, error) {
			confirmCalled = true
			return true, nil
		},
	}, Config{})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	if !confirmCalled {
		t.Fatal("expected HostKeyConfirm to be consulted when the store is skipped")
	}
	// The real store's conflicting pin must remain untouched (still the
	// "other" fingerprint, not overwritten with the accepted host key).
	pin, gerr := store.Get(context.Background(), scope.User, "tester", srv.host)
	if gerr != nil {
		t.Fatalf("Get: %v", gerr)
	}
	if pin.Fingerprint != ssh.FingerprintSHA256(otherSigner.PublicKey()) {
		t.Fatal("KnownHostsSkipStore must never write to the real store")
	}
}
