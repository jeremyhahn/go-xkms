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
	"crypto/fips140"
	"crypto/rand"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
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
	if !requireHandshake(t, err) {
		return
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
	// Under GODEBUG=fips140=only, the handshake's key exchange fails (see
	// requireHandshake) before the server's host key is ever verified
	// against the extra file this test targets, so the error is a
	// handshake failure, not *known_hosts.MismatchError.
	if !fips140.Enforced() {
		var mm *known_hosts.MismatchError
		if !errors.As(err, &mm) {
			t.Fatalf("expected MismatchError, got %T: %v", err, err)
		}
	} else if err == nil {
		t.Fatal("expected an error under GODEBUG=fips140=only")
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
	if !requireHandshake(t, err) {
		return
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
	if !requireHandshake(t, err) {
		return
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

// captureHandler is a minimal slog.Handler test double that records every
// Handle call, so a test can assert a specific best-effort log line was (or
// was not) emitted without depending on text/JSON formatting.
type captureHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r)
	return nil
}

func (h *captureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *captureHandler) WithGroup(string) slog.Handler      { return h }

func (h *captureHandler) hasMessage(msg string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, r := range h.records {
		if r.Message == msg {
			return true
		}
	}
	return false
}

// badMarshalKey wraps a real ssh.PublicKey but reports an empty wire-format
// encoding, forcing known_hosts.Emit to fail with *NoPublicKeyError. It
// exists purely as a test seam for the Emit-failure branch below — nothing
// else in this package can make Emit fail on a key that just came off a real
// SSH handshake.
type badMarshalKey struct {
	ssh.PublicKey
}

func (badMarshalKey) Marshal() []byte { return nil }

// TestFirstContactConfirmer_EmitFailureIsLoggedNotFatal covers the branch
// where known_hosts.Emit cannot render the accepted key: the confirmer still
// accepts the connection (the trust decision was already made by
// HostKeyConfirm), skips the KnownHostsExtraFiles mirror entirely, and logs
// the Emit failure with slog.Warn — the same best-effort convention already
// used for an AppendMissing failure.
func TestFirstContactConfirmer_EmitFailureIsLoggedNotFatal(t *testing.T) {
	handler := &captureHandler{}
	prev := slog.Default()
	slog.SetDefault(slog.New(handler))
	t.Cleanup(func() { slog.SetDefault(prev) })

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	badKey := badMarshalKey{signer.PublicKey()}

	extFile := filepath.Join(t.TempDir(), "known_hosts") // must stay untouched

	confirmer := firstContactConfirmer(DialRequest{
		HostKeyScope:         scope.User,
		HostKeyOwner:         "tester",
		KnownHostsExtraFiles: []string{extFile},
		HostKeyConfirm: func(context.Context, string, ssh.PublicKey) (bool, error) {
			return true, nil
		},
	})

	accept, cerr := confirmer(context.Background(), "badhost.example.com", badKey)
	if cerr != nil {
		t.Fatalf("confirmer: %v", cerr)
	}
	if !accept {
		t.Fatal("expected the confirmer to accept — HostKeyConfirm already approved the key")
	}

	if !handler.hasMessage("ssh/console: failed to render an accepted host key for known_hosts mirroring") {
		t.Fatal("expected the Emit failure to be logged")
	}
	if _, statErr := os.Stat(extFile); !os.IsNotExist(statErr) {
		t.Fatal("expected no known_hosts mirror file to be created when Emit fails")
	}
}

// TestFirstContactConfirmer_AppendMissingFailureIsLoggedNotFatal covers the
// mirror-write branch: Emit succeeds but AppendMissing cannot open the
// destination (a directory, not a file), so the confirmer still accepts the
// connection -- the trust decision was already made by HostKeyConfirm -- and
// logs the failure with slog.Warn rather than propagating it.
func TestFirstContactConfirmer_AppendMissingFailureIsLoggedNotFatal(t *testing.T) {
	handler := &captureHandler{}
	prev := slog.Default()
	slog.SetDefault(slog.New(handler))
	t.Cleanup(func() { slog.SetDefault(prev) })

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	// A path under a directory that does not exist passes the earlier
	// LookupFile check (a missing file just means "not yet known") but
	// AppendMissing's os.OpenFile(O_CREATE) cannot create the file without
	// its parent directory, so the mirror write fails deterministically.
	unwritableDest := filepath.Join(t.TempDir(), "no-such-dir", "known_hosts")

	confirmer := firstContactConfirmer(DialRequest{
		HostKeyScope:         scope.User,
		HostKeyOwner:         "tester",
		KnownHostsExtraFiles: []string{unwritableDest},
		HostKeyConfirm: func(context.Context, string, ssh.PublicKey) (bool, error) {
			return true, nil
		},
	})

	accept, cerr := confirmer(context.Background(), "badhost.example.com", signer.PublicKey())
	if cerr != nil {
		t.Fatalf("confirmer: %v", cerr)
	}
	if !accept {
		t.Fatal("expected the confirmer to accept -- HostKeyConfirm already approved the key")
	}

	if !handler.hasMessage("ssh/console: failed to mirror an accepted host key into an external known_hosts file") {
		t.Fatal("expected the AppendMissing failure to be logged")
	}
}
