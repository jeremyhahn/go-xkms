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

//go:build integration

package ssh

// This suite drives the real `xkey ssh sessions` command against the shared
// SSH store — the persistent-session records the GUI restores as console
// tabs after a reload/restart. Records are seeded through the same
// sdk/sshstore path the GUI writes through, proving CLI↔GUI store
// compatibility, and only sessions explicitly persisted ever appear.

import (
	"path/filepath"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
	sshsdk "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/sshstore"
)

// sharedSSHDAOs opens the helper's shared SSH store exactly the way the GUI
// does (a DAO factory over sshstore.ResolveBackend) and closes it when the
// test ends.
func sharedSSHDAOs(t *testing.T, h *SSHTestHelper) *qrdbsdk.DAOFactory {
	t.Helper()
	backend, err := sshstore.ResolveBackend(filepath.Join(h.HomeDir(), "data"), xkmssdk.StorageEngineFile, nil)
	if err != nil {
		t.Fatalf("ResolveBackend: %v", err)
	}
	t.Cleanup(func() {
		if cerr := backend.Close(); cerr != nil {
			t.Errorf("close ssh store: %v", cerr)
		}
	})
	kv, err := xkmssdk.NewKVStoreAdapter(backend)
	if err != nil {
		t.Fatalf("NewKVStoreAdapter: %v", err)
	}
	return xkmssdk.NewStoreDAOFactory(kv)
}

// seedPersistedSession writes a session record into the helper's shared SSH
// store exactly the way the GUI does.
func seedPersistedSession(t *testing.T, h *SSHTestHelper, rec *sshsdk.ConsoleSessionRecord) string {
	t.Helper()
	store, err := sshsdk.NewConsoleSessionStore(sharedSSHDAOs(t, h))
	if err != nil {
		t.Fatalf("NewConsoleSessionStore: %v", err)
	}
	defer func() { _ = store.Close() }()
	if serr := store.Save(rec); serr != nil {
		t.Fatalf("Save session: %v", serr)
	}
	return rec.ID
}

// TestSSHSessionsListEmpty verifies a fresh store reports no persistent
// sessions — the memory-only default never records anything.
func TestSSHSessionsListEmpty(t *testing.T) {
	h := NewSSHTestHelper(t)
	res := h.RunSSH("sessions", "list")
	if !res.Success() {
		t.Fatalf("sessions list failed: %s", res.Combined())
	}
	if !res.OutputContains("No persistent sessions found") {
		t.Fatalf("expected empty-list message, got: %s", res.Combined())
	}
}

// TestSSHSessionsListAndRemove seeds records through the GUI's store path and
// verifies the CLI lists (most recent first, with origins) and removes them.
func TestSSHSessionsListAndRemove(t *testing.T) {
	h := NewSSHTestHelper(t)

	idOneTime := seedPersistedSession(t, h, &sshsdk.ConsoleSessionRecord{
		Title: "deploy@web1", Host: "web1", Port: 2222, User: "deploy", KeyName: "laptop",
	})
	seedPersistedSession(t, h, &sshsdk.ConsoleSessionRecord{
		Title: "omega", ProfileID: "omega-profile-id",
	})

	list := h.RunSSH("sessions", "list")
	if !list.Success() {
		t.Fatalf("sessions list failed: %s", list.Combined())
	}
	if !list.OutputContains("deploy@web1") || !list.OutputContains("deploy@web1:2222") {
		t.Fatalf("one-time session missing from list: %s", list.Combined())
	}
	if !list.OutputContains("profile:omega-profile-id") {
		t.Fatalf("profile session origin missing from list: %s", list.Combined())
	}

	rm := h.RunSSH("sessions", "rm", idOneTime)
	if !rm.Success() {
		t.Fatalf("sessions rm failed: %s", rm.Combined())
	}
	after := h.RunSSH("sessions", "list")
	if after.OutputContains("deploy@web1") {
		t.Fatalf("removed session still listed: %s", after.Combined())
	}
	if !after.OutputContains("omega") {
		t.Fatalf("remaining session missing after rm: %s", after.Combined())
	}

	// Removing an unknown ID fails with a not-found error.
	missing := h.RunSSH("sessions", "rm", "does-not-exist")
	if missing.Success() {
		t.Fatal("sessions rm of unknown ID should fail")
	}
	if !missing.OutputContains("not found") {
		t.Fatalf("expected not-found error, got: %s", missing.Combined())
	}
}

// TestSSHProfileAddPersistSession verifies the profile-level opt-in
// round-trips through the store (GUI profile connects honor it).
func TestSSHProfileAddPersistSession(t *testing.T) {
	h := NewSSHTestHelper(t)

	add := h.RunSSH("profile", "add",
		"--name", "persist-box", "--host", "web1", "--user", "deploy",
		"--persist-session")
	if !add.Success() {
		t.Fatalf("profile add failed: %s", add.Combined())
	}

	store, err := sshsdk.NewProfileStore(sharedSSHDAOs(t, h))
	if err != nil {
		t.Fatalf("NewProfileStore: %v", err)
	}
	defer func() { _ = store.Close() }()
	p, err := store.Get("persist-box")
	if err != nil {
		t.Fatalf("Get profile: %v", err)
	}
	if !p.PersistSession {
		t.Fatalf("expected PersistSession=true, got %+v", p)
	}

	// Default remains memory-only.
	addDefault := h.RunSSH("profile", "add", "--name", "memory-box", "--host", "web2", "--user", "deploy")
	if !addDefault.Success() {
		t.Fatalf("profile add (default) failed: %s", addDefault.Combined())
	}
	pd, err := store.Get("memory-box")
	if err != nil {
		t.Fatalf("Get default profile: %v", err)
	}
	if pd.PersistSession {
		t.Fatalf("default profile must not persist sessions: %+v", pd)
	}
}
