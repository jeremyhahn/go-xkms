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

package migrate_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/authorized"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/known_hosts"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/migrate"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/profile"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/records"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/sessions"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// Old keys the fixture writes.
const (
	keyPath     = "ssh/users/alice/keys/id"
	sharedKey   = "ssh/shared/keys/id"
	pinPath     = "acme/ssh/shared/known_hosts/example.com"
	entryPath   = "ssh/services/deploy/authorized_keys/laptop"
	sessionPath = "ssh/sessions/abc123"
	profilePath = "ssh/profiles/p-1.json"
	folderPath  = "ssh/profiles/__folders__/prod/web"
	// Left in place: tenant-prefixed sessions and profiles, and an ssh/
	// key that matches no store.
	tenantSession = "acme/ssh/sessions/abc123"
	tenantProfile = "acme/ssh/profiles/p-1.json"
	strayKey      = "ssh/README"
	// Not part of the SSH layout at all.
	otherKey = "acme/pki/roots/ca"
)

var added = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return data
}

// newKey returns a fresh ed25519 key's SSH public key and OpenSSH PEM.
func newKey(t *testing.T) (ssh.PublicKey, []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("public key: %v", err)
	}
	return sshPub, pem.EncodeToMemory(block)
}

func authorizedLine(pub ssh.PublicKey) string {
	return strings.TrimRight(string(ssh.MarshalAuthorizedKey(pub)), "\n")
}

// legacyKey is the JSON the old keys store wrote.
func legacyKey(t *testing.T, sc scope.Scope, owner string) []byte {
	t.Helper()
	pub, pemBytes := newKey(t)
	return mustJSON(t, map[string]any{
		"v": 2, "scope": sc, "owner": owner, "name": "id",
		"algo": string(keys.AlgorithmEd25519), "fp": keys.Fingerprint(pub), "created": added,
		"pub": authorizedLine(pub), "pem_b64": types.SecretBytes(pemBytes),
	})
}

// seedLegacy fills an old store with one record of every kind plus the keys
// a run must leave alone.
func seedLegacy(t *testing.T) storage.Backend {
	t.Helper()
	pinKey, _ := newKey(t)
	entryKey, _ := newKey(t)
	session := `{"id":"abc123","title":"alice@example.com","host":"example.com","port":22,"user":"alice"}`
	values := map[string][]byte{
		keyPath: legacyKey(t, scope.User, "alice"),
		pinPath: mustJSON(t, map[string]any{
			"v": 1, "scope": "tenant", "owner": "alice", "host": "example.com",
			"fp": keys.Fingerprint(pinKey), "algo": pinKey.Type(), "added": added,
			"source": "manual", "pub": pinKey.Marshal(),
		}),
		entryPath: mustJSON(t, map[string]any{
			"v": 1, "scope": "service", "owner": "deploy", "name": "laptop",
			"added": added, "line": authorizedLine(entryKey) + " laptop",
		}),
		sessionPath:   []byte(session),
		profilePath:   []byte(`{"id":"p-1","name":"web","folder_path":"prod/web","host":"web.example.com"}`),
		folderPath:    []byte(`{}`),
		tenantSession: []byte(session),
		tenantProfile: []byte(`{"id":"p-1","name":"web","host":"web.example.com"}`),
		strayKey:      []byte(`readme`),
		otherKey:      []byte(`ca`),
	}
	legacy := storage.New()
	for key, value := range values {
		if err := legacy.Put(context.Background(), key, value); err != nil {
			t.Fatalf("seed %s: %v", key, err)
		}
	}
	return legacy
}

func remaining(t *testing.T, legacy storage.Backend) []string {
	t.Helper()
	left, err := legacy.List(context.Background(), "")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	slices.Sort(left)
	return left
}

func TestRunMovesTheOldLayout(t *testing.T) {
	ctx := t.Context()
	legacy := seedLegacy(t)
	daos := testutil.NewMemoryDAOFactory()

	report, err := migrate.Run(ctx, legacy, daos)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if want := (migrate.Report{Migrated: 6, Skipped: 3}); report != want {
		t.Fatalf("Report = %+v, want %+v", report, want)
	}
	want := []string{tenantProfile, tenantSession, otherKey, strayKey}
	slices.Sort(want)
	if left := remaining(t, legacy); !slices.Equal(left, want) {
		t.Fatalf("old store keeps %v, want %v", left, want)
	}
	readBack(t, daos)

	// A second run finds nothing left to migrate.
	report, err = migrate.Run(ctx, legacy, daos)
	if err != nil {
		t.Fatalf("second Run: %v", err)
	}
	if want := (migrate.Report{Skipped: 3}); report != want {
		t.Fatalf("second Report = %+v, want %+v", report, want)
	}
	readBack(t, daos)
}

// readBack reads every migrated record through the DAO stores.
func readBack(t *testing.T, daos *qrdbsdk.DAOFactory) {
	t.Helper()
	ctx := t.Context()
	keyStore, err := keys.NewDAOStore(daos)
	if err != nil {
		t.Fatalf("keys store: %v", err)
	}
	k, err := keyStore.Get(ctx, scope.User, "alice", "id")
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	k.Destroy()

	pinStore, err := known_hosts.NewDAOStore(daos)
	if err != nil {
		t.Fatalf("known_hosts store: %v", err)
	}
	acmePins, err := pinStore.Partition("acme")
	if err != nil {
		t.Fatalf("Partition: %v", err)
	}
	if _, err := acmePins.Get(ctx, scope.Tenant, "alice", "example.com"); err != nil {
		t.Fatalf("pin: %v", err)
	}

	entryStore, err := authorized.NewDAOStore(daos)
	if err != nil {
		t.Fatalf("authorized store: %v", err)
	}
	if _, err := entryStore.Get(ctx, scope.Service, "deploy", "laptop"); err != nil {
		t.Fatalf("authorized entry: %v", err)
	}

	sessionStore, err := sessions.NewStore(daos)
	if err != nil {
		t.Fatalf("sessions store: %v", err)
	}
	if s, err := sessionStore.Get("abc123"); err != nil || s.Title != "alice@example.com" {
		t.Fatalf("session = %+v, %v", s, err)
	}

	profileStore, err := profile.NewStore(daos)
	if err != nil {
		t.Fatalf("profile store: %v", err)
	}
	if p, err := profileStore.Get("p-1"); err != nil || p.FolderPath != "prod/web" {
		t.Fatalf("profile = %+v, %v", p, err)
	}
	if folders, err := profileStore.ListFolders(); err != nil || !slices.Contains(folders, "prod/web") {
		t.Fatalf("folders = %v, %v", folders, err)
	}
}

func TestRunEmptyStore(t *testing.T) {
	report, err := migrate.Run(t.Context(), storage.New(), testutil.NewMemoryDAOFactory())
	if err != nil || report != (migrate.Report{}) {
		t.Fatalf("Run = %+v, %v", report, err)
	}
}

func TestRunCorruptRecordStaysAndIsTyped(t *testing.T) {
	ctx := t.Context()
	legacy := storage.New()
	corrupt := map[string]string{
		keyPath:     `{"scope":"user","owner":"alice","name":"id","pub":"not a key"}`,
		entryPath:   `{`,
		sessionPath: `{"id":"abc123"}`,
		profilePath: `{"id":"other","name":"web","host":"h"}`,
	}
	for key, value := range corrupt {
		if err := legacy.Put(ctx, key, []byte(value)); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	report, err := migrate.Run(ctx, legacy, testutil.NewMemoryDAOFactory())
	if want := (migrate.Report{Failed: 4}); report != want {
		t.Fatalf("Report = %+v, want %+v", report, want)
	}
	var failed *migrate.RecordsFailedError
	if !errors.As(err, &failed) || len(failed.Errs) != 4 {
		t.Fatalf("Run error = %v, want *RecordsFailedError with 4 records", err)
	}
	for _, e := range failed.Errs {
		var recordErr *migrate.RecordError
		if !errors.As(e, &recordErr) || recordErr.Op != "import" {
			t.Fatalf("record error = %v, want an import *RecordError", e)
		}
	}
	var legacyErr *records.LegacyRecordError
	if !errors.As(err, &legacyErr) {
		t.Fatalf("Run error = %v, want a *records.LegacyRecordError among them", err)
	}
	if !errors.Is(err, sessions.ErrLegacyRecord) || !errors.Is(err, profile.ErrLegacyRecord) {
		t.Fatalf("Run error = %v, want the session and profile ErrLegacyRecord", err)
	}
	if left := remaining(t, legacy); len(left) != 4 {
		t.Fatalf("old store keeps %v, want all 4 corrupt records", left)
	}
}

func TestRunFailedPutKeepsTheOldKey(t *testing.T) {
	ctx := t.Context()
	daos := testutil.NewMemoryDAOFactory()
	// bob already holds the shared key the old store gave alice.
	keyStore, err := keys.NewDAOStore(daos)
	if err != nil {
		t.Fatalf("keys store: %v", err)
	}
	bobs, err := keys.Generate(ctx, keys.GenerateOptions{Algorithm: keys.AlgorithmEd25519})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	defer bobs.Destroy()
	bobs.Scope, bobs.Owner, bobs.Name = scope.Tenant, "bob", "id"
	if err := keyStore.Put(ctx, bobs); err != nil {
		t.Fatalf("Put: %v", err)
	}
	legacy := storage.New()
	if err := legacy.Put(ctx, sharedKey, legacyKey(t, scope.Tenant, "alice")); err != nil {
		t.Fatalf("seed: %v", err)
	}

	report, err := migrate.Run(ctx, legacy, daos)
	var conflict *records.LegacyOwnerConflictError
	if !errors.As(err, &conflict) || report.Failed != 1 || report.Migrated != 0 {
		t.Fatalf("Run = %+v, %v, want one owner conflict", report, err)
	}
	if left := remaining(t, legacy); !slices.Equal(left, []string{sharedKey}) {
		t.Fatalf("old store keeps %v, want the unmigrated key", left)
	}
}

// failingBackend fails the operations whose error is set.
type failingBackend struct {
	storage.Backend
	listErr, getErr, deleteErr error
}

func (b *failingBackend) List(ctx context.Context, prefix string) ([]string, error) {
	if b.listErr != nil {
		return nil, b.listErr
	}
	return b.Backend.List(ctx, prefix)
}

func (b *failingBackend) Get(ctx context.Context, key string) ([]byte, error) {
	if b.getErr != nil {
		return nil, b.getErr
	}
	return b.Backend.Get(ctx, key)
}

func (b *failingBackend) Delete(ctx context.Context, key string) error {
	if b.deleteErr != nil {
		return b.deleteErr
	}
	return b.Backend.Delete(ctx, key)
}

func TestRunBackendFailures(t *testing.T) {
	boom := errors.New("boom")
	tests := []struct {
		name    string
		backend failingBackend
		op      string
	}{
		{"read", failingBackend{getErr: boom}, "read"},
		{"delete", failingBackend{deleteErr: boom}, "delete"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			tt.backend.Backend = storage.New()
			if err := tt.backend.Put(ctx, sessionPath, []byte(`{"id":"abc123","title":"t","host":"h"}`)); err != nil {
				t.Fatalf("seed: %v", err)
			}
			report, err := migrate.Run(ctx, &tt.backend, testutil.NewMemoryDAOFactory())
			var recordErr *migrate.RecordError
			if !errors.As(err, &recordErr) || recordErr.Op != tt.op || !errors.Is(err, boom) || report.Failed != 1 {
				t.Fatalf("Run = %+v, %v, want a %s *RecordError", report, err, tt.op)
			}
			if len(remaining(t, tt.backend.Backend)) != 1 {
				t.Fatal("the old record was deleted")
			}
		})
	}

	var listErr *migrate.ListError
	_, err := migrate.Run(t.Context(), &failingBackend{Backend: storage.New(), listErr: boom}, testutil.NewMemoryDAOFactory())
	if !errors.As(err, &listErr) || !errors.Is(err, boom) {
		t.Fatalf("Run error = %v, want *ListError", err)
	}
}

func TestRunInvalidInputs(t *testing.T) {
	var nilErr *migrate.NilInputError
	if _, err := migrate.Run(t.Context(), nil, testutil.NewMemoryDAOFactory()); !errors.As(err, &nilErr) || nilErr.Field != "legacy" {
		t.Fatalf("Run(nil legacy) = %v", err)
	}
	if _, err := migrate.Run(t.Context(), storage.New(), nil); !errors.As(err, &nilErr) || nilErr.Field != "daos" {
		t.Fatalf("Run(nil daos) = %v", err)
	}
}

func TestRunStopsWhenCancelled(t *testing.T) {
	legacy := seedLegacy(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	report, err := migrate.Run(ctx, legacy, testutil.NewMemoryDAOFactory())
	if !errors.Is(err, context.Canceled) || report.Migrated != 0 {
		t.Fatalf("Run = %+v, %v, want context.Canceled", report, err)
	}
}

func TestErrorMessages(t *testing.T) {
	boom := errors.New("boom")
	tests := map[string]error{
		"ssh/migrate: legacy is nil":                       &migrate.NilInputError{Field: "legacy"},
		"ssh/migrate: open keys store: boom":               &migrate.OpenError{Store: "keys", Err: boom},
		"ssh/migrate: list legacy store: boom":             &migrate.ListError{Err: boom},
		"ssh/migrate: read ssh/sessions/x: boom":           &migrate.RecordError{Path: "ssh/sessions/x", Op: "read", Err: boom},
		"ssh/migrate: 1 record(s) failed; ssh/migrate: x": &migrate.RecordsFailedError{Errs: []error{errors.New("ssh/migrate: x")}},
	}
	for want, err := range tests {
		if err.Error() != want {
			t.Errorf("Error() = %q, want %q", err.Error(), want)
		}
	}
	if !errors.Is(&migrate.OpenError{Store: "keys", Err: boom}, boom) {
		t.Error("OpenError does not unwrap")
	}
}
