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
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"

	gossh "golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

const legacyPinKey = "acme/ssh/users/alice/known_hosts/example.com"

func TestMigrateLegacyStores_MovesAndReadsBack(t *testing.T) {
	ctx := t.Context()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	hostKey, err := gossh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("public key: %v", err)
	}
	data, err := json.Marshal(map[string]any{
		"v": 1, "scope": "user", "owner": "alice", "host": "example.com",
		"fp": keys.Fingerprint(hostKey), "algo": hostKey.Type(), "pub": hostKey.Marshal(),
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	legacy := storage.New()
	if err := legacy.Put(ctx, legacyPinKey, data); err != nil {
		t.Fatalf("seed: %v", err)
	}
	daos := testutil.NewMemoryDAOFactory()

	report, err := sdkssh.MigrateLegacyStores(ctx, legacy, daos)
	if err != nil || report != (sdkssh.MigrateReport{Migrated: 1}) {
		t.Fatalf("MigrateLegacyStores = %+v, %v", report, err)
	}
	stores, err := sdkssh.NewStores(daos)
	if err != nil {
		t.Fatalf("NewStores: %v", err)
	}
	acme, err := stores.Partition("acme")
	if err != nil {
		t.Fatalf("Partition: %v", err)
	}
	if _, err := acme.KnownHosts.Get(ctx, scope.User, "alice", "example.com"); err != nil {
		t.Fatalf("migrated pin: %v", err)
	}
	if exists, err := legacy.Exists(ctx, legacyPinKey); err != nil || exists {
		t.Fatalf("old key exists = %v, %v; want it deleted", exists, err)
	}

	report, err = sdkssh.MigrateLegacyStores(ctx, legacy, daos)
	if err != nil || report != (sdkssh.MigrateReport{}) {
		t.Fatalf("second MigrateLegacyStores = %+v, %v; want nothing migrated", report, err)
	}
}

func TestMigrateLegacyStores_CorruptRecord(t *testing.T) {
	ctx := t.Context()
	legacy := storage.New()
	if err := legacy.Put(ctx, legacyPinKey, []byte(`{`)); err != nil {
		t.Fatalf("seed: %v", err)
	}
	report, err := sdkssh.MigrateLegacyStores(ctx, legacy, testutil.NewMemoryDAOFactory())
	var failed *sdkssh.MigrateRecordsFailedError
	var record *sdkssh.MigrateRecordError
	if !errors.As(err, &failed) || !errors.As(err, &record) || record.Path != legacyPinKey || report.Failed != 1 {
		t.Fatalf("MigrateLegacyStores = %+v, %v; want one failed record", report, err)
	}
	if exists, err := legacy.Exists(ctx, legacyPinKey); err != nil || !exists {
		t.Fatalf("old key exists = %v, %v; want it kept", exists, err)
	}
}
