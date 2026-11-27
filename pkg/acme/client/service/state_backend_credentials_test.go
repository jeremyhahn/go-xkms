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

package service

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	objcommon "github.com/jeremyhahn/go-objstore/pkg/common"
	objfactory "github.com/jeremyhahn/go-objstore/pkg/factory"
	qrdbstorage "github.com/jeremyhahn/go-qrdb/sdk/go/storage"
)

// acmeCredTestProvider reads both credential files, as s3 does, records what
// it was handed, and stores through the "local" provider.
const acmeCredTestProvider = "xkms-acme-credtest"

var (
	acmeCredOnce sync.Once
	acmeCredMu   sync.Mutex
	acmeCredKey  string
	acmeCredSec  string
)

func registerACMECredTestProvider(t *testing.T) {
	t.Helper()
	acmeCredOnce.Do(func() {
		err := qrdbstorage.RegisterObjStoreProvider(acmeCredTestProvider,
			qrdbstorage.ObjStoreProviderCredentials{Key: true, Secret: true},
			func(settings map[string]string, creds objcommon.Credentials) (objcommon.Storage, error) {
				if err := creds.Open(func(key, secret []byte) error {
					acmeCredMu.Lock()
					defer acmeCredMu.Unlock()
					acmeCredKey, acmeCredSec = string(key), string(secret)
					return nil
				}); err != nil {
					return nil, err
				}
				return objfactory.NewStorage("local", settings, objcommon.Credentials{})
			})
		if err != nil {
			t.Fatalf("RegisterObjStoreProvider: %v", err)
		}
	})
	acmeCredMu.Lock()
	acmeCredKey, acmeCredSec = "", ""
	acmeCredMu.Unlock()
}

// TestCreateStateBackend_ForwardsCredentialFiles is the ACME half of the
// Codex round 5 P1 on #2183: go-qrdb sdk/go v0.58.4-alpha refuses inline
// object-storage credentials, so the client's state backend takes them as
// storage.key_file and storage.secret_file and hands them to the provider.
func TestCreateStateBackend_ForwardsCredentialFiles(t *testing.T) {
	registerACMECredTestProvider(t)
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	backend, err := createStateBackend(StorageConfig{
		Backend:    acmeCredTestProvider,
		Options:    map[string]interface{}{"path": filepath.Join(dir, "state")},
		KeyFile:    write("key", "AKIDEXAMPLE"),
		SecretFile: write("secret", "s3cr3t-example"),
	})
	if err != nil {
		t.Fatalf("createStateBackend with credential files: %v", err)
	}
	t.Cleanup(func() { _ = backend.Close() })

	acmeCredMu.Lock()
	key, sec := acmeCredKey, acmeCredSec
	acmeCredMu.Unlock()
	if key != "AKIDEXAMPLE" || sec != "s3cr3t-example" {
		t.Fatalf("provider got key %q secret %q, want the files' contents", key, sec)
	}
	ctx := context.Background()
	if err := backend.Put(ctx, "accounts/1", []byte("acct")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if got, err := backend.Get(ctx, "accounts/1"); err != nil || string(got) != "acct" {
		t.Fatalf("Get = %q, %v; want acct", got, err)
	}
}
