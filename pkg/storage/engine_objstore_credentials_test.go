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

package storage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	objcommon "github.com/jeremyhahn/go-objstore/pkg/common"
	objfactory "github.com/jeremyhahn/go-objstore/pkg/factory"
	qrdbstorage "github.com/jeremyhahn/go-qrdb/sdk/go/storage"
)

// credTestProvider is an object-storage provider that reads both credential
// files, as s3 does, records what it was handed, and stores through the
// "local" provider, so a test can open an EngineObjstore with credential
// files without a cloud account.
const credTestProvider = "xkms-storage-credtest"

var (
	credTestOnce sync.Once
	credTestMu   sync.Mutex
	credTestKey  string
	credTestSec  string
)

func registerCredTestProvider(t *testing.T) {
	t.Helper()
	credTestOnce.Do(func() {
		err := qrdbstorage.RegisterObjStoreProvider(credTestProvider,
			qrdbstorage.ObjStoreProviderCredentials{Key: true, Secret: true},
			func(settings map[string]string, creds objcommon.Credentials) (objcommon.Storage, error) {
				if err := creds.Open(func(key, secret []byte) error {
					credTestMu.Lock()
					defer credTestMu.Unlock()
					credTestKey, credTestSec = string(key), string(secret)
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
	credTestMu.Lock()
	credTestKey, credTestSec = "", ""
	credTestMu.Unlock()
}

// writeCredFile writes a credential file the SDK accepts: owned by the
// process user and readable by nobody else.
func writeCredFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestOpenEngineObjstoreForwardsCredentialFiles is the Codex round 5 P1 on
// #2183: go-qrdb sdk/go v0.58.4-alpha takes object-storage credentials only
// as file references (WithObjStoreCredentialFiles), so an EngineObjstore
// with credentials must forward EngineConfig.CredentialFiles to the provider.
func TestOpenEngineObjstoreForwardsCredentialFiles(t *testing.T) {
	registerCredTestProvider(t)
	ctx := context.Background()
	dir := t.TempDir()
	b, err := OpenEngine(EngineConfig{
		Kind:     EngineObjstore,
		Provider: credTestProvider,
		Options:  map[string]string{"path": filepath.Join(dir, "store")},
		CredentialFiles: &ObjStoreCredentialFiles{
			KeyFile:    writeCredFile(t, dir, "key", "AKIDEXAMPLE"),
			SecretFile: writeCredFile(t, dir, "secret", "s3cr3t-example"),
		},
	})
	if err != nil {
		t.Fatalf("OpenEngine(objstore with credential files): %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })

	credTestMu.Lock()
	key, sec := credTestKey, credTestSec
	credTestMu.Unlock()
	if key != "AKIDEXAMPLE" || sec != "s3cr3t-example" {
		t.Fatalf("provider got key %q secret %q, want the files' contents", key, sec)
	}
	if err := b.Put(ctx, "acme/accounts/1", []byte("acct")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if got, err := b.Get(ctx, "acme/accounts/1"); err != nil || string(got) != "acct" {
		t.Fatalf("Get = %q, %v; want acct", got, err)
	}
}

// TestOpenEngineObjstoreMissingCredentialFile verifies a credential file that
// cannot be read fails the open as an EngineError that still exposes the
// SDK's typed error to errors.As.
func TestOpenEngineObjstoreMissingCredentialFile(t *testing.T) {
	registerCredTestProvider(t)
	dir := t.TempDir()
	missing := filepath.Join(dir, "no-such-key")
	_, err := OpenEngine(EngineConfig{
		Kind:     EngineObjstore,
		Provider: credTestProvider,
		Options:  map[string]string{"path": filepath.Join(dir, "store")},
		CredentialFiles: &ObjStoreCredentialFiles{
			KeyFile:    missing,
			SecretFile: writeCredFile(t, dir, "secret", "s3cr3t-example"),
		},
	})
	if err == nil {
		t.Fatal("OpenEngine with a missing key file succeeded")
	}
	var ee *EngineError
	if !errors.As(err, &ee) || ee.Op != "open-objstore" {
		t.Fatalf("error %v is not an open-objstore EngineError", err)
	}
	var fe *qrdbstorage.ObjStoreCredentialFileError
	if !errors.As(err, &fe) || fe.File != missing {
		t.Fatalf("error %v does not expose the SDK credential file error for %s", err, missing)
	}
}
