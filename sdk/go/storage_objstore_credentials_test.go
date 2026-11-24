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

package xkms

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	objcommon "github.com/jeremyhahn/go-objstore/pkg/common"
	objfactory "github.com/jeremyhahn/go-objstore/pkg/factory"
)

// sdkCredTestProvider is an object-storage provider that reads both
// credential files, as s3 does, records what it was handed, and stores
// through the "local" provider, so a test can open NewObjectStorage with
// credential files without a cloud account.
const sdkCredTestProvider = "xkms-sdk-credtest"

var (
	sdkCredTestOnce sync.Once
	sdkCredTestMu   sync.Mutex
	sdkCredTestKey  string
	sdkCredTestSec  string
)

func registerSDKCredTestProvider(t *testing.T) {
	t.Helper()
	sdkCredTestOnce.Do(func() {
		err := RegisterObjectStorageProvider(sdkCredTestProvider,
			ObjectStorageProviderCredentials{Key: true, Secret: true},
			func(settings map[string]string, creds objcommon.Credentials) (objcommon.Storage, error) {
				if err := creds.Open(func(key, secret []byte) error {
					sdkCredTestMu.Lock()
					defer sdkCredTestMu.Unlock()
					sdkCredTestKey, sdkCredTestSec = string(key), string(secret)
					return nil
				}); err != nil {
					return nil, err
				}
				return objfactory.NewStorage("local", settings, objcommon.Credentials{})
			})
		if err != nil {
			t.Fatalf("RegisterObjectStorageProvider: %v", err)
		}
	})
	sdkCredTestMu.Lock()
	sdkCredTestKey, sdkCredTestSec = "", ""
	sdkCredTestMu.Unlock()
}

func writeSDKCredFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestNewObjectStorageCredentialFiles is the Codex P1 on #2183 at
// sdk/go/storage.go: go-qrdb sdk/go v0.58.4-alpha takes object-storage
// credentials only as file references, so the SDK must re-export the
// credential-file option for NewObjectStorage to open with credentials.
func TestNewObjectStorageCredentialFiles(t *testing.T) {
	registerSDKCredTestProvider(t)
	dir := t.TempDir()
	store, err := NewObjectStorage(sdkCredTestProvider,
		map[string]string{"path": filepath.Join(dir, "store")},
		WithObjectStorageCredentialFiles(ObjectStorageCredentialFiles{
			KeyFile:    writeSDKCredFile(t, dir, "key", "AKIDEXAMPLE"),
			SecretFile: writeSDKCredFile(t, dir, "secret", "s3cr3t-example"),
		}))
	if err != nil {
		t.Fatalf("NewObjectStorage(with credential files): %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	sdkCredTestMu.Lock()
	key, sec := sdkCredTestKey, sdkCredTestSec
	sdkCredTestMu.Unlock()
	if key != "AKIDEXAMPLE" || sec != "s3cr3t-example" {
		t.Fatalf("provider got key %q secret %q, want the files' contents", key, sec)
	}
	if err := store.Set([]byte("ca/blob/1"), []byte("blob")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if got, err := store.Get([]byte("ca/blob/1")); err != nil || string(got) != "blob" {
		t.Fatalf("Get = %q, %v; want blob", got, err)
	}
}

// TestNewObjectStorageInlineCredentialRefused pins that an inline credential
// in the provider settings fails with the re-exported setting error.
func TestNewObjectStorageInlineCredentialRefused(t *testing.T) {
	dir := t.TempDir()
	_, err := NewObjectStorage("local", map[string]string{
		"path":              filepath.Join(dir, "store"),
		"secret_access_key": "s3cr3t-example",
	})
	var settingErr *ObjectStorageCredentialSettingError
	if !errors.As(err, &settingErr) {
		t.Fatalf("NewObjectStorage(inline credential) = %v, want *ObjectStorageCredentialSettingError", err)
	}
}

// TestNewObjectStorageMissingCredentialFile pins that an unreadable key file
// fails with the re-exported credential-file error.
func TestNewObjectStorageMissingCredentialFile(t *testing.T) {
	registerSDKCredTestProvider(t)
	dir := t.TempDir()
	_, err := NewObjectStorage(sdkCredTestProvider,
		map[string]string{"path": filepath.Join(dir, "store")},
		WithObjectStorageCredentialFiles(ObjectStorageCredentialFiles{
			KeyFile:    filepath.Join(dir, "missing-key"),
			SecretFile: writeSDKCredFile(t, dir, "secret", "s3cr3t-example"),
		}))
	var fileErr *ObjectStorageCredentialFileError
	if !errors.As(err, &fileErr) {
		t.Fatalf("NewObjectStorage(missing key file) = %v, want *ObjectStorageCredentialFileError", err)
	}
}
