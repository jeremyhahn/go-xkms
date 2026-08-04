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

//go:build integration && pkcs11

package sshbackend

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// softHSMLib resolves the SoftHSM2 PKCS#11 module path, honoring PKCS11_MODULE.
func softHSMLib() string {
	if p := os.Getenv("PKCS11_MODULE"); p != "" {
		return p
	}
	for _, p := range []string{
		"/usr/lib/softhsm/libsofthsm2.so",
		"/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
		"/usr/local/lib/softhsm/libsofthsm2.so",
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// TestSSHBackend_PKCS11 proves SSH key generation + signing on a PKCS#11 backend
// using SoftHSM2. The private key stays in the token; signing is delegated. The
// token store is a hermetic temp directory (the host's SoftHSM config is never
// touched). Skipped when the SoftHSM2 module is not installed.
func TestSSHBackend_PKCS11(t *testing.T) {
	lib := softHSMLib()
	if lib == "" {
		t.Skip("SoftHSM2 module not found; set PKCS11_MODULE to run the PKCS#11 SSH lane")
	}
	kp := newSoftHSMProvider(t, lib)
	runMatrix(t, resolverFor("pkcs11", kp), "pkcs11", hardwareAlgos, true)
}

// newSoftHSMProvider builds a SoftHSM2-backed PKCS#11 KeyProvider against a
// fresh, hermetic token directory and initializes the token.
func newSoftHSMProvider(t *testing.T, lib string) types.KeyProvider {
	t.Helper()

	// Point SoftHSM2 at a private, empty token store so the test is hermetic and
	// the token slot starts uninitialized (Initialize then runs C_InitToken).
	tokenDir := t.TempDir()
	confPath := filepath.Join(t.TempDir(), "softhsm2.conf")
	conf := "directories.tokendir = " + tokenDir + "\n" +
		"objectstore.backend = file\n" +
		"log.level = ERROR\n"
	if err := os.WriteFile(confPath, []byte(conf), 0o600); err != nil {
		t.Fatalf("write softhsm2.conf: %v", err)
	}
	t.Setenv("SOFTHSM2_CONF", confPath)

	keyStorage, err := xkms.NewMemoryBackend()
	if err != nil {
		t.Fatalf("NewMemoryBackend (keys): %v", err)
	}
	certStorage, err := xkms.NewMemoryBackend()
	if err != nil {
		t.Fatalf("NewMemoryBackend (certs): %v", err)
	}

	const pin, soPIN = "1234", "1234"
	provider, err := xkms.NewPKCS11Backend(&xkms.PKCS11BackendConfig{
		Library:     lib,
		TokenLabel:  "ssh-backend-test",
		PIN:         pin,
		SOPIN:       soPIN,
		KeyStorage:  keyStorage,
		CertStorage: certStorage,
	})
	if err != nil {
		t.Fatalf("NewPKCS11Backend: %v", err)
	}
	if err := provider.Initialize(soPIN, pin); err != nil {
		t.Fatalf("initialize SoftHSM token: %v", err)
	}
	return provider
}
