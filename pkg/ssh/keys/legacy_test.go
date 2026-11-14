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

package keys_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/records"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// legacyKey returns the JSON the pre-DAO store wrote for a software key and
// the key's fingerprint. Fields in override replace or, when nil, drop the
// generated ones.
func legacyKey(t *testing.T, override map[string]any) ([]byte, string) {
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
	fp := keys.Fingerprint(sshPub)
	fields := map[string]any{
		"v": 2, "scope": "user", "owner": "alice", "name": "id",
		"algo": string(keys.AlgorithmEd25519), "fp": fp,
		"created": time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		"pub":     strings.TrimRight(string(ssh.MarshalAuthorizedKey(sshPub)), "\n"),
		"pem_b64": types.SecretBytes(pem.EncodeToMemory(block)),
	}
	for k, v := range override {
		if v == nil {
			delete(fields, k)
			continue
		}
		fields[k] = v
	}
	data, err := json.Marshal(fields)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return data, fp
}

func TestDAOStore_ImportLegacy_ReadsBack(t *testing.T) {
	store, _ := newLayoutStore(t)
	data, fp := legacyKey(t, nil)
	for range 2 {
		if err := store.ImportLegacy(t.Context(), "ssh/users/alice/keys/id", data); err != nil {
			t.Fatalf("ImportLegacy: %v", err)
		}
	}
	k, err := store.Get(t.Context(), scope.User, "alice", "id")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer k.Destroy()
	if k.Fingerprint != fp || k.Material == nil || k.Algorithm != keys.AlgorithmEd25519 {
		t.Fatalf("imported key = %+v", k)
	}
}

func TestDAOStore_ImportLegacy_BackendKey(t *testing.T) {
	store, _ := newLayoutStore(t)
	data, _ := legacyKey(t, map[string]any{"pem_b64": nil, "backend_id": "tpm", "backend_key_id": "k1"})
	if err := store.ImportLegacy(t.Context(), "ssh/users/alice/keys/id", data); err != nil {
		t.Fatalf("ImportLegacy: %v", err)
	}
	k, err := store.Get(t.Context(), scope.User, "alice", "id")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !k.IsBackendBacked() || k.BackendKeyID != "k1" {
		t.Fatalf("imported key = %+v", k)
	}
}

func TestDAOStore_ImportLegacy_RejectsBadRecords(t *testing.T) {
	tests := map[string]map[string]any{
		"bad public key": {"pub": "not a key"},
		"no material":    {"pem_b64": nil},
	}
	for name, override := range tests {
		t.Run(name, func(t *testing.T) {
			store, _ := newLayoutStore(t)
			data, _ := legacyKey(t, override)
			var recordErr *records.LegacyRecordError
			if err := store.ImportLegacy(t.Context(), "ssh/users/alice/keys/id", data); !errors.As(err, &recordErr) {
				t.Fatalf("ImportLegacy error = %v, want *records.LegacyRecordError", err)
			}
			var notFound *keys.KeyNotFoundError
			if _, err := store.Get(t.Context(), scope.User, "alice", "id"); !errors.As(err, &notFound) {
				t.Fatalf("Get after a rejected import = %v, want *KeyNotFoundError", err)
			}
		})
	}
}
