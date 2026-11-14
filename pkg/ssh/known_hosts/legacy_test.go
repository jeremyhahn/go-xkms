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

package known_hosts_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/records"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
)

// legacyPin returns the JSON the pre-DAO store wrote for a pin and the pin's
// wire-format public key. Fields in override replace or, when nil, drop the
// generated ones.
func legacyPin(t *testing.T, override map[string]any) ([]byte, []byte) {
	t.Helper()
	pub := newEd25519PublicKey(t)
	fields := map[string]any{
		"v": 1, "scope": "tenant", "owner": "alice", "host": "example.com",
		"fp": keys.Fingerprint(pub), "algo": pub.Type(), "source": "manual",
		"added": time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		"pub":   pub.Marshal(), // encoding/json writes []byte as std base64, as the old store did
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
	return data, pub.Marshal()
}

func TestKHStore_ImportLegacy_ReadsBack(t *testing.T) {
	store, _ := newLayoutStore(t)
	data, wire := legacyPin(t, nil)
	for range 2 {
		if err := store.ImportLegacy(t.Context(), "ssh/shared/known_hosts/example.com", data); err != nil {
			t.Fatalf("ImportLegacy: %v", err)
		}
	}
	pin, err := store.Get(t.Context(), scope.Tenant, "alice", "example.com")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(pin.PublicKey, wire) || pin.Source != "manual" {
		t.Fatalf("imported pin = %+v", pin)
	}
}

func TestKHStore_ImportLegacy_RejectsBadRecords(t *testing.T) {
	tests := map[string]map[string]any{
		"no public key":   {"pub": nil},
		"bad fingerprint": {"fp": "md5:nope"},
	}
	for name, override := range tests {
		t.Run(name, func(t *testing.T) {
			store, _ := newLayoutStore(t)
			data, _ := legacyPin(t, override)
			var recordErr *records.LegacyRecordError
			if err := store.ImportLegacy(t.Context(), "ssh/shared/known_hosts/example.com", data); !errors.As(err, &recordErr) {
				t.Fatalf("ImportLegacy error = %v, want *records.LegacyRecordError", err)
			}
			if _, err := store.Get(t.Context(), scope.Tenant, "alice", "example.com"); err == nil {
				t.Fatal("a rejected pin was written")
			}
		})
	}
}
