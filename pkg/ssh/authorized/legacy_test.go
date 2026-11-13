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

package authorized_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/records"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
)

// legacyEntry returns the JSON the pre-DAO store wrote for an entry holding
// line, or a freshly generated key's line when line is empty.
func legacyEntry(t *testing.T, line string) []byte {
	t.Helper()
	if line == "" {
		k := generateKey(t, keys.AlgorithmEd25519)
		defer k.Destroy()
		line = strings.TrimRight(string(ssh.MarshalAuthorizedKey(k.PublicKey)), "\n") + " laptop"
	}
	data, err := json.Marshal(map[string]any{
		"v": 1, "scope": "service", "owner": "deploy", "name": "laptop",
		"added": time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), "line": line,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return data
}

func TestStore_ImportLegacy_ReadsBack(t *testing.T) {
	store, _ := newLayoutStore(t)
	data := legacyEntry(t, "")
	for range 2 {
		if err := store.ImportLegacy(t.Context(), "ssh/services/deploy/authorized_keys/laptop", data); err != nil {
			t.Fatalf("ImportLegacy: %v", err)
		}
	}
	rec, err := store.Get(t.Context(), scope.Service, "deploy", "laptop")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if rec.Entry == nil || rec.Entry.Comment != "laptop" || rec.AddedAt.Year() != 2026 {
		t.Fatalf("imported record = %+v", rec)
	}
}

func TestStore_ImportLegacy_RejectsBadLine(t *testing.T) {
	store, _ := newLayoutStore(t)
	data := legacyEntry(t, "not an authorized_keys line")
	var recordErr *records.LegacyRecordError
	if err := store.ImportLegacy(t.Context(), "ssh/services/deploy/authorized_keys/laptop", data); !errors.As(err, &recordErr) {
		t.Fatalf("ImportLegacy error = %v, want *records.LegacyRecordError", err)
	}
	if _, err := store.Get(t.Context(), scope.Service, "deploy", "laptop"); err == nil {
		t.Fatal("a rejected entry was written")
	}
}
