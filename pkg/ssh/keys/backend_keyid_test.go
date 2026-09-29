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

package keys

import (
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
)

// TestBackendKeyID_InjectiveAcrossHyphenBoundary is the exact regression for
// go-xkms#1238: "user/a-b/c" and "user/a/b-c" are two distinct SSH key
// addresses (owner="a-b",name="c" vs. owner="a",name="b-c"; scope.BuildKeyID
// forbids '/' inside owner or name, so both are individually well-formed).
// The old strings.ReplaceAll(id, "/", "-") mapping flattened both to
// "ssh-user-a-b-c", letting one address's backend key silently answer for
// the other.
func TestBackendKeyID_InjectiveAcrossHyphenBoundary(t *testing.T) {
	id1, err := backendKeyID(scope.User, "a-b", "c")
	if err != nil {
		t.Fatalf("backendKeyID(user, %q, %q): %v", "a-b", "c", err)
	}
	id2, err := backendKeyID(scope.User, "a", "b-c")
	if err != nil {
		t.Fatalf("backendKeyID(user, %q, %q): %v", "a", "b-c", err)
	}
	if id1 == id2 {
		t.Fatalf("backendKeyID collided: user/a-b/c and user/a/b-c both produced %q", id1)
	}
}

// TestBackendKeyID_Deterministic proves the same identity always maps to the
// same CN, which every caller relies on to find a key it created earlier.
func TestBackendKeyID_Deterministic(t *testing.T) {
	id1, err := backendKeyID(scope.Service, "tenant-x", "deploy-bot")
	if err != nil {
		t.Fatalf("backendKeyID: %v", err)
	}
	id2, err := backendKeyID(scope.Service, "tenant-x", "deploy-bot")
	if err != nil {
		t.Fatalf("backendKeyID: %v", err)
	}
	if id1 != id2 {
		t.Fatalf("backendKeyID is not deterministic: %q != %q", id1, id2)
	}
}

// backendCNPattern is the character set every backend's identifier format
// tolerates: colon-free (types.KeyAttributes.ID reserves ':' as its own
// separator) and '/'-free (the software and tpm2 backends use the CN
// directly as a storage key). hex.EncodeToString and the "ssh-" prefix plus
// the three fixed scope words never produce anything outside this set.
var backendCNPattern = regexp.MustCompile(`^[a-z0-9\-]+$`)

// TestBackendKeyID_StaysWithinBackendConstraints proves the produced CN
// never contains ':' or '/' -- the two characters that break, respectively,
// the unified xkms key ID parser (pkg/types.KeyAttributes.ID /
// pkg/keyprovider/pkcs8's parseStorageKeyID) and the software/tpm2 file-per-
// key storage layout (pkg/storage.KeyPath, pkg/tpm2/store.storageKey) -- and
// stays within maxBackendKeyIDLen for inputs that fit.
func TestBackendKeyID_StaysWithinBackendConstraints(t *testing.T) {
	cases := []struct {
		name       string
		sc         scope.Scope
		owner, key string
	}{
		{"plain", scope.User, "alice", "laptop"},
		{"colons", scope.User, "ali:ce", "lap:top"},
		{"slashes-rejected-upstream", scope.Tenant, "acme-corp", "prod key"},
		{"unicode", scope.Service, "tenant-é", "déploy"},
		{"mixed-separators", scope.User, "a-b:c/d", "e-f:g"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			owner := tc.owner
			name := tc.key
			// '/' is rejected by scope.BuildKeyID before backendKeyID ever
			// encodes anything, so this case exercises the refusal instead
			// of the encoding.
			if strings.Contains(owner, "/") || strings.Contains(name, "/") {
				if _, err := backendKeyID(tc.sc, owner, name); err == nil {
					t.Fatalf("expected scope.BuildKeyID to reject an embedded '/'")
				}
				return
			}
			id, err := backendKeyID(tc.sc, owner, name)
			if err != nil {
				t.Fatalf("backendKeyID(%q, %q, %q): %v", tc.sc, owner, name, err)
			}
			if !backendCNPattern.MatchString(id) {
				t.Fatalf("backendKeyID(%q, %q, %q) = %q, outside the safe charset", tc.sc, owner, name, id)
			}
			if len(id) > maxBackendKeyIDLen {
				t.Fatalf("backendKeyID(%q, %q, %q) = %d bytes, exceeds max %d", tc.sc, owner, name, len(id), maxBackendKeyIDLen)
			}
		})
	}
}

// TestBackendKeyID_TooLong proves an oversized identity is refused with a
// typed error rather than truncated or left to fail inside a backend.
func TestBackendKeyID_TooLong(t *testing.T) {
	huge := strings.Repeat("x", maxBackendKeyIDLen)
	_, err := backendKeyID(scope.User, huge, huge)
	var tooLong *BackendKeyIDTooLongError
	if !errors.As(err, &tooLong) {
		t.Fatalf("expected *BackendKeyIDTooLongError, got %v", err)
	}
}

// TestBackendKeyID_PropertyNoCollisions is a property test over randomly
// generated (scope, owner, name) triples, including ones that deliberately
// place '-' at every segment boundary an encoding built from naive
// delimiter substitution would confuse. It fails the moment two distinct
// triples map to the same CN.
func TestBackendKeyID_PropertyNoCollisions(t *testing.T) {
	scopes := []scope.Scope{scope.Tenant, scope.User, scope.Service}
	// Deliberately adversarial fragments: '-' runs, empty-looking
	// neighbors, and characters the old flatten-'/' scheme also had to
	// deal with.
	fragments := []string{
		"a", "b", "c", "a-b", "b-c", "a-b-c", "-", "--", "a-", "-a",
		"x--y", "tenant", "user-name", "svc_01", "key.name", "k:v",
	}

	type triple struct {
		sc          scope.Scope
		owner, name string
	}
	seen := map[string]triple{}
	for _, sc := range scopes {
		for _, owner := range fragments {
			for _, name := range fragments {
				id, err := backendKeyID(sc, owner, name)
				if err != nil {
					// Only an empty owner/name should ever be refused among
					// this fixture set, and none of fragments is empty.
					t.Fatalf("backendKeyID(%v, %q, %q): unexpected error: %v", sc, owner, name, err)
				}
				cur := triple{sc, owner, name}
				if prior, ok := seen[id]; ok && prior != cur {
					t.Fatalf("collision: %+v and %+v both produced %q", prior, cur, id)
				}
				seen[id] = cur
			}
		}
	}
}

// FuzzBackendKeyID_Injective fuzzes pairs of (owner, name) strings and fails
// if two different pairs ever produce the same CN for the same scope.
func FuzzBackendKeyID_Injective(f *testing.F) {
	seeds := []string{"a", "a-b", "a/b", "-", "a--b", "", "user", "tenant-x", "a-b-c"}
	for _, o := range seeds {
		for _, n := range seeds {
			f.Add(o, n, o+"x", n)
			f.Add(o, n, o, n+"x")
		}
	}

	f.Fuzz(func(t *testing.T, owner1, name1, owner2, name2 string) {
		id1, err1 := backendKeyID(scope.User, owner1, name1)
		id2, err2 := backendKeyID(scope.User, owner2, name2)
		if err1 != nil || err2 != nil {
			// scope.BuildKeyID (empty owner/name, embedded '/') or the
			// length guard rejected an input; nothing to compare.
			return
		}
		if id1 == id2 && (owner1 != owner2 || name1 != name2) {
			t.Fatalf("collision: (%q,%q) and (%q,%q) both produced %q", owner1, name1, owner2, name2, id1)
		}
	})
}
