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

package scope_test

import (
	"errors"
	"testing"

	xkmsscope "github.com/jeremyhahn/go-xkms/pkg/scope"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
)

func TestKindValid(t *testing.T) {
	tests := []struct {
		kind scope.Kind
		want bool
	}{
		{scope.KindKeys, true},
		{scope.KindKnownHosts, true},
		{scope.KindAuthorizedKeys, true},
		{scope.Kind(""), false},
		{scope.Kind("sessions"), false},
		{scope.Kind("KEYS"), false},
	}
	for _, tt := range tests {
		if got := tt.kind.Valid(); got != tt.want {
			t.Errorf("%q.Valid() = %v, want %v", tt.kind, got, tt.want)
		}
	}
}

func TestRecordPath_Layout(t *testing.T) {
	tests := []struct {
		kind  scope.Kind
		scope scope.Scope
		owner string
		name  string
		want  string
	}{
		{scope.KindKeys, scope.Tenant, "acme", "deploy", "ssh/shared/keys/deploy"},
		{scope.KindKeys, scope.User, "alice", "laptop", "ssh/users/alice/keys/laptop"},
		{scope.KindKeys, scope.Service, "ci", "runner", "ssh/services/ci/keys/runner"},
		{scope.KindKnownHosts, scope.Tenant, "acme", "github.com", "ssh/shared/known_hosts/github.com"},
		{scope.KindKnownHosts, scope.User, "alice", "[host]:2222", "ssh/users/alice/known_hosts/[host]:2222"},
		{scope.KindKnownHosts, scope.Service, "ci", "bastion", "ssh/services/ci/known_hosts/bastion"},
		{scope.KindAuthorizedKeys, scope.Tenant, "acme", "ops", "ssh/shared/authorized_keys/ops"},
		{scope.KindAuthorizedKeys, scope.User, "alice", "phone", "ssh/users/alice/authorized_keys/phone"},
		{scope.KindAuthorizedKeys, scope.Service, "ci", "deploy", "ssh/services/ci/authorized_keys/deploy"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got, err := tt.kind.RecordPath(tt.scope, tt.owner, tt.name)
			if err != nil {
				t.Fatalf("RecordPath: %v", err)
			}
			if got != tt.want {
				t.Fatalf("RecordPath = %q, want %q", got, tt.want)
			}
			if !tt.kind.Match(got) {
				t.Fatalf("%q.Match(%q) = false, want true", tt.kind, got)
			}
		})
	}
}

// TestRecordPath_TenantScopeDropsOwner pins that a tenant-scoped path is the
// same for every owner: the owner is the tenant, which the partition is.
func TestRecordPath_TenantScopeDropsOwner(t *testing.T) {
	a, err := scope.KindKeys.RecordPath(scope.Tenant, "acme", "deploy")
	if err != nil {
		t.Fatalf("RecordPath: %v", err)
	}
	b, err := scope.KindKeys.RecordPath(scope.Tenant, "globex", "deploy")
	if err != nil {
		t.Fatalf("RecordPath: %v", err)
	}
	if a != b {
		t.Fatalf("tenant-scoped paths differ by owner: %q vs %q", a, b)
	}
}

func TestRecordPath_Errors(t *testing.T) {
	tests := []struct {
		label string
		kind  scope.Kind
		scope scope.Scope
		owner string
		name  string
		field string // expected KeyIDMalformedError.Field; "" for other types
	}{
		{"empty owner", scope.KindKeys, scope.User, "", "n", "owner"},
		{"owner separator", scope.KindKeys, scope.User, "a/b", "n", "owner"},
		{"tenant empty owner", scope.KindKeys, scope.Tenant, "", "n", "owner"},
		{"tenant owner separator", scope.KindKeys, scope.Tenant, "a/b", "n", "owner"},
		{"empty name", scope.KindKnownHosts, scope.Service, "ci", "", "name"},
		{"name separator", scope.KindAuthorizedKeys, scope.Tenant, "acme", "a/b", "name"},
	}
	for _, tt := range tests {
		t.Run(tt.label, func(t *testing.T) {
			_, err := tt.kind.RecordPath(tt.scope, tt.owner, tt.name)
			var mal *scope.KeyIDMalformedError
			if !errors.As(err, &mal) {
				t.Fatalf("want *KeyIDMalformedError, got %T: %v", err, err)
			}
			if mal.Field != tt.field {
				t.Fatalf("Field = %q, want %q", mal.Field, tt.field)
			}
		})
	}

	t.Run("invalid kind", func(t *testing.T) {
		_, err := scope.Kind("sessions").RecordPath(scope.User, "alice", "n")
		var kerr *scope.KindInvalidError
		if !errors.As(err, &kerr) || kerr.Value != "sessions" {
			t.Fatalf("want *KindInvalidError{sessions}, got %T: %v", err, err)
		}
		if kerr.Error() != "ssh/scope: invalid kind: sessions" {
			t.Fatalf("Error() = %q", kerr.Error())
		}
	})
	t.Run("invalid scope", func(t *testing.T) {
		_, err := scope.KindKeys.RecordPath(scope.Scope("admin"), "alice", "n")
		var serr *scope.ScopeInvalidError
		if !errors.As(err, &serr) {
			t.Fatalf("want *ScopeInvalidError, got %T: %v", err, err)
		}
	})
	t.Run("traversal owner", func(t *testing.T) {
		_, err := scope.KindKeys.RecordPath(scope.User, "..", "n")
		var seg *xkmsscope.InvalidSegmentError
		if !errors.As(err, &seg) {
			t.Fatalf("want *InvalidSegmentError, got %T: %v", err, err)
		}
	})
}

func TestListPrefix(t *testing.T) {
	tests := []struct {
		scope scope.Scope
		owner string
		want  string
	}{
		{"", "", "ssh/"},
		{"", "alice", "ssh/"},
		{scope.Tenant, "", "ssh/shared/"},
		{scope.Tenant, "acme", "ssh/shared/"},
		{scope.User, "", "ssh/users/"},
		{scope.User, "alice", "ssh/users/alice/"},
		{scope.Service, "", "ssh/services/"},
		{scope.Service, "ci", "ssh/services/ci/"},
	}
	for _, tt := range tests {
		got, err := scope.ListPrefix(tt.scope, tt.owner)
		if err != nil {
			t.Fatalf("ListPrefix(%q, %q): %v", tt.scope, tt.owner, err)
		}
		if got != tt.want {
			t.Errorf("ListPrefix(%q, %q) = %q, want %q", tt.scope, tt.owner, got, tt.want)
		}
	}
}

func TestListPrefix_Errors(t *testing.T) {
	_, err := scope.ListPrefix(scope.Scope("admin"), "")
	var serr *scope.ScopeInvalidError
	if !errors.As(err, &serr) {
		t.Fatalf("invalid scope: want *ScopeInvalidError, got %T: %v", err, err)
	}
	for _, sc := range []scope.Scope{scope.Tenant, scope.User, scope.Service} {
		_, err = scope.ListPrefix(sc, "a/b")
		var mal *scope.KeyIDMalformedError
		if !errors.As(err, &mal) || mal.Field != "owner" {
			t.Fatalf("%s owner separator: want *KeyIDMalformedError{owner}, got %T: %v", sc, err, err)
		}
	}
}

func TestKindMatch(t *testing.T) {
	tests := []struct {
		key  string
		kind scope.Kind
		want bool
	}{
		{"ssh/shared/keys/deploy", scope.KindKeys, true},
		{"ssh/shared/keys/deploy", scope.KindKnownHosts, false},
		{"ssh/users/alice/known_hosts/github.com", scope.KindKnownHosts, true},
		{"ssh/users/alice/known_hosts/github.com", scope.KindKeys, false},
		{"ssh/services/ci/authorized_keys/ops", scope.KindAuthorizedKeys, true},
		// Other SSH features sharing the view.
		{"ssh/sessions/abc", scope.KindKeys, false},
		{"ssh/profiles/web", scope.KindKeys, false},
		// Malformed shapes.
		{"ssh/shared/keys/", scope.KindKeys, false},
		{"ssh/shared/keys", scope.KindKeys, false},
		{"ssh/shared/keys/a/b", scope.KindKeys, false},
		{"ssh/users//keys/n", scope.KindKeys, false},
		{"ssh/users/alice", scope.KindKeys, false},
		{"ssh/users/alice/keys/a/b", scope.KindKeys, false},
		{"other/shared/keys/n", scope.KindKeys, false},
		{"", scope.KindKeys, false},
	}
	for _, tt := range tests {
		if got := tt.kind.Match(tt.key); got != tt.want {
			t.Errorf("%q.Match(%q) = %v, want %v", tt.kind, tt.key, got, tt.want)
		}
	}
}
