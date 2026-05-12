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

package scope_test

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
)

func TestScopeValid(t *testing.T) {
	tests := []struct {
		scope scope.Scope
		want  bool
	}{
		{scope.Tenant, true},
		{scope.User, true},
		{scope.Service, true},
		{scope.Scope(""), false},
		{scope.Scope("admin"), false},
		{scope.Scope("TENANT"), false}, // Valid() is strict on canonical form
	}
	for _, tt := range tests {
		if got := tt.scope.Valid(); got != tt.want {
			t.Errorf("%q.Valid() = %v, want %v", tt.scope, got, tt.want)
		}
	}
}

func TestScopeString(t *testing.T) {
	if scope.Tenant.String() != "tenant" {
		t.Errorf("Tenant.String() = %q", scope.Tenant.String())
	}
}

func TestParse(t *testing.T) {
	tests := []struct {
		in      string
		want    scope.Scope
		wantErr bool
	}{
		{"tenant", scope.Tenant, false},
		{"user", scope.User, false},
		{"service", scope.Service, false},
		{"  TENANT ", scope.Tenant, false},
		{"User\t", scope.User, false},
		{"", "", true},
		{"admin", "", true},
		{"tenant/user", "", true},
	}
	for _, tt := range tests {
		got, err := scope.Parse(tt.in)
		if (err != nil) != tt.wantErr {
			t.Errorf("Parse(%q) err=%v wantErr=%v", tt.in, err, tt.wantErr)
			continue
		}
		if err != nil {
			var sErr *scope.ScopeInvalidError
			if !errors.As(err, &sErr) {
				t.Errorf("Parse(%q) returned %T, want *ScopeInvalidError", tt.in, err)
			}
			continue
		}
		if got != tt.want {
			t.Errorf("Parse(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestBuildKeyID(t *testing.T) {
	tests := []struct {
		name      string
		scope     scope.Scope
		owner     string
		keyName   string
		want      string
		wantErr   bool
		wantField string
	}{
		{"tenant key", scope.Tenant, "tenantA", "laptop", "tenant/tenantA/laptop", false, ""},
		{"user key", scope.User, "alice", "work", "user/alice/work", false, ""},
		{"service key", scope.Service, "deploy-bot", "prod", "service/deploy-bot/prod", false, ""},
		{"invalid scope", scope.Scope("admin"), "x", "y", "", true, ""},
		{"empty owner", scope.User, "", "x", "", true, "owner"},
		{"empty name", scope.User, "o", "", "", true, "name"},
		{"owner with slash", scope.User, "a/b", "x", "", true, "owner"},
		{"name with slash", scope.User, "o", "a/b", "", true, "name"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := scope.BuildKeyID(tt.scope, tt.owner, tt.keyName)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tt.wantErr)
			}
			if err != nil {
				if tt.wantField != "" {
					var kidErr *scope.KeyIDMalformedError
					if !errors.As(err, &kidErr) {
						t.Fatalf("got %T, want *KeyIDMalformedError", err)
					}
					if kidErr.Field != tt.wantField {
						t.Errorf("Field=%q want %q", kidErr.Field, tt.wantField)
					}
				}
				return
			}
			if got != tt.want {
				t.Errorf("got %q want %q", got, tt.want)
			}
		})
	}
}

func TestParseKeyID(t *testing.T) {
	tests := []struct {
		name      string
		in        string
		wantScope scope.Scope
		wantOwner string
		wantName  string
		wantErr   bool
	}{
		{"tenant", "tenant/t1/k1", scope.Tenant, "t1", "k1", false},
		{"user", "user/alice/laptop", scope.User, "alice", "laptop", false},
		{"service", "service/bot/prod", scope.Service, "bot", "prod", false},
		{"missing part", "user/alice", "", "", "", true},
		{"bad scope", "admin/o/n", "", "", "", true},
		{"empty owner", "user//n", "", "", "", true},
		{"empty name", "user/o/", "", "", "", true},
		{"name with slash kept", "user/o/a/b", scope.User, "o", "a/b", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc, o, n, err := scope.ParseKeyID(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if sc != tt.wantScope || o != tt.wantOwner || n != tt.wantName {
				t.Errorf("got (%q, %q, %q) want (%q, %q, %q)",
					sc, o, n, tt.wantScope, tt.wantOwner, tt.wantName)
			}
		})
	}
}

// TestRoundTrip guards the layout invariant: any key ID produced by
// BuildKeyID (with canonical inputs) re-parses to the same components.
func TestRoundTrip(t *testing.T) {
	tests := []struct {
		sc    scope.Scope
		owner string
		name  string
	}{
		{scope.Tenant, "acme", "ci-bot"},
		{scope.User, "uid-1234", "laptop"},
		{scope.Service, "deployer", "prod-01"},
		{scope.User, "user.name+tag", "name with spaces"},
	}
	for _, tt := range tests {
		id, err := scope.BuildKeyID(tt.sc, tt.owner, tt.name)
		if err != nil {
			t.Fatalf("BuildKeyID(%v, %q, %q): %v", tt.sc, tt.owner, tt.name, err)
		}
		sc, owner, name, err := scope.ParseKeyID(id)
		if err != nil {
			t.Fatalf("ParseKeyID(%q): %v", id, err)
		}
		if sc != tt.sc || owner != tt.owner || name != tt.name {
			t.Errorf("round-trip mismatch: built %q parsed (%q, %q, %q)",
				id, sc, owner, name)
		}
	}
}
