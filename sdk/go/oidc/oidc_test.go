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

package oidc_test

import (
	"errors"
	"sort"
	"testing"

	pkg "github.com/jeremyhahn/go-xkms/pkg/oidc"

	"github.com/jeremyhahn/go-xkms/sdk/go/oidc"
)

// The re-exports are aliases, not copies: values cross between this package
// and pkg/oidc unchanged.
var (
	_ *pkg.ProviderTemplate = (*oidc.ProviderTemplate)(nil)
	_ *pkg.Client           = (*oidc.Client)(nil)
	_ pkg.TokenStore        = (oidc.TokenStore)(nil)
	_ pkg.Flow              = oidc.FlowDevice
)

// TestTemplates_EveryListedTemplateResolves proves the catalog the SDK lists
// is the catalog GetTemplate serves, with each template's flows readable.
func TestTemplates_EveryListedTemplateResolves(t *testing.T) {
	names := oidc.ListTemplates()
	if len(names) == 0 {
		t.Fatal("ListTemplates returned no templates")
	}
	sort.Strings(names)
	for _, name := range names {
		tmpl, err := oidc.GetTemplate(name)
		if err != nil {
			t.Fatalf("GetTemplate(%q): %v", name, err)
		}
		if tmpl.Name != name {
			t.Fatalf("GetTemplate(%q).Name = %q", name, tmpl.Name)
		}
		if oidc.BuiltinTemplates[name] == nil {
			t.Fatalf("BuiltinTemplates is missing listed template %q", name)
		}
		supported := false
		for _, f := range []oidc.Flow{oidc.FlowDevice, oidc.FlowImport, oidc.FlowAuthorizationCode} {
			supported = supported || tmpl.SupportsFlow(f)
		}
		if !supported {
			t.Fatalf("template %q supports no flow", name)
		}
	}
}

// TestGetTemplate_UnknownNameIsTemplateNotFound proves an unknown name is the
// pkg/oidc sentinel, reachable through errors.Is across the alias.
func TestGetTemplate_UnknownNameIsTemplateNotFound(t *testing.T) {
	if _, err := oidc.GetTemplate("no-such-provider"); !errors.Is(err, pkg.ErrTemplateNotFound) {
		t.Fatalf("GetTemplate(unknown) error = %v, want ErrTemplateNotFound", err)
	}
}

// TestGenerateCodeChallenge_MatchesVerifier proves the PKCE re-exports pair: a
// fresh verifier validates and its S256 challenge is deterministic.
func TestGenerateCodeChallenge_MatchesVerifier(t *testing.T) {
	verifier, err := oidc.GenerateCodeVerifier()
	if err != nil {
		t.Fatal(err)
	}
	if a, b := oidc.GenerateCodeChallenge(verifier), oidc.GenerateCodeChallenge(verifier); a == "" || a != b {
		t.Fatalf("GenerateCodeChallenge is not a deterministic non-empty digest: %q vs %q", a, b)
	}
}
