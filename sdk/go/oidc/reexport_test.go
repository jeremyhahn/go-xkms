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
	"testing"

	pkg "github.com/jeremyhahn/go-xkms/pkg/oidc"

	"github.com/jeremyhahn/go-xkms/sdk/go/oidc"
)

// The callback error re-exports are aliases: a pointer to one is a pointer to
// the pkg/oidc type, so errors.As matches across the two packages.
var (
	_ *pkg.RedirectURLError  = (*oidc.RedirectURLError)(nil)
	_ *pkg.CallbackHostError = (*oidc.CallbackHostError)(nil)
)

// TestReexports_ConstantsMatchPkg proves the re-exported constants are
// pkg/oidc's own values, not drifted copies.
func TestReexports_ConstantsMatchPkg(t *testing.T) {
	if oidc.TokenEncodingJSON != pkg.TokenEncodingJSON {
		t.Fatalf("TokenEncodingJSON = %q, want %q", oidc.TokenEncodingJSON, pkg.TokenEncodingJSON)
	}
	if oidc.CodexAuthModeChatGPT != pkg.CodexAuthModeChatGPT {
		t.Fatalf("CodexAuthModeChatGPT = %q, want %q", oidc.CodexAuthModeChatGPT, pkg.CodexAuthModeChatGPT)
	}
}

// TestReexports_SentinelsArePkgSentinels proves each re-exported sentinel is
// the identical pkg/oidc error value, so errors.Is matches either name.
func TestReexports_SentinelsArePkgSentinels(t *testing.T) {
	for name, pair := range map[string][2]error{
		"ErrInvalidTokenEncoding": {oidc.ErrInvalidTokenEncoding, pkg.ErrInvalidTokenEncoding},
		"ErrCodexAuthInvalid":     {oidc.ErrCodexAuthInvalid, pkg.ErrCodexAuthInvalid},
		"ErrCodexAuthMode":        {oidc.ErrCodexAuthMode, pkg.ErrCodexAuthMode},
	} {
		if pair[0] == nil || pair[0] != pair[1] {
			t.Fatalf("%s = %v, want the pkg/oidc sentinel %v", name, pair[0], pair[1])
		}
	}
}
