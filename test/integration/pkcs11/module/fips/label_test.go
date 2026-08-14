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

//go:build integration && fips

package fips

import (
	"strings"
	"testing"
)

// TestFIPSLabel_ModuleSelfIdentifiesAsFIPS proves the FIPS-compiled shared
// library tells a user, through CK_INFO and CK_TOKEN_INFO, that it is a FIPS
// module.
//
// This lane dlopens the artifact the FIPS Makefile target builds with GOFIPS140,
// so the label comes from the compiled state (crypto/fips140), not the runtime
// GOFIPS140 environment — the only signal that survives into the process that
// loads a shared library. A non-FIPS build run under the environment filters
// like FIPS but must NOT carry these labels, which is exactly why the label is
// worth asserting separately from the mechanism filter.
func TestFIPSLabel_ModuleSelfIdentifiesAsFIPS(t *testing.T) {
	tok := openToken(t)

	info, err := tok.ctx.GetInfo()
	if err != nil {
		t.Fatalf("C_GetInfo: %v", err)
	}
	if !strings.Contains(info.LibraryDescription, "FIPS") {
		t.Errorf("CK_INFO.libraryDescription = %q, want it to identify the module as FIPS", info.LibraryDescription)
	}

	tokInfo, err := tok.ctx.GetTokenInfo(tok.slot)
	if err != nil {
		t.Fatalf("C_GetTokenInfo: %v", err)
	}
	if !strings.Contains(tokInfo.Model, "FIPS") {
		t.Errorf("CK_TOKEN_INFO.model = %q, want it to identify the token as FIPS", tokInfo.Model)
	}
}
