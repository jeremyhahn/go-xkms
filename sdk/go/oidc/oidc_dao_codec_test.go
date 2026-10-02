//go:build codec_json

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

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/sdk/go/oidc"
)

// TestNewDAOStore_RoundTripsThroughTheAlias proves the re-exported
// constructor builds a working, pkg/oidc.TokenStore-satisfying store over a
// go-qrdb KVStore, not merely a type that compiles.
func TestNewDAOStore_RoundTripsThroughTheAlias(t *testing.T) {
	store, err := oidc.NewDAOStore(qrdbsdk.NewMemoryKVStore())
	if err != nil {
		t.Fatalf("NewDAOStore: %v", err)
	}
	defer store.Close()

	const issuer = "https://auth.example.com"
	tokens := &oidc.TokenResponse{AccessToken: "at-1"}
	if err := store.Save(issuer, tokens); err != nil {
		t.Fatalf("Save: %v", err)
	}
	loaded, err := store.Load(issuer)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.AccessToken != tokens.AccessToken {
		t.Fatalf("Load().AccessToken = %q, want %q", loaded.AccessToken, tokens.AccessToken)
	}
}
