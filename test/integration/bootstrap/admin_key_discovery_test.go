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

//go:build integration

package bootstrap

import "testing"

// TestSDK_BootstrapKeys_AuthenticatedDiscovery makes the admin-API key
// discovery call (GET /api/v1/bootstrap/keys) the suite depends on, through
// newSDKTransport. The generated config demands an mTLS administrator on
// that route, so the transport must present the harness's admin client
// credential; without it the server answers 401 and every Noise subtest
// fails before it starts.
func TestSDK_BootstrapKeys_AuthenticatedDiscovery(t *testing.T) {
	keys, err := fetchBootstrapKeys(t)
	if err != nil {
		t.Fatalf("GET /api/v1/bootstrap/keys with the admin client credential: %v", err)
	}
	if keys == nil {
		t.Fatal("bootstrap keys response is nil")
	}
	if keys.NoisePublicKey == "" && keys.P256PublicKey == "" {
		t.Fatal("bootstrap keys response carries no listener public key")
	}
}
