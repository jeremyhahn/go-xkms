// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package enclaveprovider

import (
	"context"
	"crypto"
	"crypto/x509"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// NewSoftwareSealer exports newSoftwareSealer to the external tests.
var NewSoftwareSealer = newSoftwareSealer

// newSoftwareSealer returns an in-memory software backend and the attributes
// of a sealing key that exists on it.
func newSoftwareSealer(t *testing.T) (*software.SoftwareBackend, *types.KeyAttributes) {
	t.Helper()
	provider, err := software.NewBackend(&software.Config{KeyStorage: storage.New()})
	if err != nil {
		t.Fatalf("software.NewBackend: %v", err)
	}
	sb, ok := provider.(*software.SoftwareBackend)
	if !ok {
		t.Fatalf("software.NewBackend returned %T", provider)
	}
	t.Cleanup(func() {
		if err := sb.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	curve, err := types.ParseCurve("P-256")
	if err != nil {
		t.Fatalf("ParseCurve: %v", err)
	}
	attrs := &types.KeyAttributes{
		CN:            "enclave-provider-seal",
		KeyType:       backend.KEY_TYPE_TLS,
		StoreType:     backend.STORE_SW,
		KeyAlgorithm:  x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{Curve: curve},
		Hash:          crypto.SHA256,
	}
	if _, err := sb.GenerateKey(context.Background(), attrs); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return sb, attrs
}
