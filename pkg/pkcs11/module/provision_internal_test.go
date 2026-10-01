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

package module

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"testing"
)

func TestECPublicKeyFromPoint(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := key.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := asn1.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}

	pub, err := ecPublicKeyFromPoint(elliptic.P256(), wrapped)
	if err != nil || !pub.Equal(&key.PublicKey) {
		t.Fatalf("round trip failed: %v", err)
	}

	if _, err := ecPublicKeyFromPoint(elliptic.P256(), raw); !errors.Is(err, ErrProvisionECPoint) {
		t.Fatalf("unwrapped point error = %v, want ErrProvisionECPoint", err)
	}
	if _, err := ecPublicKeyFromPoint(elliptic.P256(), append(wrapped, 0)); !errors.Is(err, ErrProvisionECPoint) {
		t.Fatalf("trailing bytes error = %v, want ErrProvisionECPoint", err)
	}
	if _, err := ecPublicKeyFromPoint(elliptic.P384(), wrapped); err == nil {
		t.Fatal("a P-256 point decoded on P-384")
	}
}
