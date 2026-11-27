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

package software

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// The TPM object attributes of a duplicated key follow the source key's
// purpose: encryption keys decrypt, signing keys sign, and a purpose the TPM
// object cannot honour is refused (Codex round-4 P1 on #2183).
func TestTPM2DuplicateAreas_AttributesFollowKeyPurpose(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}

	cases := []struct {
		name        string
		key         any
		keyType     types.KeyType
		wantSign    bool
		wantDecrypt bool
	}{
		{"rsa-encryption", rsaKey, types.KeyTypeEncryption, false, true},
		{"ecdsa-encryption", ecKey, types.KeyTypeEncryption, false, true},
		{"rsa-signing", rsaKey, types.KeyTypeSigning, true, false},
		{"ecdsa-tls", ecKey, types.KeyTypeTLS, true, false},
		{"rsa-ca", rsaKey, types.KeyTypeCA, true, false},
	}
	for _, tc := range cases {
		public, _, err := tpm2DuplicateAreas(tc.key, tc.keyType)
		if err != nil {
			t.Fatalf("%s: tpm2DuplicateAreas: %v", tc.name, err)
		}
		attrs := public.ObjectAttributes
		if attrs.SignEncrypt != tc.wantSign || attrs.Decrypt != tc.wantDecrypt {
			t.Fatalf("%s: SignEncrypt=%v Decrypt=%v, want SignEncrypt=%v Decrypt=%v",
				tc.name, attrs.SignEncrypt, attrs.Decrypt, tc.wantSign, tc.wantDecrypt)
		}
		if !attrs.UserWithAuth || attrs.FixedTPM || attrs.FixedParent {
			t.Fatalf("%s: attributes %+v, want UserWithAuth with FixedTPM and FixedParent clear", tc.name, attrs)
		}
	}

	for _, kt := range []types.KeyType{types.KeyTypeHMAC, types.KeyTypeSecret, types.KeyTypeStorage, types.KeyType(0)} {
		if _, _, err := tpm2DuplicateAreas(rsaKey, kt); !errors.Is(err, backend.ErrInvalidAttributes) {
			t.Fatalf("key type %v: error = %v, want ErrInvalidAttributes", kt, err)
		}
	}
}
