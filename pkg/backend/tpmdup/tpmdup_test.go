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

package tpmdup

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

// rsaSRKPublic returns a marshaled RSA-2048 SRK TPMT_PUBLIC over a fresh key,
// standing in for the public area a TPM 2.0 destination hands out.
func rsaSRKPublic(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	pub := tpm2.RSASRKTemplate
	pub.Unique = tpm2.NewTPMUPublicID(tpm2.TPMAlgRSA, &tpm2.TPM2BPublicKeyRSA{Buffer: key.N.Bytes()})
	return tpm2.Marshal(pub)
}

func TestWrapBuildsDuplicationBlob(t *testing.T) {
	material := bytes.Repeat([]byte{0xC3}, 32)
	wrapped, err := Wrap(rand.Reader, rsaSRKPublic(t), material)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if wrapped.Algorithm != Algorithm || wrapped.Metadata[MetadataKey] != "1" {
		t.Fatalf("algorithm %q metadata %v", wrapped.Algorithm, wrapped.Metadata)
	}
	var blob Blob
	if err := json.Unmarshal(wrapped.WrappedKey, &blob); err != nil {
		t.Fatalf("blob is not JSON: %v", err)
	}
	if len(blob.Public) == 0 || len(blob.Duplicate) == 0 || len(blob.EncSecret) == 0 {
		t.Fatalf("blob misses a field: %+v", blob)
	}
	if bytes.Contains(wrapped.WrappedKey, material) {
		t.Fatal("plaintext key material appears in the blob")
	}
}

func TestWrapRefusesBadInput(t *testing.T) {
	srk := rsaSRKPublic(t)
	if _, err := Wrap(rand.Reader, srk, nil); !errors.Is(err, ErrWrap) {
		t.Errorf("empty material: %v, want ErrWrap", err)
	}
	if _, err := Wrap(rand.Reader, []byte{0x00, 0x01}, []byte("k")); !errors.Is(err, ErrWrap) {
		t.Errorf("malformed SRK public: %v, want ErrWrap", err)
	}
	if _, err := Wrap(bytes.NewReader(nil), srk, []byte("k")); !errors.Is(err, ErrWrap) {
		t.Errorf("empty random source: %v, want ErrWrap", err)
	}
}
