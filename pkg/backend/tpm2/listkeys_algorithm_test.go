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

package tpm2

import (
	"context"
	"crypto/x509"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/tpmblobtest"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// eccPublicBlob builds a valid NIST P-256 ECDSA TPM2B_PUBLIC blob with a unique
// public point and returns its serialized bytes, matching what SaveKeyPair
// persists as store.FSEXT_PUBLIC_BLOB (outPublic.Bytes()).
func eccPublicBlob(t *testing.T, xFill, yFill byte) []byte {
	t.Helper()
	x := make([]byte, 32)
	y := make([]byte, 32)
	for i := range x {
		x[i] = xFill
		y[i] = yFill
	}
	pub := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			SignEncrypt:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				Symmetric: tpm2.TPMTSymDefObject{Algorithm: tpm2.TPMAlgNull},
				Scheme: tpm2.TPMTECCScheme{
					Scheme: tpm2.TPMAlgECDSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgECDSA,
						&tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256},
					),
				},
				CurveID: tpm2.TPMECCNistP256,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{Buffer: x},
				Y: tpm2.TPM2BECCParameter{Buffer: y},
			},
		),
	}
	pub2b := tpm2.New2B(pub)
	return pub2b.Bytes()
}

// TestListKeys_RecoversECDSAAlgorithmAndPIVSlot verifies that ListKeys recovers
// the key algorithm from the persisted public blob and the PIV slot from the CN.
// This is the regression guard for the bug where a TPM2 PIV signing key
// (KeyAlgorithm left as the zero value) was routed down the unseal delete path
// and never removed.
func TestListKeys_RecoversECDSAAlgorithmAndPIVSlot(t *testing.T) {
	kb := tpmblobtest.New(t)

	const cn = "piv-9a"
	// A real, valid ECDSA TPM2B_PUBLIC blob saved under <cn>.pub ...
	if err := kb.Save(&types.KeyAttributes{CN: cn}, eccPublicBlob(t, 0x11, 0x22), store.FSEXT_PUBLIC_BLOB, true); err != nil {
		t.Fatalf("Save public blob error = %v", err)
	}
	// ... plus a private blob so ListKeys enumerates the key.
	if err := kb.Save(&types.KeyAttributes{CN: cn}, []byte("private"), store.FSEXT_PRIVATE_BLOB, true); err != nil {
		t.Fatalf("write private blob error = %v", err)
	}

	b := &Backend{keyBackend: kb}
	keys, err := b.ListKeys(context.Background())
	if err != nil {
		t.Fatalf("ListKeys() error = %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}

	k := keys[0]
	if k.CN != cn {
		t.Errorf("CN: expected %q, got %q", cn, k.CN)
	}
	if k.KeyAlgorithm != x509.ECDSA {
		t.Errorf("KeyAlgorithm: expected ECDSA, got %v", k.KeyAlgorithm)
	}
	if k.PIVSlot != "9a" {
		t.Errorf("PIVSlot: expected %q, got %q", "9a", k.PIVSlot)
	}
	if k.StoreType != types.StoreTPM2 {
		t.Errorf("StoreType: expected StoreTPM2, got %v", k.StoreType)
	}
}

// TestListKeys_MissingOrMalformedPublicBlobIsBestEffort verifies that when the
// public blob is missing or malformed, ListKeys still returns the key with its
// CN set and KeyAlgorithm unset, and does not error.
func TestListKeys_MissingOrMalformedPublicBlobIsBestEffort(t *testing.T) {
	t.Run("missing public blob", func(t *testing.T) {
		kb := tpmblobtest.New(t)

		const cn = "sealed-key"
		// Only a private blob exists; no .pub.
		if err := kb.Save(&types.KeyAttributes{CN: cn}, []byte("private"), store.FSEXT_PRIVATE_BLOB, true); err != nil {
			t.Fatalf("write private blob error = %v", err)
		}

		b := &Backend{keyBackend: kb}
		keys, err := b.ListKeys(context.Background())
		if err != nil {
			t.Fatalf("ListKeys() error = %v", err)
		}
		if len(keys) != 1 {
			t.Fatalf("expected 1 key, got %d", len(keys))
		}
		if keys[0].CN != cn {
			t.Errorf("CN: expected %q, got %q", cn, keys[0].CN)
		}
		if keys[0].KeyAlgorithm != x509.UnknownPublicKeyAlgorithm {
			t.Errorf("KeyAlgorithm: expected unset, got %v", keys[0].KeyAlgorithm)
		}
	})

	t.Run("malformed public blob", func(t *testing.T) {
		kb := tpmblobtest.New(t)

		const cn = "broken-key"
		if err := kb.Save(&types.KeyAttributes{CN: cn}, []byte("not a valid TPM2B_PUBLIC"), store.FSEXT_PUBLIC_BLOB, true); err != nil {
			t.Fatalf("Save malformed public blob error = %v", err)
		}
		if err := kb.Save(&types.KeyAttributes{CN: cn}, []byte("private"), store.FSEXT_PRIVATE_BLOB, true); err != nil {
			t.Fatalf("write private blob error = %v", err)
		}

		b := &Backend{keyBackend: kb}
		keys, err := b.ListKeys(context.Background())
		if err != nil {
			t.Fatalf("ListKeys() error = %v", err)
		}
		if len(keys) != 1 {
			t.Fatalf("expected 1 key, got %d", len(keys))
		}
		if keys[0].CN != cn {
			t.Errorf("CN: expected %q, got %q", cn, keys[0].CN)
		}
		if keys[0].KeyAlgorithm != x509.UnknownPublicKeyAlgorithm {
			t.Errorf("KeyAlgorithm: expected unset, got %v", keys[0].KeyAlgorithm)
		}
	})
}
