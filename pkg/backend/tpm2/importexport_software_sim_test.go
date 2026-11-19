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

//go:build tpm_simulator

package tpm2

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestSoftwareExportKeyTo_TPM2Duplicate_ImportsAndSigns proves the software
// backend's TPM2_DUPLICATE export is a real TCG duplication blob for this
// TPM's storage parent: TPM2_Import accepts it, and the imported key signs
// digests that the source key's public half verifies. This is the
// software->tpm2 key copy the api suite exercises (ruling 932).
func TestSoftwareExportKeyTo_TPM2Duplicate_ImportsAndSigns(t *testing.T) {
	b := newSimBackend(t)
	ctx := context.Background()

	sw, err := software.NewBackend(&software.Config{KeyStorage: storage.New()})
	if err != nil {
		t.Fatalf("software.NewBackend: %v", err)
	}
	t.Cleanup(func() { _ = sw.Close() })
	swIE := sw.(backend.ImportExportBackend)

	cases := []struct {
		name  string
		attrs *types.KeyAttributes
	}{
		{"rsa-2048", &types.KeyAttributes{
			CN: "dup-rsa", KeyType: types.KeyTypeTLS, StoreType: types.StoreSoftware,
			KeyAlgorithm: x509.RSA, Exportable: true, Hash: crypto.SHA256,
			RSAAttributes: &types.RSAAttributes{KeySize: 2048},
		}},
		{"ecdsa-p256", &types.KeyAttributes{
			CN: "dup-ecdsa", KeyType: types.KeyTypeTLS, StoreType: types.StoreSoftware,
			KeyAlgorithm: x509.ECDSA, Exportable: true, Hash: crypto.SHA256,
			ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
		}},
	}
	for _, tc := range cases {
		priv, err := sw.GenerateKey(ctx, tc.attrs)
		if err != nil {
			t.Fatalf("%s: software GenerateKey: %v", tc.name, err)
		}
		srcPub := priv.(crypto.Signer).Public()

		dstAttrs := &types.KeyAttributes{
			CN: tc.attrs.CN + "-copy", KeyType: tc.attrs.KeyType, StoreType: types.StoreTPM2,
			KeyAlgorithm: tc.attrs.KeyAlgorithm, Hash: crypto.SHA256,
			RSAAttributes: tc.attrs.RSAAttributes, ECCAttributes: tc.attrs.ECCAttributes,
		}
		params, err := b.GetImportParameters(ctx, dstAttrs, backend.WrappingAlgorithmTPM2Duplicate)
		if err != nil {
			t.Fatalf("%s: GetImportParameters: %v", tc.name, err)
		}
		wrapped, err := swIE.ExportKeyTo(ctx, tc.attrs, params)
		if err != nil {
			t.Fatalf("%s: software ExportKeyTo(TPM2_DUPLICATE): %v", tc.name, err)
		}
		if err := b.ImportKey(ctx, dstAttrs, wrapped); err != nil {
			t.Fatalf("%s: tpm2 ImportKey: %v", tc.name, err)
		}

		signer, err := b.Signer(ctx, dstAttrs)
		if err != nil {
			t.Fatalf("%s: tpm2 Signer: %v", tc.name, err)
		}
		digest := sha256.Sum256([]byte("copied key signs " + tc.name))
		sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
		if err != nil {
			t.Fatalf("%s: sign with the imported key: %v", tc.name, err)
		}
		switch pub := srcPub.(type) {
		case *rsa.PublicKey:
			if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
				t.Fatalf("%s: source public key does not verify the copy's signature: %v", tc.name, err)
			}
		case *ecdsa.PublicKey:
			if !ecdsa.VerifyASN1(pub, digest[:], sig) {
				t.Fatalf("%s: source public key does not verify the copy's signature", tc.name)
			}
		}
	}

	// A non-exportable source key is refused before any blob is built.
	locked := &types.KeyAttributes{
		CN: "dup-locked", KeyType: types.KeyTypeTLS, StoreType: types.StoreSoftware,
		KeyAlgorithm: x509.RSA, Hash: crypto.SHA256,
		RSAAttributes: &types.RSAAttributes{KeySize: 2048},
	}
	if _, err := sw.GenerateKey(ctx, locked); err != nil {
		t.Fatalf("software GenerateKey (non-exportable): %v", err)
	}
	params, err := b.GetImportParameters(ctx, &types.KeyAttributes{CN: "dup-locked-copy"}, backend.WrappingAlgorithmTPM2Duplicate)
	if err != nil {
		t.Fatalf("GetImportParameters: %v", err)
	}
	if _, err := swIE.ExportKeyTo(ctx, locked, params); !errors.Is(err, backend.ErrKeyNotExportable) {
		t.Fatalf("non-exportable export error = %v, want ErrKeyNotExportable", err)
	}
}
