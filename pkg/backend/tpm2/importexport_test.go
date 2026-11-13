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

package tpm2

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestExportKey_NeverReleasesHardwareKeys is a security invariant, not a
// coverage exercise: the TPM2 backend must refuse every export request. Keys
// created by this backend are fixedTPM/fixedParent, so an implementation that
// ever returned material would mean the hardware boundary had been broken.
//
// The two refusal reasons are distinct and both matter to callers: a key
// without the Exportable flag is rejected by policy (ErrKeyNotExportable),
// while an Exportable key is still rejected by capability
// (ErrExportNotSupported) — the flag must never be enough to get material out.
func TestExportKey_NeverReleasesHardwareKeys(t *testing.T) {
	b := &Backend{}
	ctx := context.Background()

	t.Run("nil attributes", func(t *testing.T) {
		wrapped, err := b.ExportKey(ctx, nil, importExportAlgorithm)
		if !errors.Is(err, ErrInvalidKeyAttributes) {
			t.Errorf("error = %v, want ErrInvalidKeyAttributes", err)
		}
		if wrapped != nil {
			t.Errorf("returned material for nil attributes: %+v", wrapped)
		}
	})

	t.Run("not marked exportable", func(t *testing.T) {
		attrs := &types.KeyAttributes{CN: "hw-key", StoreType: types.StoreTPM2}
		wrapped, err := b.ExportKey(ctx, attrs, importExportAlgorithm)
		if !errors.Is(err, backend.ErrKeyNotExportable) {
			t.Errorf("error = %v, want backend.ErrKeyNotExportable", err)
		}
		if wrapped != nil {
			t.Errorf("returned material for a non-exportable key: %+v", wrapped)
		}
	})

	t.Run("marked exportable is still refused", func(t *testing.T) {
		attrs := &types.KeyAttributes{CN: "hw-key", StoreType: types.StoreTPM2, Exportable: true}
		// Every wrapping algorithm must be refused, not just the TPM's own.
		for _, algo := range []backend.WrappingAlgorithm{
			importExportAlgorithm,
			backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
			backend.WrappingAlgorithm(""),
		} {
			wrapped, err := b.ExportKey(ctx, attrs, algo)
			if !errors.Is(err, backend.ErrExportNotSupported) {
				t.Errorf("algorithm %q: error = %v, want backend.ErrExportNotSupported", algo, err)
			}
			if wrapped != nil {
				t.Fatalf("algorithm %q: TPM2 backend released key material: %+v", algo, wrapped)
			}
		}
	})
}

// TestExportKeyTo_NeverRewrapsHardwareKeys pins that a TPM2 key is never
// re-wrapped for a foreign destination, and that bad input is refused first.
func TestExportKeyTo_NeverRewrapsHardwareKeys(t *testing.T) {
	b := &Backend{}
	attrs := &types.KeyAttributes{CN: "hw-key", StoreType: types.StoreTPM2, Exportable: true}
	tests := []struct {
		name      string
		attrs     *types.KeyAttributes
		dstParams *backend.ImportParameters
		want      error
	}{
		{"nil attributes", nil, &backend.ImportParameters{}, ErrInvalidKeyAttributes},
		{"nil destination parameters", attrs, nil, backend.ErrInvalidAttributes},
		{"valid input is still refused", attrs, &backend.ImportParameters{}, backend.ErrExportToUnsupported},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wrapped, err := b.ExportKeyTo(context.Background(), tt.attrs, tt.dstParams)
			if !errors.Is(err, tt.want) {
				t.Errorf("error = %v, want %v", err, tt.want)
			}
			if wrapped != nil {
				t.Fatalf("TPM2 backend returned wrapped material: %+v", wrapped)
			}
		})
	}
}

// TestGetImportParameters_RequiresStorageParent pins that a backend with no
// storage parent attributes refuses to hand out import parameters.
func TestGetImportParameters_RequiresStorageParent(t *testing.T) {
	b := &Backend{}
	attrs := &types.KeyAttributes{CN: "import-target", StoreType: types.StoreTPM2}
	params, err := b.GetImportParameters(context.Background(), attrs, importExportAlgorithm)
	if !errors.Is(err, ErrUnsupportedOperation) {
		t.Errorf("error = %v, want ErrUnsupportedOperation", err)
	}
	if params != nil {
		t.Fatalf("returned import parameters without a storage parent: %+v", params)
	}
}

// TestApplyKDF_RequiresParameters pins that an ECDH shared secret is never
// returned raw: the KDF parameters are required.
func TestApplyKDF_RequiresParameters(t *testing.T) {
	b := &Backend{}
	derived, err := b.applyKDF([]byte("shared-secret"), nil)
	if !errors.Is(err, ErrInvalidKDFParams) {
		t.Errorf("error = %v, want ErrInvalidKDFParams", err)
	}
	if derived != nil {
		t.Fatalf("returned key material without KDF parameters: %x", derived)
	}
}

// TestExportKeyMaterial_NeverReleasesRawMaterial mirrors the ExportKey
// invariant for the raw-material entry point, including the case where the
// caller has set Exportable — the flag must not unlock the hardware boundary
// on this path either.
func TestExportKeyMaterial_NeverReleasesRawMaterial(t *testing.T) {
	b := &Backend{}
	ctx := context.Background()

	if material, err := b.ExportKeyMaterial(ctx, nil); !errors.Is(err, ErrInvalidKeyAttributes) {
		t.Errorf("nil attrs: error = %v, want ErrInvalidKeyAttributes", err)
	} else if material != nil {
		t.Errorf("nil attrs returned %d bytes of material", len(material))
	}

	for _, exportable := range []bool{false, true} {
		attrs := &types.KeyAttributes{CN: "hw-key", StoreType: types.StoreTPM2, Exportable: exportable}
		material, err := b.ExportKeyMaterial(ctx, attrs)
		if !errors.Is(err, backend.ErrExportNotSupported) {
			t.Errorf("Exportable=%v: error = %v, want backend.ErrExportNotSupported", exportable, err)
		}
		if len(material) != 0 {
			t.Fatalf("Exportable=%v: TPM2 backend released %d bytes of raw key material", exportable, len(material))
		}
	}
}

// TestImportDuplicate_RejectsMalformedBlobsWithoutTPM covers the decode half of
// importDuplicate — the part that runs before any TPM command — so the
// malformed-input contract is pinned even on hosts without a simulator. A
// decode failure must be reported as ErrInvalidKeyAttributes (a caller-input
// problem) rather than ErrUnsupportedOperation (a hardware problem), because
// the two lead operators to very different remediation.
func TestImportDuplicate_RejectsMalformedBlobsWithoutTPM(t *testing.T) {
	b := &Backend{}

	cases := []struct {
		name    string
		encoded []byte
	}{
		{"empty", nil},
		{"not json", []byte("\xff\xfe garbage")},
		{"truncated json", []byte(`{"public":"AAEC`)},
		{"json array", []byte(`["public","duplicate"]`)},
		{"wrong field types", []byte(`{"public":42,"duplicate":true,"enc_secret":{}}`)},
		// Well-formed JSON whose public area is not a valid TPMTPublic.
		{"invalid public area", []byte(`{"public":"AAEC","duplicate":"AAEC","enc_secret":"AAEC"}`)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			public, private, err := b.importDuplicate(tc.encoded)
			if !errors.Is(err, ErrInvalidKeyAttributes) {
				t.Fatalf("error = %v, want ErrInvalidKeyAttributes", err)
			}
			if public != nil {
				t.Errorf("returned a public area for a malformed blob: %+v", public)
			}
			if len(private.Buffer) != 0 {
				t.Errorf("returned %d private bytes for a malformed blob", len(private.Buffer))
			}
		})
	}
}

// TestSigAlgoToKeyAlgo maps certificate signature algorithms onto public-key
// algorithms for the attestation path. Getting this wrong stamps an
// attestation with the wrong key algorithm, so every supported RSA/RSA-PSS
// and ECDSA variant is pinned, along with the fallback for algorithms the
// TPM cannot produce.
func TestSigAlgoToKeyAlgo(t *testing.T) {
	rsa := []x509.SignatureAlgorithm{
		x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA,
		x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS,
	}
	for _, sa := range rsa {
		if got := sigAlgoToKeyAlgo(sa); got != x509.RSA {
			t.Errorf("sigAlgoToKeyAlgo(%v) = %v, want RSA", sa, got)
		}
	}

	ecdsa := []x509.SignatureAlgorithm{
		x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512,
	}
	for _, sa := range ecdsa {
		if got := sigAlgoToKeyAlgo(sa); got != x509.ECDSA {
			t.Errorf("sigAlgoToKeyAlgo(%v) = %v, want ECDSA", sa, got)
		}
	}

	// Algorithms the TPM2 backend cannot produce must fall back to unknown
	// rather than silently claiming RSA or ECDSA.
	unsupported := []x509.SignatureAlgorithm{
		x509.UnknownSignatureAlgorithm,
		x509.SHA1WithRSA,
		x509.ECDSAWithSHA1,
		x509.PureEd25519,
		x509.DSAWithSHA256,
		x509.MD5WithRSA,
	}
	for _, sa := range unsupported {
		if got := sigAlgoToKeyAlgo(sa); got != x509.UnknownPublicKeyAlgorithm {
			t.Errorf("sigAlgoToKeyAlgo(%v) = %v, want UnknownPublicKeyAlgorithm", sa, got)
		}
	}
}
