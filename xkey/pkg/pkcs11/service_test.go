// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package pkcs11

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// TestApplyKeyTemplate_SharedByBothHalvesOfTheCeremony pins the reason the
// template is one function: GetImportParameters mints the wrapping parameters
// from the key shape and ImportKey installs the key from the same shape. If
// they diverged, a key would import "successfully" at the wrong size or curve
// and only fail much later, as a signature nobody can verify.
func TestApplyKeyTemplate_SharedByBothHalvesOfTheCeremony(t *testing.T) {
	cases := []struct {
		name string
		tmpl keyTemplate
	}{
		{"rsa default size", keyTemplate{KeyType: "RSA"}},
		{"rsa explicit size", keyTemplate{KeyType: "RSA", KeySize: 4096}},
		{"ecdsa default curve", keyTemplate{KeyType: "ECDSA"}},
		{"ecdsa explicit curve", keyTemplate{KeyType: "ECDSA", Curve: "P-384"}},
		{"ed25519", keyTemplate{KeyType: "Ed25519"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			viaImportParams := &xkms.KeyAttributes{}
			if err := applyImportKeyTemplate(viaImportParams, &transport.GetImportParametersRequest{
				KeyType: tc.tmpl.KeyType,
				KeySize: tc.tmpl.KeySize,
				Curve:   tc.tmpl.Curve,
			}); err != nil {
				t.Fatalf("applyImportKeyTemplate: %v", err)
			}

			viaImport := &xkms.KeyAttributes{}
			if err := applyKeyTemplate(viaImport, tc.tmpl); err != nil {
				t.Fatalf("applyKeyTemplate: %v", err)
			}

			if viaImportParams.KeyAlgorithm != viaImport.KeyAlgorithm {
				t.Errorf("algorithm drift: params=%v import=%v",
					viaImportParams.KeyAlgorithm, viaImport.KeyAlgorithm)
			}
			if (viaImportParams.RSAAttributes == nil) != (viaImport.RSAAttributes == nil) {
				t.Fatal("RSA attribute drift between the two halves")
			}
			if viaImportParams.RSAAttributes != nil &&
				viaImportParams.RSAAttributes.KeySize != viaImport.RSAAttributes.KeySize {
				t.Errorf("RSA key size drift: params=%d import=%d",
					viaImportParams.RSAAttributes.KeySize, viaImport.RSAAttributes.KeySize)
			}
			if (viaImportParams.ECCAttributes == nil) != (viaImport.ECCAttributes == nil) {
				t.Fatal("ECC attribute drift between the two halves")
			}
			if viaImportParams.ECCAttributes != nil &&
				viaImportParams.ECCAttributes.Curve != viaImport.ECCAttributes.Curve {
				t.Errorf("curve drift: params=%v import=%v",
					viaImportParams.ECCAttributes.Curve, viaImport.ECCAttributes.Curve)
			}
		})
	}
}

// TestApplyKeyTemplate_EmptyKeyTypeIsSymmetricOptOut verifies a symmetric
// import leaves the asymmetric attributes untouched rather than erroring.
func TestApplyKeyTemplate_EmptyKeyTypeIsSymmetricOptOut(t *testing.T) {
	attrs := &xkms.KeyAttributes{}
	if err := applyKeyTemplate(attrs, keyTemplate{}); err != nil {
		t.Fatalf("applyKeyTemplate with no key type = %v, want nil", err)
	}
	if attrs.RSAAttributes != nil || attrs.ECCAttributes != nil {
		t.Error("an empty key type must not shape the attributes")
	}
}

// TestApplyKeyTemplate_RejectsUnknownKeyType proves an unrecognised algorithm
// fails loudly instead of importing an unshaped key.
func TestApplyKeyTemplate_RejectsUnknownKeyType(t *testing.T) {
	attrs := &xkms.KeyAttributes{}
	err := applyKeyTemplate(attrs, keyTemplate{KeyType: "not-an-algorithm"})
	if !errors.Is(err, ErrImportTemplateUnsupported) {
		t.Fatalf("applyKeyTemplate = %v, want ErrImportTemplateUnsupported", err)
	}
}

// TestEmbeddedTransport_ImportKeyRejectsNilRequest covers the error path of
// the new ImportKey without requiring an initialized backend.
func TestEmbeddedTransport_ImportKeyRejectsNilRequest(t *testing.T) {
	var tr EmbeddedTransport
	if _, err := tr.ImportKey(context.Background(), nil); !errors.Is(err, ErrNilRequest) {
		t.Fatalf("ImportKey(nil) = %v, want ErrNilRequest", err)
	}
}

// TestIPCTransport_ImportKeyNotImplemented pins the IPC transport's documented
// MVP behaviour: it reports the gap rather than silently succeeding.
func TestIPCTransport_ImportKeyNotImplemented(t *testing.T) {
	var tr IPCTransport
	if _, err := tr.ImportKey(context.Background(), &transport.ImportKeyRequest{KeyID: "k"}); !errors.Is(err, ErrIPCNotImplemented) {
		t.Fatalf("ImportKey = %v, want ErrIPCNotImplemented", err)
	}
}
