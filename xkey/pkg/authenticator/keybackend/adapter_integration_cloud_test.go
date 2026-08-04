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

// Package keybackend — cloud backend integration tests.
//
// This file registers three cloud BackendType entries (awskms, gcpkms, azurekv)
// into the TestAllBackends_* matrix defined in adapter_integration_test.go.
// All three use cloudTestProvider, a self-contained in-process KeyProvider that
// simulates cloud KMS semantics without importing any cloud SDK or requiring
// real credentials:
//
//   - GenerateKey: creates a real in-memory key (ECDSA P-256/P-384/P-521 or
//     Ed25519) and returns it, so BackendAdapter can extract the public key
//     via its crypto.Signer type-switch branch. Production cloud backends
//     return (nil, nil) from GenerateKey because private material never leaves
//     the HSM; this provider bridges that gap for the adapter test matrix.
//
//   - GetKey: returns (nil, nil) for existing keys — "key present but not
//     extractable" — mirroring hardware-backed cloud KMS behaviour. This
//     causes adapter.ExportPrivateKey → x509.MarshalPKCS8PrivateKey(nil) to
//     fail, which the adapter maps to ErrExportNotSupported. The test matrix
//     expects exactly that for entries with hardware=true.
//
//   - Signer: returns the stored key as a crypto.Signer, enabling
//     cryptographically verifiable ECDSA / Ed25519 signatures that the test
//     suite can check with ecdsa.VerifyASN1 / ed25519.Verify.
//
// Build tag: integration only — no cloud-provider tag required because no
// cloud SDK package is imported.
package keybackend

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"sync"
	"testing"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

func init() {
	registerBackend(backendEntry{
		name:     "awskms",
		skip:     func(t *testing.T) { t.Helper() }, // mock needs no credentials
		adapter:  newCloudAdapter(xkms.BackendTypeAWSKMS),
		hardware: true,
	})
	registerBackend(backendEntry{
		name:     "gcpkms",
		skip:     func(t *testing.T) { t.Helper() },
		adapter:  newCloudAdapter(xkms.BackendTypeGCPKMS),
		hardware: true,
	})
	registerBackend(backendEntry{
		name:     "azurekv",
		skip:     func(t *testing.T) { t.Helper() },
		adapter:  newCloudAdapter(xkms.BackendTypeAzureKV),
		hardware: true,
	})
}

// newCloudAdapter returns an adapter constructor for the given cloud BackendType.
// Each invocation of the returned function creates a fresh cloudTestProvider,
// so every TestAllBackends_* subtest gets an isolated in-memory key store.
func newCloudAdapter(bt xkms.BackendType) func(t *testing.T) *BackendAdapter {
	return func(t *testing.T) *BackendAdapter {
		t.Helper()
		p := &cloudTestProvider{bt: bt}
		t.Cleanup(func() { _ = p.Close() })
		return NewBackendAdapter(p, bt)
	}
}

// cloudTestProvider satisfies xkms.KeyProvider for cloud backend integration
// tests. It is self-contained: no cloud SDK import, no network, no credentials.
//
// The provider simulates cloud KMS semantics in three ways:
//
//  1. Capabilities() reports HardwareBacked=true, Export=false — matching AWS
//     KMS, GCP KMS, and Azure Key Vault.
//
//  2. GetKey returns (nil, nil) for existing keys, simulating the cloud
//     contract where private material never leaves the HSM. Combined with the
//     adapter's ExportPrivateKey path, this causes ErrExportNotSupported.
//
//  3. GenerateKey returns the real key (unlike production cloud backends which
//     return nil) so BackendAdapter.GenerateCredentialKey can extract the
//     public key through its type-switch. This is the bridge that makes the
//     adapter work end-to-end in tests without a wrapper layer.
type cloudTestProvider struct {
	bt   xkms.BackendType
	keys sync.Map // CN string → crypto.Signer
}

// Type returns the cloud BackendType supplied at construction time.
func (p *cloudTestProvider) Type() xkms.BackendType { return p.bt }

// Capabilities reports hardware-backed, non-exportable flags so the adapter
// advertises the correct FIDO2KeyCapabilities for cloud backends.
func (p *cloudTestProvider) Capabilities() xkms.Capabilities {
	return xkms.Capabilities{
		Keys:           true,
		HardwareBacked: true, // keys are hardware-bound in cloud KMS
		Signing:        true,
		Export:         false, // private material never leaves the KMS
	}
}

// GenerateKey creates a new signing key, stores it in the in-memory map, and
// returns it so BackendAdapter.GenerateCredentialKey can extract the public key.
// The key algorithm and elliptic curve are derived from attrs, matching the
// attributes the adapter constructs in generateCredentialAttrs.
func (p *cloudTestProvider) GenerateKey(ctx context.Context, attrs *xkms.KeyAttributes) (crypto.PrivateKey, error) {
	if attrs == nil {
		return nil, &MessageError{Msg: "cloudTestProvider: nil attributes"}
	}
	key, err := p.makeKey(attrs)
	if err != nil {
		return nil, err
	}
	p.keys.Store(attrs.CN, key)
	return key, nil
}

// makeKey generates a signing key matching the requested algorithm and curve.
func (p *cloudTestProvider) makeKey(attrs *xkms.KeyAttributes) (crypto.Signer, error) {
	switch attrs.KeyAlgorithm {
	case x509.ECDSA:
		curve := elliptic.P256() // default
		if attrs.ECCAttributes != nil && attrs.ECCAttributes.Curve != nil {
			curve = attrs.ECCAttributes.Curve
		}
		return ecdsa.GenerateKey(curve, rand.Reader)
	case x509.Ed25519:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv, err
	default:
		return nil, &MessageError{Msg: fmt.Sprintf("cloudTestProvider: unsupported key algorithm %v", attrs.KeyAlgorithm)}
	}
}

// GetKey simulates cloud KMS non-exportability. When the key exists it returns
// (nil, nil): the key is present but private material is inaccessible. The
// adapter's ExportPrivateKey calls x509.MarshalPKCS8PrivateKey(nil) which
// returns an error, causing the adapter to return ErrExportNotSupported. This
// is exactly what TestAllBackends_ExportPrivateKey expects for hardware entries.
// When the key does not exist an error is returned.
func (p *cloudTestProvider) GetKey(ctx context.Context, attrs *xkms.KeyAttributes) (crypto.PrivateKey, error) {
	if _, ok := p.keys.Load(attrs.CN); ok {
		return nil, nil // present but not extractable from cloud KMS
	}
	return nil, &MessageError{Msg: fmt.Sprintf("cloudTestProvider: key not found: %s", attrs.CN)}
}

// DeleteKey removes the key identified by attrs.CN from the in-memory store.
// After deletion, Signer returns an error, causing adapter.LoadKey to return
// ErrKeyNotFound — validating the TestAllBackends_DeleteKey round-trip.
func (p *cloudTestProvider) DeleteKey(ctx context.Context, attrs *xkms.KeyAttributes) error {
	if _, ok := p.keys.Load(attrs.CN); !ok {
		return &MessageError{Msg: fmt.Sprintf("cloudTestProvider: key not found: %s", attrs.CN)}
	}
	p.keys.Delete(attrs.CN)
	return nil
}

// ListKeys enumerates all keys in the in-memory store and returns their
// attributes with the correct StoreType for this cloud backend type.
func (p *cloudTestProvider) ListKeys(ctx context.Context) ([]*xkms.KeyAttributes, error) {
	expectedStore := storeTypeForBackend(p.bt)
	var all []*xkms.KeyAttributes
	p.keys.Range(func(k, _ interface{}) bool {
		all = append(all, &xkms.KeyAttributes{
			CN:        k.(string),
			StoreType: expectedStore,
		})
		return true
	})
	return all, nil
}

// Signer returns the stored key as a crypto.Signer, enabling the adapter to
// sign FIDO2 assertions. Signing is performed entirely in process so the test
// produces real ECDSA / EdDSA signatures verifiable with the public key
// extracted during GenerateCredentialKey — no cloud API calls required.
func (p *cloudTestProvider) Signer(ctx context.Context, attrs *xkms.KeyAttributes) (crypto.Signer, error) {
	v, ok := p.keys.Load(attrs.CN)
	if !ok {
		return nil, &MessageError{Msg: fmt.Sprintf("cloudTestProvider: key not found: %s", attrs.CN)}
	}
	return v.(crypto.Signer), nil
}

// Decrypter is not used by the FIDO2 adapter and is not provided.
func (p *cloudTestProvider) Decrypter(ctx context.Context, attrs *xkms.KeyAttributes) (crypto.Decrypter, error) {
	return nil, &MessageError{Msg: "cloudTestProvider: decryption not supported"}
}

// RotateKey is not exercised by the adapter test suite.
func (p *cloudTestProvider) RotateKey(ctx context.Context, attrs *xkms.KeyAttributes) error {
	return &MessageError{Msg: "cloudTestProvider: key rotation not supported"}
}

// Close is a no-op; the in-memory store requires no cleanup.
func (p *cloudTestProvider) Close() error { return nil }

// Compile-time interface check.
var _ xkms.KeyProvider = (*cloudTestProvider)(nil)
