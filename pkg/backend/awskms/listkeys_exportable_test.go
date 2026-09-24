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

//go:build awskms

package awskms

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestListKeys_ReportsExportableFalseAndSensitiveTrue is the success case
// for go-xkms#932: a key created with Exportable: true must round-trip
// through ListKeys as Exportable=false, and Sensitive must read true,
// because Capabilities().Export is false unconditionally and
// ExportKey/ExportKeyMaterial (awskms.go) refuse every key this backend can
// create regardless of policy -- AWS KMS never releases key material outside
// the service boundary. Before this fix, ListKeys left both fields at the
// types.KeyAttributes zero value, which happened to read Exportable as false
// by coincidence but always misreported Sensitive as false.
func TestListKeys_ReportsExportableFalseAndSensitiveTrue(t *testing.T) {
	b, err := NewBackendWithClient(&Config{
		Region:      "us-east-1",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}, &MockKMSClient{
		CreateKeyFunc: func(ctx context.Context, params *kms.CreateKeyInput, optFns ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
			return &kms.CreateKeyOutput{
				KeyMetadata: &kmstypes.KeyMetadata{KeyId: aws.String("listkeys-exportable-key-id")},
			}, nil
		},
		CreateAliasFunc: func(ctx context.Context, params *kms.CreateAliasInput, optFns ...func(*kms.Options)) (*kms.CreateAliasOutput, error) {
			return &kms.CreateAliasOutput{}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewBackendWithClient() error = %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "listkeys-exportable-rsa",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_AWSKMS,
		KeyAlgorithm: x509.RSA,
		Exportable:   true,
	}
	if _, err := b.CreateKey(attrs); err != nil {
		t.Fatalf("CreateKey() error = %v", err)
	}

	listed, err := b.ListKeys(context.Background())
	if err != nil {
		t.Fatalf("ListKeys() error = %v", err)
	}

	var found *types.KeyAttributes
	for _, ka := range listed {
		if ka.CN == attrs.CN {
			found = ka
			break
		}
	}
	if found == nil {
		t.Fatalf("ListKeys did not report %q", attrs.CN)
	}
	if found.Exportable {
		t.Error("Exportable: expected false (AWS KMS never releases key material), got true")
	}
	if !found.Sensitive {
		t.Error("Sensitive: expected true (AWS KMS never releases plaintext), got false")
	}

	// The round-tripped attributes must stay refused, exactly as
	// findKeyAttrs/loadStoredKeyAttrs (pkg/xkms) would use them. Capabilities
	// gates this backend's ExportKey before the Exportable check even runs
	// (awskms.go), so the error is ErrExportNotSupported rather than
	// ErrKeyNotExportable -- this backend refuses every key, not just the
	// ones a caller failed to mark exportable.
	if _, err := b.ExportKey(context.Background(), found, backend.WrappingAlgorithmRSAES_OAEP_SHA_256); !errors.Is(err, backend.ErrExportNotSupported) {
		t.Errorf("ExportKey with the round-tripped attributes: expected backend.ErrExportNotSupported, got %v", err)
	}
}

// TestListKeys_ExportKeyRefusesEvenWhenCallerAssertsExportable is the error
// path: even a caller who bypasses ListKeys and hands ExportKey
// attrs.Exportable = true directly is refused, because Capabilities().Export
// is false unconditionally for this backend -- there is no per-key state
// that could ever make ExportKey succeed. This is the defence-in-depth half
// of go-xkms#932's "never silently accept it and then misreport".
func TestListKeys_ExportKeyRefusesEvenWhenCallerAssertsExportable(t *testing.T) {
	b, err := NewBackendWithClient(&Config{
		Region:      "us-east-1",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}, &MockKMSClient{})
	if err != nil {
		t.Fatalf("NewBackendWithClient() error = %v", err)
	}

	forged := &types.KeyAttributes{
		CN:           "listkeys-exportable-defense-in-depth",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_AWSKMS,
		KeyAlgorithm: x509.RSA,
		Exportable:   true,
	}

	_, err = b.ExportKey(context.Background(), forged, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	if !errors.Is(err, backend.ErrExportNotSupported) {
		t.Errorf("ExportKey: expected backend.ErrExportNotSupported, got %v", err)
	}
}
