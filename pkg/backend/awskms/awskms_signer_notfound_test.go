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

//go:build awskms

package awskms

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestBackend_Signer_NotFoundIsKeyNotFound: a fresh key name with no local
// metadata resolves alias/<CN>, and KMS answers GetPublicKey with
// NotFoundException. That is genuine absence, so Signer reports
// backend.ErrKeyNotFound and a provision-on-absence caller (the tenant login
// CA factory) generates the key instead of failing (go-xkms#2083).
func TestBackend_Signer_NotFoundIsKeyNotFound(t *testing.T) {
	var gotKeyID string
	mockClient := &MockKMSClient{
		GetPublicKeyFunc: func(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
			gotKeyID = aws.ToString(params.KeyId)
			return nil, &kmstypes.NotFoundException{Message: aws.String("Alias not found")}
		},
	}
	config := &Config{Region: "us-east-1", KeyStorage: storage.New(), CertStorage: storage.New()}
	b, err := NewBackendWithClient(config, mockClient)
	if err != nil {
		t.Fatalf("NewBackendWithClient: %v", err)
	}
	attrs := &types.KeyAttributes{CN: "fresh-login-ca", KeyType: backend.KEY_TYPE_SIGNING, StoreType: backend.STORE_AWSKMS}
	_, err = b.Signer(context.Background(), attrs)
	if !errors.Is(err, backend.ErrKeyNotFound) {
		t.Fatalf("Signer(absent) error = %v, want errors.Is(err, backend.ErrKeyNotFound)", err)
	}
	if gotKeyID != "alias/fresh-login-ca" {
		t.Errorf("GetPublicKey KeyId = %q, want alias/fresh-login-ca", gotKeyID)
	}
}

// TestBackend_Signer_OtherFailureIsNotAbsence: any GetPublicKey failure other
// than NotFoundException (access denied, throttling) must not read as absence.
func TestBackend_Signer_OtherFailureIsNotAbsence(t *testing.T) {
	mockClient := &MockKMSClient{
		GetPublicKeyFunc: func(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
			return nil, &kmstypes.KMSInternalException{Message: aws.String("internal")}
		},
	}
	config := &Config{Region: "us-east-1", KeyStorage: storage.New(), CertStorage: storage.New()}
	b, err := NewBackendWithClient(config, mockClient)
	if err != nil {
		t.Fatalf("NewBackendWithClient: %v", err)
	}
	attrs := &types.KeyAttributes{CN: "fresh-login-ca", KeyType: backend.KEY_TYPE_SIGNING, StoreType: backend.STORE_AWSKMS}
	_, err = b.Signer(context.Background(), attrs)
	if err == nil {
		t.Fatal("Signer() error = nil, want a lookup failure")
	}
	if errors.Is(err, backend.ErrKeyNotFound) {
		t.Fatalf("Signer() error = %v must not satisfy errors.Is(err, backend.ErrKeyNotFound)", err)
	}
}
