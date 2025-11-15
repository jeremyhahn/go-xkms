// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
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

	"github.com/aws/aws-sdk-go-v2/service/kms"
)

// KMSClient defines the interface for AWS KMS operations.
// This interface allows us to mock KMS operations for testing.
type KMSClient interface {
	CreateKey(ctx context.Context, params *kms.CreateKeyInput, optFns ...func(*kms.Options)) (*kms.CreateKeyOutput, error)
	Sign(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error)
	Verify(ctx context.Context, params *kms.VerifyInput, optFns ...func(*kms.Options)) (*kms.VerifyOutput, error)
	GetPublicKey(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
	ScheduleKeyDeletion(ctx context.Context, params *kms.ScheduleKeyDeletionInput, optFns ...func(*kms.Options)) (*kms.ScheduleKeyDeletionOutput, error)
	DescribeKey(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
	CreateAlias(ctx context.Context, params *kms.CreateAliasInput, optFns ...func(*kms.Options)) (*kms.CreateAliasOutput, error)
	ListAliases(ctx context.Context, params *kms.ListAliasesInput, optFns ...func(*kms.Options)) (*kms.ListAliasesOutput, error)
	ListKeys(ctx context.Context, params *kms.ListKeysInput, optFns ...func(*kms.Options)) (*kms.ListKeysOutput, error)
	UpdateAlias(ctx context.Context, params *kms.UpdateAliasInput, optFns ...func(*kms.Options)) (*kms.UpdateAliasOutput, error)
	DeleteAlias(ctx context.Context, params *kms.DeleteAliasInput, optFns ...func(*kms.Options)) (*kms.DeleteAliasOutput, error)
	Decrypt(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error)
	Encrypt(ctx context.Context, params *kms.EncryptInput, optFns ...func(*kms.Options)) (*kms.EncryptOutput, error)
	RotateKeyOnDemand(ctx context.Context, params *kms.RotateKeyOnDemandInput, optFns ...func(*kms.Options)) (*kms.RotateKeyOnDemandOutput, error)
	GetParametersForImport(ctx context.Context, params *kms.GetParametersForImportInput, optFns ...func(*kms.Options)) (*kms.GetParametersForImportOutput, error)
	ImportKeyMaterial(ctx context.Context, params *kms.ImportKeyMaterialInput, optFns ...func(*kms.Options)) (*kms.ImportKeyMaterialOutput, error)
}

// MockKMSClient is a mock implementation of the KMSClient interface for testing.
// Each operation can be customized by setting the corresponding function field.
type MockKMSClient struct {
	CreateKeyFunc              func(ctx context.Context, params *kms.CreateKeyInput, optFns ...func(*kms.Options)) (*kms.CreateKeyOutput, error)
	SignFunc                   func(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error)
	VerifyFunc                 func(ctx context.Context, params *kms.VerifyInput, optFns ...func(*kms.Options)) (*kms.VerifyOutput, error)
	GetPublicKeyFunc           func(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
	ScheduleKeyDeletionFunc    func(ctx context.Context, params *kms.ScheduleKeyDeletionInput, optFns ...func(*kms.Options)) (*kms.ScheduleKeyDeletionOutput, error)
	DescribeKeyFunc            func(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
	CreateAliasFunc            func(ctx context.Context, params *kms.CreateAliasInput, optFns ...func(*kms.Options)) (*kms.CreateAliasOutput, error)
	ListAliasesFunc            func(ctx context.Context, params *kms.ListAliasesInput, optFns ...func(*kms.Options)) (*kms.ListAliasesOutput, error)
	ListKeysFunc               func(ctx context.Context, params *kms.ListKeysInput, optFns ...func(*kms.Options)) (*kms.ListKeysOutput, error)
	UpdateAliasFunc            func(ctx context.Context, params *kms.UpdateAliasInput, optFns ...func(*kms.Options)) (*kms.UpdateAliasOutput, error)
	DeleteAliasFunc            func(ctx context.Context, params *kms.DeleteAliasInput, optFns ...func(*kms.Options)) (*kms.DeleteAliasOutput, error)
	DecryptFunc                func(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error)
	EncryptFunc                func(ctx context.Context, params *kms.EncryptInput, optFns ...func(*kms.Options)) (*kms.EncryptOutput, error)
	RotateKeyOnDemandFunc      func(ctx context.Context, params *kms.RotateKeyOnDemandInput, optFns ...func(*kms.Options)) (*kms.RotateKeyOnDemandOutput, error)
	GetParametersForImportFunc func(ctx context.Context, params *kms.GetParametersForImportInput, optFns ...func(*kms.Options)) (*kms.GetParametersForImportOutput, error)
	ImportKeyMaterialFunc      func(ctx context.Context, params *kms.ImportKeyMaterialInput, optFns ...func(*kms.Options)) (*kms.ImportKeyMaterialOutput, error)
}

// CreateKey mocks the CreateKey operation.
func (m *MockKMSClient) CreateKey(ctx context.Context, params *kms.CreateKeyInput, optFns ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
	if m.CreateKeyFunc != nil {
		return m.CreateKeyFunc(ctx, params, optFns...)
	}
	return nil, nil
}

// Sign mocks the Sign operation.
func (m *MockKMSClient) Sign(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error) {
	if m.SignFunc != nil {
		return m.SignFunc(ctx, params, optFns...)
	}
	return nil, nil
}

// Verify mocks the Verify operation.
func (m *MockKMSClient) Verify(ctx context.Context, params *kms.VerifyInput, optFns ...func(*kms.Options)) (*kms.VerifyOutput, error) {
	if m.VerifyFunc != nil {
		return m.VerifyFunc(ctx, params, optFns...)
	}
	return nil, nil
}

// GetPublicKey mocks the GetPublicKey operation.
func (m *MockKMSClient) GetPublicKey(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	if m.GetPublicKeyFunc != nil {
		return m.GetPublicKeyFunc(ctx, params, optFns...)
	}
	return nil, nil
}

// ScheduleKeyDeletion mocks the ScheduleKeyDeletion operation.
func (m *MockKMSClient) ScheduleKeyDeletion(ctx context.Context, params *kms.ScheduleKeyDeletionInput, optFns ...func(*kms.Options)) (*kms.ScheduleKeyDeletionOutput, error) {
	if m.ScheduleKeyDeletionFunc != nil {
		return m.ScheduleKeyDeletionFunc(ctx, params, optFns...)
	}
	return nil, nil
}

// DescribeKey mocks the DescribeKey operation.
func (m *MockKMSClient) DescribeKey(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	if m.DescribeKeyFunc != nil {
		return m.DescribeKeyFunc(ctx, params, optFns...)
	}
	return nil, nil
}

// CreateAlias mocks the CreateAlias operation.
func (m *MockKMSClient) CreateAlias(ctx context.Context, params *kms.CreateAliasInput, optFns ...func(*kms.Options)) (*kms.CreateAliasOutput, error) {
	if m.CreateAliasFunc != nil {
		return m.CreateAliasFunc(ctx, params, optFns...)
	}
	return nil, nil
}

// ListAliases mocks the ListAliases operation.
func (m *MockKMSClient) ListAliases(ctx context.Context, params *kms.ListAliasesInput, optFns ...func(*kms.Options)) (*kms.ListAliasesOutput, error) {
	if m.ListAliasesFunc != nil {
		return m.ListAliasesFunc(ctx, params, optFns...)
	}
	return nil, nil
}

// UpdateAlias mocks the UpdateAlias operation.
func (m *MockKMSClient) UpdateAlias(ctx context.Context, params *kms.UpdateAliasInput, optFns ...func(*kms.Options)) (*kms.UpdateAliasOutput, error) {
	if m.UpdateAliasFunc != nil {
		return m.UpdateAliasFunc(ctx, params, optFns...)
	}
	return nil, nil
}

// DeleteAlias mocks the DeleteAlias operation.
func (m *MockKMSClient) DeleteAlias(ctx context.Context, params *kms.DeleteAliasInput, optFns ...func(*kms.Options)) (*kms.DeleteAliasOutput, error) {
	if m.DeleteAliasFunc != nil {
		return m.DeleteAliasFunc(ctx, params, optFns...)
	}
	return nil, nil
}

// ListKeys mocks the ListKeys operation.
func (m *MockKMSClient) ListKeys(ctx context.Context, params *kms.ListKeysInput, optFns ...func(*kms.Options)) (*kms.ListKeysOutput, error) {
	if m.ListKeysFunc != nil {
		return m.ListKeysFunc(ctx, params, optFns...)
	}
	return nil, nil
}

// Decrypt mocks the Decrypt operation.
func (m *MockKMSClient) Decrypt(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	if m.DecryptFunc != nil {
		return m.DecryptFunc(ctx, params, optFns...)
	}
	return nil, nil
}

// Encrypt mocks the Encrypt operation.
func (m *MockKMSClient) Encrypt(ctx context.Context, params *kms.EncryptInput, optFns ...func(*kms.Options)) (*kms.EncryptOutput, error) {
	if m.EncryptFunc != nil {
		return m.EncryptFunc(ctx, params, optFns...)
	}
	return nil, nil
}

// RotateKeyOnDemand mocks the RotateKeyOnDemand operation.
func (m *MockKMSClient) RotateKeyOnDemand(ctx context.Context, params *kms.RotateKeyOnDemandInput, optFns ...func(*kms.Options)) (*kms.RotateKeyOnDemandOutput, error) {
	if m.RotateKeyOnDemandFunc != nil {
		return m.RotateKeyOnDemandFunc(ctx, params, optFns...)
	}
	return nil, nil
}

// GetParametersForImport mocks the GetParametersForImport operation.
func (m *MockKMSClient) GetParametersForImport(ctx context.Context, params *kms.GetParametersForImportInput, optFns ...func(*kms.Options)) (*kms.GetParametersForImportOutput, error) {
	if m.GetParametersForImportFunc != nil {
		return m.GetParametersForImportFunc(ctx, params, optFns...)
	}
	return nil, nil
}

// ImportKeyMaterial mocks the ImportKeyMaterial operation.
func (m *MockKMSClient) ImportKeyMaterial(ctx context.Context, params *kms.ImportKeyMaterialInput, optFns ...func(*kms.Options)) (*kms.ImportKeyMaterialOutput, error) {
	if m.ImportKeyMaterialFunc != nil {
		return m.ImportKeyMaterialFunc(ctx, params, optFns...)
	}
	return nil, nil
}
