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

package services

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	tpm2pkg "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Mock transport client for policy operations
// ---------------------------------------------------------------------------

// policyMockClient embeds mockClient and overrides PolicyVerify/PolicyExport.
type policyMockClient struct {
	mockClient
	policyVerifyFn func(ctx context.Context, req *transport.PolicyVerifyRequest) (*transport.PolicyVerifyResponse, error)
	policyExportFn func(ctx context.Context, req *transport.PolicyExportRequest) (*transport.PolicyExportResponse, error)
}

func (m *policyMockClient) Connect(context.Context) error { return nil }
func (m *policyMockClient) Close() error                  { return nil }
func (m *policyMockClient) Health(context.Context) (*transport.HealthResponse, error) {
	return nil, nil
}

func (m *policyMockClient) PolicyVerify(ctx context.Context, req *transport.PolicyVerifyRequest) (*transport.PolicyVerifyResponse, error) {
	if m.policyVerifyFn != nil {
		return m.policyVerifyFn(ctx, req)
	}
	return nil, errors.New("not configured")
}

func (m *policyMockClient) PolicyExport(ctx context.Context, req *transport.PolicyExportRequest) (*transport.PolicyExportResponse, error) {
	if m.policyExportFn != nil {
		return m.policyExportFn(ctx, req)
	}
	return nil, errors.New("not configured")
}

// ---------------------------------------------------------------------------
// SetClient / Initialize (both at 0% coverage)
// ---------------------------------------------------------------------------

func TestPlatformPolicy_Coverage_SetClient(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "test.policy"))
	svc.SetContext(context.Background())

	mc := &policyMockClient{
		policyVerifyFn: func(_ context.Context, req *transport.PolicyVerifyRequest) (*transport.PolicyVerifyResponse, error) {
			return &transport.PolicyVerifyResponse{
				Name:  req.Name,
				Valid: true,
			}, nil
		},
	}
	var c transport.Client = mc
	svc.SetClient(c)

	// Verify we can retrieve the client.
	got, err := svc.getPolicyClient()
	require.NoError(t, err)
	require.NotNil(t, got)
}

func TestPlatformPolicy_Coverage_SetClient_NilClient(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "test.policy"))

	// No client set - should return ErrPolicyNoClient.
	_, err := svc.getPolicyClient()
	assert.ErrorIs(t, err, ErrPolicyNoClient)
}

func TestPlatformPolicy_Coverage_Initialize_FileNotExist(t *testing.T) {
	policyPath := filepath.Join(t.TempDir(), "nonexistent.policy")
	svc := NewPlatformPolicyService(policyPath)

	// Initialize should return nil when file does not exist.
	err := svc.Initialize()
	assert.NoError(t, err)

	// Policy should not be loaded.
	def := svc.policy.Load()
	assert.Nil(t, def)
}

func TestPlatformPolicy_Coverage_Initialize_ValidFile(t *testing.T) {
	policyPath := filepath.Join(t.TempDir(), "test.policy")

	now := time.Now()
	def := &PlatformPolicyDefinition{
		PCRs:      []int{0, 7},
		Bank:      "sha256",
		Digests:   map[int]string{0: "aabbccdd", 7: "11223344"},
		CreatedAt: now,
		UpdatedAt: now,
	}
	data, err := json.MarshalIndent(def, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(policyPath, data, 0600))

	svc := NewPlatformPolicyService(policyPath)
	err = svc.Initialize()
	require.NoError(t, err)

	loaded := svc.policy.Load()
	require.NotNil(t, loaded)
	assert.Equal(t, []int{0, 7}, loaded.PCRs)
	assert.Equal(t, "sha256", loaded.Bank)
	assert.Equal(t, "aabbccdd", loaded.Digests[0])
}

func TestPlatformPolicy_Coverage_Initialize_InvalidJSON(t *testing.T) {
	policyPath := filepath.Join(t.TempDir(), "bad.policy")
	require.NoError(t, os.WriteFile(policyPath, []byte("not json"), 0600))

	svc := NewPlatformPolicyService(policyPath)
	err := svc.Initialize()
	assert.ErrorIs(t, err, ErrPolicyLoadFailed)
}

func TestPlatformPolicy_Coverage_Initialize_Unreadable(t *testing.T) {
	// Use a directory path as the policy file to trigger a read error.
	policyPath := t.TempDir()
	svc := NewPlatformPolicyService(policyPath)
	err := svc.Initialize()
	assert.ErrorIs(t, err, ErrPolicyLoadFailed)
}

// ---------------------------------------------------------------------------
// getPolicyContext
// ---------------------------------------------------------------------------

func TestPlatformPolicy_Coverage_GetPolicyContext_WithContext(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "test.policy"))
	ctx := context.Background()
	svc.SetContext(ctx)
	assert.Equal(t, ctx, svc.getPolicyContext())
}

func TestPlatformPolicy_Coverage_GetPolicyContext_NilContext(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "test.policy"))
	// ctx is nil by default
	got := svc.getPolicyContext()
	assert.NotNil(t, got) // should fallback to context.Background()
}

// ---------------------------------------------------------------------------
// GetStatus
// ---------------------------------------------------------------------------

func TestPlatformPolicy_Coverage_GetStatus_NoPolicyLoaded(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "test.policy"))
	svc.SetContext(context.Background())

	status, err := svc.GetStatus()
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.False(t, status.Configured)
}

func TestPlatformPolicy_Coverage_GetStatus_WithPolicy(t *testing.T) {
	mock := defaultPolicyMock()
	svc := newPolicyServiceWithMock(t, mock)

	// Create a policy first.
	_, err := svc.CreatePolicy([]int{0, 7}, "sha256")
	require.NoError(t, err)

	status, err := svc.GetStatus()
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.True(t, status.Configured)
	assert.Equal(t, []int{0, 7}, status.PCRs)
	assert.Equal(t, "sha256", status.Bank)
	assert.True(t, status.Valid)
}

// ---------------------------------------------------------------------------
// CreatePolicy
// ---------------------------------------------------------------------------

func TestPlatformPolicy_Coverage_CreatePolicy_InvalidPCRs_Empty(t *testing.T) {
	mock := defaultPolicyMock()
	svc := newPolicyServiceWithMock(t, mock)

	_, err := svc.CreatePolicy(nil, "sha256")
	assert.ErrorIs(t, err, ErrPolicyInvalidPCRs)
}

func TestPlatformPolicy_Coverage_CreatePolicy_InvalidPCRs_OutOfRange(t *testing.T) {
	mock := defaultPolicyMock()
	svc := newPolicyServiceWithMock(t, mock)

	_, err := svc.CreatePolicy([]int{-1}, "sha256")
	assert.ErrorIs(t, err, ErrPolicyInvalidPCRs)

	_, err = svc.CreatePolicy([]int{24}, "sha256")
	assert.ErrorIs(t, err, ErrPolicyInvalidPCRs)
}

func TestPlatformPolicy_Coverage_CreatePolicy_InvalidBank(t *testing.T) {
	mock := defaultPolicyMock()
	svc := newPolicyServiceWithMock(t, mock)

	_, err := svc.CreatePolicy([]int{0}, "md5")
	assert.ErrorIs(t, err, ErrPolicyInvalidBank)
}

func TestPlatformPolicy_Coverage_CreatePolicy_Success(t *testing.T) {
	mock := defaultPolicyMock()
	svc := newPolicyServiceWithMock(t, mock)

	status, err := svc.CreatePolicy([]int{0, 7}, "sha256")
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.True(t, status.Configured)
	assert.True(t, status.Valid)
	assert.Equal(t, "sha256", status.Bank)
	assert.NotEmpty(t, status.CreatedAt)
	assert.NotEmpty(t, status.UpdatedAt)
}

func TestPlatformPolicy_Coverage_CreatePolicy_TPMUnavailable(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "test.policy"))
	svc.SetContext(context.Background())
	// No TPM accessor set.

	_, err := svc.CreatePolicy([]int{0}, "sha256")
	assert.ErrorIs(t, err, ErrPolicyTPMNotAvailable)
}

// ---------------------------------------------------------------------------
// UpdatePolicy
// ---------------------------------------------------------------------------

func TestPlatformPolicy_Coverage_UpdatePolicy_NoPolicyConfigured(t *testing.T) {
	mock := defaultPolicyMock()
	svc := newPolicyServiceWithMock(t, mock)

	_, err := svc.UpdatePolicy([]int{0}, "sha256")
	assert.ErrorIs(t, err, ErrPolicyNotConfigured)
}

func TestPlatformPolicy_Coverage_UpdatePolicy_InvalidPCRs(t *testing.T) {
	mock := defaultPolicyMock()
	svc := newPolicyServiceWithMock(t, mock)

	// Create initial policy.
	_, err := svc.CreatePolicy([]int{0, 7}, "sha256")
	require.NoError(t, err)

	_, err = svc.UpdatePolicy(nil, "sha256")
	assert.ErrorIs(t, err, ErrPolicyInvalidPCRs)
}

func TestPlatformPolicy_Coverage_UpdatePolicy_InvalidBank(t *testing.T) {
	mock := defaultPolicyMock()
	svc := newPolicyServiceWithMock(t, mock)

	_, err := svc.CreatePolicy([]int{0, 7}, "sha256")
	require.NoError(t, err)

	_, err = svc.UpdatePolicy([]int{0}, "INVALID")
	assert.ErrorIs(t, err, ErrPolicyInvalidBank)
}

func TestPlatformPolicy_Coverage_UpdatePolicy_Success(t *testing.T) {
	mock := defaultPolicyMock()
	svc := newPolicyServiceWithMock(t, mock)

	created, err := svc.CreatePolicy([]int{0, 7}, "sha256")
	require.NoError(t, err)

	updated, err := svc.UpdatePolicy([]int{0, 7}, "sha256")
	require.NoError(t, err)
	require.NotNil(t, updated)
	assert.True(t, updated.Configured)
	assert.True(t, updated.Valid)
	// CreatedAt should be preserved from the original policy.
	assert.Equal(t, created.CreatedAt, updated.CreatedAt)
}

// ---------------------------------------------------------------------------
// DeletePolicy
// ---------------------------------------------------------------------------

func TestPlatformPolicy_Coverage_DeletePolicy_NoPolicyConfigured(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "test.policy"))
	err := svc.DeletePolicy()
	assert.ErrorIs(t, err, ErrPolicyNotConfigured)
}

func TestPlatformPolicy_Coverage_DeletePolicy_Success(t *testing.T) {
	mock := defaultPolicyMock()
	svc := newPolicyServiceWithMock(t, mock)

	_, err := svc.CreatePolicy([]int{0, 7}, "sha256")
	require.NoError(t, err)

	err = svc.DeletePolicy()
	assert.NoError(t, err)

	// Verify policy is removed from memory.
	def := svc.policy.Load()
	assert.Nil(t, def)
}

// ---------------------------------------------------------------------------
// VerifyPolicy
// ---------------------------------------------------------------------------

func TestPlatformPolicy_Coverage_VerifyPolicy_NoPolicyConfigured(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "test.policy"))
	svc.SetContext(context.Background())

	valid, err := svc.VerifyPolicy()
	assert.False(t, valid)
	assert.ErrorIs(t, err, ErrPolicyNotConfigured)
}

func TestPlatformPolicy_Coverage_VerifyPolicy_MatchingDigests(t *testing.T) {
	mock := defaultPolicyMock()
	svc := newPolicyServiceWithMock(t, mock)

	_, err := svc.CreatePolicy([]int{0, 7}, "sha256")
	require.NoError(t, err)

	valid, err := svc.VerifyPolicy()
	assert.NoError(t, err)
	assert.True(t, valid)
}

func TestPlatformPolicy_Coverage_VerifyPolicy_MismatchedDigests(t *testing.T) {
	mock := defaultPolicyMock()
	svc := newPolicyServiceWithMock(t, mock)

	_, err := svc.CreatePolicy([]int{0, 7}, "sha256")
	require.NoError(t, err)

	// Change the mock PCR values so digests no longer match.
	mock.pcrBanksOverride = []tpm2pkg.PCRBank{
		{
			Algorithm: "SHA256",
			PCRs: []tpm2pkg.PCR{
				{ID: 0, Value: []byte{0xFF, 0xFF, 0xFF, 0xFF}},
				{ID: 7, Value: []byte{0x11, 0x22, 0x33, 0x44}},
			},
		},
	}

	valid, err := svc.VerifyPolicy()
	assert.NoError(t, err)
	assert.False(t, valid)
}

func TestPlatformPolicy_Coverage_VerifyPolicy_TPMError(t *testing.T) {
	mock := defaultPolicyMock()
	svc := newPolicyServiceWithMock(t, mock)

	_, err := svc.CreatePolicy([]int{0, 7}, "sha256")
	require.NoError(t, err)

	// Make the TPM return an error on ReadPCRs.
	mock.pcrBanksErr = errors.New("tpm error")

	valid, err := svc.VerifyPolicy()
	assert.False(t, valid)
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// GetPolicyPCRs
// ---------------------------------------------------------------------------

func TestPlatformPolicy_Coverage_GetPolicyPCRs_NoPolicyConfigured(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "test.policy"))

	pcrs, bank, err := svc.GetPolicyPCRs()
	assert.Nil(t, pcrs)
	assert.Empty(t, bank)
	assert.ErrorIs(t, err, ErrPolicyNotConfigured)
}

func TestPlatformPolicy_Coverage_GetPolicyPCRs_Success(t *testing.T) {
	mock := defaultPolicyMock()
	svc := newPolicyServiceWithMock(t, mock)

	_, err := svc.CreatePolicy([]int{0, 7}, "sha256")
	require.NoError(t, err)

	pcrs, bank, err := svc.GetPolicyPCRs()
	require.NoError(t, err)
	assert.Equal(t, []int{0, 7}, pcrs)
	assert.Equal(t, "sha256", bank)
}

// ---------------------------------------------------------------------------
// ExportPolicy
// ---------------------------------------------------------------------------

func TestPlatformPolicy_Coverage_ExportPolicy_NoPolicyConfigured(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "test.policy"))
	svc.SetContext(context.Background())

	_, err := svc.ExportPolicy()
	assert.ErrorIs(t, err, ErrPolicyNotConfigured)
}

func TestPlatformPolicy_Coverage_ExportPolicy_Success(t *testing.T) {
	mock := defaultPolicyMock()
	svc := newPolicyServiceWithMock(t, mock)

	_, err := svc.CreatePolicy([]int{0, 7}, "sha256")
	require.NoError(t, err)

	exported, err := svc.ExportPolicy()
	require.NoError(t, err)
	assert.NotEmpty(t, exported)

	// Parse the export to verify structure.
	var exportData map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(exported), &exportData))
	assert.Equal(t, "Platform Policy", exportData["name"])
	assert.Equal(t, "sha256", exportData["pcr_bank"])
	assert.NotNil(t, exportData["pcr_selections"])
	assert.NotNil(t, exportData["pcr_digests"])
}

// ---------------------------------------------------------------------------
// GetPlatformPolicyAsPCRPolicy
// ---------------------------------------------------------------------------

func TestPlatformPolicy_Coverage_GetPlatformPolicyAsPCRPolicy_NoPolicyConfigured(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "test.policy"))
	svc.SetContext(context.Background())

	policy, err := svc.GetPlatformPolicyAsPCRPolicy()
	assert.NoError(t, err)
	assert.Nil(t, policy)
}

func TestPlatformPolicy_Coverage_GetPlatformPolicyAsPCRPolicy_WithPolicy(t *testing.T) {
	mock := defaultPolicyMock()
	svc := newPolicyServiceWithMock(t, mock)

	_, err := svc.CreatePolicy([]int{0, 7}, "sha256")
	require.NoError(t, err)

	policy, err := svc.GetPlatformPolicyAsPCRPolicy()
	require.NoError(t, err)
	require.NotNil(t, policy)
	assert.Equal(t, "Platform Policy", policy.Name)
	assert.True(t, policy.IsPlatformPolicy)
	assert.Len(t, policy.PCRSelections, 2)
	assert.NotEmpty(t, policy.PCRDigests)
	assert.NotNil(t, policy.Valid)
	assert.True(t, *policy.Valid)
}

func TestPlatformPolicy_Coverage_GetPlatformPolicyAsPCRPolicy_NoTPM(t *testing.T) {
	// Create a service with policy loaded but no TPM for validation.
	policyPath := filepath.Join(t.TempDir(), "test.policy")
	svc := NewPlatformPolicyService(policyPath)
	svc.SetContext(context.Background())

	// Manually store a policy definition.
	now := time.Now()
	def := &PlatformPolicyDefinition{
		PCRs:      []int{0, 7},
		Bank:      "sha256",
		Digests:   map[int]string{0: "aabbccdd", 7: "11223344"},
		CreatedAt: now,
		UpdatedAt: now,
	}
	svc.policy.Store(def)

	policy, err := svc.GetPlatformPolicyAsPCRPolicy()
	require.NoError(t, err)
	require.NotNil(t, policy)
	assert.True(t, policy.IsPlatformPolicy)
	// Valid should be nil when TPM is unavailable (unknown state).
	assert.Nil(t, policy.Valid)
}

// ---------------------------------------------------------------------------
// RefreshPlatformPolicyPCRs
// ---------------------------------------------------------------------------

func TestPlatformPolicy_Coverage_RefreshPlatformPolicyPCRs_NoPolicyConfigured(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "test.policy"))
	svc.SetContext(context.Background())

	_, err := svc.RefreshPlatformPolicyPCRs()
	assert.ErrorIs(t, err, ErrPolicyNotConfigured)
}

func TestPlatformPolicy_Coverage_RefreshPlatformPolicyPCRs_Success(t *testing.T) {
	mock := defaultPolicyMock()
	svc := newPolicyServiceWithMock(t, mock)

	_, err := svc.CreatePolicy([]int{0, 7}, "sha256")
	require.NoError(t, err)

	policy, err := svc.RefreshPlatformPolicyPCRs()
	require.NoError(t, err)
	require.NotNil(t, policy)
	assert.True(t, policy.IsPlatformPolicy)
	assert.NotNil(t, policy.Valid)
	assert.True(t, *policy.Valid)
}

func TestPlatformPolicy_Coverage_RefreshPlatformPolicyPCRs_TPMError(t *testing.T) {
	mock := defaultPolicyMock()
	svc := newPolicyServiceWithMock(t, mock)

	_, err := svc.CreatePolicy([]int{0, 7}, "sha256")
	require.NoError(t, err)

	mock.pcrBanksErr = errors.New("tpm error")

	_, err = svc.RefreshPlatformPolicyPCRs()
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// VerifyPolicyRemote
// ---------------------------------------------------------------------------

func TestPlatformPolicy_Coverage_VerifyPolicyRemote_EmptyName(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "test.policy"))
	svc.SetContext(context.Background())

	_, err := svc.VerifyPolicyRemote("")
	assert.ErrorIs(t, err, ErrPolicyInvalidName)
}

func TestPlatformPolicy_Coverage_VerifyPolicyRemote_NoClient(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "test.policy"))
	svc.SetContext(context.Background())

	_, err := svc.VerifyPolicyRemote("my-policy")
	assert.ErrorIs(t, err, ErrPolicyNoClient)
}

func TestPlatformPolicy_Coverage_VerifyPolicyRemote_Success(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "test.policy"))
	svc.SetContext(context.Background())

	mc := &policyMockClient{
		policyVerifyFn: func(_ context.Context, req *transport.PolicyVerifyRequest) (*transport.PolicyVerifyResponse, error) {
			return &transport.PolicyVerifyResponse{
				Name:    req.Name,
				Valid:   true,
				Message: "policy verified",
			}, nil
		},
	}
	var c transport.Client = mc
	svc.SetClient(c)

	result, err := svc.VerifyPolicyRemote("my-policy")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "my-policy", result.Name)
	assert.True(t, result.Valid)
	assert.Equal(t, "policy verified", result.Message)
}

func TestPlatformPolicy_Coverage_VerifyPolicyRemote_ClientError(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "test.policy"))
	svc.SetContext(context.Background())

	verifyErr := errors.New("verify failed")
	mc := &policyMockClient{
		policyVerifyFn: func(_ context.Context, _ *transport.PolicyVerifyRequest) (*transport.PolicyVerifyResponse, error) {
			return nil, verifyErr
		},
	}
	var c transport.Client = mc
	svc.SetClient(c)

	_, err := svc.VerifyPolicyRemote("my-policy")
	assert.ErrorIs(t, err, verifyErr)
}

// ---------------------------------------------------------------------------
// ExportPolicyRemote
// ---------------------------------------------------------------------------

func TestPlatformPolicy_Coverage_ExportPolicyRemote_EmptyName(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "test.policy"))
	svc.SetContext(context.Background())

	_, err := svc.ExportPolicyRemote("")
	assert.ErrorIs(t, err, ErrPolicyInvalidName)
}

func TestPlatformPolicy_Coverage_ExportPolicyRemote_NoClient(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "test.policy"))
	svc.SetContext(context.Background())

	_, err := svc.ExportPolicyRemote("my-policy")
	assert.ErrorIs(t, err, ErrPolicyNoClient)
}

func TestPlatformPolicy_Coverage_ExportPolicyRemote_Success(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "test.policy"))
	svc.SetContext(context.Background())

	mc := &policyMockClient{
		policyExportFn: func(_ context.Context, req *transport.PolicyExportRequest) (*transport.PolicyExportResponse, error) {
			return &transport.PolicyExportResponse{
				Data: `{"name":"` + req.Name + `","pcr_bank":"sha256"}`,
			}, nil
		},
	}
	var c transport.Client = mc
	svc.SetClient(c)

	data, err := svc.ExportPolicyRemote("my-policy")
	require.NoError(t, err)
	assert.Contains(t, data, "my-policy")
	assert.Contains(t, data, "sha256")
}

func TestPlatformPolicy_Coverage_ExportPolicyRemote_ClientError(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "test.policy"))
	svc.SetContext(context.Background())

	exportErr := errors.New("export failed")
	mc := &policyMockClient{
		policyExportFn: func(_ context.Context, _ *transport.PolicyExportRequest) (*transport.PolicyExportResponse, error) {
			return nil, exportErr
		},
	}
	var c transport.Client = mc
	svc.SetClient(c)

	_, err := svc.ExportPolicyRemote("my-policy")
	assert.ErrorIs(t, err, exportErr)
}

// ---------------------------------------------------------------------------
// normalizeBankAlg
// ---------------------------------------------------------------------------

func TestPlatformPolicy_Coverage_NormalizeBankAlg(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"SHA256", "sha256"},
		{"sha256", "sha256"},
		{"SHA386", "sha384"}, // special case
		{"sha386", "sha384"}, // special case lowercase
		{"SHA384", "sha384"},
		{"sha1", "sha1"},
		{"SHA512", "sha512"},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			assert.Equal(t, tc.expected, normalizeBankAlg(tc.input))
		})
	}
}

// ---------------------------------------------------------------------------
// validatePCRSelection / validatePCRBank
// ---------------------------------------------------------------------------

func TestPlatformPolicy_Coverage_ValidatePCRSelection(t *testing.T) {
	tests := []struct {
		name    string
		pcrs    []int
		wantErr error
	}{
		{"valid single", []int{0}, nil},
		{"valid range", []int{0, 1, 7, 23}, nil},
		{"empty", nil, ErrPolicyInvalidPCRs},
		{"empty slice", []int{}, ErrPolicyInvalidPCRs},
		{"negative", []int{-1}, ErrPolicyInvalidPCRs},
		{"too high", []int{24}, ErrPolicyInvalidPCRs},
		{"mixed valid and invalid", []int{0, 24}, ErrPolicyInvalidPCRs},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validatePCRSelection(tc.pcrs)
			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestPlatformPolicy_Coverage_ValidatePCRBank(t *testing.T) {
	tests := []struct {
		bank    string
		wantErr error
	}{
		{"sha1", nil},
		{"sha256", nil},
		{"sha384", nil},
		{"sha512", nil},
		{"md5", ErrPolicyInvalidBank},
		{"SHA256", ErrPolicyInvalidBank}, // case-sensitive
		{"", ErrPolicyInvalidBank},
	}
	for _, tc := range tests {
		t.Run(tc.bank, func(t *testing.T) {
			err := validatePCRBank(tc.bank)
			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// validatePlatformPolicyDigests
// ---------------------------------------------------------------------------

func TestPlatformPolicy_Coverage_ValidatePlatformPolicyDigests_EmptyDigests(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "test.policy"))
	svc.SetContext(context.Background())

	def := &PlatformPolicyDefinition{
		PCRs:    []int{0},
		Bank:    "sha256",
		Digests: nil, // empty
	}

	result := svc.validatePlatformPolicyDigests(def)
	assert.Nil(t, result) // unknown validity
}

func TestPlatformPolicy_Coverage_ValidatePlatformPolicyDigests_TPMUnavailable(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "test.policy"))
	svc.SetContext(context.Background())
	// No TPM accessor set.

	def := &PlatformPolicyDefinition{
		PCRs:    []int{0},
		Bank:    "sha256",
		Digests: map[int]string{0: "aabbccdd"},
	}

	result := svc.validatePlatformPolicyDigests(def)
	assert.Nil(t, result) // TPM unavailable, unknown validity
}

func TestPlatformPolicy_Coverage_ValidatePlatformPolicyDigests_Valid(t *testing.T) {
	mock := defaultPolicyMock()
	svc := newPolicyServiceWithMock(t, mock)

	// Create a policy and then validate its digests.
	_, err := svc.CreatePolicy([]int{0, 7}, "sha256")
	require.NoError(t, err)

	def := svc.policy.Load()
	require.NotNil(t, def)

	result := svc.validatePlatformPolicyDigests(def)
	require.NotNil(t, result)
	assert.True(t, *result)
}

// ---------------------------------------------------------------------------
// definitionToPCRPolicy
// ---------------------------------------------------------------------------

func TestPlatformPolicy_Coverage_DefinitionToPCRPolicy(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "test.policy"))

	now := time.Now()
	def := &PlatformPolicyDefinition{
		PCRs:      []int{0, 7},
		Bank:      "sha256",
		Digests:   map[int]string{0: "aabb", 7: "ccdd"},
		CreatedAt: now,
		UpdatedAt: now,
	}

	policy := svc.definitionToPCRPolicy(def)
	require.NotNil(t, policy)
	assert.Equal(t, "Platform Policy", policy.Name)
	assert.Equal(t, "Platform PCR-based seal/unseal policy", policy.Description)
	assert.True(t, policy.IsPlatformPolicy)
	assert.Len(t, policy.PCRSelections, 2)
	assert.Equal(t, 0, policy.PCRSelections[0].Index)
	assert.Equal(t, "sha256", policy.PCRSelections[0].Bank)
	assert.Equal(t, 7, policy.PCRSelections[1].Index)
	assert.Equal(t, "aabb", policy.PCRDigests["sha256:0"])
	assert.Equal(t, "ccdd", policy.PCRDigests["sha256:7"])
}

// ---------------------------------------------------------------------------
// savePolicy
// ---------------------------------------------------------------------------

func TestPlatformPolicy_Coverage_SavePolicy_Success(t *testing.T) {
	policyPath := filepath.Join(t.TempDir(), "test.policy")
	svc := NewPlatformPolicyService(policyPath)

	now := time.Now()
	def := &PlatformPolicyDefinition{
		PCRs:      []int{0},
		Bank:      "sha256",
		Digests:   map[int]string{0: "aabb"},
		CreatedAt: now,
		UpdatedAt: now,
	}

	err := svc.savePolicy(def)
	require.NoError(t, err)

	// Verify the file was written.
	data, readErr := os.ReadFile(policyPath)
	require.NoError(t, readErr)
	assert.Contains(t, string(data), "sha256")
}

func TestPlatformPolicy_Coverage_SavePolicy_InvalidDir(t *testing.T) {
	// Use a path that cannot be created.
	svc := NewPlatformPolicyService("/dev/null/impossible/path/test.policy")

	now := time.Now()
	def := &PlatformPolicyDefinition{
		PCRs:      []int{0},
		Bank:      "sha256",
		Digests:   map[int]string{0: "aabb"},
		CreatedAt: now,
		UpdatedAt: now,
	}

	err := svc.savePolicy(def)
	assert.ErrorIs(t, err, ErrPolicySaveFailed)
}

// ---------------------------------------------------------------------------
// policyTypeMap validation
// ---------------------------------------------------------------------------

func TestPlatformPolicy_Coverage_PolicyTypeMap(t *testing.T) {
	tests := []struct {
		input    string
		expected PolicyType
		ok       bool
	}{
		{"none", PolicyTypeNone, true},
		{"password", PolicyTypePassword, true},
		{"platform_policy", PolicyTypePlatformPolicy, true},
		{"custom_pcr", PolicyTypeCustomPCR, true},
		{"invalid", "", false},
		{"", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got, ok := policyTypeMap[tc.input]
			assert.Equal(t, tc.ok, ok)
			if ok {
				assert.Equal(t, tc.expected, got)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Error sentinel uniqueness
// ---------------------------------------------------------------------------

func TestPlatformPolicy_Coverage_ErrorsUnique(t *testing.T) {
	errs := []error{
		ErrPolicyNotConfigured,
		ErrPolicyTPMNotAvailable,
		ErrPolicyInvalidPCRs,
		ErrPolicyInvalidBank,
		ErrPolicySaveFailed,
		ErrPolicyLoadFailed,
		ErrPolicyVerifyFailed,
		ErrPolicyExportFailed,
		ErrPolicyNoClient,
		ErrPolicyInvalidName,
	}
	seen := make(map[string]bool)
	for _, err := range errs {
		msg := err.Error()
		assert.False(t, seen[msg], "duplicate error message: %s", msg)
		seen[msg] = true
		assert.NotEmpty(t, msg)
	}
}
