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
	"path/filepath"
	"testing"

	tpm2pkg "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// policyMockTPM embeds mockTPM and provides configurable ReadPCRs.
type policyMockTPM struct {
	mockTPM
	pcrBanksOverride []tpm2pkg.PCRBank
	pcrBanksErr      error
}

func (m *policyMockTPM) ReadPCRs(_ []uint) ([]tpm2pkg.PCRBank, error) {
	return m.pcrBanksOverride, m.pcrBanksErr
}

// defaultPolicyMock returns a policyMockTPM with SHA256 PCR values for
// PCR 0 and PCR 7.
func defaultPolicyMock() *policyMockTPM {
	return &policyMockTPM{
		mockTPM: *defaultMockTPM(),
		pcrBanksOverride: []tpm2pkg.PCRBank{
			{
				Algorithm: "SHA256",
				PCRs: []tpm2pkg.PCR{
					{ID: 0, Value: []byte{0xAA, 0xBB, 0xCC, 0xDD}},
					{ID: 7, Value: []byte{0x11, 0x22, 0x33, 0x44}},
				},
			},
		},
	}
}

// newPolicyServiceWithMock creates a PlatformPolicyService wired to the given
// mock via a shared TPMAccessor.
func newPolicyServiceWithMock(t *testing.T, mock *policyMockTPM) *PlatformPolicyService {
	t.Helper()
	policyPath := filepath.Join(t.TempDir(), "platform.policy")
	svc := NewPlatformPolicyService(policyPath)
	svc.SetTPMAccessor(NewTPMAccessor(func() tpm2pkg.TrustedPlatformModule { return mock }))
	svc.SetContext(context.Background())
	return svc
}

// ---------------------------------------------------------------------------
// Constructor & lifecycle
// ---------------------------------------------------------------------------

func TestNewPlatformPolicyService(t *testing.T) {
	svc := NewPlatformPolicyService("/tmp/test.policy")
	require.NotNil(t, svc)
	assert.NotNil(t, svc.log)
	assert.Equal(t, "/tmp/test.policy", svc.policyPath)
}

func TestPlatformPolicyService_SetContext(t *testing.T) {
	svc := NewPlatformPolicyService("/tmp/test.policy")
	ctx := context.Background()
	svc.SetContext(ctx)
	assert.Equal(t, ctx, svc.ctx)
}

func TestPlatformPolicyService_SetTPMAccessor(t *testing.T) {
	svc := NewPlatformPolicyService("/tmp/test.policy")
	called := false
	svc.SetTPMAccessor(NewTPMAccessor(func() tpm2pkg.TrustedPlatformModule {
		called = true
		return nil
	}))
	_, err := svc.getTPM()
	assert.True(t, called)
	assert.ErrorIs(t, err, ErrPolicyTPMNotAvailable)
}

func TestPlatformPolicyService_getTPM_NilAccessor(t *testing.T) {
	svc := NewPlatformPolicyService("/tmp/test.policy")
	_, err := svc.getTPM()
	assert.ErrorIs(t, err, ErrPolicyTPMNotAvailable)
}

func TestPlatformPolicyService_getTPM_FuncReturnsNil(t *testing.T) {
	svc := NewPlatformPolicyService("/tmp/test.policy")
	svc.SetTPMAccessor(NewTPMAccessor(func() tpm2pkg.TrustedPlatformModule { return nil }))
	_, err := svc.getTPM()
	assert.ErrorIs(t, err, ErrPolicyTPMNotAvailable)
}
