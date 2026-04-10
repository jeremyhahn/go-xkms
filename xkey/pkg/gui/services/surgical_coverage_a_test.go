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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/pin"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	tpm2pkg "github.com/jeremyhahn/go-xkms/pkg/tpm2"
)

// ---------------------------------------------------------------------------
// Mocks (prefixed sa to avoid conflicts)
// ---------------------------------------------------------------------------

// saPanicPINBackend panics on every method to trigger panic recovery paths.
type saPanicPINBackend struct {
	mockPINBackend
}

func (m *saPanicPINBackend) Strategy() pin.StrategyID   { panic("saPanic: Strategy") }
func (m *saPanicPINBackend) SOPINSet() bool             { panic("saPanic: SOPINSet") }
func (m *saPanicPINBackend) UserPINSet() bool           { panic("saPanic: UserPINSet") }
func (m *saPanicPINBackend) IsInitialized() bool        { panic("saPanic: IsInitialized") }
func (m *saPanicPINBackend) SetSOPIN(_, _ string) error { panic("saPanic: SetSOPIN") }
func (m *saPanicPINBackend) SetUserPIN(_, _ string) error {
	panic("saPanic: SetUserPIN")
}
func (m *saPanicPINBackend) ChangeSOPIN(_, _ string) error {
	panic("saPanic: ChangeSOPIN")
}
func (m *saPanicPINBackend) ChangeUserPIN(_, _ string) error {
	panic("saPanic: ChangeUserPIN")
}
func (m *saPanicPINBackend) VerifyUserPIN(_ string) error {
	panic("saPanic: VerifyUserPIN")
}
func (m *saPanicPINBackend) VerifySOPIN(_ string) error {
	panic("saPanic: VerifySOPIN")
}
func (m *saPanicPINBackend) GetLockoutStatus() *pin.LockoutStatus {
	panic("saPanic: GetLockoutStatus")
}
func (m *saPanicPINBackend) ResetLockout(_ string) error {
	panic("saPanic: ResetLockout")
}
func (m *saPanicPINBackend) SetMaxAttempts(_ int) {
	panic("saPanic: SetMaxAttempts")
}

// saPanicTPM panics on ReadPCRs to trigger panic recovery in readPCRDigests
// and verifyDigests.
type saPanicTPM struct {
	mockTPM
	pcrBanksOverride []tpm2pkg.PCRBank
	pcrBanksErr      error
}

func (m *saPanicTPM) ReadPCRs(_ []uint) ([]tpm2pkg.PCRBank, error) {
	panic("saPanic: ReadPCRs")
}

// saSealer holds configuration for seal service tests. Converted to an
// SDK sealMockClient via saWireSealClient.
type saSealer struct {
	canSeal   bool
	sealErr   error
	unsealErr error
	sealData  *types.SealedData
}

// saWireSealClient wires a sealMockClient into the given SealService,
// deriving SDK client behavior from the saSealer configuration.
func saWireSealClient(svc *SealService, s *saSealer) {
	mc := &sealMockClient{
		sealFn: func(_ context.Context, req *transport.SealRequest) (*transport.SealResponse, error) {
			if s.sealErr != nil {
				return nil, s.sealErr
			}
			ciphertext := req.Data
			if s.sealData != nil {
				ciphertext = s.sealData.Ciphertext
			}
			return &transport.SealResponse{
				Backend:    req.Backend,
				Ciphertext: ciphertext,
				TPMPublic:  []byte("tpm-public"),
				TPMPrivate: []byte("tpm-private"),
			}, nil
		},
		unsealFn: func(_ context.Context, req *transport.UnsealRequest) (*transport.UnsealResponse, error) {
			if s.unsealErr != nil {
				return nil, s.unsealErr
			}
			return &transport.UnsealResponse{Plaintext: req.Ciphertext}, nil
		},
		canSealFn: func(_ context.Context, backend string) (*transport.CanSealResponse, error) {
			return &transport.CanSealResponse{CanSeal: s.canSeal, Backend: backend}, nil
		},
	}
	svc.SetClientFunc(func() xkms.Client { return mc })
}

// saWirePanicClient wires a sealMockClient that panics on all operations,
// used to test panic recovery in SealService methods.
func saWirePanicClient(svc *SealService) {
	mc := &sealMockClient{
		sealFn: func(_ context.Context, _ *transport.SealRequest) (*transport.SealResponse, error) {
			panic("saPanic: Seal")
		},
		unsealFn: func(_ context.Context, _ *transport.UnsealRequest) (*transport.UnsealResponse, error) {
			panic("saPanic: Unseal")
		},
		canSealFn: func(_ context.Context, _ string) (*transport.CanSealResponse, error) {
			panic("saPanic: CanSeal")
		},
	}
	svc.SetClientFunc(func() xkms.Client { return mc })
}

// TestSA_PlatformPolicy_GetStatus_InnerRecovery covers L172-176 indirectly:
// When readPCRDigests catches its own panic, GetStatus receives an error from
// verifyDigests and returns a status with Valid=false (not a panic).
// The outer panic recovery defer (L171-177) still executes on normal return
// but recover() returns nil, so the panic branch is not taken.
func TestSA_PlatformPolicy_GetStatus_InnerRecovery(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "p.json"))
	svc.SetTPMAccessor(NewTPMAccessor(func() tpm2pkg.TrustedPlatformModule {
		return &saPanicTPM{mockTPM: *defaultMockTPM()}
	}))
	svc.SetContext(context.Background())

	// Store a policy that triggers readPCRDigests -> ReadPCRs -> panic
	// inside verifyDigests, called by GetStatus.
	svc.policy.Store(&PlatformPolicyDefinition{
		PCRs:      []int{0},
		Bank:      "sha256",
		Digests:   map[int]string{0: "aabb"},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})

	// The inner readPCRDigests has its own panic recovery (L564-569) that
	// catches the ReadPCRs panic and returns an error. verifyDigests then
	// returns (false, err), and GetStatus returns Valid=false.
	status, err := svc.GetStatus()
	assert.NoError(t, err)
	assert.NotNil(t, status)
	assert.True(t, status.Configured)
	assert.False(t, status.Valid)
}

// TestSA_PlatformPolicy_CreatePolicy_InnerRecovery covers L200-204 indirectly:
// CreatePolicy calls readPCRDigests which has its own panic recovery. The panic
// in ReadPCRs is caught internally and returned as an error to CreatePolicy.
func TestSA_PlatformPolicy_CreatePolicy_InnerRecovery(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "p.json"))
	svc.SetTPMAccessor(NewTPMAccessor(func() tpm2pkg.TrustedPlatformModule {
		return &saPanicTPM{mockTPM: *defaultMockTPM()}
	}))
	svc.SetContext(context.Background())

	status, err := svc.CreatePolicy([]int{0}, "sha256")
	assert.Nil(t, status)
	assert.Error(t, err)
	// Error comes from readPCRDigests' own recovery, not CreatePolicy's.
	assert.Contains(t, err.Error(), "panic in readPCRDigests")
}

// TestSA_PlatformPolicy_CreatePolicy_SaveFails covers L228-230:
// CreatePolicy returns error when savePolicy fails.
func TestSA_PlatformPolicy_CreatePolicy_SaveFails(t *testing.T) {
	// Use an unwritable directory for the policy path.
	dir := t.TempDir()
	unwritable := filepath.Join(dir, "noperm")
	require.NoError(t, os.MkdirAll(unwritable, 0500))
	policyPath := filepath.Join(unwritable, "subdir", "policy.json")

	svc := NewPlatformPolicyService(policyPath)
	svc.SetTPMAccessor(NewTPMAccessor(func() tpm2pkg.TrustedPlatformModule {
		return &policyMockTPM{
			mockTPM: *defaultMockTPM(),
			pcrBanksOverride: []tpm2pkg.PCRBank{
				{Algorithm: "SHA256", PCRs: []tpm2pkg.PCR{{ID: 0, Value: []byte{0xAA}}}},
			},
		}
	}))
	svc.SetContext(context.Background())

	status, err := svc.CreatePolicy([]int{0}, "sha256")
	assert.Nil(t, status)
	assert.ErrorIs(t, err, ErrPolicySaveFailed)
}

// TestSA_PlatformPolicy_UpdatePolicy_InnerRecovery covers L248-252 indirectly:
// UpdatePolicy calls readPCRDigests which catches its own panic.
func TestSA_PlatformPolicy_UpdatePolicy_InnerRecovery(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "p.json"))
	svc.SetTPMAccessor(NewTPMAccessor(func() tpm2pkg.TrustedPlatformModule {
		return &saPanicTPM{mockTPM: *defaultMockTPM()}
	}))
	svc.SetContext(context.Background())

	// Must have existing policy for UpdatePolicy to proceed past nil check.
	svc.policy.Store(&PlatformPolicyDefinition{
		PCRs: []int{0}, Bank: "sha256",
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})

	status, err := svc.UpdatePolicy([]int{0}, "sha256")
	assert.Nil(t, status)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "panic in readPCRDigests")
}

// TestSA_PlatformPolicy_UpdatePolicy_SaveFails covers L280-282:
// UpdatePolicy returns error when savePolicy fails.
func TestSA_PlatformPolicy_UpdatePolicy_SaveFails(t *testing.T) {
	dir := t.TempDir()
	unwritable := filepath.Join(dir, "noperm")
	require.NoError(t, os.MkdirAll(unwritable, 0500))
	policyPath := filepath.Join(unwritable, "subdir", "policy.json")

	svc := NewPlatformPolicyService(policyPath)
	svc.SetTPMAccessor(NewTPMAccessor(func() tpm2pkg.TrustedPlatformModule {
		return &policyMockTPM{
			mockTPM: *defaultMockTPM(),
			pcrBanksOverride: []tpm2pkg.PCRBank{
				{Algorithm: "SHA256", PCRs: []tpm2pkg.PCR{{ID: 0, Value: []byte{0xAA}}}},
			},
		}
	}))
	svc.SetContext(context.Background())

	svc.policy.Store(&PlatformPolicyDefinition{
		PCRs: []int{0}, Bank: "sha256",
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})

	status, err := svc.UpdatePolicy([]int{0}, "sha256")
	assert.Nil(t, status)
	assert.ErrorIs(t, err, ErrPolicySaveFailed)
}

// TestSA_PlatformPolicy_DeletePolicy_RemoveError covers L305-307:
// DeletePolicy returns ErrPolicySaveFailed when os.Remove fails (not ENOENT).
func TestSA_PlatformPolicy_DeletePolicy_RemoveError(t *testing.T) {
	dir := t.TempDir()
	// Create a directory at the policy path; os.Remove on a non-empty
	// directory fails with a non-ENOENT error.
	policyPath := filepath.Join(dir, "policy.json")
	require.NoError(t, os.Mkdir(policyPath, 0700))
	// Put a file inside so os.Remove on the directory fails.
	require.NoError(t, os.WriteFile(filepath.Join(policyPath, "blocker"), []byte("x"), 0600))

	svc := NewPlatformPolicyService(policyPath)
	svc.policy.Store(&PlatformPolicyDefinition{
		PCRs: []int{0}, Bank: "sha256",
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})

	err := svc.DeletePolicy()
	assert.ErrorIs(t, err, ErrPolicySaveFailed)
}

// TestSA_PlatformPolicy_VerifyPolicy_InnerRecovery covers L316-320 indirectly:
// VerifyPolicy calls verifyDigests which calls readPCRDigests, both with their
// own panic recovery. The inner recovery catches the TPM panic.
func TestSA_PlatformPolicy_VerifyPolicy_InnerRecovery(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "p.json"))
	svc.SetTPMAccessor(NewTPMAccessor(func() tpm2pkg.TrustedPlatformModule {
		return &saPanicTPM{mockTPM: *defaultMockTPM()}
	}))
	svc.SetContext(context.Background())

	svc.policy.Store(&PlatformPolicyDefinition{
		PCRs: []int{0}, Bank: "sha256",
		Digests:   map[int]string{0: "aabb"},
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})

	valid, err := svc.VerifyPolicy()
	assert.False(t, valid)
	assert.Error(t, err)
	// Error propagated from readPCRDigests' recovery through verifyDigests.
	assert.Contains(t, err.Error(), "panic in readPCRDigests")
}

// TestSA_PlatformPolicy_ExportPolicy_NormalPath covers L346-349 defer and L378-381:
// ExportPolicy defer block runs on every call (covering L345-350 defer registration).
// The panic recovery branch (L346-349) requires an actual panic in the function body
// which is unreachable with the current data types.
func TestSA_PlatformPolicy_ExportPolicy_NormalPath(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "p.json"))
	svc.SetContext(context.Background())

	svc.policy.Store(&PlatformPolicyDefinition{
		PCRs:      []int{0, 7},
		Bank:      "sha256",
		Digests:   map[int]string{0: "aabb", 7: "ccdd"},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})

	result, err := svc.ExportPolicy()
	require.NoError(t, err)
	assert.Contains(t, result, "Platform Policy")
	assert.Contains(t, result, "sha256")
}

// TestSA_PlatformPolicy_GetPlatformPolicyAsPCRPolicy_InnerRecovery covers L391-395:
// The inner recovery in verifyDigests catches the TPM panic. The outer function
// returns a policy with Valid=nil (unknown state).
func TestSA_PlatformPolicy_GetPlatformPolicyAsPCRPolicy_InnerRecovery(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "p.json"))
	svc.SetTPMAccessor(NewTPMAccessor(func() tpm2pkg.TrustedPlatformModule {
		return &saPanicTPM{mockTPM: *defaultMockTPM()}
	}))
	svc.SetContext(context.Background())

	// Store policy with digests to trigger verifyDigests -> readPCRDigests -> panic.
	svc.policy.Store(&PlatformPolicyDefinition{
		PCRs:      []int{0},
		Bank:      "sha256",
		Digests:   map[int]string{0: "aabb"},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})

	policy, err := svc.GetPlatformPolicyAsPCRPolicy()
	// The panic in readPCRDigests is caught by readPCRDigests' own recovery,
	// which returns an error. validatePlatformPolicyDigests returns nil
	// (unknown state). The outer function returns successfully.
	assert.NoError(t, err)
	assert.NotNil(t, policy)
	assert.Nil(t, policy.Valid) // TPM unavailable => validity unknown
}

// TestSA_PlatformPolicy_RefreshPlatformPolicyPCRs_InnerRecovery covers L416-420:
// readPCRDigests has its own panic recovery that catches the inner panic
// and returns an error. RefreshPlatformPolicyPCRs receives that error.
func TestSA_PlatformPolicy_RefreshPlatformPolicyPCRs_InnerRecovery(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "p.json"))
	svc.SetTPMAccessor(NewTPMAccessor(func() tpm2pkg.TrustedPlatformModule {
		return &saPanicTPM{mockTPM: *defaultMockTPM()}
	}))
	svc.SetContext(context.Background())

	svc.policy.Store(&PlatformPolicyDefinition{
		PCRs: []int{0}, Bank: "sha256",
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})

	policy, err := svc.RefreshPlatformPolicyPCRs()
	assert.Nil(t, policy)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "panic in readPCRDigests")
}

// TestSA_PlatformPolicy_RefreshPolicyPCRs_SaveFails covers L436-438:
// RefreshPlatformPolicyPCRs returns error when savePolicy fails.
func TestSA_PlatformPolicy_RefreshPolicyPCRs_SaveFails(t *testing.T) {
	dir := t.TempDir()
	unwritable := filepath.Join(dir, "noperm")
	require.NoError(t, os.MkdirAll(unwritable, 0500))
	policyPath := filepath.Join(unwritable, "subdir", "policy.json")

	svc := NewPlatformPolicyService(policyPath)
	svc.SetTPMAccessor(NewTPMAccessor(func() tpm2pkg.TrustedPlatformModule {
		return &policyMockTPM{
			mockTPM: *defaultMockTPM(),
			pcrBanksOverride: []tpm2pkg.PCRBank{
				{Algorithm: "SHA256", PCRs: []tpm2pkg.PCR{{ID: 0, Value: []byte{0xAA}}}},
			},
		}
	}))
	svc.SetContext(context.Background())

	svc.policy.Store(&PlatformPolicyDefinition{
		PCRs: []int{0}, Bank: "sha256",
		Digests:   map[int]string{0: "aa"},
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})

	policy, err := svc.RefreshPlatformPolicyPCRs()
	assert.Nil(t, policy)
	assert.ErrorIs(t, err, ErrPolicySaveFailed)
}

// TestSA_PlatformPolicy_ReadPCRDigests_Panic covers L565-569:
// Panic recovery in readPCRDigests.
func TestSA_PlatformPolicy_ReadPCRDigests_Panic(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "p.json"))
	svc.SetTPMAccessor(NewTPMAccessor(func() tpm2pkg.TrustedPlatformModule {
		return &saPanicTPM{mockTPM: *defaultMockTPM()}
	}))
	svc.SetContext(context.Background())

	digests, err := svc.readPCRDigests([]int{0}, "sha256")
	assert.Nil(t, digests)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "panic in readPCRDigests")
}

// TestSA_PlatformPolicy_VerifyDigests_Panic covers L615-619:
// Panic recovery in verifyDigests.
func TestSA_PlatformPolicy_VerifyDigests_Panic(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "p.json"))
	svc.SetTPMAccessor(NewTPMAccessor(func() tpm2pkg.TrustedPlatformModule {
		return &saPanicTPM{mockTPM: *defaultMockTPM()}
	}))
	svc.SetContext(context.Background())

	def := &PlatformPolicyDefinition{
		PCRs:    []int{0},
		Bank:    "sha256",
		Digests: map[int]string{0: "aabb"},
	}

	valid, err := svc.verifyDigests(def)
	assert.False(t, valid)
	assert.Error(t, err)
	// readPCRDigests catches its own panic and returns error;
	// verifyDigests passes that error through (not its own panic recovery).
	assert.Contains(t, err.Error(), "panic in readPCRDigests")
}

// TestSA_PlatformPolicy_VerifyDigests_BadStoredHex covers L633-635:
// verifyDigests returns ErrPolicyVerifyFailed when hex.DecodeString(storedHex) fails.
func TestSA_PlatformPolicy_VerifyDigests_BadStoredHex(t *testing.T) {
	svc := newPolicyServiceWithMock(t, defaultPolicyMock())

	def := &PlatformPolicyDefinition{
		PCRs:    []int{0},
		Bank:    "sha256",
		Digests: map[int]string{0: "not-valid-hex!!"},
	}

	valid, err := svc.verifyDigests(def)
	assert.False(t, valid)
	assert.ErrorIs(t, err, ErrPolicyVerifyFailed)
}

// TestSA_PlatformPolicy_VerifyDigests_PCRNotFound covers L629-630:
// verifyDigests returns (false, nil) when a stored PCR index is not in live data.
func TestSA_PlatformPolicy_VerifyDigests_PCRNotFound(t *testing.T) {
	mock := &policyMockTPM{
		mockTPM: *defaultMockTPM(),
		pcrBanksOverride: []tpm2pkg.PCRBank{
			{
				Algorithm: "SHA256",
				// PCR 0 present but PCR 7 missing in live data
				PCRs: []tpm2pkg.PCR{
					{ID: 0, Value: []byte{0xAA, 0xBB}},
				},
			},
		},
	}
	svc := newPolicyServiceWithMock(t, mock)

	def := &PlatformPolicyDefinition{
		PCRs: []int{0, 7},
		Bank: "sha256",
		Digests: map[int]string{
			0: hex.EncodeToString([]byte{0xAA, 0xBB}),
			7: hex.EncodeToString([]byte{0x11, 0x22}), // PCR 7 not in live data
		},
	}

	valid, err := svc.verifyDigests(def)
	assert.False(t, valid)
	assert.NoError(t, err) // returns false, nil for missing PCR
}

// TestSA_PlatformPolicy_VerifyDigests_Match covers L642-647:
// verifyDigests returns (true, nil) when all stored and live digests match.
func TestSA_PlatformPolicy_VerifyDigests_Match(t *testing.T) {
	pcrValue := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	mock := &policyMockTPM{
		mockTPM: *defaultMockTPM(),
		pcrBanksOverride: []tpm2pkg.PCRBank{
			{
				Algorithm: "SHA256",
				PCRs: []tpm2pkg.PCR{
					{ID: 0, Value: pcrValue},
				},
			},
		},
	}
	svc := newPolicyServiceWithMock(t, mock)

	def := &PlatformPolicyDefinition{
		PCRs:    []int{0},
		Bank:    "sha256",
		Digests: map[int]string{0: hex.EncodeToString(pcrValue)},
	}

	valid, err := svc.verifyDigests(def)
	assert.True(t, valid)
	assert.NoError(t, err)
}

// TestSA_PlatformPolicy_VerifyDigests_Mismatch covers L642-643:
// verifyDigests returns (false, nil) when digests do not match.
func TestSA_PlatformPolicy_VerifyDigests_Mismatch(t *testing.T) {
	mock := &policyMockTPM{
		mockTPM: *defaultMockTPM(),
		pcrBanksOverride: []tpm2pkg.PCRBank{
			{
				Algorithm: "SHA256",
				PCRs: []tpm2pkg.PCR{
					{ID: 0, Value: []byte{0x11, 0x22}},
				},
			},
		},
	}
	svc := newPolicyServiceWithMock(t, mock)

	def := &PlatformPolicyDefinition{
		PCRs:    []int{0},
		Bank:    "sha256",
		Digests: map[int]string{0: hex.EncodeToString([]byte{0xFF, 0xEE})},
	}

	valid, err := svc.verifyDigests(def)
	assert.False(t, valid)
	assert.NoError(t, err)
}

// TestSA_PlatformPolicy_SavePolicy_Success covers savePolicy normal path.
func TestSA_PlatformPolicy_SavePolicy_Success(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "test.policy")
	svc := NewPlatformPolicyService(policyPath)

	def := &PlatformPolicyDefinition{
		PCRs:      []int{0, 7},
		Bank:      "sha256",
		Digests:   map[int]string{0: "aa", 7: "bb"},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	err := svc.savePolicy(def)
	assert.NoError(t, err)

	// Verify file was written.
	data, readErr := os.ReadFile(policyPath)
	require.NoError(t, readErr)
	assert.Contains(t, string(data), "sha256")
}

// TestSA_PlatformPolicy_SavePolicy_WriteFileFail covers L664-666:
// savePolicy returns ErrPolicySaveFailed when os.WriteFile fails.
func TestSA_PlatformPolicy_SavePolicy_WriteFileFail(t *testing.T) {
	dir := t.TempDir()
	// Create the parent directory as read-only so WriteFile fails.
	subdir := filepath.Join(dir, "readonly")
	require.NoError(t, os.MkdirAll(subdir, 0700))
	policyPath := filepath.Join(subdir, "test.policy")

	svc := NewPlatformPolicyService(policyPath)

	// Make the directory read-only AFTER the service is created.
	require.NoError(t, os.Chmod(subdir, 0500))
	t.Cleanup(func() { os.Chmod(subdir, 0700) })

	def := &PlatformPolicyDefinition{
		PCRs:      []int{0},
		Bank:      "sha256",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	err := svc.savePolicy(def)
	assert.ErrorIs(t, err, ErrPolicySaveFailed)
}

// TestSA_PlatformPolicy_SavePolicy_RenameSuccess covers L668-670:
// Verify the full save flow including rename.
func TestSA_PlatformPolicy_SavePolicy_RenameSuccess(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "test.policy")
	svc := NewPlatformPolicyService(policyPath)

	def := &PlatformPolicyDefinition{
		PCRs:      []int{0, 7},
		Bank:      "sha256",
		Digests:   map[int]string{0: "aa", 7: "bb"},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	require.NoError(t, svc.savePolicy(def))
	// Verify the file exists (the rename succeeded).
	_, err := os.Stat(policyPath)
	assert.NoError(t, err)
}

// =========================================================================
// pin_service.go tests
// =========================================================================

// TestSA_PINService_GetPINStatus_Panic covers L79-83:
// Panic recovery in GetPINStatus.
func TestSA_PINService_GetPINStatus_Panic(t *testing.T) {
	svc := NewPINService()
	svc.SetContext(context.Background())
	mgr := &saPanicPINBackend{}
	pSvc := pin.NewService(mgr, slog.Default())
	svc.SetPINService(pSvc)

	result, err := svc.GetPINStatus()
	assert.Nil(t, result)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "panic in GetPINStatus")
}

// TestSA_PINService_SetSOPIN_Panic covers L102-105:
// Panic recovery in SetSOPIN.
func TestSA_PINService_SetSOPIN_Panic(t *testing.T) {
	svc := NewPINService()
	svc.SetContext(context.Background())
	pSvc := pin.NewService(&saPanicPINBackend{}, slog.Default())
	svc.SetPINService(pSvc)

	err := svc.SetSOPIN("old-pin-123", "new-pin-456")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "panic in SetSOPIN")
}

// TestSA_PINService_SetUserPIN_Panic covers L119-122:
// Panic recovery in SetUserPIN.
func TestSA_PINService_SetUserPIN_Panic(t *testing.T) {
	svc := NewPINService()
	svc.SetContext(context.Background())
	pSvc := pin.NewService(&saPanicPINBackend{}, slog.Default())
	svc.SetPINService(pSvc)

	err := svc.SetUserPIN("so-pin-123", "user-pin-456")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "panic in SetUserPIN")
}

// TestSA_PINService_VerifyUserPIN_Panic covers L200-203:
// Panic recovery in VerifyUserPIN.
func TestSA_PINService_VerifyUserPIN_Panic(t *testing.T) {
	svc := NewPINService()
	svc.SetContext(context.Background())
	pSvc := pin.NewService(&saPanicPINBackend{}, slog.Default())
	svc.SetPINService(pSvc)

	err := svc.VerifyUserPIN("pin")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "panic in VerifyUserPIN")
}

// TestSA_PINService_VerifySOPIN_Panic covers L217-220:
// Panic recovery in VerifySOPIN.
func TestSA_PINService_VerifySOPIN_Panic(t *testing.T) {
	svc := NewPINService()
	svc.SetContext(context.Background())
	pSvc := pin.NewService(&saPanicPINBackend{}, slog.Default())
	svc.SetPINService(pSvc)

	err := svc.VerifySOPIN("pin")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "panic in VerifySOPIN")
}

// TestSA_PINService_GetLockoutStatus_Panic covers L234-238:
// Panic recovery in GetLockoutStatus.
func TestSA_PINService_GetLockoutStatus_Panic(t *testing.T) {
	svc := NewPINService()
	svc.SetContext(context.Background())
	pSvc := pin.NewService(&saPanicPINBackend{}, slog.Default())
	svc.SetPINService(pSvc)

	result, err := svc.GetLockoutStatus()
	assert.Nil(t, result)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "panic in GetLockoutStatus")
}

// TestSA_PINService_ResetLockout_Panic covers L252-255:
// Panic recovery in ResetLockout.
func TestSA_PINService_ResetLockout_Panic(t *testing.T) {
	svc := NewPINService()
	svc.SetContext(context.Background())
	pSvc := pin.NewService(&saPanicPINBackend{}, slog.Default())
	svc.SetPINService(pSvc)

	err := svc.ResetLockout("so-pin")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "panic in ResetLockout")
}

// =========================================================================
// seal_service.go tests
// =========================================================================

// TestSA_SealService_CanSeal_Panic covers L264-269:
// Panic recovery in CanSeal. The CanSeal panic recovery only logs; it does
// not set return values, so the zero values (false, nil) are returned.
func TestSA_SealService_CanSeal_Panic(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetContext(context.Background())
	saWirePanicClient(svc)

	result, err := svc.CanSeal()
	// The panic is recovered; the function returns its zero values.
	assert.False(t, result)
	assert.NoError(t, err)
}

// TestSA_SealService_ListBlobs_Empty covers L284-290 defer registration:
// ListBlobs with empty storage directory runs through the defer.
func TestSA_SealService_ListBlobs_Empty(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetContext(context.Background())

	entries, err := svc.ListBlobs()
	assert.NoError(t, err)
	assert.Empty(t, entries)
}

// TestSA_SealService_ListBlobs_ReadDirFail covers L301-303:
// ListBlobs returns empty when os.ReadDir fails.
func TestSA_SealService_ListBlobs_ReadDirFail(t *testing.T) {
	dir := t.TempDir()
	svc := NewSealService(dir)
	svc.SetContext(context.Background())

	// Remove the storage dir so ReadDir fails.
	require.NoError(t, os.RemoveAll(dir))

	entries, err := svc.ListBlobs()
	assert.NoError(t, err)
	assert.Empty(t, entries)
}

// TestSA_SealService_ListBlobs_WithBlobs covers L306-345:
// ListBlobs iterates directory, loads blobs, classifies categories, sorts by time.
func TestSA_SealService_ListBlobs_WithBlobs(t *testing.T) {
	dir := t.TempDir()
	svc := NewSealService(dir)
	svc.SetContext(context.Background())

	now := time.Now()

	// Create two blobs with different timestamps.
	blob1 := &sealedBlobStorage{
		ID:         "blob-older",
		Label:      "user_pin", // user category (deletable from UI)
		SizeBytes:  100,
		PolicyType: "password",
		SealedData: &types.SealedData{Backend: types.BackendTypeTPM2, Ciphertext: []byte("a")},
		CreatedAt:  now.Add(-1 * time.Hour),
	}
	blob2 := &sealedBlobStorage{
		ID:         "blob-newer",
		Label:      "my-secret", // user category, no PolicyType (defaults to "none")
		SizeBytes:  200,
		SealedData: &types.SealedData{Backend: types.BackendTypeTPM2, Ciphertext: []byte("b")},
		CreatedAt:  now,
	}

	for _, blob := range []*sealedBlobStorage{blob1, blob2} {
		data, err := json.Marshal(blob)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(
			filepath.Join(dir, blob.ID+".sealed.json"), data, 0600,
		))
	}

	// Create a non-JSON file (should be skipped at L307).
	require.NoError(t, os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("skip me"), 0600))

	// Create a subdirectory (should be skipped at L307).
	require.NoError(t, os.Mkdir(filepath.Join(dir, "subdir.json"), 0700))

	// Create a corrupted JSON file (loadBlob fails, logged at L312-313).
	require.NoError(t, os.WriteFile(filepath.Join(dir, "corrupted.json"), []byte("{invalid"), 0600))

	entries, err := svc.ListBlobs()
	require.NoError(t, err)
	require.Len(t, entries, 2)

	// Sorted newest first.
	assert.Equal(t, "blob-newer", entries[0].ID)
	assert.Equal(t, "blob-older", entries[1].ID)

	// Category defaults.
	assert.Equal(t, "user", entries[0].Category)   // "my-secret" => user
	assert.Equal(t, "user", entries[1].Category)   // "user_pin" => user (deletable from UI)
	assert.Equal(t, "none", entries[0].PolicyType) // empty => "none"
	assert.Equal(t, "password", entries[1].PolicyType)
}

// TestSA_SealService_SealData_Panic covers L353-357:
// Panic recovery in SealData.
func TestSA_SealService_SealData_Panic(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetContext(context.Background())
	saWirePanicClient(svc)

	req := &SealRequest{
		Label: "test",
		Data:  base64.StdEncoding.EncodeToString([]byte("hello")),
	}

	entry, err := svc.SealData(req)
	assert.Nil(t, entry)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "panic in SealData")
}

// TestSA_SealService_SealData_DecodeFail covers L363-366:
// SealData returns ErrSealDecodeFailed when base64 data is invalid.
func TestSA_SealService_SealData_DecodeFail(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetContext(context.Background())

	req := &SealRequest{
		Label: "test",
		Data:  "not-valid-base64!!!",
	}

	entry, err := svc.SealData(req)
	assert.Nil(t, entry)
	assert.ErrorIs(t, err, ErrSealDecodeFailed)
}

// TestSA_SealService_SealData_BackendNotFound covers L378-380:
// SealData returns ErrSealBackendNotFound when the backend is not registered.
func TestSA_SealService_SealData_BackendNotFound(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetContext(context.Background())
	// Don't register any sealers.
	// No SDK client configured, so SealData/UnsealData will return ErrSealBackendNotFound.

	req := &SealRequest{
		Label:   "test",
		Data:    base64.StdEncoding.EncodeToString([]byte("hello")),
		Backend: "nonexistent",
	}

	entry, err := svc.SealData(req)
	assert.Nil(t, entry)
	assert.ErrorIs(t, err, ErrSealBackendNotFound)
}

// TestSA_SealService_SealData_InvalidPolicyType covers L404-406:
// SealData returns ErrSealInvalidPolicyType for an unknown policy type.
func TestSA_SealService_SealData_InvalidPolicyType(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetContext(context.Background())
	saWireSealClient(svc, &saSealer{canSeal: true})

	req := &SealRequest{
		Label:      "test",
		Data:       base64.StdEncoding.EncodeToString([]byte("hello")),
		PolicyType: "totally-invalid-policy",
	}

	entry, err := svc.SealData(req)
	assert.Nil(t, entry)
	assert.ErrorIs(t, err, ErrSealInvalidPolicyType)
}

// TestSA_SealService_SealData_NilContext covers L412-413:
// SealData falls back to context.Background() when ctx is nil.
func TestSA_SealService_SealData_NilContext(t *testing.T) {
	svc := NewSealService(t.TempDir())
	// Intentionally do NOT call svc.SetContext() so ctx is nil.
	saWireSealClient(svc, &saSealer{canSeal: true})

	req := &SealRequest{
		Label: "test-nil-ctx",
		Data:  base64.StdEncoding.EncodeToString([]byte("data")),
	}

	entry, err := svc.SealData(req)
	require.NoError(t, err)
	assert.NotNil(t, entry)
	assert.Equal(t, "test-nil-ctx", entry.Label)
}

// TestSA_SealService_SealData_NormalSealPath covers the successful seal path.
func TestSA_SealService_SealData_NormalSealPath(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetContext(context.Background())
	saWireSealClient(svc, &saSealer{canSeal: true})

	req := &SealRequest{
		Label: "test-secret",
		Data:  base64.StdEncoding.EncodeToString([]byte("sensitive data")),
	}

	entry, err := svc.SealData(req)
	require.NoError(t, err)
	assert.NotNil(t, entry)
	assert.Equal(t, "test-secret", entry.Label)
	assert.Equal(t, "user", entry.Category)
}

// TestSA_SealService_SealData_PasswordPolicy covers password policy path.
func TestSA_SealService_SealData_PasswordPolicy(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetContext(context.Background())
	saWireSealClient(svc, &saSealer{canSeal: true})

	req := &SealRequest{
		Label:      "test-password",
		Data:       base64.StdEncoding.EncodeToString([]byte("secret")),
		PolicyType: "password",
		Password:   "my-strong-password",
	}

	entry, err := svc.SealData(req)
	require.NoError(t, err)
	assert.NotNil(t, entry)
	assert.Equal(t, "password", entry.PolicyType)
}

// TestSA_SealService_SealData_SaveBlobFail covers L453-455:
// SealData returns error when saveBlob fails (e.g., storage dir not writable).
func TestSA_SealService_SealData_SaveBlobFail(t *testing.T) {
	dir := t.TempDir()
	svc := NewSealService(dir)
	svc.SetContext(context.Background())
	saWireSealClient(svc, &saSealer{canSeal: true})

	// Make the storage directory read-only so saveBlob fails.
	require.NoError(t, os.Chmod(dir, 0500))
	t.Cleanup(func() { os.Chmod(dir, 0700) })

	req := &SealRequest{
		Label: "test",
		Data:  base64.StdEncoding.EncodeToString([]byte("hello")),
	}

	entry, err := svc.SealData(req)
	assert.Nil(t, entry)
	assert.Error(t, err)
}

// TestSA_SealService_SealData_LabelEmpty covers L360-361:
// SealData returns ErrSealInvalidLabel when label is empty.
func TestSA_SealService_SealData_LabelEmpty(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetContext(context.Background())

	entry, err := svc.SealData(&SealRequest{Label: "", Data: "aGVsbG8="})
	assert.Nil(t, entry)
	assert.ErrorIs(t, err, ErrSealInvalidLabel)
}

// TestSA_SealService_SealData_DataEmpty covers L363-365:
// SealData returns ErrSealInvalidData when data is empty.
func TestSA_SealService_SealData_DataEmpty(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetContext(context.Background())

	entry, err := svc.SealData(&SealRequest{Label: "test", Data: ""})
	assert.Nil(t, entry)
	assert.ErrorIs(t, err, ErrSealInvalidData)
}

// TestSA_SealService_SealData_NilRequest covers L360:
// SealData returns ErrSealInvalidLabel when request is nil.
func TestSA_SealService_SealData_NilRequest(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetContext(context.Background())

	entry, err := svc.SealData(nil)
	assert.Nil(t, entry)
	assert.ErrorIs(t, err, ErrSealInvalidLabel)
}

// TestSA_SealService_UnsealData_Panic covers L472-476:
// Panic recovery in UnsealData.
func TestSA_SealService_UnsealData_Panic(t *testing.T) {
	dir := t.TempDir()
	svc := NewSealService(dir)
	svc.SetContext(context.Background())
	saWirePanicClient(svc)

	// Create a blob file that can be loaded, so the unseal reaches the sealer.
	blob := &sealedBlobStorage{
		ID:    "test-blob-id",
		Label: "test",
		SealedData: &types.SealedData{
			Backend:    types.BackendTypeTPM2,
			Ciphertext: []byte("encrypted"),
		},
		CreatedAt: time.Now(),
	}
	data, err := json.Marshal(blob)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test-blob-id.sealed.json"), data, 0600))

	result, unsealErr := svc.UnsealData("test-blob-id", "")
	assert.Empty(t, result)
	assert.Error(t, unsealErr)
	assert.Contains(t, unsealErr.Error(), "panic in UnsealData")
}

// TestSA_SealService_DeleteBlob_RemoveFail covers L540-542:
// DeleteBlob returns ErrSealStorageFailed when os.Remove fails.
func TestSA_SealService_DeleteBlob_RemoveFail(t *testing.T) {
	dir := t.TempDir()
	svc := NewSealService(dir)
	svc.SetContext(context.Background())

	blobID := "test-remove-fail"
	blobPath := filepath.Join(dir, blobID+".sealed.json")

	// Create the blob as a directory (os.Remove on non-empty dir fails).
	require.NoError(t, os.Mkdir(blobPath, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(blobPath, "blocker"), []byte("x"), 0600))

	err := svc.DeleteBlob(blobID)
	assert.ErrorIs(t, err, ErrSealStorageFailed)
}

// TestSA_SealService_SaveBlob_StorageDirNotSet covers ensureStorageDir with empty dir.
func TestSA_SealService_SaveBlob_StorageDirNotSet(t *testing.T) {
	svc := NewSealService("") // empty storageDir
	svc.SetContext(context.Background())

	blob := &sealedBlobStorage{
		ID:    "test-id",
		Label: "test",
		SealedData: &types.SealedData{
			Backend:    types.BackendTypeTPM2,
			Ciphertext: []byte("data"),
		},
		CreatedAt: time.Now(),
	}

	err := svc.saveBlob(blob)
	assert.ErrorIs(t, err, ErrSealStorageFailed)
}

// TestSA_SealService_SaveBlob_WriteFileFail covers L578-580:
// saveBlob returns ErrSealStorageFailed when os.WriteFile fails.
func TestSA_SealService_SaveBlob_WriteFileFail(t *testing.T) {
	dir := t.TempDir()
	svc := NewSealService(dir)
	svc.SetContext(context.Background())

	// Make directory read-only so WriteFile fails.
	require.NoError(t, os.Chmod(dir, 0500))
	t.Cleanup(func() { os.Chmod(dir, 0700) })

	blob := &sealedBlobStorage{
		ID:    "test-id",
		Label: "test",
		SealedData: &types.SealedData{
			Backend:    types.BackendTypeTPM2,
			Ciphertext: []byte("data"),
		},
		CreatedAt: time.Now(),
	}

	err := svc.saveBlob(blob)
	assert.ErrorIs(t, err, ErrSealStorageFailed)
}

// TestSA_SealService_SaveBlob_Success covers the successful saveBlob path.
func TestSA_SealService_SaveBlob_Success(t *testing.T) {
	dir := t.TempDir()
	svc := NewSealService(dir)
	svc.SetContext(context.Background())

	blob := &sealedBlobStorage{
		ID:    "test-save",
		Label: "test",
		SealedData: &types.SealedData{
			Backend:    types.BackendTypeTPM2,
			Ciphertext: []byte("data"),
		},
		CreatedAt: time.Now(),
	}

	err := svc.saveBlob(blob)
	assert.NoError(t, err)

	// Verify the file exists.
	_, statErr := os.Stat(filepath.Join(dir, "test-save.sealed.json"))
	assert.NoError(t, statErr)
}

// TestSA_SealService_HandlePolicyPlatformPolicy_UnknownBank covers L637-639:
// handlePolicyPlatformPolicy falls back to SHA256 when bank is not in pcrBankAlgMap.
func TestSA_SealService_HandlePolicyPlatformPolicy_UnknownBank(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetContext(context.Background())

	// Create a PlatformPolicyService with an unusual bank name.
	ppSvc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "p.json"))
	ppSvc.policy.Store(&PlatformPolicyDefinition{
		PCRs:      []int{0},
		Bank:      "sm3", // not in pcrBankAlgMap, triggers fallback at L637-639
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})
	svc.SetPlatformPolicyService(ppSvc)

	req := &SealRequest{Label: "test", Data: base64.StdEncoding.EncodeToString([]byte("data"))}
	opts := &types.SealOptions{}

	err := handlePolicyPlatformPolicy(svc, req, opts)
	assert.NoError(t, err)
	assert.NotNil(t, opts.TPMPolicy)
}

// TestSA_SealService_HashPassword_Success covers L706-713:
// hashPassword returns valid hash.
func TestSA_SealService_HashPassword_Success(t *testing.T) {
	hash, err := hashPassword("test-password")
	require.NoError(t, err)
	assert.Contains(t, hash, ":")

	// Verify round-trip.
	assert.True(t, verifyPassword("test-password", hash))
	assert.False(t, verifyPassword("wrong-password", hash))
}

// TestSA_SealService_EnsureStorageDir_Relative covers ensureStorageDir relative path check.
func TestSA_SealService_EnsureStorageDir_Relative(t *testing.T) {
	svc := NewSealService("relative/path")
	err := svc.ensureStorageDir()
	assert.ErrorIs(t, err, ErrSealStorageDirRelative)
}

// TestSA_SealService_SealData_NotSupported covers sealer.CanSeal() == false.
func TestSA_SealService_SealData_NotSupported(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetContext(context.Background())
	saWireSealClient(svc, &saSealer{canSeal: false, sealErr: ErrSealNotSupported})

	req := &SealRequest{
		Label: "test",
		Data:  base64.StdEncoding.EncodeToString([]byte("hello")),
	}

	entry, err := svc.SealData(req)
	assert.Nil(t, entry)
	assert.ErrorIs(t, err, ErrSealNotSupported)
}

// TestSA_SealService_SealData_PolicyRequiresTPM covers TPM-only policy on non-TPM backend.
func TestSA_SealService_SealData_PolicyRequiresTPM(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetContext(context.Background())
	saWireSealClient(svc, &saSealer{canSeal: true})
	svc.SetDefaultBackend("software")

	req := &SealRequest{
		Label:      "test",
		Data:       base64.StdEncoding.EncodeToString([]byte("hello")),
		PolicyType: "platform_policy",
	}

	entry, err := svc.SealData(req)
	assert.Nil(t, entry)
	assert.ErrorIs(t, err, ErrSealPolicyRequiresTPM)
}

// TestSA_SealService_SealData_SealerError covers sealer.Seal returning error.
func TestSA_SealService_SealData_SealerError(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetContext(context.Background())
	errSeal := errors.New("sa: seal failed")
	saWireSealClient(svc, &saSealer{canSeal: true, sealErr: errSeal})

	req := &SealRequest{
		Label: "test",
		Data:  base64.StdEncoding.EncodeToString([]byte("hello")),
	}

	entry, err := svc.SealData(req)
	assert.Nil(t, entry)
	assert.ErrorIs(t, err, errSeal)
}

// TestSA_SealService_SealData_DefaultBackendFallback covers L374-376:
// SealData uses default backend when request doesn't specify one.
func TestSA_SealService_SealData_DefaultBackendFallback(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetContext(context.Background())
	saWireSealClient(svc, &saSealer{canSeal: true})
	svc.SetDefaultBackend("custom")

	req := &SealRequest{
		Label: "test-default",
		Data:  base64.StdEncoding.EncodeToString([]byte("hello")),
		// Backend intentionally empty to use default
	}

	entry, err := svc.SealData(req)
	require.NoError(t, err)
	assert.NotNil(t, entry)
}

// TestSA_SealService_SealData_ExplicitBackend covers L373:
// SealData uses explicitly provided backend.
func TestSA_SealService_SealData_ExplicitBackend(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetContext(context.Background())
	saWireSealClient(svc, &saSealer{canSeal: true})
	svc.SetDefaultBackend(string(types.BackendTypeTPM2)) // set a different default

	req := &SealRequest{
		Label:   "test-explicit",
		Data:    base64.StdEncoding.EncodeToString([]byte("hello")),
		Backend: "explicit-backend",
	}

	entry, err := svc.SealData(req)
	require.NoError(t, err)
	assert.NotNil(t, entry)
}

// TestSA_SealService_UnsealData_BackendNotFound covers unseal with unregistered backend.
func TestSA_SealService_UnsealData_BackendNotFound(t *testing.T) {
	dir := t.TempDir()
	svc := NewSealService(dir)
	svc.SetContext(context.Background())
	// Clear all sealers.
	// No SDK client configured, so SealData/UnsealData will return ErrSealBackendNotFound.

	blob := &sealedBlobStorage{
		ID:    "test-unseal-nobe",
		Label: "test",
		SealedData: &types.SealedData{
			Backend:    types.BackendType("nonexistent"),
			Ciphertext: []byte("data"),
		},
		CreatedAt: time.Now(),
	}
	data, err := json.Marshal(blob)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test-unseal-nobe.sealed.json"), data, 0600))

	result, unsealErr := svc.UnsealData("test-unseal-nobe", "")
	assert.Empty(t, result)
	assert.ErrorIs(t, unsealErr, ErrSealBackendNotFound)
}

// TestSA_SealService_UnsealData_Success covers the successful unseal path.
func TestSA_SealService_UnsealData_Success(t *testing.T) {
	dir := t.TempDir()
	svc := NewSealService(dir)
	svc.SetContext(context.Background())
	saWireSealClient(svc, &saSealer{canSeal: true})

	plaintext := []byte("sensitive-data-1234")
	blob := &sealedBlobStorage{
		ID:    "test-unseal-ok",
		Label: "test",
		SealedData: &types.SealedData{
			Backend:    types.BackendTypeTPM2,
			Ciphertext: plaintext,
		},
		CreatedAt: time.Now(),
	}
	data, err := json.Marshal(blob)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test-unseal-ok.sealed.json"), data, 0600))

	result, unsealErr := svc.UnsealData("test-unseal-ok", "")
	assert.NoError(t, unsealErr)
	decoded, decErr := base64.StdEncoding.DecodeString(result)
	require.NoError(t, decErr)
	assert.Equal(t, plaintext, decoded)
}

// TestSA_SealService_UnsealData_BlobNotFound covers unseal with missing blob.
func TestSA_SealService_UnsealData_BlobNotFound(t *testing.T) {
	dir := t.TempDir()
	svc := NewSealService(dir)
	svc.SetContext(context.Background())

	result, err := svc.UnsealData("nonexistent-blob", "")
	assert.Empty(t, result)
	assert.ErrorIs(t, err, ErrSealBlobNotFound)
}

// TestSA_SealService_SealData_PasswordRequired covers password policy with empty password.
func TestSA_SealService_SealData_PasswordRequired(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetContext(context.Background())
	saWireSealClient(svc, &saSealer{canSeal: true})

	req := &SealRequest{
		Label:      "test",
		Data:       base64.StdEncoding.EncodeToString([]byte("hello")),
		PolicyType: "password",
		Password:   "", // empty password
	}

	entry, err := svc.SealData(req)
	assert.Nil(t, entry)
	assert.ErrorIs(t, err, ErrSealPasswordRequired)
}

// TestSA_SealService_UnsealData_PasswordRequired covers unseal with password policy but no password.
func TestSA_SealService_UnsealData_PasswordRequired(t *testing.T) {
	dir := t.TempDir()
	svc := NewSealService(dir)
	svc.SetContext(context.Background())
	saWireSealClient(svc, &saSealer{canSeal: true})

	blob := &sealedBlobStorage{
		ID:         "test-pw-required",
		Label:      "test",
		PolicyType: string(PolicyTypePassword),
		Password:   "somehash:somevalue",
		SealedData: &types.SealedData{
			Backend:    types.BackendTypeTPM2,
			Ciphertext: []byte("data"),
		},
		CreatedAt: time.Now(),
	}
	data, err := json.Marshal(blob)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test-pw-required.sealed.json"), data, 0600))

	result, unsealErr := svc.UnsealData("test-pw-required", "")
	assert.Empty(t, result)
	assert.ErrorIs(t, unsealErr, ErrSealPasswordRequired)
}

// TestSA_SealService_UnsealData_PasswordMismatch covers unseal with wrong password.
func TestSA_SealService_UnsealData_PasswordMismatch(t *testing.T) {
	dir := t.TempDir()
	svc := NewSealService(dir)
	svc.SetContext(context.Background())
	saWireSealClient(svc, &saSealer{canSeal: true})

	// Create a blob with a properly hashed password.
	hash, hashErr := hashPassword("correct-password")
	require.NoError(t, hashErr)

	blob := &sealedBlobStorage{
		ID:         "test-pw-mismatch",
		Label:      "test",
		PolicyType: string(PolicyTypePassword),
		Password:   hash,
		SealedData: &types.SealedData{
			Backend:    types.BackendTypeTPM2,
			Ciphertext: []byte("data"),
		},
		CreatedAt: time.Now(),
	}
	data, err := json.Marshal(blob)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test-pw-mismatch.sealed.json"), data, 0600))

	result, unsealErr := svc.UnsealData("test-pw-mismatch", "wrong-password")
	assert.Empty(t, result)
	assert.ErrorIs(t, unsealErr, ErrSealPolicyMismatch)
}

// TestSA_SealService_UnsealData_PasswordSuccess covers successful unseal with correct password.
func TestSA_SealService_UnsealData_PasswordSuccess(t *testing.T) {
	dir := t.TempDir()
	svc := NewSealService(dir)
	svc.SetContext(context.Background())
	saWireSealClient(svc, &saSealer{canSeal: true})

	hash, hashErr := hashPassword("correct-password")
	require.NoError(t, hashErr)

	plaintext := []byte("secret-data")
	blob := &sealedBlobStorage{
		ID:         "test-pw-success",
		Label:      "test",
		PolicyType: string(PolicyTypePassword),
		Password:   hash,
		SealedData: &types.SealedData{
			Backend:    types.BackendTypeTPM2,
			Ciphertext: plaintext,
		},
		CreatedAt: time.Now(),
	}
	data, err := json.Marshal(blob)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test-pw-success.sealed.json"), data, 0600))

	result, unsealErr := svc.UnsealData("test-pw-success", "correct-password")
	assert.NoError(t, unsealErr)
	decoded, decErr := base64.StdEncoding.DecodeString(result)
	require.NoError(t, decErr)
	assert.Equal(t, plaintext, decoded)
}

// TestSA_SealService_ClassifyCategory covers classifyCategory for system and user labels.
func TestSA_SealService_ClassifyCategory(t *testing.T) {
	assert.Equal(t, "system", classifyCategory("password_master_key"))
	assert.Equal(t, "user", classifyCategory("user_pin"))
	assert.Equal(t, "system", classifyCategory("auto-unseal-passphrase"))
	assert.Equal(t, "user", classifyCategory("my-secret"))
}

// TestSA_SealService_SplitPasswordHash covers splitPasswordHash edge cases.
func TestSA_SealService_SplitPasswordHash(t *testing.T) {
	assert.Nil(t, splitPasswordHash("no-colon"))
	assert.Nil(t, splitPasswordHash(""))

	parts := splitPasswordHash("salt:hash")
	require.NotNil(t, parts)
	assert.Equal(t, "salt", parts[0])
	assert.Equal(t, "hash", parts[1])
}

// TestSA_SealService_VerifyPassword_BadStoredFormat covers verifyPassword with bad stored hash.
func TestSA_SealService_VerifyPassword_BadStoredFormat(t *testing.T) {
	// No colon separator.
	assert.False(t, verifyPassword("password", "nocolon"))

	// Invalid hex in salt.
	assert.False(t, verifyPassword("password", "zzzz:abcd"))

	// Invalid hex in hash.
	assert.False(t, verifyPassword("password", "abcd:zzzz"))
}

// TestSA_SealService_UnsealData_UnsealerError covers sealer.Unseal returning error.
func TestSA_SealService_UnsealData_UnsealerError(t *testing.T) {
	dir := t.TempDir()
	svc := NewSealService(dir)
	svc.SetContext(context.Background())
	errUnseal := fmt.Errorf("sa: unseal error")
	saWireSealClient(svc, &saSealer{canSeal: true, unsealErr: errUnseal})

	blob := &sealedBlobStorage{
		ID:    "test-unseal-err",
		Label: "test",
		SealedData: &types.SealedData{
			Backend:    types.BackendTypeTPM2,
			Ciphertext: []byte("data"),
		},
		CreatedAt: time.Now(),
	}
	data, err := json.Marshal(blob)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test-unseal-err.sealed.json"), data, 0600))

	result, unsealErr := svc.UnsealData("test-unseal-err", "")
	assert.Empty(t, result)
	assert.Error(t, unsealErr)
}

// TestSA_SealService_DeleteBlob_Success covers L527-544 successful deletion.
func TestSA_SealService_DeleteBlob_Success(t *testing.T) {
	dir := t.TempDir()
	svc := NewSealService(dir)
	svc.SetContext(context.Background())

	blobID := "test-delete-ok"
	blobPath := filepath.Join(dir, blobID+".sealed.json")
	require.NoError(t, os.WriteFile(blobPath, []byte(`{}`), 0600))

	err := svc.DeleteBlob(blobID)
	assert.NoError(t, err)

	// Verify file was deleted.
	_, statErr := os.Stat(blobPath)
	assert.True(t, os.IsNotExist(statErr))
}

// TestSA_SealService_DeleteBlob_NotFound covers L536-537:
// DeleteBlob returns ErrSealBlobNotFound when blob file doesn't exist.
func TestSA_SealService_DeleteBlob_NotFound(t *testing.T) {
	dir := t.TempDir()
	svc := NewSealService(dir)
	svc.SetContext(context.Background())

	err := svc.DeleteBlob("nonexistent-blob")
	assert.ErrorIs(t, err, ErrSealBlobNotFound)
}
