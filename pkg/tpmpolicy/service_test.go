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

package tpmpolicy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	pkgtpm2 "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/vtpm"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests need no TPM: they cover validation, encodings and the
// registry-only paths of the service. The TPM-backed behaviour is covered by
// service_simulator_test.go and vtpm_test.go.

// validConfig returns a Config whose every required field is set. Its TPM is
// an unopened TPM2 that the registry-only paths never reach.
func validConfig(t *testing.T) Config {
	t.Helper()
	registry, err := NewRegistry(storage.NewMemory())
	require.NoError(t, err)
	tpm := &pkgtpm2.TPM2{}
	return Config{
		Registry:    registry,
		TPM:         tpm,
		PlatformSRK: &types.KeyAttributes{TPMAttributes: &types.TPMAttributes{}},
		Keys:        store.NewFileBackend(quietLogger, storage.NewMemory()),
		KeyStorage:  storage.NewMemory(),
		Sealer:      tpm,
		Logger:      quietLogger,
	}
}

// newOfflineService returns a Service over validConfig.
func newOfflineService(t *testing.T) (*Service, *Registry) {
	t.Helper()
	cfg := validConfig(t)
	svc, err := NewService(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, svc.Close()) })
	return svc, cfg.Registry
}

func TestNewService_RequiresEveryDependency(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
		want   error
	}{
		{"registry", func(c *Config) { c.Registry = nil }, ErrNilRegistry},
		{"tpm", func(c *Config) { c.TPM = nil }, ErrNilTPM},
		{"platform SRK", func(c *Config) { c.PlatformSRK = nil }, ErrNilPlatformSRK},
		{"platform SRK TPM attributes", func(c *Config) { c.PlatformSRK = &types.KeyAttributes{} }, ErrNilPlatformSRK},
		{"keys", func(c *Config) { c.Keys = nil }, ErrNilKeys},
		{"key storage", func(c *Config) { c.KeyStorage = nil }, ErrNilKeyStorage},
		{"sealer", func(c *Config) { c.Sealer = nil }, ErrNilSealer},
		{"vTPM config", func(c *Config) { c.VTPM = &vtpm.Config{} }, vtpm.ErrStateDirRequired},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig(t)
			tc.mutate(&cfg)
			svc, err := NewService(cfg)
			require.ErrorIs(t, err, tc.want)
			assert.Nil(t, svc)
		})
	}
}

func TestNewService_DefaultsLoggerAndClock(t *testing.T) {
	cfg := validConfig(t)
	cfg.Logger = nil
	svc, err := NewService(cfg)
	require.NoError(t, err)
	assert.NotNil(t, svc.logger)
	assert.False(t, svc.clock().IsZero())
	require.NoError(t, svc.Close())
}

func TestValidateSelection(t *testing.T) {
	bank, alg, pcrs, err := validateSelection("SHA256", []uint{23, 0, 7})
	require.NoError(t, err)
	assert.Equal(t, "sha256", bank)
	assert.Equal(t, tpm2.TPMAlgSHA256, alg)
	assert.Equal(t, []uint{0, 7, 23}, pcrs)

	var badBank *InvalidPCRBankError
	var badPCR *InvalidPCRError
	for _, tc := range []struct {
		name  string
		bank  string
		pcrs  []uint
		check func(error) bool
	}{
		{"unknown bank", "sm3_256", []uint{0}, func(err error) bool { return errors.As(err, &badBank) }},
		{"empty bank", "", []uint{0}, func(err error) bool { return errors.As(err, &badBank) }},
		{"no PCRs", "sha256", nil, func(err error) bool { return errors.Is(err, ErrEmptyPCRSelection) }},
		{"PCR above 23", "sha1", []uint{24}, func(err error) bool { return errors.As(err, &badPCR) && !badPCR.Duplicate }},
		{"duplicate PCR", "sha384", []uint{7, 7}, func(err error) bool { return errors.As(err, &badPCR) && badPCR.Duplicate }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, err := validateSelection(tc.bank, tc.pcrs)
			require.Error(t, err)
			assert.True(t, tc.check(err), "got %v", err)
		})
	}

	_, _, _, err = validateSelection("sha256", []uint{3, 3})
	var dup *InvalidPCRError
	require.ErrorAs(t, err, &dup)
	assert.True(t, dup.Duplicate)
	assert.Contains(t, dup.Error(), "more than once")
}

// TestPCRDigest_MatchesTheCompositePrimitive cross-checks the session-hash
// composite against pkg/tpm2's PCRCompositeDigest, which it equals for the
// SHA-256 bank.
func TestPCRDigest_MatchesTheCompositePrimitive(t *testing.T) {
	values := map[uint][]byte{
		7:  bytes.Repeat([]byte{0x07}, sha256.Size),
		23: bytes.Repeat([]byte{0x23}, sha256.Size),
	}
	want, err := pkgtpm2.PCRCompositeDigest(pkgtpm2.PCRBankSHA256, []int{23, 7}, map[string]string{
		"sha256:7":  hex.EncodeToString(values[7]),
		"sha256:23": hex.EncodeToString(values[23]),
	})
	require.NoError(t, err)
	assert.Equal(t, want, pcrDigest([]uint{7, 23}, values))

	sha1Values := map[uint][]byte{23: bytes.Repeat([]byte{0x01}, 20)}
	sum := sha256.Sum256(sha1Values[23])
	assert.Equal(t, sum[:], pcrDigest([]uint{23}, sha1Values), "the SHA-1 bank is hashed with the session's SHA-256")
}

func TestScopeSecrets_RoundTrip(t *testing.T) {
	shared, err := newScopeSecrets("acme", true)
	require.NoError(t, err)
	decoded, err := decodeScopeSecrets(shared.encode())
	require.NoError(t, err)
	assert.Equal(t, shared, decoded)
	assert.LessOrEqual(t, len(shared.encode()), 128, "a TPM sealed data object holds at most 128 bytes")

	system, err := newScopeSecrets("system", false)
	require.NoError(t, err)
	decoded, err = decodeScopeSecrets(system.encode())
	require.NoError(t, err)
	assert.Nil(t, decoded.StorageKeyAuth)
	assert.NotEqual(t, system.AuthorityAuth, system.NVWriteAuth)

	_, err = decodeScopeSecrets(make([]byte, secretSize))
	require.ErrorIs(t, err, ErrMalformedSecrets)
}

// TestRandomSecret_HasNoZeroByte guards the go-tpm HMAC-key defect the
// secrets avoid: an auth value with a zero byte never authorizes.
func TestRandomSecret_HasNoZeroByte(t *testing.T) {
	seen := map[string]bool{}
	for range 512 {
		secret, err := randomSecret()
		require.NoError(t, err)
		require.Len(t, secret, secretSize)
		require.NotContains(t, secret, byte(0))
		seen[string(secret)] = true
	}
	assert.Len(t, seen, 512)
}

var errTransportDown = errors.New("test: transport down")

func TestScope_Authority(t *testing.T) {
	scope := &Scope{Tenant: "acme", Authority: Authority{Generation: 3}, Rotating: &Authority{Generation: 4}}
	current, err := scope.authority(3)
	require.NoError(t, err)
	assert.Same(t, &scope.Authority, current)
	next, err := scope.authority(4)
	require.NoError(t, err)
	assert.Same(t, scope.Rotating, next)
	_, err = scope.authority(2)
	var unknown *UnknownAuthorityError
	require.ErrorAs(t, err, &unknown)
	assert.Equal(t, uint64(2), unknown.Generation)
}

func TestScopeTPM_CloseReleasesOnce(t *testing.T) {
	calls := 0
	st := &ScopeTPM{release: func() error { calls++; return errTransportDown }}
	require.ErrorIs(t, st.Close(), errTransportDown)
	require.NoError(t, st.Close())
	assert.Equal(t, 1, calls)
	require.NoError(t, (&ScopeTPM{}).Close(), "a persistent parent has nothing to release")
}

func TestCheckPolicyName(t *testing.T) {
	require.NoError(t, checkPolicyName("boot"))
	require.ErrorIs(t, checkPolicyName(PlatformPolicy), ErrReservedPolicy)
	var invalid *InvalidNameError
	require.ErrorAs(t, checkPolicyName(""), &invalid)
	require.ErrorAs(t, checkPolicyName("a/b"), &invalid)
	assert.Equal(t, PlatformPolicy, policyOrPlatform(""))
	assert.Equal(t, "boot", policyOrPlatform("boot"))
}

// TestService_ModeNoneRefusesRegistryOperations proves a tenant whose mode is
// none is refused even by the operations that only read or write the
// registry.
func TestService_ModeNoneRefusesRegistryOperations(t *testing.T) {
	svc, registry := newOfflineService(t)
	ctx := context.Background()

	mode, err := svc.Mode(ctx, "acme")
	require.NoError(t, err)
	assert.Equal(t, ModeShared, mode, "a tenant with no scope has the default mode")
	mode, err = svc.Mode(ctx, "")
	require.NoError(t, err)
	assert.Equal(t, ModeShared, mode, "the system scope is always on the physical TPM")

	require.NoError(t, registry.PutScope(ctx, &Scope{Tenant: "acme", Mode: ModeNone}))
	_, err = svc.Policy(ctx, "acme", "boot")
	require.ErrorIs(t, err, ErrTPMModeNone)
	_, err = svc.ListPolicies(ctx, "acme")
	require.ErrorIs(t, err, ErrTPMModeNone)
	_, err = svc.AutoUnsealPolicy(ctx, "acme")
	require.ErrorIs(t, err, ErrTPMModeNone)
	require.ErrorIs(t, svc.Assign(ctx, "acme", ObjectKey, "k", "", nil), ErrTPMModeNone)
	require.ErrorIs(t, svc.Unassign(ctx, "acme", ObjectKey, "k"), ErrTPMModeNone)
	_, err = svc.PolicyOf(ctx, "acme", ObjectKey, "k")
	require.ErrorIs(t, err, ErrTPMModeNone)
	_, err = svc.ObjectsOf(ctx, "acme", "")
	require.ErrorIs(t, err, ErrTPMModeNone)
	_, err = svc.ScopeTPM(ctx, "acme")
	require.ErrorIs(t, err, ErrTPMModeNone)
	_, err = svc.RotateAuthority(ctx, "acme")
	require.ErrorIs(t, err, ErrTPMModeNone)
	require.NoError(t, svc.SetMode(ctx, "acme", ModeNone, nil), "setting the current mode is a no-op")
	require.ErrorIs(t, svc.StartVTPM(ctx, "acme"), ErrVTPMUnavailable)
	assert.Equal(t, vtpm.Status{Tenant: "acme"}, svc.VTPMStatus("acme"))

	var badTenant *InvalidTenantError
	_, err = svc.Mode(ctx, "a:b")
	require.ErrorAs(t, err, &badTenant)
	_, err = svc.EnsureScope(ctx, "a/b", nil)
	require.ErrorAs(t, err, &badTenant)
	_, err = svc.ScopeTPM(ctx, "..")
	require.ErrorAs(t, err, &badTenant)
	require.ErrorAs(t, svc.SetMode(ctx, "a/b", ModeNone, nil), &badTenant)
	_, err = svc.ObjectsOf(ctx, "a/b", "")
	require.ErrorAs(t, err, &badTenant)
}

// TestService_ResolverReadsTheRegistry proves the PolicyBindingResolver
// answers from the stored policy and scope -- one approval per branch, in
// branch order, carrying the branch's conditions -- reports the policy's
// auth_value condition, refuses a revoked policy, and refuses an approval by
// an authority the scope does not record.
func TestService_ResolverReadsTheRegistry(t *testing.T) {
	svc, registry := newOfflineService(t)
	ctx := context.Background()
	signature := tpm2.Marshal(tpm2.TPMTSignature{
		SigAlg: tpm2.TPMAlgECDSA,
		Signature: tpm2.NewTPMUSignature(tpm2.TPMAlgECDSA, &tpm2.TPMSSignatureECC{
			Hash:       tpm2.TPMAlgSHA256,
			SignatureR: tpm2.TPM2BECCParameter{Buffer: []byte{1}},
			SignatureS: tpm2.TPM2BECCParameter{Buffer: []byte{2}},
		}),
	})
	require.NoError(t, registry.PutScope(ctx, &Scope{
		Tenant: "acme", Mode: ModeShared, Counter: 0x01500001, Epoch: 5,
		Authority: Authority{Generation: 1, Public: []byte{0x00, 0x23}},
	}))
	pcr := pcrBranch()
	pcr.Conditions[0].PCRDigest = []byte{9}
	locality := Branch{Conditions: []Condition{{Type: ConditionAuthValue}, {Type: ConditionLocality, Localities: []uint{0, 3}}}}
	policy := &Policy{
		Name:      "boot",
		Branches:  []Branch{pcr, locality},
		Index:     0x01500002,
		PolicyRef: pkgtpm2.PolicyRef("acme", "boot"),
		Approvals: []*Approval{
			{Epoch: 5, AuthorityGeneration: 1, Signature: signature},
			{Epoch: 5, AuthorityGeneration: 1, Signature: signature},
		},
	}
	require.NoError(t, registry.CreatePolicy(ctx, "acme", policy))

	info, err := svc.PolicyIndex("acme", "boot")
	require.NoError(t, err)
	assert.Equal(t, pkgtpm2.PolicyIndexInfo{Index: 0x01500002, HashAlg: tpm2.TPMAlgSHA256, AuthValueCondition: true}, info)

	approvals, err := svc.Approvals("acme", "boot")
	require.NoError(t, err)
	require.Len(t, approvals, 2)
	for _, approval := range approvals {
		assert.Equal(t, tpm2.TPMHandle(0x01500001), approval.Counter)
		assert.Equal(t, uint64(5), approval.Epoch)
		assert.Equal(t, policy.PolicyRef, approval.PolicyRef)
		assert.Equal(t, tpm2.TPMAlgECDSA, approval.Signature.SigAlg)
	}
	require.Len(t, approvals[0].Branch.Conditions, 1)
	assert.Equal(t, pkgtpm2.PolicyConditionPCR, approvals[0].Branch.Conditions[0].Type)
	assert.Equal(t, []byte{9}, approvals[0].Branch.Conditions[0].PCRDigest)
	assert.True(t, approvals[1].Branch.HasAuthValue())
	assert.True(t, approvals[1].Branch.Conditions[1].Locality.TPMLocThree)

	policy.Approvals[1].AuthorityGeneration = 7
	require.NoError(t, registry.UpdatePolicy(ctx, "acme", policy))
	var unknown *UnknownAuthorityError
	_, err = svc.Approvals("acme", "boot")
	require.ErrorAs(t, err, &unknown)

	policy.Approvals[1].AuthorityGeneration = 1
	policy.Approvals[1].Signature = []byte{0xff}
	require.NoError(t, registry.UpdatePolicy(ctx, "acme", policy))
	var storeErr *StoreError
	_, err = svc.Approvals("acme", "boot")
	require.ErrorAs(t, err, &storeErr)

	policy.Approvals[1] = nil
	require.NoError(t, registry.UpdatePolicy(ctx, "acme", policy))
	_, err = svc.Approvals("acme", "boot")
	require.ErrorIs(t, err, ErrPolicyRevoked, "a policy missing any branch approval is revoked")

	policy.revoke()
	require.NoError(t, registry.UpdatePolicy(ctx, "acme", policy))
	_, err = svc.Approvals("acme", "boot")
	require.ErrorIs(t, err, ErrPolicyRevoked)
}

func TestErrorMessages(t *testing.T) {
	cause := errors.New("cause")
	for _, err := range []error{
		&InvalidPCRBankError{Bank: "sm3"},
		&InvalidPCRError{PCR: 30},
		&PCRBankUnavailableError{Bank: "sha512"},
		&UnknownAuthorityError{Scope: "acme", Generation: 2},
		&CounterRollbackError{Scope: "acme", Counter: 1, Epoch: 2},
		&TPMError{Scope: "acme", Op: "op", Err: cause},
		&SecretsError{Scope: "acme", Op: "op", Err: cause},
		&VTPMError{Tenant: "acme", Op: "op", Err: cause},
		&InvalidTenantError{Tenant: "a/b", Err: cause},
		&InvalidNameError{Name: "a/b"},
		&InvalidModeError{Mode: "bogus"},
		&StoreError{Op: "get", Key: "k", Err: cause},
		&PolicyInUseError{Policy: "boot", Objects: []string{"key/a"}},
		&ScopeInUseError{Tenant: "acme", Objects: []string{"key/a"}},
		&InvalidLocalityError{Locality: 5},
		&InvalidLocalityError{Locality: 1, Duplicate: true},
		&UnknownConditionTypeError{Type: "time"},
		&DuplicateConditionError{Type: ConditionPCR},
		&ConditionOperandError{Type: ConditionAuthValue, Operand: "bank"},
		&InvalidBranchError{Branch: 1, Err: ErrEmptyBranch},
		&DescriptionTooLongError{Length: 5000, Max: maxDescription},
	} {
		assert.Contains(t, err.Error(), "tpmpolicy:")
	}
	for _, err := range []error{
		&TPMError{Err: cause}, &SecretsError{Err: cause}, &VTPMError{Err: cause},
		&InvalidTenantError{Err: cause}, &StoreError{Err: cause}, &InvalidBranchError{Err: cause},
	} {
		assert.ErrorIs(t, err, cause)
	}
}
