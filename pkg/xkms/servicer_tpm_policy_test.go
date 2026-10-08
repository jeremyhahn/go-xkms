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

package xkms

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/tpmpolicytest"
	tpmpolicy "github.com/jeremyhahn/go-xkms/pkg/tpm2/policy"
)

// These tests drive the TPM policy servicer over a real policy service that
// has no TPM (tpmpolicytest.NewOffline): they cover tenant binding, system
// scope, request validation and the registry-backed operations. The
// TPM-backed operations are exercised end to end over the simulator in
// pkg/server's tpm_policy_simulator_test.go.

// newTPMPolicyService returns an XKMSService with an offline TPM policy
// service, and that service's registry.
func newTPMPolicyService(t *testing.T) (*XKMSService, *tpmpolicy.Service, *tpmpolicy.Registry) {
	t.Helper()
	policies, registry := tpmpolicytest.NewOffline(t)
	svc := &XKMSService{}
	svc.SetTPMPolicyService(policies)
	return svc, policies, registry
}

// TestTPMPolicyTarget_BindsTheCallersTenant proves a tenant-scoped caller
// acts on its own tenant whether or not it names it, cannot name another,
// and a cross-tenant caller -- or a context with no identity, the
// in-process path -- addresses any tenant, "" being the system scope.
func TestTPMPolicyTarget_BindsTheCallersTenant(t *testing.T) {
	got, err := targetTenant(tenantCtx("acme"), "op", "")
	require.NoError(t, err)
	assert.Equal(t, "acme", got)

	got, err = targetTenant(tenantCtx("acme"), "op", "acme")
	require.NoError(t, err)
	assert.Equal(t, "acme", got)

	_, err = targetTenant(tenantCtx("acme"), "op", "globex")
	requireBindingRefusal(t, err, "tenant naming another tenant")

	got, err = targetTenant(systemCtx(), "op", "globex")
	require.NoError(t, err)
	assert.Equal(t, "globex", got)

	got, err = targetTenant(systemCtx(), "op", "")
	require.NoError(t, err)
	assert.Empty(t, got, "a system caller naming no tenant acts on the system scope")

	got, err = targetTenant(context.Background(), "op", "acme")
	require.NoError(t, err)
	assert.Equal(t, "acme", got)
}

// TestTPMPolicy_TenantCannotAddressAnotherTenant proves every TPM policy
// operation refuses a tenant-scoped caller naming another tenant, with the
// binding's not-found refusal, before the service is consulted.
func TestTPMPolicy_TenantCannotAddressAnotherTenant(t *testing.T) {
	svc, _, _ := newTPMPolicyService(t)
	ctx := tenantCtx("acme")
	ops := map[string]func() error{
		"create": func() error {
			_, err := svc.TPMPolicyCreate(ctx, &transport.TPMPolicyCreateRequest{TenantID: "globex", Name: "boot", Branches: []transport.TPMPolicyBranch{transport.TPMPolicyPCRBranch("sha256", []uint{7})}})
			return err
		},
		"get": func() error {
			_, err := svc.TPMPolicyGet(ctx, &transport.TPMPolicyRequest{TenantID: "globex", Name: "boot"})
			return err
		},
		"list": func() error {
			_, err := svc.TPMPolicyList(ctx, &transport.TPMPolicyListRequest{TenantID: "globex"})
			return err
		},
		"update": func() error {
			_, err := svc.TPMPolicyUpdate(ctx, &transport.TPMPolicyRequest{TenantID: "globex", Name: "boot"})
			return err
		},
		"revoke": func() error {
			_, err := svc.TPMPolicyRevoke(ctx, &transport.TPMPolicyRequest{TenantID: "globex", Name: "boot"})
			return err
		},
		"verify": func() error {
			_, err := svc.TPMPolicyVerify(ctx, &transport.TPMPolicyRequest{TenantID: "globex", Name: "boot"})
			return err
		},
		"delete": func() error {
			return svc.TPMPolicyDelete(ctx, &transport.TPMPolicyDeleteRequest{TenantID: "globex", Name: "boot"})
		},
		"objects": func() error {
			_, err := svc.TPMPolicyObjects(ctx, &transport.TPMPolicyRequest{TenantID: "globex", Name: "boot"})
			return err
		},
		"describe": func() error {
			_, err := svc.TPMPolicySetDescription(ctx, &transport.TPMPolicyDescriptionRequest{TenantID: "globex", Name: "boot", Description: "d"})
			return err
		},
		"auto-unseal": func() error {
			_, err := svc.TPMPolicySetAutoUnseal(ctx, &transport.TPMPolicyAutoUnsealRequest{TenantID: "globex", Name: "boot", Enabled: true})
			return err
		},
		"object policy": func() error {
			_, err := svc.TPMObjectPolicy(ctx, &transport.TPMObjectPolicyRequest{TenantID: "globex", KeyID: "signer"})
			return err
		},
		"rotate": func() error {
			_, err := svc.TPMPolicyRotateAuthority(ctx, &transport.TPMAuthorityRotateRequest{TenantID: "globex"})
			return err
		},
	}
	for name, op := range ops {
		t.Run(name, func(t *testing.T) {
			requireBindingRefusal(t, op(), name)
		})
	}
}

// TestTenantTPMMode_SystemScopeOnly proves a tenant-scoped caller cannot
// read or change any tenant's TPM mode or vTPM -- not even its own -- while
// the system caller can.
func TestTenantTPMMode_SystemScopeOnly(t *testing.T) {
	svc, _, _ := newTPMPolicyService(t)
	for name, call := range tpmpolicytest.Calls(tenantCtx("acme"), svc) {
		switch name {
		case "GetTenantTPMMode", "SetTenantTPMMode", "TenantVTPMStatus", "TenantVTPMStart", "TenantVTPMStop":
			t.Run(name, func(t *testing.T) {
				requireBindingRefusal(t, call(), name)
			})
		}
	}
	_, err := svc.SetTenantTPMMode(tenantCtx("acme"), &transport.SetTenantTPMModeRequest{TenantID: "acme", Mode: "none"})
	requireBindingRefusal(t, err, "a tenant setting its own mode")

	ctx := systemCtx()
	mode, err := svc.GetTenantTPMMode(ctx, "acme")
	require.NoError(t, err)
	assert.Equal(t, transport.TenantTPMModeResponse{TenantID: "acme", Mode: "shared"}, *mode)

	set, err := svc.SetTenantTPMMode(ctx, &transport.SetTenantTPMModeRequest{TenantID: "acme", Mode: "none"})
	require.NoError(t, err)
	assert.Equal(t, "none", set.Mode)
	mode, err = svc.GetTenantTPMMode(ctx, "acme")
	require.NoError(t, err)
	assert.Equal(t, "none", mode.Mode)
}

// TestTenantTPMMode_RefusesBadInput proves the mode operations refuse a
// missing tenant, an unknown mode, the system scope and an unavailable vTPM
// with their typed errors.
func TestTenantTPMMode_RefusesBadInput(t *testing.T) {
	svc, _, _ := newTPMPolicyService(t)
	ctx := systemCtx()

	_, err := svc.GetTenantTPMMode(ctx, "")
	require.ErrorIs(t, err, ErrTenantIDRequired)
	_, err = svc.SetTenantTPMMode(ctx, nil)
	require.ErrorIs(t, err, ErrNilRequest)

	_, err = svc.SetTenantTPMMode(ctx, &transport.SetTenantTPMModeRequest{TenantID: "acme", Mode: "cloud"})
	var modeErr *tpmpolicy.InvalidModeError
	require.ErrorAs(t, err, &modeErr)

	_, err = svc.SetTenantTPMMode(ctx, &transport.SetTenantTPMModeRequest{TenantID: "system", Mode: "none"})
	require.ErrorIs(t, err, tpmpolicy.ErrSystemScopeMode)

	_, err = svc.SetTenantTPMMode(ctx, &transport.SetTenantTPMModeRequest{TenantID: "acme", Mode: "vtpm"})
	require.ErrorIs(t, err, tpmpolicy.ErrVTPMUnavailable)
	_, err = svc.TenantVTPMStart(ctx, "acme")
	require.ErrorIs(t, err, tpmpolicy.ErrVTPMUnavailable)
	_, err = svc.TenantVTPMStop(ctx, "acme")
	require.ErrorIs(t, err, tpmpolicy.ErrVTPMUnavailable)

	status, err := svc.TenantVTPMStatus(ctx, "acme")
	require.NoError(t, err)
	assert.Equal(t, transport.TenantVTPMStatusResponse{TenantID: "acme"}, *status, "no supervisor, no running vTPM")
}

// TestTPMPolicy_NotConfigured proves every operation answers ErrNotConfigured
// on a node without a TPM policy service, after the tenant binding.
func TestTPMPolicy_NotConfigured(t *testing.T) {
	svc := &XKMSService{}
	for name, call := range tpmpolicytest.Calls(systemCtx(), svc) {
		t.Run(name, func(t *testing.T) {
			assert.ErrorIs(t, call(), ErrNotConfigured)
		})
	}
	_, err := svc.TPMPolicyGet(tenantCtx("acme"), &transport.TPMPolicyRequest{TenantID: "globex", Name: "boot"})
	requireBindingRefusal(t, err, "the binding is checked before the configuration")
}

// TestTPMPolicy_NilRequest proves every request-taking operation refuses a
// nil request.
func TestTPMPolicy_NilRequest(t *testing.T) {
	svc, _, _ := newTPMPolicyService(t)
	ctx := systemCtx()
	errs := []error{
		func() error { _, err := svc.TPMPolicyCreate(ctx, nil); return err }(),
		func() error { _, err := svc.TPMPolicyGet(ctx, nil); return err }(),
		func() error { _, err := svc.TPMPolicyList(ctx, nil); return err }(),
		func() error { _, err := svc.TPMPolicyUpdate(ctx, nil); return err }(),
		func() error { _, err := svc.TPMPolicyRevoke(ctx, nil); return err }(),
		func() error { _, err := svc.TPMPolicyVerify(ctx, nil); return err }(),
		svc.TPMPolicyDelete(ctx, nil),
		func() error { _, err := svc.TPMPolicyObjects(ctx, nil); return err }(),
		func() error { _, err := svc.TPMPolicySetAutoUnseal(ctx, nil); return err }(),
		func() error { _, err := svc.TPMPolicySetDescription(ctx, nil); return err }(),
		func() error { _, err := svc.TPMObjectPolicy(ctx, nil); return err }(),
		func() error { _, err := svc.TPMPolicyRotateAuthority(ctx, nil); return err }(),
	}
	for i, err := range errs {
		assert.ErrorIs(t, err, ErrNilRequest, "operation %d", i)
	}
}

// TestTPMPolicy_TenantListsItsOwnScope proves a tenant lists its own scope's
// policies, and a tenant whose TPM mode is none is refused with the policy
// service's typed error.
func TestTPMPolicy_TenantListsItsOwnScope(t *testing.T) {
	svc, _, registry := newTPMPolicyService(t)

	list, err := svc.TPMPolicyList(tenantCtx("acme"), &transport.TPMPolicyListRequest{})
	require.NoError(t, err)
	assert.Empty(t, list.Policies)
	assert.NotNil(t, list.Policies, "an empty list encodes as [], not null")

	require.NoError(t, registry.PutScope(context.Background(), &tpmpolicy.Scope{Tenant: "initech", Mode: tpmpolicy.ModeNone}))
	_, err = svc.TPMPolicyList(tenantCtx("initech"), &transport.TPMPolicyListRequest{})
	require.ErrorIs(t, err, tpmpolicy.ErrTPMModeNone)
	require.ErrorIs(t, svc.TPMPolicyDelete(tenantCtx("initech"), &transport.TPMPolicyDeleteRequest{Name: "boot"}), tpmpolicy.ErrTPMModeNone)
	_, err = svc.TPMPolicyRotateAuthority(tenantCtx("initech"), &transport.TPMAuthorityRotateRequest{})
	require.ErrorIs(t, err, tpmpolicy.ErrTPMModeNone)
}

// TestTPMPolicyCreate_ValidatesBeforeTheTPM proves a create request naming
// the reserved platform policy or carrying a malformed branch is refused with
// a typed error before the TPM is reached.
func TestTPMPolicyCreate_ValidatesBeforeTheTPM(t *testing.T) {
	svc, _, _ := newTPMPolicyService(t)
	ctx := tenantCtx("acme")
	create := func(branches ...transport.TPMPolicyBranch) error {
		_, err := svc.TPMPolicyCreate(ctx, &transport.TPMPolicyCreateRequest{Name: "boot", Branches: branches})
		return err
	}

	_, err := svc.TPMPolicyCreate(ctx, &transport.TPMPolicyCreateRequest{Name: tpmpolicy.PlatformPolicy, Branches: []transport.TPMPolicyBranch{transport.TPMPolicyPCRBranch("sha256", []uint{7})}})
	require.ErrorIs(t, err, tpmpolicy.ErrReservedPolicy)

	var bankErr *tpmpolicy.InvalidPCRBankError
	require.ErrorAs(t, create(transport.TPMPolicyPCRBranch("md5", []uint{7})), &bankErr)
	require.ErrorIs(t, create(transport.TPMPolicyPCRBranch("sha256", nil)), tpmpolicy.ErrEmptyPCRSelection)
	require.ErrorIs(t, create(), tpmpolicy.ErrNoBranches)
	require.ErrorIs(t, create(transport.TPMPolicyBranch{}), tpmpolicy.ErrEmptyBranch)

	var localityErr *tpmpolicy.InvalidLocalityError
	require.ErrorAs(t, create(transport.TPMPolicyBranch{Conditions: []transport.TPMPolicyCondition{
		{Type: transport.TPMPolicyConditionLocality, Localities: []uint{5}},
	}}), &localityErr)
	var unknownErr *tpmpolicy.UnknownConditionTypeError
	require.ErrorAs(t, create(transport.TPMPolicyBranch{Conditions: []transport.TPMPolicyCondition{{Type: "time"}}}), &unknownErr)

	supplied := transport.TPMPolicyPCRBranch("sha256", []uint{7})
	supplied.Conditions[0].PCRValues = map[uint]string{7: "00"}
	require.ErrorIs(t, create(supplied), tpmpolicy.ErrPCRValuesSupplied, "PCR values are captured, never supplied")
	digest := transport.TPMPolicyPCRBranch("sha256", []uint{7})
	digest.Conditions[0].PCRDigest = "00"
	require.ErrorIs(t, create(digest), tpmpolicy.ErrPCRValuesSupplied)

	_, err = svc.TPMPolicyGet(ctx, &transport.TPMPolicyRequest{Name: "bad/name"})
	var nameErr *tpmpolicy.InvalidNameError
	require.ErrorAs(t, err, &nameErr)
}

// TestTPMPolicySetDescription_ValidatesBeforeTheTPM proves a description
// change naming the reserved platform policy, or longer than the service
// allows, is refused with a typed error before the TPM is reached.
func TestTPMPolicySetDescription_ValidatesBeforeTheTPM(t *testing.T) {
	svc, _, _ := newTPMPolicyService(t)
	ctx := tenantCtx("acme")

	_, err := svc.TPMPolicySetDescription(ctx, &transport.TPMPolicyDescriptionRequest{Name: tpmpolicy.PlatformPolicy, Description: "d"})
	require.ErrorIs(t, err, tpmpolicy.ErrReservedPolicy)

	var tooLong *tpmpolicy.DescriptionTooLongError
	_, err = svc.TPMPolicySetDescription(ctx, &transport.TPMPolicyDescriptionRequest{Name: "boot", Description: strings.Repeat("d", 4097)})
	require.ErrorAs(t, err, &tooLong)
}

// TestTPMObjectPolicy_ResolvesInTheCallersTenant proves an object's policy is
// found in the caller's own tenant only: another tenant's object of the same
// name is not found, and a system caller may name the tenant.
func TestTPMObjectPolicy_ResolvesInTheCallersTenant(t *testing.T) {
	svc, policies, _ := newTPMPolicyService(t)
	require.NoError(t, policies.Assign(context.Background(), "acme", tpmpolicy.ObjectKey, "signer", "", []byte{0xAB}))

	got, err := svc.TPMObjectPolicy(tenantCtx("acme"), &transport.TPMObjectPolicyRequest{KeyID: "signer"})
	require.NoError(t, err)
	assert.Equal(t, "key/signer", got.ObjectID)
	assert.Equal(t, "key", got.Kind)
	assert.Equal(t, tpmpolicy.PlatformPolicy, got.Policy)
	assert.Equal(t, "ab", got.AuthPolicy)
	assert.NotEmpty(t, got.CreatedAt)

	_, err = svc.TPMObjectPolicy(tenantCtx("globex"), &transport.TPMObjectPolicyRequest{KeyID: "signer"})
	require.ErrorIs(t, err, tpmpolicy.ErrNotAssigned, "another tenant's key ID resolves to nothing")

	_, err = svc.TPMObjectPolicy(tenantCtx("acme"), &transport.TPMObjectPolicyRequest{KeyID: "signer", Kind: "sealed"})
	require.ErrorIs(t, err, tpmpolicy.ErrNotAssigned)

	sys, err := svc.TPMObjectPolicy(systemCtx(), &transport.TPMObjectPolicyRequest{TenantID: "acme", KeyID: "signer"})
	require.NoError(t, err)
	assert.Equal(t, "key/signer", sys.ObjectID)

	_, err = svc.TPMObjectPolicy(tenantCtx("acme"), &transport.TPMObjectPolicyRequest{KeyID: "signer", Kind: "blob"})
	var kindErr *InvalidTPMObjectKindError
	require.ErrorAs(t, err, &kindErr)
	assert.Contains(t, kindErr.Error(), `"blob"`)

	_, err = svc.TPMObjectPolicy(tenantCtx("acme"), &transport.TPMObjectPolicyRequest{KeyID: "tpm2:bogus-type:x:y"})
	var parseErr *ErrKeyIDParse
	require.ErrorAs(t, err, &parseErr)
}

// TestTPMPolicyObjects_ListsAPolicysObjects proves the objects of a policy
// are listed for the caller's tenant, and an unused policy lists none.
func TestTPMPolicyObjects_ListsAPolicysObjects(t *testing.T) {
	svc, policies, _ := newTPMPolicyService(t)
	ctx := context.Background()
	require.NoError(t, policies.Assign(ctx, "acme", tpmpolicy.ObjectKey, "b", "", nil))
	require.NoError(t, policies.Assign(ctx, "acme", tpmpolicy.ObjectKey, "a", "", nil))

	got, err := svc.TPMPolicyObjects(tenantCtx("acme"), &transport.TPMPolicyRequest{Name: tpmpolicy.PlatformPolicy})
	require.NoError(t, err)
	assert.Equal(t, []string{"key/a", "key/b"}, got.Objects)

	none, err := svc.TPMPolicyObjects(tenantCtx("globex"), &transport.TPMPolicyRequest{Name: tpmpolicy.PlatformPolicy})
	require.NoError(t, err)
	assert.Equal(t, []string{}, none.Objects)
}

// TestTPMPolicyToTransport proves a stored policy's API form carries its
// description and branches, hex-encodes its captured values, and reports its
// approval per branch and overall, or its revocation.
func TestTPMPolicyToTransport(t *testing.T) {
	at := time.Date(2026, 9, 29, 12, 0, 0, 0, time.FixedZone("EST", -5*3600))
	p := &tpmpolicy.Policy{
		Name:        "boot",
		Description: "firmware or PIN",
		Branches: []tpmpolicy.Branch{
			{Conditions: []tpmpolicy.Condition{
				{Type: tpmpolicy.ConditionPCR, Bank: "sha256", PCRs: []uint{7}, PCRValues: map[uint][]byte{7: {0xDE, 0xAD}}, PCRDigest: []byte{0x01}},
				{Type: tpmpolicy.ConditionLocality, Localities: []uint{0}},
			}},
			{Conditions: []tpmpolicy.Condition{{Type: tpmpolicy.ConditionAuthValue}}},
		},
		Index:     0x01500010,
		Approvals: []*tpmpolicy.Approval{{Epoch: 3, AuthorityGeneration: 2}, {Epoch: 3, AuthorityGeneration: 2}},
		CreatedAt: at,
		UpdatedAt: at,
	}
	got := tpmPolicyToTransport("acme", p)
	assert.Equal(t, "acme", got.TenantID)
	assert.Equal(t, "firmware or PIN", got.Description)
	assert.Equal(t, []transport.TPMPolicyBranch{
		{Conditions: []transport.TPMPolicyCondition{
			{Type: "pcr", Bank: "sha256", PCRs: []uint{7}, PCRValues: map[uint]string{7: "dead"}, PCRDigest: "01"},
			{Type: "locality", Localities: []uint{0}},
		}, Approved: true},
		{Conditions: []transport.TPMPolicyCondition{{Type: "auth_value"}}, Approved: true},
	}, got.Branches)
	assert.True(t, got.Approved)
	assert.Equal(t, uint64(3), got.Epoch)
	assert.Equal(t, uint64(2), got.AuthorityGeneration)
	assert.Equal(t, "2026-09-29T17:00:00Z", got.CreatedAt)

	p.Approvals = []*tpmpolicy.Approval{nil, nil}
	revoked := tpmPolicyToTransport("", p)
	assert.False(t, revoked.Approved)
	assert.False(t, revoked.Branches[0].Approved)
	assert.Zero(t, revoked.Epoch)

	assert.False(t, tpmPolicyToTransport("", &tpmpolicy.Policy{Name: "empty"}).Approved, "a policy without branches is not approved")
	assert.Empty(t, formatTPMTime(time.Time{}))
}
