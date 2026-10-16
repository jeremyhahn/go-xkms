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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/tpmpolicytest"
	tpmpolicy "github.com/jeremyhahn/go-xkms/pkg/tpm2/policy"
)

// TestNewTenantTPMPolicies_RequiresAService proves the adapter refuses a nil
// policy service with ErrNotConfigured, the error XKMSService reports for an
// unconfigured node.
func TestNewTenantTPMPolicies_RequiresAService(t *testing.T) {
	_, err := NewTenantTPMPolicies(nil, "acme")
	require.ErrorIs(t, err, ErrNotConfigured)
}

// TestTenantTPMPolicies_IgnoresTheRequestTenant proves the adapter acts on
// its fixed tenant whatever a request names: authorizing the tenant is the
// caller's job, not the adapter's.
func TestTenantTPMPolicies_IgnoresTheRequestTenant(t *testing.T) {
	policies, _ := tpmpolicytest.NewOffline(t)
	ctx := context.Background()
	require.NoError(t, policies.Assign(ctx, "", tpmpolicy.ObjectSealed, "vault", "", nil))
	system, err := NewTenantTPMPolicies(policies, "")
	require.NoError(t, err)

	got, err := system.TPMObjectPolicy(ctx, &transport.TPMObjectPolicyRequest{TenantID: "acme", KeyID: "vault", Kind: transport.TPMObjectKindSealed})
	require.NoError(t, err)
	assert.Equal(t, "sealed/vault", got.ObjectID)

	objects, err := system.TPMPolicyObjects(ctx, &transport.TPMPolicyRequest{TenantID: "acme", Name: tpmpolicy.PlatformPolicy})
	require.NoError(t, err)
	assert.Equal(t, []string{"sealed/vault"}, objects.Objects)
}

// TestTenantTPMPolicies_NilRequest proves every adapter operation refuses a
// nil request, since it is callable without XKMSService in front of it.
func TestTenantTPMPolicies_NilRequest(t *testing.T) {
	policies, _ := tpmpolicytest.NewOffline(t)
	p, err := NewTenantTPMPolicies(policies, "")
	require.NoError(t, err)
	ctx := context.Background()
	errs := []error{
		func() error { _, err := p.TPMPolicyCreate(ctx, nil); return err }(),
		func() error { _, err := p.TPMPolicyGet(ctx, nil); return err }(),
		func() error { _, err := p.TPMPolicyList(ctx, nil); return err }(),
		func() error { _, err := p.TPMPolicyUpdate(ctx, nil); return err }(),
		func() error { _, err := p.TPMPolicyRevoke(ctx, nil); return err }(),
		func() error { _, err := p.TPMPolicyVerify(ctx, nil); return err }(),
		p.TPMPolicyDelete(ctx, nil),
		func() error { _, err := p.TPMPolicyObjects(ctx, nil); return err }(),
		func() error { _, err := p.TPMPolicySetAutoUnseal(ctx, nil); return err }(),
		func() error { _, err := p.TPMPolicySetDescription(ctx, nil); return err }(),
		func() error { _, err := p.TPMObjectPolicy(ctx, nil); return err }(),
		func() error { _, err := p.TPMPolicyRotateAuthority(ctx, nil); return err }(),
	}
	for i, err := range errs {
		assert.ErrorIs(t, err, ErrNilRequest, "operation %d", i)
	}
}

// TestTenantTPMPolicies_BranchUpdate proves an update naming a branch needs
// its reference values and the reverse, and a complete branch update reaches
// the policy service's reference-value update rather than a live capture.
func TestTenantTPMPolicies_BranchUpdate(t *testing.T) {
	policies, _ := tpmpolicytest.NewOffline(t)
	p, err := NewTenantTPMPolicies(policies, "")
	require.NoError(t, err)
	ctx := context.Background()
	branch := 0

	_, err = p.TPMPolicyUpdate(ctx, &transport.TPMPolicyUpdateRequest{Name: "boot", Branch: &branch})
	require.ErrorIs(t, err, ErrTPMPolicyBranchUpdate, "a branch without reference values")
	_, err = p.TPMPolicyUpdate(ctx, &transport.TPMPolicyUpdateRequest{Name: "boot", ReferenceValues: []byte{0xd2}})
	require.ErrorIs(t, err, ErrTPMPolicyBranchUpdate, "reference values without a branch")

	_, err = p.TPMPolicyUpdate(ctx, &transport.TPMPolicyUpdateRequest{Name: "boot", Branch: &branch, ReferenceValues: []byte{0xd2}})
	require.ErrorIs(t, err, tpmpolicy.ErrNoReferenceSigner, "the branch update is the service's, which trusts no signer here")
}

// TestParseTPMObjectKind proves the API's object kinds map to the policy
// service's, "" meaning a key, and any other kind is a typed error.
func TestParseTPMObjectKind(t *testing.T) {
	tests := []struct {
		kind string
		want tpmpolicy.ObjectKind
	}{
		{"", tpmpolicy.ObjectKey},
		{transport.TPMObjectKindKey, tpmpolicy.ObjectKey},
		{transport.TPMObjectKindSealed, tpmpolicy.ObjectSealed},
	}
	for _, tt := range tests {
		got, err := ParseTPMObjectKind(tt.kind)
		require.NoError(t, err, tt.kind)
		assert.Equal(t, tt.want, got, tt.kind)
	}

	_, err := ParseTPMObjectKind("blob")
	var kindErr *InvalidTPMObjectKindError
	require.ErrorAs(t, err, &kindErr)
	assert.Equal(t, "blob", kindErr.Kind)
}
