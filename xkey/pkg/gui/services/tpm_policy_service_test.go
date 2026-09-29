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

package services

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/xkey/internal/tpmpolicyfake"
)

// newServerTPMPolicies returns a TPMPolicyService in server mode over a
// fake xkmsd whose PCR 7 reads 0xaa.
func newServerTPMPolicies(t *testing.T) (*TPMPolicyService, *tpmpolicyfake.Fake) {
	t.Helper()
	fake := &tpmpolicyfake.Fake{}
	fake.SetPCR(7, []byte{0xaa})
	svc := NewTPMPolicyService()
	svc.SetContext(context.Background())
	svc.SetClient(fake)
	return svc, fake
}

func TestTPMPolicyService_StatusFollowsTheBackend(t *testing.T) {
	svc := NewTPMPolicyService()
	status := svc.GetStatus()
	assert.False(t, status.Available)
	assert.Equal(t, TPMPolicyModeUnavailable, status.Mode)

	svc.SetClient(&tpmpolicyfake.Fake{})
	status = svc.GetStatus()
	assert.True(t, status.Available)
	assert.Equal(t, TPMPolicyModeServer, status.Mode)

	// A disconnect (nil client) returns the service to local mode, which is
	// unavailable here because there is no local TPM.
	svc.SetClient(nil)
	assert.Equal(t, TPMPolicyModeUnavailable, svc.GetStatus().Mode)
}

func TestTPMPolicyService_UnavailableWithoutABackend(t *testing.T) {
	svc := NewTPMPolicyService()
	_, err := svc.ListPolicies()
	assert.ErrorIs(t, err, ErrTPMPolicyUnavailable)
	_, err = svc.CreatePolicy("boot", "sha256", []uint{7}, false, "")
	assert.ErrorIs(t, err, ErrTPMPolicyUnavailable)
	_, err = svc.RotateAuthority()
	assert.ErrorIs(t, err, ErrTPMPolicyUnavailable)
	assert.ErrorIs(t, svc.DeletePolicy("boot", ""), ErrTPMPolicyUnavailable)
}

func TestTPMPolicyService_CreateDefaultsTheBankAndReturnsCapturedValues(t *testing.T) {
	svc, _ := newServerTPMPolicies(t)
	p, err := svc.CreatePolicy("boot", "", []uint{7}, false, "")
	require.NoError(t, err)
	assert.Equal(t, "boot", p.Name)
	assert.Equal(t, "sha256", p.Bank)
	assert.Equal(t, "aa", p.PCRValues[7])
	assert.True(t, p.Approved)
	assert.False(t, p.Builtin)
}

func TestTPMPolicyService_RejectsMissingAndBuiltinNames(t *testing.T) {
	svc, _ := newServerTPMPolicies(t)
	_, err := svc.CreatePolicy(" ", "sha256", []uint{7}, false, "")
	assert.ErrorIs(t, err, ErrTPMPolicyNameRequired)
	_, err = svc.CreatePolicy(xkms.TPMPolicyPlatform, "sha256", []uint{7}, false, "")
	assert.ErrorIs(t, err, ErrTPMPolicyBuiltin)
	_, err = svc.UpdatePolicy(xkms.TPMPolicyPlatform)
	assert.ErrorIs(t, err, ErrTPMPolicyBuiltin)
	_, err = svc.RevokePolicy("")
	assert.ErrorIs(t, err, ErrTPMPolicyNameRequired)
	_, err = svc.VerifyPolicy(xkms.TPMPolicyPlatform)
	assert.ErrorIs(t, err, ErrTPMPolicyBuiltin)
	assert.ErrorIs(t, svc.DeletePolicy(xkms.TPMPolicyPlatform, ""), ErrTPMPolicyBuiltin)
	_, err = svc.SetAutoUnseal(xkms.TPMPolicyPlatform, true)
	assert.ErrorIs(t, err, ErrTPMPolicyBuiltin)
	_, err = svc.GetPolicy("")
	assert.ErrorIs(t, err, ErrTPMPolicyNameRequired)
	_, err = svc.PolicyObjects("")
	assert.ErrorIs(t, err, ErrTPMPolicyNameRequired)
}

func TestTPMPolicyService_ListStartsWithThePlatformPolicyAndCountsObjects(t *testing.T) {
	svc, fake := newServerTPMPolicies(t)
	_, err := svc.CreatePolicy("boot", "sha256", []uint{7}, false, "")
	require.NoError(t, err)
	fake.Assign("", "key", "k1", "boot")
	fake.Assign("", "key", "k2", "boot")
	fake.Assign("", "key", "k3", "")

	policies, err := svc.ListPolicies()
	require.NoError(t, err)
	require.Len(t, policies, 2)
	assert.Equal(t, xkms.TPMPolicyPlatform, policies[0].Name)
	assert.True(t, policies[0].Builtin)
	assert.Equal(t, 1, policies[0].ObjectCount)
	assert.Equal(t, "boot", policies[1].Name)
	assert.Equal(t, 2, policies[1].ObjectCount)
}

func TestTPMPolicyService_GetUnknownPolicyFails(t *testing.T) {
	svc, _ := newServerTPMPolicies(t)
	_, err := svc.GetPolicy("missing")
	assert.ErrorIs(t, err, xkms.ErrTPMPolicyNotFound)
}

func TestTPMPolicyService_DeleteIsRefusedWhileObjectsAreBound(t *testing.T) {
	svc, fake := newServerTPMPolicies(t)
	_, err := svc.CreatePolicy("boot", "sha256", []uint{7}, false, "")
	require.NoError(t, err)
	fake.Assign("", "key", "k1", "boot")
	fake.Assign("", "sealed", "s1", "boot")

	err = svc.DeletePolicy("boot", "")
	var inUse *xkms.TPMPolicyInUseError
	require.ErrorAs(t, err, &inUse)
	assert.Equal(t, []string{"key/k1", "sealed/s1"}, inUse.Objects)
	assert.Contains(t, err.Error(), "key/k1")

	objects, err := svc.PolicyObjects("boot")
	require.NoError(t, err)
	assert.Equal(t, []string{"key/k1", "sealed/s1"}, objects)
}

func TestTPMPolicyService_DeleteUnusedPolicy(t *testing.T) {
	svc, _ := newServerTPMPolicies(t)
	_, err := svc.CreatePolicy("boot", "sha256", []uint{7}, false, "")
	require.NoError(t, err)
	require.NoError(t, svc.DeletePolicy("boot", ""))
	_, err = svc.GetPolicy("boot")
	assert.ErrorIs(t, err, xkms.ErrTPMPolicyNotFound)
}

func TestTPMPolicyService_VerifyUpdateAndRevoke(t *testing.T) {
	svc, fake := newServerTPMPolicies(t)
	_, err := svc.CreatePolicy("boot", "sha256", []uint{7}, false, "")
	require.NoError(t, err)

	fake.SetPCR(7, []byte{0xbb})
	v, err := svc.VerifyPolicy("boot")
	require.NoError(t, err)
	assert.False(t, v.Match)
	assert.Equal(t, []uint{7}, v.Mismatched)

	p, err := svc.UpdatePolicy("boot")
	require.NoError(t, err)
	assert.Equal(t, "bb", p.PCRValues[7])
	v, err = svc.VerifyPolicy("boot")
	require.NoError(t, err)
	assert.True(t, v.Match)
	assert.Empty(t, v.Mismatched)
	assert.True(t, v.Approved)

	p, err = svc.RevokePolicy("boot")
	require.NoError(t, err)
	assert.False(t, p.Approved)
	v, err = svc.VerifyPolicy("boot")
	require.NoError(t, err)
	assert.False(t, v.Approved)
}

func TestTPMPolicyService_SetAutoUnsealMarksOnePolicy(t *testing.T) {
	svc, _ := newServerTPMPolicies(t)
	for _, name := range []string{"a", "b"} {
		_, err := svc.CreatePolicy(name, "sha256", []uint{7}, false, "")
		require.NoError(t, err)
	}
	p, err := svc.SetAutoUnseal("a", true)
	require.NoError(t, err)
	assert.True(t, p.AutoUnseal)
	_, err = svc.SetAutoUnseal("b", true)
	require.NoError(t, err)

	a, err := svc.GetPolicy("a")
	require.NoError(t, err)
	assert.False(t, a.AutoUnseal, "setting the mark clears it from every other policy")

	_, err = svc.SetAutoUnseal("missing", true)
	assert.ErrorIs(t, err, xkms.ErrTPMPolicyNotFound)
}

func TestTPMPolicyService_KeyPolicy(t *testing.T) {
	svc, fake := newServerTPMPolicies(t)
	fake.Assign("", "key", "k1", "")
	info, err := svc.KeyPolicy("k1")
	require.NoError(t, err)
	assert.Equal(t, "key/k1", info.ObjectID)
	assert.Equal(t, xkms.TPMPolicyPlatform, info.Policy)

	_, err = svc.KeyPolicy(" ")
	assert.ErrorIs(t, err, ErrTPMPolicyKeyIDRequired)
	_, err = svc.KeyPolicy("unknown")
	assert.ErrorIs(t, err, xkms.ErrTPMPolicyNotAssigned)
}

func TestTPMPolicyService_RotateAuthority(t *testing.T) {
	svc, _ := newServerTPMPolicies(t)
	a, err := svc.RotateAuthority()
	require.NoError(t, err)
	assert.Equal(t, uint64(2), a.Generation)
	assert.NotEmpty(t, a.AuthorityName)
}

func TestTPMPolicyService_ServerModeRecordsNothingLocally(t *testing.T) {
	svc, _ := newServerTPMPolicies(t)
	// Without a local service there is no local object to record; the
	// server records the objects it creates itself.
	require.NoError(t, svc.assignLocal(context.Background(), xkms.TPMObjectKindKey, "k1", "boot"))
	require.NoError(t, svc.unassignLocal(context.Background(), xkms.TPMObjectKindKey, "k1"))
	require.NoError(t, svc.deleteLocalObject(context.Background(), "obj"))
}

// panickingTPMPolicies is a server whose every call panics.
type panickingTPMPolicies struct{ tpmpolicyfake.Fake }

func (p *panickingTPMPolicies) TPMPolicyList(context.Context, *transport.TPMPolicyListRequest) (*transport.TPMPolicyListResponse, error) {
	panic("boom")
}

func TestTPMPolicyService_PanicsBecomeErrors(t *testing.T) {
	svc := NewTPMPolicyService()
	svc.SetClient(&panickingTPMPolicies{})
	_, err := svc.ListPolicies()
	require.Error(t, err)
	var msg *MessageError
	assert.True(t, errors.As(err, &msg))
	assert.Contains(t, err.Error(), "ListPolicies")
}

func TestOpenLocalTPMPolicies_RequiresItsDependencies(t *testing.T) {
	_, err := OpenLocalTPMPolicies(LocalTPMPolicyParams{})
	assert.ErrorIs(t, err, ErrLocalTPMPolicyNoTPM)
	_, err = OpenLocalTPMPolicies(LocalTPMPolicyParams{TPM: defaultMockTPM()})
	assert.ErrorIs(t, err, ErrLocalTPMPolicyNoKeys)

	store, err := xkms.NewMemoryBackend()
	require.NoError(t, err)
	keys := xkms.NewFileBackend(slog.Default(), store)
	_, err = OpenLocalTPMPolicies(LocalTPMPolicyParams{TPM: defaultMockTPM(), Keys: keys})
	assert.ErrorIs(t, err, ErrLocalTPMPolicyNoDataDir)
	_, err = OpenLocalTPMPolicies(LocalTPMPolicyParams{TPM: defaultMockTPM(), Keys: keys, DataDir: t.TempDir()})
	assert.ErrorIs(t, err, ErrLocalTPMPolicyNoStoreOpener)
}

func TestObjectName(t *testing.T) {
	name, err := objectName("tpm2:signing:ecdsa-p256:mykey")
	require.NoError(t, err)
	assert.Equal(t, "mykey", name)
	name, err = objectName("mykey")
	require.NoError(t, err)
	assert.Equal(t, "mykey", name)
	_, err = objectName("")
	assert.ErrorIs(t, err, ErrTPMPolicyKeyIDRequired)
}

// failingTPMPolicies is a server that fails every TPM policy call.
type failingTPMPolicies struct {
	tpmpolicyfake.Fake
	err error
}

func (f *failingTPMPolicies) TPMPolicyCreate(context.Context, *transport.TPMPolicyCreateRequest) (*transport.TPMPolicy, error) {
	return nil, f.err
}
func (f *failingTPMPolicies) TPMPolicyGet(context.Context, *transport.TPMPolicyRequest) (*transport.TPMPolicy, error) {
	return nil, f.err
}
func (f *failingTPMPolicies) TPMPolicyList(context.Context, *transport.TPMPolicyListRequest) (*transport.TPMPolicyListResponse, error) {
	return nil, f.err
}
func (f *failingTPMPolicies) TPMPolicyUpdate(context.Context, *transport.TPMPolicyRequest) (*transport.TPMPolicy, error) {
	return nil, f.err
}
func (f *failingTPMPolicies) TPMPolicyRevoke(context.Context, *transport.TPMPolicyRequest) (*transport.TPMPolicy, error) {
	return nil, f.err
}
func (f *failingTPMPolicies) TPMPolicyVerify(context.Context, *transport.TPMPolicyRequest) (*transport.TPMPolicyVerifyResponse, error) {
	return nil, f.err
}
func (f *failingTPMPolicies) TPMPolicyDelete(context.Context, *transport.TPMPolicyDeleteRequest) error {
	return f.err
}
func (f *failingTPMPolicies) TPMPolicyObjects(context.Context, *transport.TPMPolicyRequest) (*transport.TPMPolicyObjectsResponse, error) {
	return nil, f.err
}
func (f *failingTPMPolicies) TPMPolicySetAutoUnseal(context.Context, *transport.TPMPolicyAutoUnsealRequest) (*transport.TPMPolicy, error) {
	return nil, f.err
}
func (f *failingTPMPolicies) TPMObjectPolicy(context.Context, *transport.TPMObjectPolicyRequest) (*transport.TPMObjectPolicyResponse, error) {
	return nil, f.err
}
func (f *failingTPMPolicies) TPMPolicyRotateAuthority(context.Context, *transport.TPMAuthorityRotateRequest) (*transport.TPMAuthorityRotateResponse, error) {
	return nil, f.err
}

func TestTPMPolicyService_ServerErrorsPropagate(t *testing.T) {
	errServer := errors.New("server unavailable")
	svc := NewTPMPolicyService()
	svc.SetClient(&failingTPMPolicies{err: errServer})

	calls := map[string]func() error{
		"CreatePolicy": func() error { _, err := svc.CreatePolicy("boot", "sha256", []uint{7}, false, "owner"); return err },
		"ListPolicies": func() error { _, err := svc.ListPolicies(); return err },
		"GetPolicy":    func() error { _, err := svc.GetPolicy("boot"); return err },
		"UpdatePolicy": func() error { _, err := svc.UpdatePolicy("boot"); return err },
		"RevokePolicy": func() error { _, err := svc.RevokePolicy("boot"); return err },
		"VerifyPolicy": func() error { _, err := svc.VerifyPolicy("boot"); return err },
		"DeletePolicy": func() error { return svc.DeletePolicy("boot", "owner") },
		"PolicyObjects": func() error {
			_, err := svc.PolicyObjects("boot")
			return err
		},
		"KeyPolicy":       func() error { _, err := svc.KeyPolicy("k1"); return err },
		"SetAutoUnseal":   func() error { _, err := svc.SetAutoUnseal("boot", true); return err },
		"RotateAuthority": func() error { _, err := svc.RotateAuthority(); return err },
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			assert.ErrorIs(t, call(), errServer)
		})
	}
}

// objectsFailing is a server whose object listing fails, so the counts the
// policy operations add cannot be computed.
type objectsFailing struct {
	tpmpolicyfake.Fake
	err error
}

func (o *objectsFailing) TPMPolicyObjects(context.Context, *transport.TPMPolicyRequest) (*transport.TPMPolicyObjectsResponse, error) {
	return nil, o.err
}

func TestTPMPolicyService_ObjectCountErrorsPropagate(t *testing.T) {
	errObjects := errors.New("objects unavailable")
	server := &objectsFailing{err: errObjects}
	svc := NewTPMPolicyService()
	svc.SetClient(server)
	_, err := server.TPMPolicyCreate(context.Background(), &transport.TPMPolicyCreateRequest{Name: "boot", PCRs: []uint{7}})
	require.NoError(t, err)

	_, err = svc.ListPolicies()
	assert.ErrorIs(t, err, errObjects)
	_, err = svc.GetPolicy("boot")
	assert.ErrorIs(t, err, errObjects)
	_, err = svc.UpdatePolicy("boot")
	assert.ErrorIs(t, err, errObjects)
	_, err = svc.SetAutoUnseal("boot", true)
	assert.ErrorIs(t, err, errObjects)
}

func TestOwnerAuthBytes(t *testing.T) {
	assert.Nil(t, ownerAuthBytes(""))
	assert.Equal(t, []byte("owner"), ownerAuthBytes("owner"))
}

func TestLocalTPMPolicies_AccessorSerializesAndReportsAnUnavailableTPM(t *testing.T) {
	l := &LocalTPMPolicies{accessor: NewTPMAccessor(func() xkms.TrustedPlatformModule { return nil })}
	assert.ErrorIs(t, l.Assign(context.Background(), xkms.TPMObjectKindKey, "k1", ""), ErrTPMNotAvailable)
	_, err := l.AutoUnsealPolicy(context.Background())
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
	_, err = l.UnsealObject(context.Background(), "obj")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}
