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

// Package tpmpolicytest builds TPM policy services for tests that exercise
// the API layers above pkg/tpmpolicy without a TPM.
package tpmpolicytest

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/tpmblobtest"
	pkgtpm2 "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	tpmpolicy "github.com/jeremyhahn/go-xkms/pkg/tpm2/policy"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// NewOffline returns a real tpmpolicy.Service over in-memory stores and an
// unopened TPM, and its registry. Every operation that reads or writes only
// the registry works -- tenant modes none and vtpm (refused without a vTPM
// supervisor), listing, object assignments -- while one that reaches the TPM
// must not be called. It exercises the transports, tenant binding and error
// mapping above the service without a TPM; the service's TPM behaviour is
// tested over the simulator. The service is closed when the test ends.
func NewOffline(t *testing.T) (*tpmpolicy.Service, *tpmpolicy.Registry) {
	t.Helper()
	registry, err := tpmpolicy.NewRegistry(testutil.NewMemoryDAOFactory(), 0)
	require.NoError(t, err)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	tpm := &pkgtpm2.TPM2{}
	svc, err := tpmpolicy.NewService(tpmpolicy.Config{
		Registry:    registry,
		TPM:         tpm,
		PlatformSRK: &types.KeyAttributes{TPMAttributes: &types.TPMAttributes{}},
		Keys:        tpmblobtest.New(t),
		TenantKeys:  tpmblobtest.New(t),
		Sealer:      tpm,
		Logger:      logger,
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, svc.Close()) })
	return svc, registry
}

// Calls returns one call of every transport.TPMPolicyService method on svc,
// keyed by method name, each with a minimal well-formed request naming the
// caller's own scope: policy "boot", key "signer", and tenant "acme" for the
// tenant methods. A test runs them to prove a property of the whole method
// set, such as refusing before a transport is connected.
func Calls(ctx context.Context, svc transport.TPMPolicyService) map[string]func() error {
	return map[string]func() error{
		"TPMPolicyCreate": func() error {
			_, err := svc.TPMPolicyCreate(ctx, &transport.TPMPolicyCreateRequest{
				Name: "boot", Branches: []transport.TPMPolicyBranch{transport.TPMPolicyPCRBranch("sha256", []uint{7})},
			})
			return err
		},
		"TPMPolicyGet":  func() error { _, err := svc.TPMPolicyGet(ctx, &transport.TPMPolicyRequest{Name: "boot"}); return err },
		"TPMPolicyList": func() error { _, err := svc.TPMPolicyList(ctx, &transport.TPMPolicyListRequest{}); return err },
		"TPMPolicyUpdate": func() error {
			_, err := svc.TPMPolicyUpdate(ctx, &transport.TPMPolicyRequest{Name: "boot"})
			return err
		},
		"TPMPolicyRevoke": func() error {
			_, err := svc.TPMPolicyRevoke(ctx, &transport.TPMPolicyRequest{Name: "boot"})
			return err
		},
		"TPMPolicyVerify": func() error {
			_, err := svc.TPMPolicyVerify(ctx, &transport.TPMPolicyRequest{Name: "boot"})
			return err
		},
		"TPMPolicyDelete": func() error { return svc.TPMPolicyDelete(ctx, &transport.TPMPolicyDeleteRequest{Name: "boot"}) },
		"TPMPolicyObjects": func() error {
			_, err := svc.TPMPolicyObjects(ctx, &transport.TPMPolicyRequest{Name: "boot"})
			return err
		},
		"TPMPolicySetAutoUnseal": func() error {
			_, err := svc.TPMPolicySetAutoUnseal(ctx, &transport.TPMPolicyAutoUnsealRequest{Name: "boot", Enabled: true})
			return err
		},
		"TPMPolicySetDescription": func() error {
			_, err := svc.TPMPolicySetDescription(ctx, &transport.TPMPolicyDescriptionRequest{Name: "boot", Description: "boot chain"})
			return err
		},
		"TPMObjectPolicy": func() error {
			_, err := svc.TPMObjectPolicy(ctx, &transport.TPMObjectPolicyRequest{KeyID: "signer"})
			return err
		},
		"TPMPolicyRotateAuthority": func() error {
			_, err := svc.TPMPolicyRotateAuthority(ctx, &transport.TPMAuthorityRotateRequest{})
			return err
		},
		"GetTenantTPMMode": func() error { _, err := svc.GetTenantTPMMode(ctx, "acme"); return err },
		"SetTenantTPMMode": func() error {
			_, err := svc.SetTenantTPMMode(ctx, &transport.SetTenantTPMModeRequest{TenantID: "acme", Mode: "none"})
			return err
		},
		"TenantVTPMStatus": func() error { _, err := svc.TenantVTPMStatus(ctx, "acme"); return err },
		"TenantVTPMStart":  func() error { _, err := svc.TenantVTPMStart(ctx, "acme"); return err },
		"TenantVTPMStop":   func() error { _, err := svc.TenantVTPMStop(ctx, "acme"); return err },
	}
}
