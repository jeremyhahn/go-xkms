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

// policy_run_test.go exercises the "xkmsctl policy" command tree against a
// mock PolicyService, covering the happy path and error handling for each
// subcommand.
package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/spf13/pflag"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

var errPolicyRunBoom = errors.New("boom")

// clearPCRs empties the create command's --pcrs IntSlice. resetCmdFlags sets
// each flag to its DefValue, but pflag's IntSlice.Set appends rather than
// replaces, so a value from a prior test would otherwise leak forward.
func clearPCRs(t *testing.T) {
	t.Helper()
	if sv, ok := policyCreateCmd.Flags().Lookup("pcrs").Value.(pflag.SliceValue); ok {
		_ = sv.Replace(nil)
	}
}

// mockPolicyClient implements the PolicyService subset of client.Client used
// by the policy commands; every other method comes from the embedded base.
type mockPolicyClient struct {
	mockBackendsClient

	createResp *transport.PolicyCreateResponse
	createErr  error
	listResp   *transport.PolicyListResponse
	listErr    error
	getResp    *transport.PolicyGetResponse
	getErr     error
	deleteErr  error
	refreshOut *transport.PolicyGetResponse
	refreshErr error
	verifyResp *transport.PolicyVerifyResponse
	verifyErr  error
	exportResp *transport.PolicyExportResponse
	exportErr  error

	gotCreateReq *transport.PolicyCreateRequest
	gotGetReq    *transport.PolicyGetRequest
	gotDeleteReq *transport.PolicyDeleteRequest
	gotVerifyReq *transport.PolicyVerifyRequest
	gotExportReq *transport.PolicyExportRequest
}

func (m *mockPolicyClient) PolicyCreate(_ context.Context, req *transport.PolicyCreateRequest) (*transport.PolicyCreateResponse, error) {
	m.gotCreateReq = req
	return m.createResp, m.createErr
}

func (m *mockPolicyClient) PolicyList(_ context.Context) (*transport.PolicyListResponse, error) {
	return m.listResp, m.listErr
}

func (m *mockPolicyClient) PolicyGet(_ context.Context, req *transport.PolicyGetRequest) (*transport.PolicyGetResponse, error) {
	m.gotGetReq = req
	return m.getResp, m.getErr
}

func (m *mockPolicyClient) PolicyDelete(_ context.Context, req *transport.PolicyDeleteRequest) error {
	m.gotDeleteReq = req
	return m.deleteErr
}

func (m *mockPolicyClient) PolicyRefresh(_ context.Context, _ *transport.PolicyRefreshRequest) (*transport.PolicyGetResponse, error) {
	return m.refreshOut, m.refreshErr
}

func (m *mockPolicyClient) PolicyVerify(_ context.Context, req *transport.PolicyVerifyRequest) (*transport.PolicyVerifyResponse, error) {
	m.gotVerifyReq = req
	return m.verifyResp, m.verifyErr
}

func (m *mockPolicyClient) PolicyExport(_ context.Context, req *transport.PolicyExportRequest) (*transport.PolicyExportResponse, error) {
	m.gotExportReq = req
	return m.exportResp, m.exportErr
}

func newPolicyConfig(mock *mockPolicyClient) *Config {
	return &Config{
		OutputFormat: "text",
		ClientFactory: func(*Config) (client.Client, error) {
			return mock, nil
		},
	}
}

func TestPolicyCreateCmd_Success(t *testing.T) {
	resetCmdFlags(t, policyCreateCmd)
	clearPCRs(t)
	t.Cleanup(func() { resetCmdFlags(t, policyCreateCmd); clearPCRs(t) })
	mock := &mockPolicyClient{createResp: &transport.PolicyCreateResponse{
		Name: "boot", Bank: "sha256", PCRs: []int{0, 7},
	}}
	withGlobalConfig(t, newPolicyConfig(mock))
	_ = policyCreateCmd.Flags().Set("pcrs", "0,7")

	out := captureStdout(t, func() {
		policyCreateCmd.Run(policyCreateCmd, []string{"boot"})
	})
	if mock.gotCreateReq == nil || mock.gotCreateReq.Name != "boot" {
		t.Fatalf("PolicyCreate request mismatch: %+v", mock.gotCreateReq)
	}
	if len(mock.gotCreateReq.PCRs) != 2 {
		t.Errorf("expected 2 PCRs, got %v", mock.gotCreateReq.PCRs)
	}
	if !strings.Contains(out, "boot") {
		t.Errorf("expected policy name in output, got %q", out)
	}
}

func TestPolicyCreateCmd_RequiresPCRs(t *testing.T) {
	resetCmdFlags(t, policyCreateCmd)
	clearPCRs(t)
	t.Cleanup(func() { resetCmdFlags(t, policyCreateCmd); clearPCRs(t) })
	withGlobalConfig(t, newPolicyConfig(&mockPolicyClient{}))

	code := captureExit(t, func() {
		policyCreateCmd.Run(policyCreateCmd, []string{"boot"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1 without --pcrs, got %d", code)
	}
}

func TestPolicyCreateCmd_Error(t *testing.T) {
	resetCmdFlags(t, policyCreateCmd)
	clearPCRs(t)
	t.Cleanup(func() { resetCmdFlags(t, policyCreateCmd); clearPCRs(t) })
	withGlobalConfig(t, newPolicyConfig(&mockPolicyClient{createErr: errPolicyRunBoom}))
	_ = policyCreateCmd.Flags().Set("pcrs", "0,7")

	code := captureExit(t, func() {
		policyCreateCmd.Run(policyCreateCmd, []string{"boot"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestPolicyListCmd_Success(t *testing.T) {
	withGlobalConfig(t, newPolicyConfig(&mockPolicyClient{listResp: &transport.PolicyListResponse{
		Policies: []transport.PolicyGetResponse{{Name: "boot", Bank: "sha256"}},
	}}))

	out := captureStdout(t, func() {
		policyListCmd.Run(policyListCmd, nil)
	})
	if !strings.Contains(out, "boot") {
		t.Errorf("expected policy in list output, got %q", out)
	}
}

func TestPolicyListCmd_Error(t *testing.T) {
	withGlobalConfig(t, newPolicyConfig(&mockPolicyClient{listErr: errPolicyRunBoom}))

	code := captureExit(t, func() {
		policyListCmd.Run(policyListCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestPolicyGetCmd_SuccessAndError(t *testing.T) {
	withGlobalConfig(t, newPolicyConfig(&mockPolicyClient{getResp: &transport.PolicyGetResponse{Name: "boot"}}))
	out := captureStdout(t, func() {
		policyGetCmd.Run(policyGetCmd, []string{"boot"})
	})
	if !strings.Contains(out, "boot") {
		t.Errorf("expected policy name, got %q", out)
	}

	withGlobalConfig(t, newPolicyConfig(&mockPolicyClient{getErr: errPolicyRunBoom}))
	code := captureExit(t, func() {
		policyGetCmd.Run(policyGetCmd, []string{"boot"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestPolicyDeleteCmd_SuccessAndError(t *testing.T) {
	mock := &mockPolicyClient{}
	withGlobalConfig(t, newPolicyConfig(mock))
	captureStdout(t, func() {
		policyDeleteCmd.Run(policyDeleteCmd, []string{"boot"})
	})
	if mock.gotDeleteReq == nil || mock.gotDeleteReq.Name != "boot" {
		t.Errorf("PolicyDelete request mismatch: %+v", mock.gotDeleteReq)
	}

	withGlobalConfig(t, newPolicyConfig(&mockPolicyClient{deleteErr: errPolicyRunBoom}))
	code := captureExit(t, func() {
		policyDeleteCmd.Run(policyDeleteCmd, []string{"boot"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestPolicyVerifyCmd_SuccessAndError(t *testing.T) {
	withGlobalConfig(t, newPolicyConfig(&mockPolicyClient{verifyResp: &transport.PolicyVerifyResponse{
		Name: "boot", Valid: true,
	}}))
	out := captureStdout(t, func() {
		policyVerifyCmd.Run(policyVerifyCmd, []string{"boot"})
	})
	if !strings.Contains(strings.ToLower(out), "boot") {
		t.Errorf("expected verify output to mention policy, got %q", out)
	}

	withGlobalConfig(t, newPolicyConfig(&mockPolicyClient{verifyErr: errPolicyRunBoom}))
	code := captureExit(t, func() {
		policyVerifyCmd.Run(policyVerifyCmd, []string{"boot"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestPolicyExportCmd_SuccessAndError(t *testing.T) {
	resetCmdFlags(t, policyExportCmd)
	t.Cleanup(func() { resetCmdFlags(t, policyExportCmd) })
	withGlobalConfig(t, newPolicyConfig(&mockPolicyClient{exportResp: &transport.PolicyExportResponse{
		Data: "policy-blob",
	}}))
	out := captureStdout(t, func() {
		policyExportCmd.Run(policyExportCmd, []string{"boot"})
	})
	if !strings.Contains(out, "policy-blob") {
		t.Errorf("expected exported data in output, got %q", out)
	}

	resetCmdFlags(t, policyExportCmd)
	withGlobalConfig(t, newPolicyConfig(&mockPolicyClient{exportErr: errPolicyRunBoom}))
	code := captureExit(t, func() {
		policyExportCmd.Run(policyExportCmd, []string{"boot"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}
