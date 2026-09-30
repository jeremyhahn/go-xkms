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

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
)

// errTPMRunBoom stands in for a server failure.
var errTPMRunBoom = errors.New("boom")

// mockTPMClient serves the TPM policy API of client.Client from canned
// answers and records every request; every other method comes from the
// embedded base.
type mockTPMClient struct {
	mockBackendsClient

	policy       *client.TPMPolicy
	list         *client.TPMPolicyListResponse
	verification *client.TPMPolicyVerifyResponse
	objects      *client.TPMPolicyObjectsResponse
	object       *client.TPMObjectPolicyResponse
	authority    *client.TPMAuthorityRotateResponse
	mode         *client.TenantTPMModeResponse
	vtpm         *client.TenantVTPMStatusResponse
	err          error

	// requests records each call's request, keyed by method.
	requests map[string]any
}

func (m *mockTPMClient) record(method string, req any) error {
	if m.requests == nil {
		m.requests = map[string]any{}
	}
	m.requests[method] = req
	return m.err
}

func (m *mockTPMClient) TPMPolicyCreate(_ context.Context, req *client.TPMPolicyCreateRequest) (*client.TPMPolicy, error) {
	return m.policy, m.record("create", req)
}
func (m *mockTPMClient) TPMPolicyGet(_ context.Context, req *client.TPMPolicyRequest) (*client.TPMPolicy, error) {
	return m.policy, m.record("get", req)
}
func (m *mockTPMClient) TPMPolicyList(_ context.Context, req *client.TPMPolicyListRequest) (*client.TPMPolicyListResponse, error) {
	return m.list, m.record("list", req)
}
func (m *mockTPMClient) TPMPolicyUpdate(_ context.Context, req *client.TPMPolicyRequest) (*client.TPMPolicy, error) {
	return m.policy, m.record("update", req)
}
func (m *mockTPMClient) TPMPolicyRevoke(_ context.Context, req *client.TPMPolicyRequest) (*client.TPMPolicy, error) {
	return m.policy, m.record("revoke", req)
}
func (m *mockTPMClient) TPMPolicyVerify(_ context.Context, req *client.TPMPolicyRequest) (*client.TPMPolicyVerifyResponse, error) {
	return m.verification, m.record("verify", req)
}
func (m *mockTPMClient) TPMPolicyDelete(_ context.Context, req *client.TPMPolicyDeleteRequest) error {
	return m.record("delete", req)
}
func (m *mockTPMClient) TPMPolicyObjects(_ context.Context, req *client.TPMPolicyRequest) (*client.TPMPolicyObjectsResponse, error) {
	return m.objects, m.record("objects", req)
}
func (m *mockTPMClient) TPMPolicySetAutoUnseal(_ context.Context, req *client.TPMPolicyAutoUnsealRequest) (*client.TPMPolicy, error) {
	return m.policy, m.record("auto", req)
}
func (m *mockTPMClient) TPMPolicySetDescription(_ context.Context, req *client.TPMPolicyDescriptionRequest) (*client.TPMPolicy, error) {
	return m.policy, m.record("describe", req)
}
func (m *mockTPMClient) TPMObjectPolicy(_ context.Context, req *client.TPMObjectPolicyRequest) (*client.TPMObjectPolicyResponse, error) {
	return m.object, m.record("object", req)
}
func (m *mockTPMClient) TPMPolicyRotateAuthority(_ context.Context, req *client.TPMAuthorityRotateRequest) (*client.TPMAuthorityRotateResponse, error) {
	return m.authority, m.record("rotate", req)
}
func (m *mockTPMClient) GetTenantTPMMode(_ context.Context, tenantID string) (*client.TenantTPMModeResponse, error) {
	return m.mode, m.record("getMode", tenantID)
}
func (m *mockTPMClient) SetTenantTPMMode(_ context.Context, req *client.SetTenantTPMModeRequest) (*client.TenantTPMModeResponse, error) {
	return m.mode, m.record("setMode", req)
}
func (m *mockTPMClient) TenantVTPMStatus(_ context.Context, tenantID string) (*client.TenantVTPMStatusResponse, error) {
	return m.vtpm, m.record("status", tenantID)
}
func (m *mockTPMClient) TenantVTPMStart(_ context.Context, tenantID string) (*client.TenantVTPMStatusResponse, error) {
	return m.vtpm, m.record("start", tenantID)
}
func (m *mockTPMClient) TenantVTPMStop(_ context.Context, tenantID string) (*client.TenantVTPMStatusResponse, error) {
	return m.vtpm, m.record("stop", tenantID)
}

// runTPMCmd runs cmd with args and flags over mock and returns its output
// and exit code (-1 when it did not exit).
func runTPMCmd(t *testing.T, mock *mockTPMClient, cmd *cobra.Command, args []string, flags map[string]string) (string, int) {
	t.Helper()
	pairs := make([][2]string, 0, len(flags))
	for name, value := range flags {
		pairs = append(pairs, [2]string{name, value})
	}
	return runTPMCmdFlags(t, mock, cmd, args, pairs...)
}

// runTPMCmdFlags is runTPMCmd with flags set in order, so a repeatable flag
// can be set more than once.
func runTPMCmdFlags(t *testing.T, mock *mockTPMClient, cmd *cobra.Command, args []string, flags ...[2]string) (string, int) {
	t.Helper()
	resetTPMCmdFlags(t, cmd)
	t.Cleanup(func() { resetTPMCmdFlags(t, cmd) })
	withGlobalConfig(t, &Config{
		OutputFormat:  "text",
		ClientFactory: func(*Config) (client.Client, error) { return mock, nil },
	})
	for _, flag := range flags {
		require.NoError(t, cmd.Flags().Set(flag[0], flag[1]))
	}
	code := -1
	out := captureStdout(t, func() {
		code = captureExit(t, func() { cmd.Run(cmd, args) })
	})
	return out, code
}

// resetTPMCmdFlags resets cmd's flags to their defaults, emptying slice
// flags, whose Set appends.
func resetTPMCmdFlags(t *testing.T, cmd *cobra.Command) {
	t.Helper()
	resetCmdFlags(t, cmd)
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		if sv, ok := f.Value.(pflag.SliceValue); ok {
			require.NoError(t, sv.Replace(nil))
		}
	})
}

// pcrBranch is the one pcr branch --pcrs 0,7 describes.
func pcrBranch() []client.TPMPolicyBranch {
	return []client.TPMPolicyBranch{client.TPMPolicyPCRBranch("sha256", []uint{0, 7})}
}

// TestTPMPolicyCreateCmd sends the policy's name, description, the one pcr
// branch --pcrs describes, tenant and auto-unseal mark, and prints the
// created policy.
func TestTPMPolicyCreateCmd(t *testing.T) {
	created := &client.TPMPolicy{Name: "boot", Description: "firmware", Approved: true, Branches: []client.TPMPolicyBranch{{
		Conditions: []client.TPMPolicyCondition{{Type: "pcr", Bank: "sha256", PCRs: []uint{0, 7}, PCRValues: map[uint]string{7: "aa"}}},
		Approved:   true,
	}}}
	mock := &mockTPMClient{policy: created}
	out, code := runTPMCmd(t, mock, tpmPolicyCreateCmd, []string{"boot"},
		map[string]string{"pcrs": "0,7", "tenant": "acme", "auto-unseal": "true", "description": "firmware"})
	assert.Equal(t, -1, code)
	req := mock.requests["create"].(*client.TPMPolicyCreateRequest)
	assert.Equal(t, &client.TPMPolicyCreateRequest{TenantID: "acme", Name: "boot", Description: "firmware", Branches: pcrBranch(), AutoUnseal: true}, req)
	assert.Contains(t, out, "TPM Policy Created")
	assert.Contains(t, out, "Description: firmware")
	assert.Contains(t, out, "pcr=sha256:0,7")
	assert.Contains(t, out, "PCR 7")
}

// TestTPMPolicyCreateCmd_Branches sends each --branch as one branch, in
// order.
func TestTPMPolicyCreateCmd_Branches(t *testing.T) {
	mock := &mockTPMClient{policy: &client.TPMPolicy{Name: "strict"}}
	_, code := runTPMCmdFlags(t, mock, tpmPolicyCreateCmd, []string{"strict"},
		[2]string{"branch", "pcr=sha384:0,7;auth_value;locality=0"}, [2]string{"branch", "auth_value"})
	assert.Equal(t, -1, code)
	req := mock.requests["create"].(*client.TPMPolicyCreateRequest)
	assert.Equal(t, []client.TPMPolicyBranch{
		{Conditions: []client.TPMPolicyCondition{
			{Type: "pcr", Bank: "sha384", PCRs: []uint{0, 7}},
			{Type: "auth_value"},
			{Type: "locality", Localities: []uint{0}},
		}},
		{Conditions: []client.TPMPolicyCondition{{Type: "auth_value"}}},
	}, req.Branches)
}

// TestTPMPolicyCreateCmd_Refusals exits non-zero, sending nothing, without
// --pcrs or --branch, with a negative PCR, with --pcrs or --bank beside
// --branch, or with a malformed --branch; and when the server refuses.
func TestTPMPolicyCreateCmd_Refusals(t *testing.T) {
	for name, flags := range map[string]map[string]string{
		"no selection":    nil,
		"negative PCR":    {"pcrs": "-1"},
		"pcrs and branch": {"pcrs": "7", "branch": "auth_value"},
		"bank and branch": {"bank": "sha1", "branch": "auth_value"},
		"bad branch":      {"branch": "time=5"},
	} {
		t.Run(name, func(t *testing.T) {
			mock := &mockTPMClient{}
			_, code := runTPMCmd(t, mock, tpmPolicyCreateCmd, []string{"boot"}, flags)
			assert.Equal(t, 1, code)
			assert.Empty(t, mock.requests, "nothing is sent")
		})
	}

	_, code := runTPMCmd(t, &mockTPMClient{err: errTPMRunBoom}, tpmPolicyCreateCmd, []string{"boot"}, map[string]string{"pcrs": "7"})
	assert.Equal(t, 1, code)
}

// TestTPMPolicyDescribeCmd sends the name, tenant and text, and exits
// non-zero on a server error.
func TestTPMPolicyDescribeCmd(t *testing.T) {
	mock := &mockTPMClient{policy: &client.TPMPolicy{Name: "boot", Description: "firmware"}}
	out, code := runTPMCmd(t, mock, tpmPolicyDescribeCmd, []string{"boot", "firmware"}, map[string]string{"tenant": "acme"})
	assert.Equal(t, -1, code)
	assert.Equal(t, &client.TPMPolicyDescriptionRequest{TenantID: "acme", Name: "boot", Description: "firmware"}, mock.requests["describe"])
	assert.Contains(t, out, "Description: firmware")

	_, code = runTPMCmd(t, &mockTPMClient{err: errTPMRunBoom}, tpmPolicyDescribeCmd, []string{"boot", ""}, nil)
	assert.Equal(t, 1, code)
}

// TestTPMPolicyListCmd prints a table of policies, or a note when there
// are none, and exits non-zero on a server error.
func TestTPMPolicyListCmd(t *testing.T) {
	mock := &mockTPMClient{list: &client.TPMPolicyListResponse{Policies: []client.TPMPolicy{{Name: "boot", Description: "firmware", Branches: pcrBranch()}}}}
	out, code := runTPMCmd(t, mock, tpmPolicyListCmd, nil, map[string]string{"tenant": "acme"})
	assert.Equal(t, -1, code)
	assert.Contains(t, out, "boot")
	assert.Contains(t, out, "pcr=sha256:0,7")
	assert.Contains(t, out, "firmware")
	assert.Equal(t, "acme", mock.requests["list"].(*client.TPMPolicyListRequest).TenantID)

	out, _ = runTPMCmd(t, &mockTPMClient{list: &client.TPMPolicyListResponse{}}, tpmPolicyListCmd, nil, nil)
	assert.Contains(t, out, "No TPM policies found")

	_, code = runTPMCmd(t, &mockTPMClient{err: errTPMRunBoom}, tpmPolicyListCmd, nil, nil)
	assert.Equal(t, 1, code)
}

// TestTPMPolicyNameCmds sends each policy-name command's name and tenant,
// prints its answer, and exits non-zero on a server error.
func TestTPMPolicyNameCmds(t *testing.T) {
	tests := []struct {
		cmd    *cobra.Command
		method string
		want   string
	}{
		{tpmPolicyGetCmd, "get", "TPM Policy:"},
		{tpmPolicyUpdateCmd, "update", "TPM Policy Updated"},
		{tpmPolicyRevokeCmd, "revoke", "TPM Policy Revoked"},
		{tpmPolicyObjectsCmd, "objects", "key/a"},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			mock := &mockTPMClient{
				policy:  &client.TPMPolicy{Name: "boot"},
				objects: &client.TPMPolicyObjectsResponse{Name: "boot", Objects: []string{"key/a"}},
			}
			out, code := runTPMCmd(t, mock, tt.cmd, []string{"boot"}, map[string]string{"tenant": "acme"})
			assert.Equal(t, -1, code)
			assert.Equal(t, &client.TPMPolicyRequest{TenantID: "acme", Name: "boot"}, mock.requests[tt.method])
			assert.Contains(t, out, tt.want)

			_, code = runTPMCmd(t, &mockTPMClient{err: errTPMRunBoom}, tt.cmd, []string{"boot"}, nil)
			assert.Equal(t, 1, code)
		})
	}
}

// TestTPMPolicyVerifyCmd reports each branch and succeeds only when every
// branch's live PCRs match and it is approved.
func TestTPMPolicyVerifyCmd(t *testing.T) {
	out, code := runTPMCmd(t, &mockTPMClient{verification: &client.TPMPolicyVerifyResponse{
		Name: "boot", Match: true, Approved: true, Branches: []client.TPMPolicyBranchVerification{{Match: true, Approved: true}},
	}}, tpmPolicyVerifyCmd, []string{"boot"}, nil)
	assert.Equal(t, -1, code)
	assert.Contains(t, out, "Branch 0: PCRs match, approved: true")
	assert.Contains(t, out, "matches the live PCR values")

	out, code = runTPMCmd(t, &mockTPMClient{verification: &client.TPMPolicyVerifyResponse{
		Name: "boot", Approved: true, Branches: []client.TPMPolicyBranchVerification{{Mismatched: []uint{7}, Approved: true}},
	}}, tpmPolicyVerifyCmd, []string{"boot"}, nil)
	assert.Equal(t, 1, code, "a PCR mismatch fails the command")
	assert.Contains(t, out, "PCRs [7] differ")

	_, code = runTPMCmd(t, &mockTPMClient{verification: &client.TPMPolicyVerifyResponse{Name: "boot", Match: true}},
		tpmPolicyVerifyCmd, []string{"boot"}, nil)
	assert.Equal(t, 1, code, "an unapproved policy fails the command")
}

// TestTPMPolicyDeleteCmd sends the name and owner authorization and reports
// a refusal, such as a policy still in use, as a failure.
func TestTPMPolicyDeleteCmd(t *testing.T) {
	mock := &mockTPMClient{}
	out, code := runTPMCmd(t, mock, tpmPolicyDeleteCmd, []string{"boot"}, map[string]string{"owner-auth": "owner-secret"})
	assert.Equal(t, -1, code)
	assert.Contains(t, out, `TPM policy "boot" deleted`)
	assert.Equal(t, []byte("owner-secret"), mock.requests["delete"].(*client.TPMPolicyDeleteRequest).OwnerAuth)

	_, code = runTPMCmd(t, &mockTPMClient{err: errTPMRunBoom}, tpmPolicyDeleteCmd, []string{"boot"}, nil)
	assert.Equal(t, 1, code)
}

// TestTPMPolicyAutoUnsealCmd sets the mark, or clears it with --disable.
func TestTPMPolicyAutoUnsealCmd(t *testing.T) {
	mock := &mockTPMClient{policy: &client.TPMPolicy{Name: "boot"}}
	_, code := runTPMCmd(t, mock, tpmPolicyAutoUnsealCmd, []string{"boot"}, nil)
	assert.Equal(t, -1, code)
	assert.True(t, mock.requests["auto"].(*client.TPMPolicyAutoUnsealRequest).Enabled)

	_, code = runTPMCmd(t, mock, tpmPolicyAutoUnsealCmd, []string{"boot"}, map[string]string{"disable": "true"})
	assert.Equal(t, -1, code)
	assert.False(t, mock.requests["auto"].(*client.TPMPolicyAutoUnsealRequest).Enabled)

	_, code = runTPMCmd(t, &mockTPMClient{err: errTPMRunBoom}, tpmPolicyAutoUnsealCmd, []string{"boot"}, nil)
	assert.Equal(t, 1, code)
}

// TestTPMAuthorityRotateCmd rotates the tenant's authority and prints it.
func TestTPMAuthorityRotateCmd(t *testing.T) {
	mock := &mockTPMClient{authority: &client.TPMAuthorityRotateResponse{Generation: 2, AuthorityName: "000b", Epoch: 3}}
	out, code := runTPMCmd(t, mock, tpmAuthorityRotateCmd, nil, nil)
	assert.Equal(t, -1, code)
	assert.Contains(t, out, "Generation: 2")
	assert.Contains(t, out, "system")

	_, code = runTPMCmd(t, &mockTPMClient{err: errTPMRunBoom}, tpmAuthorityRotateCmd, nil, nil)
	assert.Equal(t, 1, code)
}

// TestKeyPolicyCmd asks for a key's policy, or a sealed object's with
// --sealed.
func TestKeyPolicyCmd(t *testing.T) {
	mock := &mockTPMClient{object: &client.TPMObjectPolicyResponse{ObjectID: "key/signer", Policy: "boot", AuthPolicy: "ab"}}
	out, code := runTPMCmd(t, mock, keyPolicyCmd, []string{"signer"}, nil)
	assert.Equal(t, -1, code)
	assert.Contains(t, out, "TPM Policy:  boot")
	assert.Equal(t, client.TPMObjectKindKey, mock.requests["object"].(*client.TPMObjectPolicyRequest).Kind)

	_, code = runTPMCmd(t, mock, keyPolicyCmd, []string{"vault"}, map[string]string{"sealed": "true"})
	assert.Equal(t, -1, code)
	assert.Equal(t, client.TPMObjectKindSealed, mock.requests["object"].(*client.TPMObjectPolicyRequest).Kind)

	_, code = runTPMCmd(t, &mockTPMClient{err: errTPMRunBoom}, keyPolicyCmd, []string{"signer"}, nil)
	assert.Equal(t, 1, code)
}

// TestTenantTPMModeCmd shows a tenant's mode, or sets it when a mode is
// given.
func TestTenantTPMModeCmd(t *testing.T) {
	mock := &mockTPMClient{mode: &client.TenantTPMModeResponse{TenantID: "acme", Mode: "shared"}}
	out, code := runTPMCmd(t, mock, tenantTPMModeCmd, []string{"acme"}, nil)
	assert.Equal(t, -1, code)
	assert.Contains(t, out, "Tenant acme TPM mode: shared")
	assert.Equal(t, "acme", mock.requests["getMode"])

	_, code = runTPMCmd(t, mock, tenantTPMModeCmd, []string{"acme", "VTPM"}, nil)
	assert.Equal(t, -1, code)
	assert.Equal(t, &client.SetTenantTPMModeRequest{TenantID: "acme", Mode: "vtpm"}, mock.requests["setMode"])

	_, code = runTPMCmd(t, &mockTPMClient{err: errTPMRunBoom}, tenantTPMModeCmd, []string{"acme", "none"}, nil)
	assert.Equal(t, 1, code)
}

// TestTenantVTPMCmds shows, starts and stops a tenant's vTPM.
func TestTenantVTPMCmds(t *testing.T) {
	for method, cmd := range map[string]*cobra.Command{"status": tenantVTPMStatusCmd, "start": tenantVTPMStartCmd, "stop": tenantVTPMStopCmd} {
		t.Run(method, func(t *testing.T) {
			mock := &mockTPMClient{vtpm: &client.TenantVTPMStatusResponse{TenantID: "acme", Running: true, PID: 42}}
			out, code := runTPMCmd(t, mock, cmd, []string{"acme"}, nil)
			assert.Equal(t, -1, code)
			assert.Equal(t, "acme", mock.requests[method])
			assert.Contains(t, out, "PID:      42")

			_, code = runTPMCmd(t, &mockTPMClient{err: errTPMRunBoom}, cmd, []string{"acme"}, nil)
			assert.Equal(t, 1, code)
		})
	}
}

// TestPCRIndices converts --pcrs, refusing a negative index.
func TestPCRIndices(t *testing.T) {
	got, err := pcrIndices([]int{0, 7})
	require.NoError(t, err)
	assert.Equal(t, []uint{0, 7}, got)

	got, err = pcrIndices(nil)
	require.NoError(t, err)
	assert.Empty(t, got)
	_, err = pcrIndices([]int{7, -2})
	assert.ErrorIs(t, err, ErrInvalidTPMPolicyPCR)
}

// TestResolveOwnerAuth leaves an unset owner authorization empty, and reads
// "-" from standard input.
func TestResolveOwnerAuth(t *testing.T) {
	none, err := resolveOwnerAuth("")
	require.NoError(t, err)
	assert.Nil(t, none)

	value, err := resolveOwnerAuth("secret")
	require.NoError(t, err)
	assert.Equal(t, []byte("secret"), value)

	old := secretStdin
	t.Cleanup(func() { secretStdin = old })
	secretStdin = strings.NewReader("from-stdin\n")
	piped, err := resolveOwnerAuth("-")
	require.NoError(t, err)
	assert.Equal(t, []byte("from-stdin"), piped)
}

// TestGenerateKey_CarriesTheTPMPolicy proves key generate --tpm-policy
// reaches the request.
func TestGenerateKey_CarriesTheTPMPolicy(t *testing.T) {
	mock := &mockKeyClient{generateKeyResp: &client.GenerateKeyResponse{KeyID: "signer"}}
	cfg := &Config{Backend: "tpm2", ClientFactory: func(*Config) (client.Client, error) { return mock, nil }}
	generateKey(cfg, NewPrinter("json", new(bytes.Buffer)), "signer", "signing", keyGenOptions{KeyAlgorithm: "ecdsa", Curve: "P-256", TPMPolicy: "boot"})
	require.NotNil(t, mock.generateKeyReq)
	assert.Equal(t, "boot", mock.generateKeyReq.TPMPolicy)
}

// TestSealData_TPMSealedObject proves seal --tpm-policy and --password reach
// the request, and a TPM2 sealed object's areas and ID are output for
// unseal.
func TestSealData_TPMSealedObject(t *testing.T) {
	mock := &mockSealClient{sealResp: &client.SealResponse{Backend: "tpm2", TPMPublic: []byte("pub"), TPMPrivate: []byte("priv"), KeyID: "xkms-sealing-key-tpm2"}}
	cfg := &Config{Backend: "tpm2", ClientFactory: func(*Config) (client.Client, error) { return mock, nil }}
	buf := new(bytes.Buffer)
	sealData(cfg, NewPrinter("json", buf), "", []byte("secret"), nil, sealTPMParams{Policy: "boot", Password: "pw"})

	require.NotNil(t, mock.lastSeal)
	assert.Equal(t, "boot", mock.lastSeal.TPMPolicy)
	assert.Equal(t, "pw", mock.lastSeal.Password)
	assert.Contains(t, buf.String(), base64.StdEncoding.EncodeToString([]byte("pub")))
	assert.Contains(t, buf.String(), base64.StdEncoding.EncodeToString([]byte("priv")))
	assert.Contains(t, buf.String(), "xkms-sealing-key-tpm2")
}

// TestUnsealData_TPMSealedObject proves the TPM areas and password reach the
// unseal request.
func TestUnsealData_TPMSealedObject(t *testing.T) {
	mock := &mockSealClient{unsealResp: &client.UnsealResponse{Plaintext: []byte("secret")}}
	cfg := &Config{Backend: "tpm2", ClientFactory: func(*Config) (client.Client, error) { return mock, nil }}
	buf := new(bytes.Buffer)
	unsealData(cfg, NewPrinter("json", buf), "", nil, nil, nil, nil, unsealTPMParams{Public: []byte("pub"), Private: []byte("priv"), Password: "pw"})

	require.NotNil(t, mock.lastUnseal)
	assert.Equal(t, []byte("pub"), mock.lastUnseal.TPMPublic)
	assert.Equal(t, []byte("priv"), mock.lastUnseal.TPMPrivate)
	assert.Equal(t, "pw", mock.lastUnseal.Password)
	assert.Contains(t, buf.String(), "secret")
}

// TestDecodeUnsealTPMParams decodes both areas, and refuses one without the
// other or an area that is not base64.
func TestDecodeUnsealTPMParams(t *testing.T) {
	pub, priv := base64.StdEncoding.EncodeToString([]byte("pub")), base64.StdEncoding.EncodeToString([]byte("priv"))
	got, err := decodeUnsealTPMParams(pub, priv, "pw")
	require.NoError(t, err)
	assert.Equal(t, unsealTPMParams{Public: []byte("pub"), Private: []byte("priv"), Password: "pw"}, got)

	none, err := decodeUnsealTPMParams("", "", "")
	require.NoError(t, err)
	assert.Nil(t, none.Public)

	_, err = decodeUnsealTPMParams(pub, "", "")
	assert.ErrorIs(t, err, ErrTPMAreasRequired)
	_, err = decodeUnsealTPMParams("%%%", priv, "")
	assert.ErrorIs(t, err, ErrInvalidBase64TPMArea)
	_, err = decodeUnsealTPMParams(pub, "%%%", "")
	assert.ErrorIs(t, err, ErrInvalidBase64TPMArea)
}
