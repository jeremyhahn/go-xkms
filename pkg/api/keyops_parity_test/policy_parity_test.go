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

package keyops_parity_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	grpcapi "github.com/jeremyhahn/go-xkms/pkg/api/grpc"
	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	restapi "github.com/jeremyhahn/go-xkms/pkg/api/rest"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/seal/policy"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// TestPolicy_RESTAndGRPCAgree proves that PCR policy management -- which, per
// go-xkms#691, went from a REST-only capability to one every network
// transport's servicer implements against the same pkg/seal/policy.Manager
// -- returns equivalent results across REST and gRPC. It exists so a future
// transport that regresses to an ErrNotSupported stub, or a REST wire-format
// change that the client translation in pkg/api/rest/wire drifts from, fails
// a test rather than shipping silently: pkg/api/rest/policy_handlers.go
// still owns its own (pre-dating the shared-transport-type convention) wire
// shapes, so this is the one place both sides of that translation are
// exercised against a real go-xkms.
func TestPolicy_RESTAndGRPCAgree(t *testing.T) {
	svc, _, _ := setupService(t)

	mgr, err := policy.NewManager(fakePCRReader{}, policy.NewMemoryPolicyStore())
	require.NoError(t, err)
	svc.SetPolicyManager(mgr)

	restHandler := newPolicyRESTServer(t, svc, mgr)
	grpcService := grpcapi.NewService(nil, nil, svc)

	// Create over REST, read back over gRPC: both transports must resolve
	// to the same underlying policy.Manager record.
	createResp := policyCreateOverREST(t, restHandler, "boot", "sha256", []int{0, 1, 7})
	assert.Equal(t, "boot", createResp.Name)
	assert.Equal(t, "sha256", createResp.Bank)
	assert.ElementsMatch(t, []int{0, 1, 7}, createResp.PCRIndices)
	require.Len(t, createResp.PCRValues, 3)

	grpcGetResp, err := grpcService.PolicyGet(context.Background(), &pb.PolicyGetRequest{Name: "boot"})
	require.NoError(t, err)
	assert.Equal(t, "boot", grpcGetResp.Name)
	assert.Equal(t, "sha256", grpcGetResp.Bank)
	assert.ElementsMatch(t, []int32{0, 1, 7}, grpcGetResp.Pcrs)
	require.Len(t, grpcGetResp.Values, 3)

	restGetResp, code := policyGetOverREST(t, restHandler, "boot")
	require.Equal(t, http.StatusOK, code)
	assert.Equal(t, grpcGetResp.Name, restGetResp.Name)
	assert.Equal(t, grpcGetResp.Bank, restGetResp.Bank)
	assert.ElementsMatch(t, restGetResp.PCRIndices, pcrs32ToInt(grpcGetResp.Pcrs))

	// Verify agrees on both transports: the policy was just captured, so it
	// must still match current (fake, deterministic) PCR values.
	grpcVerifyResp, err := grpcService.PolicyVerify(context.Background(), &pb.PolicyVerifyRequest{Name: "boot"})
	require.NoError(t, err)
	assert.True(t, grpcVerifyResp.Valid)

	restVerifyResp := policyVerifyOverREST(t, restHandler, "boot")
	assert.True(t, restVerifyResp.Valid)
	assert.Equal(t, grpcVerifyResp.Valid, restVerifyResp.Valid)

	// List agrees on both transports.
	grpcListResp, err := grpcService.PolicyList(context.Background(), &pb.PolicyListRequest{})
	require.NoError(t, err)
	require.Len(t, grpcListResp.Policies, 1)

	restListResp := policyListOverREST(t, restHandler)
	require.Equal(t, 1, restListResp.Total)
	assert.Equal(t, int(grpcListResp.Total), restListResp.Total)

	// Export agrees on both transports: both must produce a non-empty
	// document for the same policy.
	grpcExportResp, err := grpcService.PolicyExport(context.Background(), &pb.PolicyExportRequest{Name: "boot"})
	require.NoError(t, err)
	assert.NotEmpty(t, grpcExportResp.Data)

	restExportResp := policyExportOverREST(t, restHandler, "boot")
	assert.NotEmpty(t, restExportResp.PolicyJSON)

	// Delete over gRPC; both transports must then agree the policy is gone.
	_, err = grpcService.PolicyDelete(context.Background(), &pb.PolicyDeleteRequest{Name: "boot"})
	require.NoError(t, err)

	_, code = policyGetOverREST(t, restHandler, "boot")
	assert.Equal(t, http.StatusNotFound, code)

	_, err = grpcService.PolicyGet(context.Background(), &pb.PolicyGetRequest{Name: "boot"})
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

// TestPolicy_ValidationAgrees proves REST and gRPC agree on a malformed
// create request: an empty PCR index list is invalid on both, in each
// transport's own vocabulary (HTTP 400 / gRPC InvalidArgument).
func TestPolicy_ValidationAgrees(t *testing.T) {
	svc, _, _ := setupService(t)

	mgr, err := policy.NewManager(fakePCRReader{}, policy.NewMemoryPolicyStore())
	require.NoError(t, err)
	svc.SetPolicyManager(mgr)

	restHandler := newPolicyRESTServer(t, svc, mgr)
	grpcService := grpcapi.NewService(nil, nil, svc)

	body, err := json.Marshal(map[string]interface{}{
		"name": "empty",
		"bank": "sha256",
	})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies/", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	restHandler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	_, err = grpcService.PolicyCreate(context.Background(), &pb.PolicyCreateRequest{
		Name: "empty",
		Bank: "sha256",
	})
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

// fakePCRReader returns deterministic, index-derived PCR values so a policy
// capture is reproducible and later re-verification of the same indices
// succeeds.
type fakePCRReader struct{}

func (fakePCRReader) ReadPCRs(_ string, indices []int) (map[int][]byte, error) {
	values := make(map[int][]byte, len(indices))
	for _, idx := range indices {
		values[idx] = []byte{byte(idx), 0xAA, 0xBB} // #nosec G115 - PCR indices are 0-23
	}
	return values, nil
}

// newPolicyRESTServer builds a REST server over the shared service and
// policy manager, returning its HTTP handler. Authentication is explicitly
// NoOp and RBAC is off, matching newRESTServer: this test's subject is
// result parity, not authorization (the policy:* RequirePermission gate on
// /api/v1/policies is exercised by pkg/api/rest's own
// TestPolicyCreateRoute_RequiresPolicyCreate). The server still requires at
// least one backend to construct even though policy management does not
// use one, so this borrows setupService's.
func newPolicyRESTServer(t *testing.T, svc *xkms.XKMSService, mgr *policy.Manager) http.Handler {
	t.Helper()

	backends := make(map[string]xkms.Backend, len(svc.BackendNames()))
	for _, name := range svc.BackendNames() {
		b, err := svc.LookupBackend(name)
		require.NoError(t, err)
		backends[name] = b
	}

	server, err := restapi.NewServer(&restapi.Config{
		Port:          0,
		Authenticator: auth.NewNoOpAuthenticator(),
		Backends:      backends,
		XKMSService:   svc,
		PolicyManager: mgr,
	})
	require.NoError(t, err)
	return server.Handler()
}

func policyCreateOverREST(t *testing.T, handler http.Handler, name, bank string, pcrs []int) *restapi.PolicyCreateResponse {
	t.Helper()
	body, err := json.Marshal(restapi.PolicyCreateRequest{Name: name, Bank: bank, PCRIndices: pcrs})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies/", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())

	var resp restapi.PolicyCreateResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	return &resp
}

func policyGetOverREST(t *testing.T, handler http.Handler, name string) (*restapi.PolicyGetResponse, int) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/policies/"+name, nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		return nil, w.Code
	}
	var resp restapi.PolicyGetResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	return &resp, w.Code
}

func policyListOverREST(t *testing.T, handler http.Handler) *restapi.PolicyListResponse {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/policies/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var resp restapi.PolicyListResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	return &resp
}

func policyVerifyOverREST(t *testing.T, handler http.Handler, name string) *restapi.PolicyVerifyResponse {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies/"+name+"/verify", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var resp restapi.PolicyVerifyResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	return &resp
}

func policyExportOverREST(t *testing.T, handler http.Handler, name string) *restapi.PolicyExportResponse {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/policies/"+name+"/export", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var resp restapi.PolicyExportResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	return &resp
}

func pcrs32ToInt(pcrs []int32) []int {
	out := make([]int, len(pcrs))
	for i, v := range pcrs {
		out[i] = int(v)
	}
	return out
}
