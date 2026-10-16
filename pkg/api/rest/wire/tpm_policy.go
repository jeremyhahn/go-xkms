// Copyright (c) 2026 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-or-later

package wire

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// TPM policy REST paths. The server's route table (pkg/api/rest/routes.go)
// registers the same paths with {name}, {id} and {tenantID} placeholders.
const (
	// TPMPoliciesPath is the collection of a tenant's TPM policies.
	TPMPoliciesPath = "/api/v1/tpm/policies"

	// TPMAuthorityRotatePath rotates a tenant's policy authority.
	TPMAuthorityRotatePath = "/api/v1/tpm/authority/rotate"
)

// ErrNilRequest is returned by the API clients (TPMPolicyClient,
// OIDCCredentialClient) for a nil request.
var ErrNilRequest = errors.New("wire: request is nil")

// DecodeError reports a response body that is not the expected JSON.
type DecodeError struct {
	Path string
	Err  error
}

// Error implements the error interface.
func (e *DecodeError) Error() string {
	return fmt.Sprintf("wire: decode response of %s: %v", e.Path, e.Err)
}

// Unwrap returns the JSON error.
func (e *DecodeError) Unwrap() error { return e.Err }

// TPMPolicyPath returns the path of a named TPM policy, followed by an
// optional action segment ("update", "objects", ...).
func TPMPolicyPath(name string, action ...string) string {
	path := TPMPoliciesPath + "/" + url.PathEscape(name)
	for _, a := range action {
		path += "/" + a
	}
	return path
}

// TPMObjectPolicyPath returns the path of the TPM policy of the key keyID.
func TPMObjectPolicyPath(keyID string) string {
	return "/api/v1/keys/" + url.PathEscape(keyID) + "/tpm-policy"
}

// TenantTPMPath returns the path of a tenant's TPM mode, followed by an
// optional sub-path ("vtpm", "vtpm/start", "vtpm/stop").
func TenantTPMPath(tenantID string, sub ...string) string {
	path := "/api/v1/tenants/" + url.PathEscape(tenantID) + "/tpm"
	for _, s := range sub {
		path += "/" + s
	}
	return path
}

// withQuery appends the non-empty query parameters to path.
func withQuery(path string, params map[string]string) string {
	q := url.Values{}
	for k, v := range params {
		if v != "" {
			q.Set(k, v)
		}
	}
	if len(q) == 0 {
		return path
	}
	return path + "?" + q.Encode()
}

// Requester performs one REST request: body, when non-nil, is sent as JSON,
// and the raw response body is returned. A non-2xx status is an error.
type Requester func(ctx context.Context, method, path string, body any) ([]byte, error)

// Compile-time check that the client serves the whole TPM policy API.
var _ transport.TPMPolicyService = TPMPolicyClient{}

// TPMPolicyClient serves transport.TPMPolicyService over the REST routes.
// The REST and QUIC transports (QUIC serves the same router over HTTP/3)
// delegate to it with their own Requester.
type TPMPolicyClient struct {
	// Do performs the requests.
	Do Requester
}

// call performs a request and decodes its JSON response into out, when out
// is non-nil.
func (c TPMPolicyClient) call(ctx context.Context, method, path string, body, out any) error {
	return callJSON(ctx, c.Do, method, path, body, out)
}

// callJSON performs a request through do and decodes its JSON response into
// out, when out is non-nil.
func callJSON(ctx context.Context, do Requester, method, path string, body, out any) error {
	data, err := do(ctx, method, path, body)
	if err != nil {
		return err
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return &DecodeError{Path: path, Err: err}
	}
	return nil
}

// policy performs a request answered by a TPM policy.
func (c TPMPolicyClient) policy(ctx context.Context, method, path string, body any) (*transport.TPMPolicy, error) {
	var resp transport.TPMPolicy
	if err := c.call(ctx, method, path, body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// TPMPolicyCreate creates a named TPM policy.
func (c TPMPolicyClient) TPMPolicyCreate(ctx context.Context, req *transport.TPMPolicyCreateRequest) (*transport.TPMPolicy, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	return c.policy(ctx, http.MethodPost, TPMPoliciesPath, req)
}

// TPMPolicyGet returns a named TPM policy.
func (c TPMPolicyClient) TPMPolicyGet(ctx context.Context, req *transport.TPMPolicyRequest) (*transport.TPMPolicy, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	return c.policy(ctx, http.MethodGet, withQuery(TPMPolicyPath(req.Name), map[string]string{"tenant_id": req.TenantID}), nil)
}

// TPMPolicyList returns a tenant's TPM policies.
func (c TPMPolicyClient) TPMPolicyList(ctx context.Context, req *transport.TPMPolicyListRequest) (*transport.TPMPolicyListResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	var resp transport.TPMPolicyListResponse
	path := withQuery(TPMPoliciesPath, map[string]string{"tenant_id": req.TenantID})
	if err := c.call(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// TPMPolicyUpdate re-captures a TPM policy, or updates one branch from
// signed reference values, and re-approves it.
func (c TPMPolicyClient) TPMPolicyUpdate(ctx context.Context, req *transport.TPMPolicyUpdateRequest) (*transport.TPMPolicy, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	return c.policy(ctx, http.MethodPost, TPMPolicyPath(req.Name, "update"), req)
}

// TPMPolicyRevoke withdraws a TPM policy's approval.
func (c TPMPolicyClient) TPMPolicyRevoke(ctx context.Context, req *transport.TPMPolicyRequest) (*transport.TPMPolicy, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	return c.policy(ctx, http.MethodPost, TPMPolicyPath(req.Name, "revoke"), req)
}

// TPMPolicyVerify compares a TPM policy's PCR values with the live ones.
func (c TPMPolicyClient) TPMPolicyVerify(ctx context.Context, req *transport.TPMPolicyRequest) (*transport.TPMPolicyVerifyResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	var resp transport.TPMPolicyVerifyResponse
	if err := c.call(ctx, http.MethodPost, TPMPolicyPath(req.Name, "verify"), req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// TPMPolicyDelete deletes a TPM policy no object is assigned to.
func (c TPMPolicyClient) TPMPolicyDelete(ctx context.Context, req *transport.TPMPolicyDeleteRequest) error {
	if req == nil {
		return ErrNilRequest
	}
	return c.call(ctx, http.MethodDelete, TPMPolicyPath(req.Name), req, nil)
}

// TPMPolicyObjects lists the objects assigned to a TPM policy.
func (c TPMPolicyClient) TPMPolicyObjects(ctx context.Context, req *transport.TPMPolicyRequest) (*transport.TPMPolicyObjectsResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	var resp transport.TPMPolicyObjectsResponse
	path := withQuery(TPMPolicyPath(req.Name, "objects"), map[string]string{"tenant_id": req.TenantID})
	if err := c.call(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// TPMPolicySetAutoUnseal sets or clears a TPM policy's auto-unseal mark.
func (c TPMPolicyClient) TPMPolicySetAutoUnseal(ctx context.Context, req *transport.TPMPolicyAutoUnsealRequest) (*transport.TPMPolicy, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	return c.policy(ctx, http.MethodPost, TPMPolicyPath(req.Name, "auto-unseal"), req)
}

// TPMPolicySetDescription replaces a TPM policy's description.
func (c TPMPolicyClient) TPMPolicySetDescription(ctx context.Context, req *transport.TPMPolicyDescriptionRequest) (*transport.TPMPolicy, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	return c.policy(ctx, http.MethodPost, TPMPolicyPath(req.Name, "description"), req)
}

// TPMObjectPolicy returns the TPM policy a key or sealed object was created
// under.
func (c TPMPolicyClient) TPMObjectPolicy(ctx context.Context, req *transport.TPMObjectPolicyRequest) (*transport.TPMObjectPolicyResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	var resp transport.TPMObjectPolicyResponse
	path := withQuery(TPMObjectPolicyPath(req.KeyID), map[string]string{"tenant_id": req.TenantID, "kind": req.Kind})
	if err := c.call(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// TPMPolicyRotateAuthority rotates a tenant's TPM policy authority.
func (c TPMPolicyClient) TPMPolicyRotateAuthority(ctx context.Context, req *transport.TPMAuthorityRotateRequest) (*transport.TPMAuthorityRotateResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	var resp transport.TPMAuthorityRotateResponse
	if err := c.call(ctx, http.MethodPost, TPMAuthorityRotatePath, req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetTenantTPMMode returns a tenant's TPM mode.
func (c TPMPolicyClient) GetTenantTPMMode(ctx context.Context, tenantID string) (*transport.TenantTPMModeResponse, error) {
	var resp transport.TenantTPMModeResponse
	if err := c.call(ctx, http.MethodGet, TenantTPMPath(tenantID), nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// SetTenantTPMMode changes a tenant's TPM mode.
func (c TPMPolicyClient) SetTenantTPMMode(ctx context.Context, req *transport.SetTenantTPMModeRequest) (*transport.TenantTPMModeResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	var resp transport.TenantTPMModeResponse
	if err := c.call(ctx, http.MethodPut, TenantTPMPath(req.TenantID), req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// TenantVTPMStatus reports a tenant's virtual TPM.
func (c TPMPolicyClient) TenantVTPMStatus(ctx context.Context, tenantID string) (*transport.TenantVTPMStatusResponse, error) {
	return c.vtpm(ctx, http.MethodGet, TenantTPMPath(tenantID, "vtpm"))
}

// TenantVTPMStart starts a tenant's virtual TPM.
func (c TPMPolicyClient) TenantVTPMStart(ctx context.Context, tenantID string) (*transport.TenantVTPMStatusResponse, error) {
	return c.vtpm(ctx, http.MethodPost, TenantTPMPath(tenantID, "vtpm", "start"))
}

// TenantVTPMStop stops a tenant's virtual TPM.
func (c TPMPolicyClient) TenantVTPMStop(ctx context.Context, tenantID string) (*transport.TenantVTPMStatusResponse, error) {
	return c.vtpm(ctx, http.MethodPost, TenantTPMPath(tenantID, "vtpm", "stop"))
}

// vtpm performs a request answered by a vTPM status.
func (c TPMPolicyClient) vtpm(ctx context.Context, method, path string) (*transport.TenantVTPMStatusResponse, error) {
	var resp transport.TenantVTPMStatusResponse
	if err := c.call(ctx, method, path, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
