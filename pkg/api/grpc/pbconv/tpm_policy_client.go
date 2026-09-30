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

package pbconv

import (
	"context"
	"errors"

	"google.golang.org/grpc"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// ErrNilRequest is returned by TPMPolicyClient for a nil request.
var ErrNilRequest = errors.New("pbconv: request is nil")

// Compile-time check that the client serves the whole TPM policy API.
var _ transport.TPMPolicyService = TPMPolicyClient{}

// TPMPolicyClient serves transport.TPMPolicyService over a generated
// xkms.v1 client. The gRPC and Unix-socket transports, which both speak the
// generated protocol, delegate to it once they hold a connection. Errors are
// the server's gRPC status errors, unchanged.
type TPMPolicyClient struct {
	// Client is the connected generated client.
	Client pb.KeystoreServiceClient
}

// TPMPolicyCreate creates a named TPM policy.
func (c TPMPolicyClient) TPMPolicyCreate(ctx context.Context, req *transport.TPMPolicyCreateRequest) (*transport.TPMPolicy, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.TPMPolicyCreate(ctx, TPMPolicyCreateRequestToProto(req))
	if err != nil {
		return nil, err
	}
	return TPMPolicyFromProto(resp), nil
}

// TPMPolicyGet returns a named TPM policy.
func (c TPMPolicyClient) TPMPolicyGet(ctx context.Context, req *transport.TPMPolicyRequest) (*transport.TPMPolicy, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	return c.policyCall(ctx, req, c.Client.TPMPolicyGet)
}

// TPMPolicyUpdate re-captures and re-approves a TPM policy.
func (c TPMPolicyClient) TPMPolicyUpdate(ctx context.Context, req *transport.TPMPolicyRequest) (*transport.TPMPolicy, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	return c.policyCall(ctx, req, c.Client.TPMPolicyUpdate)
}

// TPMPolicyRevoke withdraws a TPM policy's approval.
func (c TPMPolicyClient) TPMPolicyRevoke(ctx context.Context, req *transport.TPMPolicyRequest) (*transport.TPMPolicy, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	return c.policyCall(ctx, req, c.Client.TPMPolicyRevoke)
}

// policyCall runs rpc, an RPC that takes a policy name and returns a policy.
// The caller has refused a nil request.
func (c TPMPolicyClient) policyCall(ctx context.Context, req *transport.TPMPolicyRequest,
	rpc func(context.Context, *pb.TPMPolicyRequest, ...grpc.CallOption) (*pb.TPMPolicy, error)) (*transport.TPMPolicy, error) {

	resp, err := rpc(ctx, TPMPolicyRequestToProto(req))
	if err != nil {
		return nil, err
	}
	return TPMPolicyFromProto(resp), nil
}

// TPMPolicyList returns a tenant's TPM policies.
func (c TPMPolicyClient) TPMPolicyList(ctx context.Context, req *transport.TPMPolicyListRequest) (*transport.TPMPolicyListResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.TPMPolicyList(ctx, &pb.TPMPolicyListRequest{TenantId: req.TenantID})
	if err != nil {
		return nil, err
	}
	return TPMPolicyListResponseFromProto(resp), nil
}

// TPMPolicyVerify compares a policy's PCR values with the live ones.
func (c TPMPolicyClient) TPMPolicyVerify(ctx context.Context, req *transport.TPMPolicyRequest) (*transport.TPMPolicyVerifyResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.TPMPolicyVerify(ctx, TPMPolicyRequestToProto(req))
	if err != nil {
		return nil, err
	}
	return TPMPolicyVerifyResponseFromProto(resp), nil
}

// TPMPolicyDelete deletes a TPM policy.
func (c TPMPolicyClient) TPMPolicyDelete(ctx context.Context, req *transport.TPMPolicyDeleteRequest) error {
	if req == nil {
		return ErrNilRequest
	}
	_, err := c.Client.TPMPolicyDelete(ctx, TPMPolicyDeleteRequestToProto(req))
	return err
}

// TPMPolicyObjects lists the objects assigned to a TPM policy.
func (c TPMPolicyClient) TPMPolicyObjects(ctx context.Context, req *transport.TPMPolicyRequest) (*transport.TPMPolicyObjectsResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.TPMPolicyObjects(ctx, TPMPolicyRequestToProto(req))
	if err != nil {
		return nil, err
	}
	return TPMPolicyObjectsResponseFromProto(resp), nil
}

// TPMPolicySetAutoUnseal sets or clears a policy's auto-unseal mark.
func (c TPMPolicyClient) TPMPolicySetAutoUnseal(ctx context.Context, req *transport.TPMPolicyAutoUnsealRequest) (*transport.TPMPolicy, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.TPMPolicySetAutoUnseal(ctx, TPMPolicyAutoUnsealRequestToProto(req))
	if err != nil {
		return nil, err
	}
	return TPMPolicyFromProto(resp), nil
}

// TPMPolicySetDescription replaces a policy's description.
func (c TPMPolicyClient) TPMPolicySetDescription(ctx context.Context, req *transport.TPMPolicyDescriptionRequest) (*transport.TPMPolicy, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.TPMPolicySetDescription(ctx, TPMPolicyDescriptionRequestToProto(req))
	if err != nil {
		return nil, err
	}
	return TPMPolicyFromProto(resp), nil
}

// TPMObjectPolicy returns the policy a TPM object was created under.
func (c TPMPolicyClient) TPMObjectPolicy(ctx context.Context, req *transport.TPMObjectPolicyRequest) (*transport.TPMObjectPolicyResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.TPMObjectPolicy(ctx, TPMObjectPolicyRequestToProto(req))
	if err != nil {
		return nil, err
	}
	return TPMObjectPolicyResponseFromProto(resp), nil
}

// TPMPolicyRotateAuthority rotates a tenant's policy authority.
func (c TPMPolicyClient) TPMPolicyRotateAuthority(ctx context.Context, req *transport.TPMAuthorityRotateRequest) (*transport.TPMAuthorityRotateResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.TPMPolicyRotateAuthority(ctx, &pb.TPMAuthorityRotateRequest{TenantId: req.TenantID})
	if err != nil {
		return nil, err
	}
	return TPMAuthorityRotateResponseFromProto(resp), nil
}

// GetTenantTPMMode returns a tenant's TPM mode.
func (c TPMPolicyClient) GetTenantTPMMode(ctx context.Context, tenantID string) (*transport.TenantTPMModeResponse, error) {
	resp, err := c.Client.GetTenantTPMMode(ctx, &pb.TenantTPMModeRequest{TenantId: tenantID})
	if err != nil {
		return nil, err
	}
	return TenantTPMModeResponseFromProto(resp), nil
}

// SetTenantTPMMode changes a tenant's TPM mode.
func (c TPMPolicyClient) SetTenantTPMMode(ctx context.Context, req *transport.SetTenantTPMModeRequest) (*transport.TenantTPMModeResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.SetTenantTPMMode(ctx, SetTenantTPMModeRequestToProto(req))
	if err != nil {
		return nil, err
	}
	return TenantTPMModeResponseFromProto(resp), nil
}

// TenantVTPMStatus reports a tenant's virtual TPM.
func (c TPMPolicyClient) TenantVTPMStatus(ctx context.Context, tenantID string) (*transport.TenantVTPMStatusResponse, error) {
	return c.vtpmCall(ctx, tenantID, c.Client.TenantVTPMStatus)
}

// TenantVTPMStart starts a tenant's virtual TPM.
func (c TPMPolicyClient) TenantVTPMStart(ctx context.Context, tenantID string) (*transport.TenantVTPMStatusResponse, error) {
	return c.vtpmCall(ctx, tenantID, c.Client.TenantVTPMStart)
}

// TenantVTPMStop stops a tenant's virtual TPM.
func (c TPMPolicyClient) TenantVTPMStop(ctx context.Context, tenantID string) (*transport.TenantVTPMStatusResponse, error) {
	return c.vtpmCall(ctx, tenantID, c.Client.TenantVTPMStop)
}

// vtpmCall runs rpc, a vTPM lifecycle RPC of tenantID.
func (c TPMPolicyClient) vtpmCall(ctx context.Context, tenantID string,
	rpc func(context.Context, *pb.TenantVTPMRequest, ...grpc.CallOption) (*pb.TenantVTPMStatusResponse, error)) (*transport.TenantVTPMStatusResponse, error) {

	resp, err := rpc(ctx, &pb.TenantVTPMRequest{TenantId: tenantID})
	if err != nil {
		return nil, err
	}
	return TenantVTPMStatusResponseFromProto(resp), nil
}
