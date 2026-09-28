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

package grpc

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/seal/policy"
)

// The Policy* RPC handlers (service_policy.go) had no direct tests at all:
// every one of their request-validation, authorization delegation and
// "xkms service not initialized" branches was unexercised. These tests pin
// the validation and error-mapping contract every handler shares, using
// newTestService()'s allow-all authorizer/no-op audit logger and a nil
// xkmsService, which is exactly the "unconfigured backend" shape a
// misconfigured or policy-disabled deployment presents.

// TestPolicyCreate_RequiresName proves a request with no name (nil request
// or an empty Name field) is refused before authorization or the service
// layer ever run.
func TestPolicyCreate_RequiresName(t *testing.T) {
	svc := newTestService()

	_, err := svc.PolicyCreate(context.Background(), nil)
	assertPolicyInvalidArgument(t, err)

	_, err = svc.PolicyCreate(context.Background(), &pb.PolicyCreateRequest{})
	assertPolicyInvalidArgument(t, err)
}

// TestPolicyCreate_UnavailableWithNoXKMSService proves a validly-named
// request that clears authorization still fails closed -- Unavailable, not
// a nil-pointer panic -- when no xkms service is configured.
func TestPolicyCreate_UnavailableWithNoXKMSService(t *testing.T) {
	svc := newTestService()
	_, err := svc.PolicyCreate(context.Background(), &pb.PolicyCreateRequest{Name: "boot-policy", Bank: "sha256", Pcrs: []int32{0, 7}})
	assertPolicyUnavailable(t, err)
}

func TestPolicyGet_RequiresName(t *testing.T) {
	svc := newTestService()

	_, err := svc.PolicyGet(context.Background(), nil)
	assertPolicyInvalidArgument(t, err)

	_, err = svc.PolicyGet(context.Background(), &pb.PolicyGetRequest{})
	assertPolicyInvalidArgument(t, err)
}

func TestPolicyGet_UnavailableWithNoXKMSService(t *testing.T) {
	svc := newTestService()
	_, err := svc.PolicyGet(context.Background(), &pb.PolicyGetRequest{Name: "boot-policy"})
	assertPolicyUnavailable(t, err)
}

// TestPolicyList_UnavailableWithNoXKMSService proves PolicyList -- the one
// handler with no name to validate -- still fails closed rather than
// dereferencing a nil xkmsService.
func TestPolicyList_UnavailableWithNoXKMSService(t *testing.T) {
	svc := newTestService()
	_, err := svc.PolicyList(context.Background(), &pb.PolicyListRequest{})
	assertPolicyUnavailable(t, err)
}

func TestPolicyDelete_RequiresName(t *testing.T) {
	svc := newTestService()

	_, err := svc.PolicyDelete(context.Background(), nil)
	assertPolicyInvalidArgument(t, err)

	_, err = svc.PolicyDelete(context.Background(), &pb.PolicyDeleteRequest{})
	assertPolicyInvalidArgument(t, err)
}

func TestPolicyDelete_UnavailableWithNoXKMSService(t *testing.T) {
	svc := newTestService()
	_, err := svc.PolicyDelete(context.Background(), &pb.PolicyDeleteRequest{Name: "boot-policy"})
	assertPolicyUnavailable(t, err)
}

func TestPolicyRefresh_RequiresName(t *testing.T) {
	svc := newTestService()

	_, err := svc.PolicyRefresh(context.Background(), nil)
	assertPolicyInvalidArgument(t, err)

	_, err = svc.PolicyRefresh(context.Background(), &pb.PolicyRefreshRequest{})
	assertPolicyInvalidArgument(t, err)
}

func TestPolicyRefresh_UnavailableWithNoXKMSService(t *testing.T) {
	svc := newTestService()
	_, err := svc.PolicyRefresh(context.Background(), &pb.PolicyRefreshRequest{Name: "boot-policy"})
	assertPolicyUnavailable(t, err)
}

func TestPolicyVerify_RequiresName(t *testing.T) {
	svc := newTestService()

	_, err := svc.PolicyVerify(context.Background(), nil)
	assertPolicyInvalidArgument(t, err)

	_, err = svc.PolicyVerify(context.Background(), &pb.PolicyVerifyRequest{})
	assertPolicyInvalidArgument(t, err)
}

func TestPolicyVerify_UnavailableWithNoXKMSService(t *testing.T) {
	svc := newTestService()
	_, err := svc.PolicyVerify(context.Background(), &pb.PolicyVerifyRequest{Name: "boot-policy"})
	assertPolicyUnavailable(t, err)
}

func TestPolicyExport_RequiresName(t *testing.T) {
	svc := newTestService()

	_, err := svc.PolicyExport(context.Background(), nil)
	assertPolicyInvalidArgument(t, err)

	_, err = svc.PolicyExport(context.Background(), &pb.PolicyExportRequest{})
	assertPolicyInvalidArgument(t, err)
}

func TestPolicyExport_UnavailableWithNoXKMSService(t *testing.T) {
	svc := newTestService()
	_, err := svc.PolicyExport(context.Background(), &pb.PolicyExportRequest{Name: "boot-policy"})
	assertPolicyUnavailable(t, err)
}

// TestMapPolicyError_NilIsNil proves the pass-through case: a nil domain
// error must not be turned into a non-nil gRPC status.
func TestMapPolicyError_NilIsNil(t *testing.T) {
	assert.NoError(t, mapPolicyError(nil))
}

// TestMapPolicyError_UnclassifiedFallsBackToInternal proves an error absent
// from apierrors.PolicySentinelClasses -- every table entry itself is
// covered by TestApierrors_Parity's shared sweep -- still renders as
// codes.Internal rather than an unmapped zero-value code.
func TestMapPolicyError_UnclassifiedFallsBackToInternal(t *testing.T) {
	err := mapPolicyError(errors.New("tpm: unexpected EOF"))
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())
}

// TestMapPolicyError_ClassifiedSentinel spot-checks one PolicySentinelClasses
// entry end to end (through mapPolicyError, not apierrors.ClassOf directly)
// so a break in the wiring between the two -- not just the table itself --
// would fail a test.
func TestMapPolicyError_ClassifiedSentinel(t *testing.T) {
	err := mapPolicyError(policy.ErrPolicyNotFound)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

// TestPolicyProtoConversions_RoundTrip proves the PCR index and value proto
// conversions (pcrsToProto / pcrsFromProto / pcrValuesToProto) and the
// policyGetResponseToProto assembly they back are lossless and preserve
// every field, including the boundary PCR indices (0 and 23).
func TestPolicyProtoConversions_RoundTrip(t *testing.T) {
	pcrs := []int{0, 7, 23}
	proto := pcrsToProto(pcrs)
	assert.Equal(t, []int32{0, 7, 23}, proto)
	assert.Equal(t, pcrs, pcrsFromProto(proto))

	values := map[int]string{0: "aa", 7: "bb", 23: "cc"}
	protoValues := pcrValuesToProto(values)
	assert.Equal(t, map[int32]string{0: "aa", 7: "bb", 23: "cc"}, protoValues)

	resp := policyGetResponseToProto(&transport.PolicyGetResponse{Name: "boot-policy", Bank: "sha256", PCRs: pcrs, Values: values})
	assert.Equal(t, "boot-policy", resp.Name)
	assert.Equal(t, "sha256", resp.Bank)
	assert.Equal(t, []int32{0, 7, 23}, resp.Pcrs)
	assert.Equal(t, map[int32]string{0: "aa", 7: "bb", 23: "cc"}, resp.Values)
}

// TestPcrsToProto_EmptyInput and the map equivalent prove the conversions
// return an empty (non-nil) collection for an empty input rather than nil,
// matching PCRValuesToHex's contract in pkg/api/rest/wire.
func TestPcrsToProto_EmptyInput(t *testing.T) {
	assert.Empty(t, pcrsToProto(nil))
	assert.Empty(t, pcrsFromProto(nil))
	assert.NotNil(t, pcrValuesToProto(nil))
	assert.Empty(t, pcrValuesToProto(nil))
}

// assertPolicyInvalidArgument fails the test unless err is a gRPC
// InvalidArgument status.
func assertPolicyInvalidArgument(t *testing.T, err error) {
	t.Helper()
	st, ok := status.FromError(err)
	require.True(t, ok, "expected a gRPC status error, got %v", err)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

// assertPolicyUnavailable fails the test unless err is a gRPC Unavailable
// status.
func assertPolicyUnavailable(t *testing.T, err error) {
	t.Helper()
	st, ok := status.FromError(err)
	require.True(t, ok, "expected a gRPC status error, got %v", err)
	assert.Equal(t, codes.Unavailable, st.Code())
}
