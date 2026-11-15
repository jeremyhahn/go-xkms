package rest

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// restInviteDenyRBAC grants everything but users:invite: a caller that
// passes the users:create transport gate and lacks the invite grant.
type restInviteDenyRBAC struct{}

func (restInviteDenyRBAC) Authorize(_ context.Context, _ *qrdbtransport.Identity, resource, action string) error {
	if resource+":"+action == string(qrdbsdk.PermissionUsersInvite) {
		return &qrdbsdk.PermissionDeniedError{}
	}
	return nil
}

func (restInviteDenyRBAC) ListPermissions(context.Context, *qrdbtransport.Identity) ([]qrdbtransport.PermissionInfo, error) {
	return nil, nil
}

func (restInviteDenyRBAC) ListOwnPermissions(context.Context) ([]qrdbtransport.PermissionInfo, error) {
	return nil, nil
}

// TestHandleCreateUser_InviteDeniedIsForbidden is SPEC row
// authz-device-onboarding on REST: the service's users:invite refusal is
// the caller's missing grant, so it answers 403 as the RBAC gate does, not
// 500.
func TestHandleCreateUser_InviteDeniedIsForbidden(t *testing.T) {
	r := setupUserHandlerTest(t, &restMockUserClient{}, &restMockRoleClient{})
	svc, err := xkms.Get()
	require.NoError(t, err)
	svc.SetAuthorizer(auth.NewAuthorizer(restInviteDenyRBAC{}))

	req := httptest.NewRequest(http.MethodPost, "/users/",
		bytes.NewBufferString(`{"username":"invitee","email":"invitee@example.com"}`))
	req = req.WithContext(auth.WithIdentity(req.Context(),
		&auth.Identity{Subject: "creator", TenantID: qrdbsdk.SystemTenantID}))
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code, "body: %s", rr.Body.String())
}
