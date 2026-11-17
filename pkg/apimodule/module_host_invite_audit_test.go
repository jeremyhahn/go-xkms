package apimodule

import (
	"context"
	"errors"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/audit"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// TestModule_HostMount_InviteDenialIsAudited is SPEC row
// authz-device-onboarding with docs/audit-log/engineering.md ("Denials are
// logged, always") on the self-built ServiceModule path: the module wires
// the host node's audit plane into the service alongside the authorizer,
// so the users:invite refusal CreateUser makes below the transport gate
// lands in the node's audit trail.
func TestModule_HostMount_InviteDenialIsAudited(t *testing.T) {
	client := newHostNodeClient(t)
	ctx := context.Background()
	_, err := client.Roles().CreateRole(ctx, &qrdbtransport.CreateRoleRequest{
		ID:          "creator",
		Name:        "creator",
		TenantID:    qrdbsdk.SystemTenantID,
		Permissions: []string{string(qrdbsdk.PermissionUsersCreate)},
	})
	require.NoError(t, err)

	h := mountLikeHost(t, client)
	h.svc.SetUserClients(client.Users(), client.Roles())
	h.module.hostStores(h.svc)

	creator := &auth.Identity{Subject: "creator", TenantID: qrdbsdk.SystemTenantID, Roles: []string{"creator"}}
	_, err = h.svc.CreateUser(auth.WithIdentity(ctx, creator), &transport.CreateUserRequest{
		Username: "invitee",
		Email:    "invitee@example.com",
		TenantID: qrdbsdk.SystemTenantID,
	})
	var denied *qrdbsdk.PermissionDeniedError
	require.True(t, errors.As(err, &denied), "want PermissionDeniedError, got %v", err)

	page, err := client.Audit().QueryAudit(ctx, qrdbtransport.AuditFilter{Resource: "users", Action: "invite"})
	require.NoError(t, err)
	require.NotEmpty(t, page.Events, "the refusal must reach the node's audit trail")
	require.Equal(t, "creator", page.Events[len(page.Events)-1].Actor)
}

// failingAuditClient is a node audit plane whose writes fail.
type failingAuditClient struct{ qrdbtransport.AuditClient }

func (failingAuditClient) EmitAudit(context.Context, qrdbtransport.AuditEvent) error {
	return errors.New("audit plane down")
}

// TestModule_HostAuditSink_WriteFailureFailsClosed: a decision the node's
// audit plane cannot record is not acted on; the module's sink returns the
// write failure, which the service's audit seam turns into go-qrdb's
// AuditGateError.
func TestModule_HostAuditSink_WriteFailureFailsClosed(t *testing.T) {
	sink := &clientAuditSink{audit: failingAuditClient{}}
	err := audit.Emit(context.Background(), sink, &audit.Event{
		Timestamp: time.Now(), Action: "invite", Resource: "users", Outcome: audit.OutcomeDeny,
	})
	var gate *qrdbsdk.AuditGateError
	require.True(t, errors.As(err, &gate), "want an AuditGateError, got %v", err)
}
