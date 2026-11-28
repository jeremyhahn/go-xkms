package xkms

import (
	"errors"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/audit"
	"github.com/jeremyhahn/go-xkms/pkg/audit/audittest"
)

// TestCreateUser_InviteDenialIsAudited is SPEC row authz-device-onboarding
// with docs/audit-log/engineering.md ("Denials are logged, always"): the
// users:invite refusal CreateUser makes below the transport gate leaves a
// deny record, not only the transport's earlier users:create allowance.
func TestCreateUser_InviteDenialIsAudited(t *testing.T) {
	svc, created, ctx := inviteAuthzService(t, permUsersCreate)
	rec := &audittest.Recorder{}
	svc.SetAuditLogger(rec)
	t.Cleanup(func() { svc.SetAuditLogger(nil) })

	_, err := svc.CreateUser(ctx, &transport.CreateUserRequest{Username: "erin", Email: "erin@example.com"})
	var denied *qrdbsdk.PermissionDeniedError
	require.True(t, errors.As(err, &denied), "want a PermissionDeniedError, got %v", err)
	assert.Equal(t, 0, *created)

	ev := rec.LastEvent()
	require.NotNil(t, ev, "the refusal must be audited")
	assert.Equal(t, audit.OutcomeDeny, ev.Outcome)
	assert.Equal(t, "users", ev.Resource)
	assert.Equal(t, "invite", ev.Action)
	assert.Equal(t, "operator", ev.Subject)
}

// TestCreateUser_InviteAllowanceIsAudited: the granted decision is recorded
// too, so the trail shows who minted each invitation.
func TestCreateUser_InviteAllowanceIsAudited(t *testing.T) {
	svc, _, ctx := inviteAuthzService(t, permUsersCreate, permUsersInvite)
	rec := &audittest.Recorder{}
	svc.SetAuditLogger(rec)
	t.Cleanup(func() { svc.SetAuditLogger(nil) })

	_, err := svc.CreateUser(ctx, &transport.CreateUserRequest{Username: "erin", Email: "erin@example.com"})
	require.NoError(t, err)
	var invite *audit.Event
	for _, ev := range rec.Events() {
		if ev.Resource == "users" && ev.Action == "invite" {
			invite = ev
		}
	}
	require.NotNil(t, invite, "the users:invite decision must be audited")
	assert.Equal(t, audit.OutcomeAllow, invite.Outcome)
}

// TestCreateUser_InviteAuditFailureFailsClosed: a decision that cannot be
// audited is not acted on; the write failure comes back as go-qrdb's
// AuditGateError and no account is created.
func TestCreateUser_InviteAuditFailureFailsClosed(t *testing.T) {
	svc, created, ctx := inviteAuthzService(t, permUsersCreate, permUsersInvite)
	svc.SetAuditLogger(&audittest.Failing{Err: errors.New("sink down")})
	t.Cleanup(func() { svc.SetAuditLogger(nil) })

	_, err := svc.CreateUser(ctx, &transport.CreateUserRequest{Username: "erin", Email: "erin@example.com"})
	var gate *qrdbsdk.AuditGateError
	require.True(t, errors.As(err, &gate), "want an AuditGateError, got %v", err)
	assert.Equal(t, 0, *created, "no account without an audited decision")
}
