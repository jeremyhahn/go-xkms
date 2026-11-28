package services

import (
	"context"
	"errors"
	"testing"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAuditServiceAuthorizer_EnforcesAuditRead proves the Wails-bound
// AuditService refuses reads and exports without an authorizer, without a
// go-qrdb identity, or on a denial, and serves them on an audit:read grant,
// exactly like AdminService (personal mode policy does not bypass it).
func TestAuditServiceAuthorizer_EnforcesAuditRead(t *testing.T) {
	store, err := audit.NewQRDBStore(xkms.NewQRDBAuditRingBuffer(16))
	require.NoError(t, err)
	store.LogKeyOperation(audit.OpKeyCreated, "software", "k1", true, nil, 1)

	reader := xkms.QRDBWithIdentity(context.Background(), auditReaderIdentity)

	refusal := func(t *testing.T, svc *AuditService, reason string) {
		t.Helper()
		_, err := svc.GetEntries(nil)
		var refused *AuditReadDeniedError
		require.ErrorAs(t, err, &refused)
		assert.Equal(t, reason, refused.Reason)
		assert.ErrorIs(t, err, ErrAdminNotAuthorized)

		_, err = svc.ExportEntries("json", nil)
		require.ErrorAs(t, err, &refused)
		assert.Equal(t, reason, refused.Reason)
	}

	t.Run("missing authorizer refuses", func(t *testing.T) {
		svc := NewAuditService(store)
		svc.SetContext(reader)
		refusal(t, svc, "no authorizer")
	})

	t.Run("missing identity refuses", func(t *testing.T) {
		svc := NewAuditService(store)
		authorizer := &recordingAuthorizer{}
		svc.SetAuthorizer(authorizer)
		svc.SetContext(context.Background())
		refusal(t, svc, "no identity")
		assert.Nil(t, authorizer.identity, "authorizer must not be asked without an identity")
	})

	t.Run("denial refuses", func(t *testing.T) {
		svc := NewAuditService(store)
		denial := errors.New("audit:read not granted")
		svc.SetAuthorizer(&recordingAuthorizer{denial: denial})
		svc.SetContext(reader)
		refusal(t, svc, "denied")
		_, err := svc.GetEntries(nil)
		assert.ErrorIs(t, err, denial)
	})

	t.Run("grant reads and exports", func(t *testing.T) {
		svc := NewAuditService(store)
		authorizer := &recordingAuthorizer{}
		svc.SetAuthorizer(authorizer)
		svc.SetContext(reader)

		entries, err := svc.GetEntries(nil)
		require.NoError(t, err)
		require.Len(t, entries, 1)
		assert.Equal(t, auditReaderIdentity, authorizer.identity)
		perm := xkms.QRDBPermissionAuditRead
		assert.Equal(t, xkms.QRDBPermissionResource(perm), authorizer.resource)
		assert.Equal(t, xkms.QRDBPermissionAction(perm), authorizer.action)

		data, err := svc.ExportEntries("json", nil)
		require.NoError(t, err)
		assert.NotEmpty(t, data)
	})

	t.Run("clearing the authorizer refuses again", func(t *testing.T) {
		svc := NewAuditService(store)
		svc.SetAuthorizer(&recordingAuthorizer{})
		svc.SetAuthorizer(nil)
		svc.SetContext(reader)
		refusal(t, svc, "no authorizer")
	})
}
