// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package services

import (
	"context"
	"errors"
	"testing"

	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	pkgxkms "github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

// errAuditGrantMissing is the fake RBAC client's denial.
var errAuditGrantMissing = errors.New("fake rbac: permission denied")

// auditGrantRBAC grants exactly one resource:action permission.
type auditGrantRBAC struct {
	grant string
}

func (r *auditGrantRBAC) Authorize(_ context.Context, _ *qrdbtransport.Identity, resource, action string) error {
	if resource+":"+action == r.grant {
		return nil
	}
	return errAuditGrantMissing
}

func (r *auditGrantRBAC) ListPermissions(_ context.Context, _ *qrdbtransport.Identity) ([]qrdbtransport.PermissionInfo, error) {
	return nil, errAuditGrantMissing
}

func (r *auditGrantRBAC) ListOwnPermissions(ctx context.Context) ([]qrdbtransport.PermissionInfo, error) {
	return r.ListPermissions(ctx, nil)
}

// adminServiceFrom wires an AdminService the way app.go does: SetAuthorizer
// only with a non-nil accessor result.
func adminServiceFrom(svc *pkgxkms.XKMSService, ctx context.Context) *AdminService {
	s := NewAdminService()
	if a := svc.Authorizer(); a != nil {
		s.SetAuthorizer(a)
	}
	s.SetContext(ctx)
	return s
}

func auditReadGrant() string {
	perm := xkmssdk.QRDBPermissionAuditRead
	return xkmssdk.QRDBPermissionResource(perm) + ":" + xkmssdk.QRDBPermissionAction(perm)
}

// TestAdminServiceAuthorizer_NoRBACStillRefuses proves a service without
// go-qrdb RBAC never turns the audit-read refusal into allow-all.
func TestAdminServiceAuthorizer_NoRBACStillRefuses(t *testing.T) {
	ctx := xkmssdk.QRDBWithIdentity(context.Background(), &auth.Identity{Subject: "alice"})

	for name, svc := range map[string]*pkgxkms.XKMSService{
		"none wired": {},
		"disabled": func() *pkgxkms.XKMSService {
			s := &pkgxkms.XKMSService{}
			s.SetAuthorizer(auth.NewAuthorizer(nil))
			return s
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			err := adminServiceFrom(svc, ctx).authorizeAuditRead()
			var denied *AuditReadDeniedError
			require.ErrorAs(t, err, &denied)
			assert.Equal(t, "no authorizer", denied.Reason)
		})
	}
}

// TestAdminServiceAuthorizer_EnforcesAuditRead proves an enabled authorizer
// admits an identity holding audit:read and refuses one without it.
func TestAdminServiceAuthorizer_EnforcesAuditRead(t *testing.T) {
	ctx := xkmssdk.QRDBWithIdentity(context.Background(), &auth.Identity{Subject: "alice", TenantID: "acme"})

	t.Run("granted", func(t *testing.T) {
		svc := &pkgxkms.XKMSService{}
		svc.SetAuthorizer(auth.NewAuthorizer(&auditGrantRBAC{grant: auditReadGrant()}))
		require.NoError(t, adminServiceFrom(svc, ctx).authorizeAuditRead())
	})

	t.Run("not granted", func(t *testing.T) {
		svc := &pkgxkms.XKMSService{}
		svc.SetAuthorizer(auth.NewAuthorizer(&auditGrantRBAC{grant: "audit:delete"}))
		err := adminServiceFrom(svc, ctx).authorizeAuditRead()
		var denied *AuditReadDeniedError
		require.ErrorAs(t, err, &denied)
		assert.Equal(t, "denied", denied.Reason)
		require.ErrorIs(t, err, errAuditGrantMissing)
	})

	t.Run("no identity", func(t *testing.T) {
		svc := &pkgxkms.XKMSService{}
		svc.SetAuthorizer(auth.NewAuthorizer(&auditGrantRBAC{grant: auditReadGrant()}))
		err := adminServiceFrom(svc, context.Background()).authorizeAuditRead()
		var denied *AuditReadDeniedError
		require.ErrorAs(t, err, &denied)
		assert.Equal(t, "no identity", denied.Reason)
	})
}
