package token

import (
	"context"
	"testing"
	"time"
)

// RefreshKeyForTest exposes the refresh record key to the external tests,
// which write a record without a tenant straight into QRDB.
func RefreshKeyForTest(family, jti string) string { return refreshKey(family, jti) }

// AssertTenantScopedRevoke saves refresh families for the same subject
// "alice" in tenants "t1" and "t2", revokes ("t1", "alice") and checks that
// only t1's family is revoked: t2's token still rotates. It is exported for
// the external QRDB test on the embedded node.
func AssertTenantScopedRevoke(t *testing.T, ctx context.Context, s RefreshStore) {
	t.Helper()
	exp := time.Now().Add(time.Hour).Unix()
	r1 := &Record{JTI: "j1", Family: "f1", Tenant: "t1", Subject: "alice", ExpiresAt: exp}
	r2 := &Record{JTI: "j2", Family: "f2", Tenant: "t2", Subject: "alice", ExpiresAt: exp}
	if err := s.Save(ctx, r1); err != nil {
		t.Fatalf("Save t1: %v", err)
	}
	if err := s.Save(ctx, r2); err != nil {
		t.Fatalf("Save t2: %v", err)
	}

	if err := s.RevokeBySubject(ctx, "", "alice"); err == nil {
		t.Fatal("RevokeBySubject with an empty tenant: want error")
	}
	if err := s.RevokeBySubject(ctx, "t1", ""); err == nil {
		t.Fatal("RevokeBySubject with an empty subject: want error")
	}
	if rec, err := s.Get(ctx, "f1", "j1"); err != nil || rec == nil {
		t.Fatalf("t1 record after refused revokes: rec=%v err=%v", rec, err)
	}

	if err := s.RevokeBySubject(ctx, "t1", "alice"); err != nil {
		t.Fatalf("RevokeBySubject(t1, alice): %v", err)
	}
	if rec, err := s.Get(ctx, "f1", "j1"); err == nil && rec != nil {
		t.Fatalf("t1 family must be revoked, got %+v", rec)
	}
	rec, err := s.Get(ctx, "f2", "j2")
	if err != nil || rec == nil {
		t.Fatalf("t2 family must survive t1's revoke: rec=%v err=%v", rec, err)
	}
	if rec.Tenant != "t2" || rec.Subject != "alice" {
		t.Fatalf("t2 record = %+v", rec)
	}
	if err := s.MarkRotated(ctx, "f2", "j2"); err != nil {
		t.Fatalf("t2 token must still rotate: %v", err)
	}
}

func TestMemoryRefreshStore_RevokeBySubject_TenantScoped(t *testing.T) {
	AssertTenantScopedRevoke(t, context.Background(), NewMemoryRefreshStore())
}

func TestMemoryRefreshStore_Save_RefusesRecordWithoutTenant(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryRefreshStore()
	rec := &Record{JTI: "j0", Family: "f0", Subject: "alice", ExpiresAt: time.Now().Add(time.Hour).Unix()}
	if err := s.Save(ctx, rec); err == nil {
		t.Fatal("Save of a record without a tenant: want error")
	}
	for _, tenant := range []string{"t1", "t2"} {
		if err := s.RevokeBySubject(ctx, tenant, "alice"); err != nil {
			t.Fatalf("RevokeBySubject(%s): %v", tenant, err)
		}
	}
	if got, err := s.Get(ctx, "f0", "j0"); err == nil && got != nil {
		t.Fatalf("record without a tenant must not be kept, got %+v", got)
	}
	if err := s.MarkRotated(ctx, "f0", "j0"); err == nil {
		t.Fatal("rotate of a record without a tenant: want error")
	}
}
