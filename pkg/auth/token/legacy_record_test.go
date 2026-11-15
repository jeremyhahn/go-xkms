package token

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// stripTenantFromStoredRecords rewrites every refresh record in kv as a
// release before tenant-scoped revocation serialized it: without the
// tenant_id field.
func stripTenantFromStoredRecords(t *testing.T, kv *guardedMemoryKV) {
	t.Helper()
	entries, err := kv.Scan(context.Background(), refreshPrefix)
	require.NoError(t, err)
	require.NotEmpty(t, entries)
	for key, data := range entries {
		var fields map[string]any
		require.NoError(t, json.Unmarshal(data, &fields))
		require.Contains(t, fields, "tenant_id")
		delete(fields, "tenant_id")
		legacy, err := json.Marshal(fields)
		require.NoError(t, err)
		require.NoError(t, kv.Put(context.Background(), key, legacy))
	}
}

// A refresh record written before records carried a tenant names only its
// subject. Revoking that account in its own (non-system) tenant must end the
// session too, or re-enabling or recreating the account revives the token.
func TestRevokeBySubject_RevokesAPreTenantRecordOfTheSubjectInAnyTenant(t *testing.T) {
	ctx := context.Background()
	kv := newGuardedMemoryKV()
	store, err := NewQRDBRefreshStore(kv)
	require.NoError(t, err)
	issuer := newIssuerWithStore(t, store)

	acmeAlice := testIdentity()
	acmeAlice.Subject = "alice"
	acmeAlice.TenantID = "acme"
	acmeBob := testIdentity()
	acmeBob.Subject = "bob"
	acmeBob.TenantID = "acme"

	alicePair, err := issuer.Mint(ctx, acmeAlice)
	require.NoError(t, err)
	bobPair, err := issuer.Mint(ctx, acmeBob)
	require.NoError(t, err)
	stripTenantFromStoredRecords(t, kv)

	require.NoError(t, issuer.RevokeBySubject(ctx, "acme", "alice"))

	_, err = issuer.Refresh(ctx, alicePair.RefreshToken)
	var revokedErr *RefreshRevokedError
	require.ErrorAs(t, err, &revokedErr, "acme/alice's pre-tenant session ends with her account")
	_, err = issuer.Refresh(ctx, bobPair.RefreshToken)
	require.NoError(t, err, "another subject's pre-tenant session survives")
}

// The memory store holds the same contract for a record with no tenant.
func TestRevokeBySubject_MemoryStoreRevokesATenantlessRecordInAnyTenant(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryRefreshStore()
	require.NoError(t, store.Save(ctx, &Record{
		JTI: "jti-1", Family: "fam-alice", Subject: "alice",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}))

	require.NoError(t, store.RevokeBySubject(ctx, "acme", "alice"))

	got, err := store.Get(ctx, "fam-alice", "jti-1")
	require.NoError(t, err)
	require.Nil(t, got, "a tenantless record of the subject is revoked in every tenant")
}
