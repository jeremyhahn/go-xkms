// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

package token

import (
	"context"
	"errors"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// refreshOwnerStores are the stores the owner check runs against: the
// in-memory store and the QRDB store over the guarded test KV.
func refreshOwnerStores() map[string]func(t *testing.T) RefreshStore {
	return map[string]func(t *testing.T) RefreshStore{
		"memory": func(*testing.T) RefreshStore { return NewMemoryRefreshStore() },
		"qrdb": func(t *testing.T) RefreshStore {
			store, err := NewQRDBRefreshStore(newGuardedMemoryKV(), WithCallContext(rbacServiceBind))
			require.NoError(t, err)
			return store
		},
	}
}

// refreshRecordOf returns the family, jti and stored record of a refresh token.
func refreshRecordOf(t *testing.T, issuer *Issuer, store RefreshStore, refreshToken string) (string, string, *Record) {
	t.Helper()
	claims, err := issuer.verifyRefresh(refreshToken)
	require.NoError(t, err)
	family, _ := claims["fam"].(string)
	jti, _ := claims["jti"].(string)
	rec, err := store.Get(context.Background(), family, jti)
	require.NoError(t, err)
	require.NotNil(t, rec)
	return family, jti, rec
}

// rewriteRefreshRecord replaces the stored record of a refresh token with a
// mutated copy, as a record written by another owner or an older release.
func rewriteRefreshRecord(t *testing.T, issuer *Issuer, store RefreshStore, refreshToken string, mutate func(*Record)) {
	t.Helper()
	_, _, rec := refreshRecordOf(t, issuer, store, refreshToken)
	cp := *rec
	mutate(&cp)
	require.NoError(t, store.Save(context.Background(), &cp))
}

func TestRefresh_RefusesRecordOwnedByAnotherSubjectOrTenant(t *testing.T) {
	cases := map[string]func(*Record){
		"other subject":       func(r *Record) { r.Subject = "bob" },
		"other tenant":        func(r *Record) { r.TenantID = "tenant-b" },
		"system tenant":       func(r *Record) { r.TenantID = qrdbsdk.SystemTenantID },
		"tenantless (legacy)": func(r *Record) { r.TenantID = "" },
	}
	for storeName, newStore := range refreshOwnerStores() {
		for caseName, mutate := range cases {
			t.Run(storeName+"/"+caseName, func(t *testing.T) {
				store := newStore(t)
				issuer := newIssuerWithStore(t, store)

				pair, err := issuer.Mint(context.Background(), testIdentity())
				require.NoError(t, err)
				rewriteRefreshRecord(t, issuer, store, pair.RefreshToken, mutate)

				next, err := issuer.Refresh(context.Background(), pair.RefreshToken)
				var revokedErr *RefreshRevokedError
				require.ErrorAs(t, err, &revokedErr)
				require.Nil(t, next, "a refused refresh mints nothing")

				_, _, rec := refreshRecordOf(t, issuer, store, pair.RefreshToken)
				require.False(t, rec.Rotated, "a refused refresh leaves the record unrotated")
			})
		}
	}
}

// TestRefresh_ForeignOwnerReuseDoesNotRevokeFamily pins the order of the owner
// and reuse checks: a token that names a rotated record of another owner gets
// the generic revocation and cannot revoke that owner's family through reuse
// handling, so the live successor still refreshes.
func TestRefresh_ForeignOwnerReuseDoesNotRevokeFamily(t *testing.T) {
	cases := map[string]func(*Record){
		"other subject": func(r *Record) { r.Subject = "bob" },
		"other tenant":  func(r *Record) { r.TenantID = "tenant-b" },
		"system tenant": func(r *Record) { r.TenantID = qrdbsdk.SystemTenantID },
	}
	for storeName, newStore := range refreshOwnerStores() {
		for caseName, mutate := range cases {
			t.Run(storeName+"/"+caseName, func(t *testing.T) {
				store := newStore(t)
				issuer := newIssuerWithStore(t, store)

				a, err := issuer.Mint(context.Background(), testIdentity())
				require.NoError(t, err)
				b, err := issuer.Refresh(context.Background(), a.RefreshToken)
				require.NoError(t, err)

				rewriteRefreshRecord(t, issuer, store, a.RefreshToken, mutate)
				_, _, rec := refreshRecordOf(t, issuer, store, a.RefreshToken)
				require.True(t, rec.Rotated, "the foreign record is a rotated one")

				next, err := issuer.Refresh(context.Background(), a.RefreshToken)
				var revokedErr *RefreshRevokedError
				require.ErrorAs(t, err, &revokedErr)
				var reuseErr *RefreshReuseError
				require.False(t, errors.As(err, &reuseErr), "a foreign token is not handled as reuse")
				require.Nil(t, next, "a refused refresh mints nothing")

				succ, err := issuer.Refresh(context.Background(), b.RefreshToken)
				require.NoError(t, err, "the family is not revoked and its successor still refreshes")
				require.NotEmpty(t, succ.RefreshToken)
			})
		}
	}
}

func TestRefresh_MatchingOwnerRotates(t *testing.T) {
	for storeName, newStore := range refreshOwnerStores() {
		t.Run(storeName, func(t *testing.T) {
			store := newStore(t)
			issuer := newIssuerWithStore(t, store)

			pair, err := issuer.Mint(context.Background(), testIdentity())
			require.NoError(t, err)

			next, err := issuer.Refresh(context.Background(), pair.RefreshToken)
			require.NoError(t, err)
			require.NotEmpty(t, next.RefreshToken)

			_, _, rec := refreshRecordOf(t, issuer, store, pair.RefreshToken)
			require.True(t, rec.Rotated)
		})
	}
}

func TestRefresh_SystemTenantSessionRecordsCanonicalTenant(t *testing.T) {
	for storeName, newStore := range refreshOwnerStores() {
		t.Run(storeName, func(t *testing.T) {
			store := newStore(t)
			issuer := newIssuerWithStore(t, store)

			// A system-tenant session carries no tenant claim; its record
			// names the system tenant, so it is not mistaken for a legacy one.
			sys := &auth.Identity{Subject: "root", Metadata: map[string]string{"username": "root"}}
			pair, err := issuer.Mint(context.Background(), sys)
			require.NoError(t, err)
			_, _, rec := refreshRecordOf(t, issuer, store, pair.RefreshToken)
			require.Equal(t, qrdbsdk.SystemTenantID, rec.TenantID)

			next, err := issuer.Refresh(context.Background(), pair.RefreshToken)
			require.NoError(t, err)
			_, _, succ := refreshRecordOf(t, issuer, store, next.RefreshToken)
			require.Equal(t, qrdbsdk.SystemTenantID, succ.TenantID)
		})
	}
}
