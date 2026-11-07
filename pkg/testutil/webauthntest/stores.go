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

// Package webauthntest builds the WebAuthn relying party's stores the way
// production does -- users on a qrdb user client, credentials on DAO
// entities -- entirely in memory, for tests outside pkg/webauthn.
package webauthntest

import (
	"context"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"

	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/webauthn"
)

// TenantID is the qrdb tenant the stores scope their users to.
const TenantID = "system"

// Stores is a paired user and credential store over one qrdb user client
// and one in-process DAO factory.
type Stores struct {
	// Users resolves WebAuthn users from the qrdb user records.
	Users webauthn.UserStore

	// Credentials persists credentials on DAO entities.
	Credentials webauthn.CredentialStore

	// records is the qrdb user client the stores read users from.
	records qrdbtransport.UserClient
}

// SetStanding rewrites the lifecycle and auth-method policy on the qrdb
// record of email's account, the way an administrator suspends an account or
// withdraws a factor. It needs a user client that hands out its stored
// records, as the testutil fake does, and fails the test otherwise.
func (s *Stores) SetStanding(t testing.TB, email string, state qrdbsdk.Lifecycle, methods []string) {
	t.Helper()
	record, err := s.records.GetUserByEmail(context.Background(), TenantID, email)
	if err != nil {
		t.Fatalf("webauthntest: look up %s: %v", email, err)
	}
	record.Lifecycle = string(state)
	record.AuthMethods = methods
	stored, err := s.records.GetUserByEmail(context.Background(), TenantID, email)
	if err != nil {
		t.Fatalf("webauthntest: re-read %s: %v", email, err)
	}
	if stored.Lifecycle != string(state) {
		t.Fatalf("webauthntest: user client %T does not hand out its stored records", s.records)
	}
}

// NewStores returns stores over a fresh in-memory fake qrdb identity plane.
// It fails the test if they cannot be built.
func NewStores(t testing.TB) *Stores {
	t.Helper()
	client, _, err := testutil.NewQRDBFakeClient()
	if err != nil {
		t.Fatalf("webauthntest: fake qrdb client: %v", err)
	}
	return NewStoresFor(t, client.Users())
}

// NewStoresFor returns stores whose users are the records of users, for a
// test that already models the qrdb accounts the relying party must see.
// It fails the test if the stores cannot be built.
func NewStoresFor(t testing.TB, users qrdbtransport.UserClient) *Stores {
	t.Helper()
	us, creds, err := webauthn.NewQRDBUserStoreAdapter(webauthn.QRDBUserStoreOptions{
		Users:      users,
		DAOFactory: testutil.NewMemoryDAOFactory(),
		TenantID:   TenantID,
		KV:         testutil.NewQRDBFakeTransport(),
	})
	if err != nil {
		t.Fatalf("webauthntest: store adapter: %v", err)
	}
	return &Stores{Users: us, Credentials: creds, records: users}
}
