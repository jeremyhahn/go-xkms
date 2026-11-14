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

package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// errUnknownTestUser is returned by the discoverable user handler for a user
// handle that names no registered user.
var errUnknownTestUser = errors.New("client test: unknown user handle")

// discoverableTestUser is a relying-party user for the go-webauthn round trip.
type discoverableTestUser struct {
	id          []byte
	credentials []webauthn.Credential
}

func (u *discoverableTestUser) WebAuthnID() []byte                         { return u.id }
func (u *discoverableTestUser) WebAuthnName() string                       { return "alice@example.com" }
func (u *discoverableTestUser) WebAuthnDisplayName() string                { return "Alice" }
func (u *discoverableTestUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

// TestSoftwareAdapter_DiscoverableLogin_GoWebAuthn drives a passkey
// registration and a discoverable login (empty allowCredentials) between
// go-webauthn and the software adapter. ValidateDiscoverableLogin rejects an
// assertion with a blank user handle, so this pins the userHandle member.
func TestSoftwareAdapter_DiscoverableLogin_GoWebAuthn(t *testing.T) {
	rp, err := webauthn.New(&webauthn.Config{
		RPID:          "localhost",
		RPDisplayName: "Test RP",
		RPOrigins:     []string{"https://localhost"},
	})
	if err != nil {
		t.Fatalf("webauthn.New() error: %v", err)
	}
	adapter := NewSoftwareAdapter()
	user := &discoverableTestUser{id: []byte("user-handle-0001")}

	creation, regSession, err := rp.BeginRegistration(user,
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired))
	if err != nil {
		t.Fatalf("BeginRegistration() error: %v", err)
	}
	creationJSON, err := json.Marshal(creation)
	if err != nil {
		t.Fatalf("marshal creation options: %v", err)
	}
	attestation, err := adapter.MakeCredential(context.Background(),
		&CeremonyOptions{OptionsJSON: creationJSON, Origin: "https://localhost"})
	if err != nil {
		t.Fatalf("MakeCredential() error: %v", err)
	}
	parsedCreation, err := protocol.ParseCredentialCreationResponseBytes(attestation)
	if err != nil {
		t.Fatalf("ParseCredentialCreationResponseBytes() error: %v", err)
	}
	credential, err := rp.CreateCredential(user, *regSession, parsedCreation)
	if err != nil {
		t.Fatalf("CreateCredential() error: %v", err)
	}
	user.credentials = append(user.credentials, *credential)

	assertionOpts, loginSession, err := rp.BeginDiscoverableLogin()
	if err != nil {
		t.Fatalf("BeginDiscoverableLogin() error: %v", err)
	}
	assertionJSON, err := json.Marshal(assertionOpts)
	if err != nil {
		t.Fatalf("marshal assertion options: %v", err)
	}
	assertion, err := adapter.GetAssertion(context.Background(),
		&CeremonyOptions{OptionsJSON: assertionJSON, Origin: "https://localhost"})
	if err != nil {
		t.Fatalf("GetAssertion() error: %v", err)
	}
	parsedAssertion, err := protocol.ParseCredentialRequestResponseBytes(assertion)
	if err != nil {
		t.Fatalf("ParseCredentialRequestResponseBytes() error: %v", err)
	}

	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		if !bytes.Equal(userHandle, user.id) {
			return nil, errUnknownTestUser
		}
		return user, nil
	}
	validated, err := rp.ValidateDiscoverableLogin(handler, *loginSession, parsedAssertion)
	if err != nil {
		t.Fatalf("ValidateDiscoverableLogin() error: %v", err)
	}
	if !bytes.Equal(validated.ID, credential.ID) {
		t.Errorf("validated credential ID = %x, want %x", validated.ID, credential.ID)
	}
}

func TestExtractUserHandle(t *testing.T) {
	userID := []byte("user-123")
	handle, err := extractUserHandle(map[int]interface{}{
		0x04: map[interface{}]interface{}{"id": userID, "name": "alice"},
	})
	if err != nil {
		t.Fatalf("extractUserHandle() error: %v", err)
	}
	if !bytes.Equal(handle, userID) {
		t.Errorf("extractUserHandle() = %q, want %q", handle, userID)
	}

	handle, err = extractUserHandle(map[int]interface{}{0x01: "credential"})
	if err != nil || handle != nil {
		t.Errorf("extractUserHandle() without user = (%q, %v), want (nil, nil)", handle, err)
	}
}

func TestExtractUserHandle_Malformed(t *testing.T) {
	tests := []struct {
		name string
		user interface{}
	}{
		{name: "not_a_map", user: []byte("user-123")},
		{name: "id_not_bytes", user: map[interface{}]interface{}{"id": "user-123"}},
		{name: "id_missing", user: map[interface{}]interface{}{"name": "alice"}},
		{name: "id_empty", user: map[interface{}]interface{}{"id": []byte{}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := extractUserHandle(map[int]interface{}{0x04: tt.user})
			if !errors.Is(err, ErrCTAPOperationFailed) {
				t.Errorf("extractUserHandle() error = %v, want ErrCTAPOperationFailed", err)
			}
		})
	}
}
