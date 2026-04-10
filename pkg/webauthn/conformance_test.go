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

package webauthn

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// conformanceTestConfig returns a Config suitable for Chrome WebAuthn conformance testing.
func conformanceTestConfig() *Config {
	return &Config{
		RPID:          "localhost",
		RPDisplayName: "Test",
		RPOrigins:     []string{"https://localhost:8443"},
	}
}

// conformanceTestService creates a fully wired service with memory stores
// for conformance testing.
func conformanceTestService(t *testing.T) *Service {
	t.Helper()
	svc, err := NewService(ServiceParams{
		Config:          conformanceTestConfig(),
		UserStore:       NewMemoryUserStore(),
		SessionStore:    NewMemorySessionStore(),
		CredentialStore: NewMemoryCredentialStore(),
	})
	require.NoError(t, err)
	return svc
}

// registrationOptionsJSON calls BeginRegistration and returns the JSON-decoded
// map[string]interface{} representation of the options along with the raw bytes.
func registrationOptionsJSON(t *testing.T, svc *Service) map[string]interface{} {
	t.Helper()
	ctx := context.Background()

	options, sessionID, err := svc.BeginRegistration(ctx, "user@localhost", "Test User")
	require.NoError(t, err)
	require.NotEmpty(t, sessionID)

	data, err := json.Marshal(options)
	require.NoError(t, err)

	var result map[string]interface{}
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	return result
}

// TestConformance_RegistrationOptionsJSON validates that the JSON structure
// produced by BeginRegistration matches exactly what Chrome expects for
// navigator.credentials.create(). Chrome requires specific field names,
// nesting under "publicKey", and particular default values.
func TestConformance_RegistrationOptionsJSON(t *testing.T) {
	svc := conformanceTestService(t)
	result := registrationOptionsJSON(t, svc)

	// Chrome expects the top-level wrapper to have a "publicKey" field.
	publicKey, ok := result["publicKey"].(map[string]interface{})
	require.True(t, ok, "response must contain publicKey object")

	// -- rp --
	rp, ok := publicKey["rp"].(map[string]interface{})
	require.True(t, ok, "publicKey must contain rp object")
	assert.Equal(t, "localhost", rp["id"], "rp.id must be localhost")
	assert.Equal(t, "Test", rp["name"], "rp.name must be Test")

	// -- user --
	user, ok := publicKey["user"].(map[string]interface{})
	require.True(t, ok, "publicKey must contain user object")

	userID, ok := user["id"]
	require.True(t, ok, "user.id must be present")
	userIDStr, ok := userID.(string)
	require.True(t, ok, "user.id must be a string (base64url-encoded)")
	assert.NotEmpty(t, userIDStr, "user.id must not be empty")

	userName, ok := user["name"]
	require.True(t, ok, "user.name must be present")
	assert.NotEmpty(t, userName, "user.name must not be empty")

	userDisplayName, ok := user["displayName"]
	require.True(t, ok, "user.displayName must be present")
	assert.NotEmpty(t, userDisplayName, "user.displayName must not be empty")

	// -- challenge --
	challenge, ok := publicKey["challenge"]
	require.True(t, ok, "publicKey must contain challenge")
	challengeStr, ok := challenge.(string)
	require.True(t, ok, "challenge must be a string (base64url-encoded)")
	assert.NotEmpty(t, challengeStr, "challenge must not be empty")

	// -- pubKeyCredParams --
	params, ok := publicKey["pubKeyCredParams"].([]interface{})
	require.True(t, ok, "publicKey must contain pubKeyCredParams array")
	require.GreaterOrEqual(t, len(params), 1, "pubKeyCredParams must have at least 1 entry")

	firstParam, ok := params[0].(map[string]interface{})
	require.True(t, ok, "pubKeyCredParams[0] must be an object")
	assert.Equal(t, "public-key", firstParam["type"], "pubKeyCredParams[0].type must be public-key")

	// ES256 = COSE algorithm -7. JSON numbers decode as float64.
	algValue, ok := firstParam["alg"].(float64)
	require.True(t, ok, "pubKeyCredParams[0].alg must be a number")
	assert.Equal(t, float64(-7), algValue, "pubKeyCredParams[0].alg must be -7 (ES256)")

	// -- authenticatorSelection --
	authSel, ok := publicKey["authenticatorSelection"].(map[string]interface{})
	require.True(t, ok, "publicKey must contain authenticatorSelection object")

	residentKey, ok := authSel["residentKey"].(string)
	require.True(t, ok, "authenticatorSelection.residentKey must be a string")
	assert.Equal(t, "preferred", residentKey, "authenticatorSelection.residentKey must be preferred")

	// Chrome requires requireResidentKey to be explicitly present as a boolean,
	// not omitted from JSON. With residentKey=preferred, this must be false.
	requireRK, ok := authSel["requireResidentKey"]
	require.True(t, ok, "authenticatorSelection.requireResidentKey must be present (not omitted)")
	requireRKBool, ok := requireRK.(bool)
	require.True(t, ok, "authenticatorSelection.requireResidentKey must be a boolean")
	assert.False(t, requireRKBool, "authenticatorSelection.requireResidentKey must be false for preferred")

	userVerification, ok := authSel["userVerification"].(string)
	require.True(t, ok, "authenticatorSelection.userVerification must be a string")
	assert.Equal(t, "preferred", userVerification, "authenticatorSelection.userVerification must be preferred")

	// -- timeout --
	timeout, ok := publicKey["timeout"].(float64)
	require.True(t, ok, "publicKey.timeout must be a number")
	assert.Greater(t, timeout, float64(0), "publicKey.timeout must be > 0")

	// -- attestation --
	attestation, ok := publicKey["attestation"].(string)
	require.True(t, ok, "publicKey.attestation must be a string")
	assert.Equal(t, "none", attestation, "publicKey.attestation must be none")
}

// TestConformance_RegistrationOptionsRequiredFields validates that all
// Chrome-required fields carry meaningful values with sufficient entropy
// and correct types. A missing or undersized challenge, for example, will
// cause Chrome to reject the options outright.
func TestConformance_RegistrationOptionsRequiredFields(t *testing.T) {
	svc := conformanceTestService(t)
	result := registrationOptionsJSON(t, svc)

	publicKey, ok := result["publicKey"].(map[string]interface{})
	require.True(t, ok)

	// Challenge must decode to at least 16 bytes (WebAuthn spec minimum).
	challengeStr, ok := publicKey["challenge"].(string)
	require.True(t, ok)
	challengeBytes, err := base64.RawURLEncoding.DecodeString(challengeStr)
	require.NoError(t, err, "challenge must be valid base64url")
	assert.GreaterOrEqual(t, len(challengeBytes), 16,
		"challenge must be at least 16 bytes when decoded (WebAuthn spec requirement)")

	// user.id must be present and non-empty.
	user, ok := publicKey["user"].(map[string]interface{})
	require.True(t, ok)
	userIDStr, ok := user["id"].(string)
	require.True(t, ok, "user.id must be a string")
	assert.NotEmpty(t, userIDStr, "user.id must not be empty")

	// rp.id must be present and non-empty.
	rp, ok := publicKey["rp"].(map[string]interface{})
	require.True(t, ok)
	rpID, ok := rp["id"].(string)
	require.True(t, ok, "rp.id must be a string")
	assert.NotEmpty(t, rpID, "rp.id must not be empty")

	// pubKeyCredParams must include ES256 (-7).
	params, ok := publicKey["pubKeyCredParams"].([]interface{})
	require.True(t, ok)

	foundES256 := false
	for _, p := range params {
		pMap, ok := p.(map[string]interface{})
		if !ok {
			continue
		}
		if alg, ok := pMap["alg"].(float64); ok && alg == -7 {
			foundES256 = true
			break
		}
	}
	assert.True(t, foundES256, "pubKeyCredParams must include ES256 (alg: -7)")

	// timeout must be > 0.
	timeout, ok := publicKey["timeout"].(float64)
	require.True(t, ok, "timeout must be a number")
	assert.Greater(t, timeout, float64(0), "timeout must be > 0")
}

// TestConformance_RequireResidentKeyPresence validates that for every
// ResidentKeyRequirement setting, the serialized JSON always includes the
// requireResidentKey boolean field. Chrome relies on this legacy field for
// backwards compatibility. If it is omitted (via omitempty on a nil *bool),
// Chrome may reject the options or fall back to unexpected behavior.
func TestConformance_RequireResidentKeyPresence(t *testing.T) {
	requirements := []struct {
		setting       string
		expectRKValue bool
	}{
		{setting: "required", expectRKValue: true},
		{setting: "preferred", expectRKValue: false},
		{setting: "discouraged", expectRKValue: false},
	}

	for _, tc := range requirements {
		t.Run(tc.setting, func(t *testing.T) {
			cfg := conformanceTestConfig()
			cfg.ResidentKeyRequirement = tc.setting

			svc, err := NewService(ServiceParams{
				Config:          cfg,
				UserStore:       NewMemoryUserStore(),
				SessionStore:    NewMemorySessionStore(),
				CredentialStore: NewMemoryCredentialStore(),
			})
			require.NoError(t, err)

			ctx := context.Background()
			options, _, err := svc.BeginRegistration(ctx, "rk-test@localhost", "RK Test User")
			require.NoError(t, err)

			data, err := json.Marshal(options)
			require.NoError(t, err)

			var result map[string]interface{}
			err = json.Unmarshal(data, &result)
			require.NoError(t, err)

			publicKey, ok := result["publicKey"].(map[string]interface{})
			require.True(t, ok)

			authSel, ok := publicKey["authenticatorSelection"].(map[string]interface{})
			require.True(t, ok, "authenticatorSelection must be present")

			// The critical Chrome compatibility check: requireResidentKey must
			// always be present as an explicit boolean, never omitted.
			requireRK, present := authSel["requireResidentKey"]
			require.True(t, present,
				"requireResidentKey must be present in JSON for residentKey=%q (Chrome compatibility)", tc.setting)

			requireRKBool, ok := requireRK.(bool)
			require.True(t, ok, "requireResidentKey must be a boolean, got %T", requireRK)
			assert.Equal(t, tc.expectRKValue, requireRKBool,
				"requireResidentKey must be %v for residentKey=%q", tc.expectRKValue, tc.setting)

			// Also verify the residentKey string is present and matches.
			residentKey, ok := authSel["residentKey"].(string)
			require.True(t, ok, "residentKey must be a string")
			assert.Equal(t, tc.setting, residentKey,
				"residentKey must match configured value %q", tc.setting)
		})
	}
}

// TestConformance_LoginOptionsJSON validates that the JSON structure produced
// by BeginLogin with a known user ID matches Chrome's expectations for
// navigator.credentials.get(). This includes verifying rpId, challenge,
// timeout, userVerification, and allowCredentials fields.
func TestConformance_LoginOptionsJSON(t *testing.T) {
	svc := conformanceTestService(t)
	ctx := context.Background()

	// First, register a user so they have credentials in the store.
	// We manually create a user and insert a mock credential to avoid
	// the full registration ceremony which requires authenticator interaction.
	email := "login-test@localhost"
	displayName := "Login Test User"
	user, err := svc.users.Create(ctx, email, displayName)
	require.NoError(t, err)

	mockCredential := &Credential{
		ID:              []byte("mock-credential-id-12345"),
		UserID:          user.WebAuthnID(),
		PublicKey:       []byte("mock-public-key-bytes"),
		AttestationType: "none",
		Flags: CredentialFlags{
			UserPresent: true,
		},
		Authenticator: AuthenticatorData{
			AAGUID:    make([]byte, 16),
			SignCount: 0,
		},
	}

	err = svc.creds.Save(ctx, mockCredential)
	require.NoError(t, err)

	// Add credential to user so BeginLogin can find it.
	user.AddCredential(mockCredential)
	err = svc.users.Save(ctx, user)
	require.NoError(t, err)

	// Begin login with the user's ID.
	options, sessionID, err := svc.BeginLogin(ctx, user.WebAuthnID())
	require.NoError(t, err)
	require.NotEmpty(t, sessionID)

	data, err := json.Marshal(options)
	require.NoError(t, err)

	var result map[string]interface{}
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	publicKey, ok := result["publicKey"].(map[string]interface{})
	require.True(t, ok, "response must contain publicKey object")

	// rpId must be present.
	rpID, ok := publicKey["rpId"].(string)
	require.True(t, ok, "publicKey.rpId must be a string")
	assert.Equal(t, "localhost", rpID, "publicKey.rpId must be localhost")

	// challenge must be present and non-empty.
	challenge, ok := publicKey["challenge"].(string)
	require.True(t, ok, "publicKey.challenge must be a string")
	assert.NotEmpty(t, challenge, "publicKey.challenge must not be empty")

	// timeout must be present and > 0.
	timeout, ok := publicKey["timeout"].(float64)
	require.True(t, ok, "publicKey.timeout must be a number")
	assert.Greater(t, timeout, float64(0), "publicKey.timeout must be > 0")

	// userVerification must be present.
	uv, ok := publicKey["userVerification"].(string)
	require.True(t, ok, "publicKey.userVerification must be a string")
	assert.NotEmpty(t, uv, "publicKey.userVerification must not be empty")

	// allowCredentials must be present when a user ID is provided.
	allowCreds, ok := publicKey["allowCredentials"].([]interface{})
	require.True(t, ok, "publicKey.allowCredentials must be an array when user ID is provided")
	assert.NotEmpty(t, allowCreds, "allowCredentials must not be empty for a user with credentials")

	// Each entry in allowCredentials must have type and id.
	for i, entry := range allowCreds {
		credDesc, ok := entry.(map[string]interface{})
		require.True(t, ok, "allowCredentials[%d] must be an object", i)
		assert.Equal(t, "public-key", credDesc["type"],
			"allowCredentials[%d].type must be public-key", i)
		assert.NotEmpty(t, credDesc["id"],
			"allowCredentials[%d].id must not be empty", i)
	}
}

// TestConformance_DiscoverableLoginOptions validates that when BeginLogin is
// called with a nil userID (the passkey / discoverable credential flow),
// the response omits allowCredentials and still includes all other required
// fields. Chrome uses the absence of allowCredentials to trigger the
// passkey selection UI.
func TestConformance_DiscoverableLoginOptions(t *testing.T) {
	svc := conformanceTestService(t)
	ctx := context.Background()

	// Begin discoverable login (nil userID).
	options, sessionID, err := svc.BeginLogin(ctx, nil)
	require.NoError(t, err)
	require.NotEmpty(t, sessionID)

	data, err := json.Marshal(options)
	require.NoError(t, err)

	var result map[string]interface{}
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	publicKey, ok := result["publicKey"].(map[string]interface{})
	require.True(t, ok, "response must contain publicKey object")

	// allowCredentials must be absent or empty for passkey flow.
	// The go-webauthn library omits the field entirely when empty (omitempty).
	allowCreds, present := publicKey["allowCredentials"]
	if present {
		// If present, it must be an empty array or nil.
		allowCredsSlice, ok := allowCreds.([]interface{})
		if ok {
			assert.Empty(t, allowCredsSlice,
				"allowCredentials must be empty for discoverable login")
		}
	}
	// If not present at all, that is also correct for the passkey flow.

	// All other required fields must still be present.
	rpID, ok := publicKey["rpId"].(string)
	require.True(t, ok, "publicKey.rpId must be a string")
	assert.Equal(t, "localhost", rpID, "publicKey.rpId must be localhost")

	challenge, ok := publicKey["challenge"].(string)
	require.True(t, ok, "publicKey.challenge must be a string")
	assert.NotEmpty(t, challenge, "publicKey.challenge must not be empty")

	challengeBytes, err := base64.RawURLEncoding.DecodeString(challenge)
	require.NoError(t, err, "challenge must be valid base64url")
	assert.GreaterOrEqual(t, len(challengeBytes), 16,
		"challenge must be at least 16 bytes for discoverable login")

	timeout, ok := publicKey["timeout"].(float64)
	require.True(t, ok, "publicKey.timeout must be a number")
	assert.Greater(t, timeout, float64(0), "publicKey.timeout must be > 0")

	uv, ok := publicKey["userVerification"].(string)
	require.True(t, ok, "publicKey.userVerification must be a string")
	assert.NotEmpty(t, uv, "publicKey.userVerification must not be empty")
}
