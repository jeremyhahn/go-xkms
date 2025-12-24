// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build integration && fido2

package fido2

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// WebAuthnServer simulates a WebAuthn relying party server
type WebAuthnServer struct {
	server     *httptest.Server
	challenges map[string][]byte // username -> challenge
	sessions   map[string]*WebAuthnSession
}

// WebAuthnSession represents a server-side WebAuthn session
type WebAuthnSession struct {
	Username     string
	Challenge    []byte
	CredentialID []byte
	PublicKey    []byte
	Salt         []byte
	AAGUID       []byte
	SignCount    uint32
	Created      time.Time
}

// RegistrationRequest from client
type RegistrationRequest struct {
	Username    string `json:"username"`
	DisplayName string `json:"display_name,omitempty"`
}

// RegistrationResponse to client with challenge
type RegistrationResponse struct {
	Challenge        string                   `json:"challenge"`
	RelyingParty     map[string]string        `json:"rp"`
	User             map[string]interface{}   `json:"user"`
	PubKeyCredParams []map[string]interface{} `json:"pubKeyCredParams"`
	Timeout          int                      `json:"timeout"`
}

// RegistrationVerificationRequest from client after credential creation
type RegistrationVerificationRequest struct {
	Username     string `json:"username"`
	CredentialID string `json:"credential_id"`
	PublicKey    string `json:"public_key"`
	Salt         string `json:"salt"`
	AAGUID       string `json:"aaguid,omitempty"`
	SignCount    uint32 `json:"sign_count,omitempty"`
}

// AuthenticationRequest from client
type AuthenticationRequest struct {
	Username string `json:"username"`
}

// AuthenticationResponse to client with challenge
type AuthenticationResponse struct {
	Challenge    string   `json:"challenge"`
	CredentialID string   `json:"credential_id"`
	Salt         string   `json:"salt"`
	Timeout      int      `json:"timeout"`
	RPID         string   `json:"rpId"`
	AllowList    []string `json:"allowCredentials,omitempty"`
}

// AuthenticationVerificationRequest from client after assertion
type AuthenticationVerificationRequest struct {
	Username   string `json:"username"`
	DerivedKey string `json:"derived_key"`
}

// NewWebAuthnServer creates a new test WebAuthn server
func NewWebAuthnServer() *WebAuthnServer {
	srv := &WebAuthnServer{
		challenges: make(map[string][]byte),
		sessions:   make(map[string]*WebAuthnSession),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/webauthn/register/begin", srv.handleRegisterBegin)
	mux.HandleFunc("/webauthn/register/verify", srv.handleRegisterVerify)
	mux.HandleFunc("/webauthn/authenticate/begin", srv.handleAuthenticateBegin)
	mux.HandleFunc("/webauthn/authenticate/verify", srv.handleAuthenticateVerify)
	mux.HandleFunc("/webauthn/session", srv.handleGetSession)

	srv.server = httptest.NewServer(mux)
	return srv
}

// Close closes the test server
func (s *WebAuthnServer) Close() {
	s.server.Close()
}

// URL returns the server URL
func (s *WebAuthnServer) URL() string {
	return s.server.URL
}

// handleRegisterBegin handles registration initialization
func (s *WebAuthnServer) handleRegisterBegin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Generate challenge
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		http.Error(w, "Failed to generate challenge", http.StatusInternalServerError)
		return
	}

	s.challenges[req.Username] = challenge

	// Generate user ID
	userID := make([]byte, 16)
	rand.Read(userID)

	// Prepare response
	resp := RegistrationResponse{
		Challenge: base64.RawURLEncoding.EncodeToString(challenge),
		RelyingParty: map[string]string{
			"id":   "go-keychain-test",
			"name": "Go Keychain Test Server",
		},
		User: map[string]interface{}{
			"id":          base64.RawURLEncoding.EncodeToString(userID),
			"name":        req.Username,
			"displayName": req.DisplayName,
		},
		PubKeyCredParams: []map[string]interface{}{
			{"type": "public-key", "alg": -7}, // ES256
		},
		Timeout: 60000,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleRegisterVerify handles registration verification
func (s *WebAuthnServer) handleRegisterVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RegistrationVerificationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Verify challenge exists
	challenge, exists := s.challenges[req.Username]
	if !exists {
		http.Error(w, "Challenge not found", http.StatusBadRequest)
		return
	}
	delete(s.challenges, req.Username)

	// Decode credential data
	credID, err := base64.StdEncoding.DecodeString(req.CredentialID)
	if err != nil {
		http.Error(w, "Invalid credential ID", http.StatusBadRequest)
		return
	}

	pubKey, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil {
		http.Error(w, "Invalid public key", http.StatusBadRequest)
		return
	}

	salt, err := base64.StdEncoding.DecodeString(req.Salt)
	if err != nil {
		http.Error(w, "Invalid salt", http.StatusBadRequest)
		return
	}

	var aaguid []byte
	if req.AAGUID != "" {
		aaguid, _ = base64.StdEncoding.DecodeString(req.AAGUID)
	}

	// Store session
	s.sessions[req.Username] = &WebAuthnSession{
		Username:     req.Username,
		Challenge:    challenge,
		CredentialID: credID,
		PublicKey:    pubKey,
		Salt:         salt,
		AAGUID:       aaguid,
		SignCount:    req.SignCount,
		Created:      time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Registration successful",
	})
}

// handleAuthenticateBegin handles authentication initialization
func (s *WebAuthnServer) handleAuthenticateBegin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req AuthenticationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Check if user has registered
	session, exists := s.sessions[req.Username]
	if !exists {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Generate new challenge
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		http.Error(w, "Failed to generate challenge", http.StatusInternalServerError)
		return
	}

	s.challenges[req.Username] = challenge

	// Prepare response
	resp := AuthenticationResponse{
		Challenge:    base64.RawURLEncoding.EncodeToString(challenge),
		CredentialID: base64.StdEncoding.EncodeToString(session.CredentialID),
		Salt:         base64.StdEncoding.EncodeToString(session.Salt),
		Timeout:      60000,
		RPID:         "go-keychain-test",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleAuthenticateVerify handles authentication verification
func (s *WebAuthnServer) handleAuthenticateVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req AuthenticationVerificationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Verify challenge exists
	_, exists := s.challenges[req.Username]
	if !exists {
		http.Error(w, "Challenge not found", http.StatusBadRequest)
		return
	}
	delete(s.challenges, req.Username)

	// Verify derived key format
	derivedKey, err := base64.StdEncoding.DecodeString(req.DerivedKey)
	if err != nil {
		http.Error(w, "Invalid derived key", http.StatusBadRequest)
		return
	}

	if len(derivedKey) != 32 {
		http.Error(w, "Invalid derived key length", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Authentication successful",
	})
}

// handleGetSession handles session retrieval
func (s *WebAuthnServer) handleGetSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := r.URL.Query().Get("username")
	if username == "" {
		http.Error(w, "Username required", http.StatusBadRequest)
		return
	}

	session, exists := s.sessions[username]
	if !exists {
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"username":      session.Username,
		"credential_id": base64.StdEncoding.EncodeToString(session.CredentialID),
		"salt":          base64.StdEncoding.EncodeToString(session.Salt),
		"created":       session.Created,
	})
}

// TestWebAuthnServerRegistrationFlow tests the registration ceremony
func TestWebAuthnServerRegistrationFlow(t *testing.T) {
	fido2Cfg := LoadFIDO2TestConfig()
	fido2Cfg.RequireDevice(t)

	srv := NewWebAuthnServer()
	defer srv.Close()

	t.Log("=== WebAuthn Server Registration Flow Test ===")

	username := GenerateUniqueUsername("server-reg-test")

	// Step 1: Begin registration
	t.Log("Step 1: Beginning registration...")

	reqBody := map[string]string{
		"username":     username,
		"display_name": fmt.Sprintf("Test User %s", username),
	}
	reqData, _ := json.Marshal(reqBody)

	resp, err := http.Post(srv.URL()+"/webauthn/register/begin",
		"application/json", bytes.NewReader(reqData))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var regResp RegistrationResponse
	err = json.NewDecoder(resp.Body).Decode(&regResp)
	require.NoError(t, err)

	assert.NotEmpty(t, regResp.Challenge)
	assert.Equal(t, "go-keychain-test", regResp.RelyingParty["id"])

	t.Logf("Registration challenge received: %s", regResp.Challenge[:16]+"...")

	// Step 2: Perform FIDO2 enrollment
	t.Log("Step 2: Enrolling FIDO2 credential...")
	t.Log("Please touch your security key...")

	enrollment, handler := fido2Cfg.EnrollTestCredential(t, username)
	defer CleanupCredential(t, handler)

	// Step 3: Verify registration
	t.Log("Step 3: Verifying registration with server...")

	verifyReq := RegistrationVerificationRequest{
		Username:     username,
		CredentialID: base64.StdEncoding.EncodeToString(enrollment.CredentialID),
		PublicKey:    base64.StdEncoding.EncodeToString(enrollment.PublicKey),
		Salt:         base64.StdEncoding.EncodeToString(enrollment.Salt),
		SignCount:    enrollment.SignCount,
	}

	if len(enrollment.AAGUID) > 0 {
		verifyReq.AAGUID = base64.StdEncoding.EncodeToString(enrollment.AAGUID)
	}

	verifyData, _ := json.Marshal(verifyReq)
	resp, err = http.Post(srv.URL()+"/webauthn/register/verify",
		"application/json", bytes.NewReader(verifyData))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var verifyResp map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&verifyResp)
	require.NoError(t, err)

	assert.True(t, verifyResp["success"].(bool))

	t.Log("Registration flow completed successfully!")
}

// TestWebAuthnServerAuthenticationFlow tests the authentication ceremony
func TestWebAuthnServerAuthenticationFlow(t *testing.T) {
	fido2Cfg := LoadFIDO2TestConfig()
	fido2Cfg.RequireDevice(t)

	srv := NewWebAuthnServer()
	defer srv.Close()

	t.Log("=== WebAuthn Server Authentication Flow Test ===")

	username := GenerateUniqueUsername("server-auth-test")

	// Setup: Register a credential
	t.Log("Setup: Registering credential...")

	enrollment, handler := fido2Cfg.EnrollTestCredential(t, username)
	defer CleanupCredential(t, handler)

	// Store session in server
	srv.sessions[username] = &WebAuthnSession{
		Username:     username,
		CredentialID: enrollment.CredentialID,
		PublicKey:    enrollment.PublicKey,
		Salt:         enrollment.Salt,
		AAGUID:       enrollment.AAGUID,
		SignCount:    enrollment.SignCount,
		Created:      time.Now(),
	}

	// Step 1: Begin authentication
	t.Log("Step 1: Beginning authentication...")

	authReqBody := map[string]string{"username": username}
	authReqData, _ := json.Marshal(authReqBody)

	resp, err := http.Post(srv.URL()+"/webauthn/authenticate/begin",
		"application/json", bytes.NewReader(authReqData))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var authResp AuthenticationResponse
	err = json.NewDecoder(resp.Body).Decode(&authResp)
	require.NoError(t, err)

	assert.NotEmpty(t, authResp.Challenge)
	assert.NotEmpty(t, authResp.CredentialID)
	assert.NotEmpty(t, authResp.Salt)

	t.Logf("Authentication challenge received: %s", authResp.Challenge[:16]+"...")

	// Step 2: Perform FIDO2 authentication
	t.Log("Step 2: Authenticating with FIDO2...")
	t.Log("Please touch your security key...")

	derivedKey := fido2Cfg.AuthenticateWithCredential(t, handler, enrollment)

	// Step 3: Verify authentication
	t.Log("Step 3: Verifying authentication with server...")

	verifyReq := AuthenticationVerificationRequest{
		Username:   username,
		DerivedKey: base64.StdEncoding.EncodeToString(derivedKey),
	}

	verifyData, _ := json.Marshal(verifyReq)
	resp, err = http.Post(srv.URL()+"/webauthn/authenticate/verify",
		"application/json", bytes.NewReader(verifyData))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var verifyResp map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&verifyResp)
	require.NoError(t, err)

	assert.True(t, verifyResp["success"].(bool))

	t.Log("Authentication flow completed successfully!")
}

// TestWebAuthnServerSessionManagement tests session storage and retrieval
func TestWebAuthnServerSessionManagement(t *testing.T) {
	fido2Cfg := LoadFIDO2TestConfig()
	fido2Cfg.RequireDevice(t)

	srv := NewWebAuthnServer()
	defer srv.Close()

	t.Log("=== WebAuthn Server Session Management Test ===")

	username := GenerateUniqueUsername("session-test")

	// Register a credential
	enrollment, handler := fido2Cfg.EnrollTestCredential(t, username)
	defer CleanupCredential(t, handler)

	// Store session
	srv.sessions[username] = &WebAuthnSession{
		Username:     username,
		CredentialID: enrollment.CredentialID,
		Salt:         enrollment.Salt,
		Created:      time.Now(),
	}

	// Retrieve session
	resp, err := http.Get(srv.URL() + "/webauthn/session?username=" + username)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var session map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&session)
	require.NoError(t, err)

	assert.Equal(t, username, session["username"])
	assert.NotEmpty(t, session["credential_id"])
	assert.NotEmpty(t, session["salt"])
	assert.NotEmpty(t, session["created"])

	t.Log("Session management test completed")
}

// TestWebAuthnServerErrorHandling tests error scenarios
func TestWebAuthnServerErrorHandling(t *testing.T) {
	srv := NewWebAuthnServer()
	defer srv.Close()

	t.Log("=== WebAuthn Server Error Handling Test ===")

	t.Run("RegisterWithoutBody", func(t *testing.T) {
		resp, err := http.Post(srv.URL()+"/webauthn/register/begin", "application/json", nil)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("VerifyWithoutChallenge", func(t *testing.T) {
		reqBody := map[string]string{
			"username":      "nonexistent",
			"credential_id": "fake",
		}
		reqData, _ := json.Marshal(reqBody)
		resp, err := http.Post(srv.URL()+"/webauthn/register/verify",
			"application/json", bytes.NewReader(reqData))
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("AuthenticateNonexistentUser", func(t *testing.T) {
		reqBody := map[string]string{"username": "nonexistent"}
		reqData, _ := json.Marshal(reqBody)
		resp, err := http.Post(srv.URL()+"/webauthn/authenticate/begin",
			"application/json", bytes.NewReader(reqData))
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("GetSessionNonexistentUser", func(t *testing.T) {
		resp, err := http.Get(srv.URL() + "/webauthn/session?username=nonexistent")
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Log("Error handling tests completed")
}

// TestWebAuthnServerConcurrentSessions tests multiple concurrent sessions
func TestWebAuthnServerConcurrentSessions(t *testing.T) {
	fido2Cfg := LoadFIDO2TestConfig()
	fido2Cfg.RequireDevice(t)

	srv := NewWebAuthnServer()
	defer srv.Close()

	t.Log("=== WebAuthn Server Concurrent Sessions Test ===")

	// Register two different users
	user1 := GenerateUniqueUsername("concurrent-1")
	user2 := GenerateUniqueUsername("concurrent-2")

	// User 1 registration
	t.Log("Registering user 1...")
	enrollment1, handler1 := fido2Cfg.EnrollTestCredential(t, user1)
	defer CleanupCredential(t, handler1)

	srv.sessions[user1] = &WebAuthnSession{
		Username:     user1,
		CredentialID: enrollment1.CredentialID,
		Salt:         enrollment1.Salt,
		Created:      time.Now(),
	}

	// User 2 registration
	time.Sleep(1 * time.Second)
	t.Log("Registering user 2...")
	enrollment2, handler2 := fido2Cfg.EnrollTestCredential(t, user2)
	defer CleanupCredential(t, handler2)

	srv.sessions[user2] = &WebAuthnSession{
		Username:     user2,
		CredentialID: enrollment2.CredentialID,
		Salt:         enrollment2.Salt,
		Created:      time.Now(),
	}

	// Verify both sessions exist independently
	resp1, err := http.Get(srv.URL() + "/webauthn/session?username=" + user1)
	require.NoError(t, err)
	defer resp1.Body.Close()
	assert.Equal(t, http.StatusOK, resp1.StatusCode)

	resp2, err := http.Get(srv.URL() + "/webauthn/session?username=" + user2)
	require.NoError(t, err)
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusOK, resp2.StatusCode)

	// Verify sessions are different
	var session1, session2 map[string]interface{}
	json.NewDecoder(resp1.Body).Decode(&session1)

	resp2, _ = http.Get(srv.URL() + "/webauthn/session?username=" + user2)
	json.NewDecoder(resp2.Body).Decode(&session2)

	assert.NotEqual(t, session1["credential_id"], session2["credential_id"],
		"Sessions should have different credentials")

	t.Log("Concurrent sessions test completed")
}

// readBody is a helper to read response body
func readBody(r io.Reader) string {
	body, _ := io.ReadAll(r)
	return string(body)
}
