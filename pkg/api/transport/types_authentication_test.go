package transport

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBeginAuthenticationRequest_DecodesEmail verifies the login key is read
// from "email", the field's only name on the wire.
func TestBeginAuthenticationRequest_DecodesEmail(t *testing.T) {
	var req BeginAuthenticationRequest
	require.NoError(t, json.Unmarshal([]byte(`{"email":"alice@example.com"}`), &req))
	assert.Equal(t, "alice@example.com", req.Email)
}

// TestBeginAuthenticationRequest_UsernameKeyIgnored verifies the removed
// "username" spelling is no longer read (owner rule 2026-09-22, PR 2 — no
// aliases for old names).
func TestBeginAuthenticationRequest_UsernameKeyIgnored(t *testing.T) {
	var req BeginAuthenticationRequest
	require.NoError(t, json.Unmarshal([]byte(`{"username":"alice@example.com"}`), &req))
	assert.Empty(t, req.Email)
}

// TestBeginAuthenticationRequest_EncodesEmailOnly verifies the client sends
// the login key under "email" alone and round-trips.
func TestBeginAuthenticationRequest_EncodesEmailOnly(t *testing.T) {
	data, err := json.Marshal(&BeginAuthenticationRequest{Email: "alice@example.com"})
	require.NoError(t, err)
	assert.JSONEq(t, `{"email":"alice@example.com"}`, string(data))

	var decoded BeginAuthenticationRequest
	require.NoError(t, json.Unmarshal(data, &decoded))
	assert.Equal(t, BeginAuthenticationRequest{Email: "alice@example.com"}, decoded)
}

// TestFinishAuthenticationRequest_DecodesEmail verifies the finish request
// resolves its login key from "email" and keeps its other fields.
func TestFinishAuthenticationRequest_DecodesEmail(t *testing.T) {
	var req FinishAuthenticationRequest
	require.NoError(t, json.Unmarshal([]byte(`{"session_id":"s1","email":"alice@example.com","assertion_json":"{}"}`), &req))
	assert.Equal(t, FinishAuthenticationRequest{SessionID: "s1", Email: "alice@example.com", AssertionJSON: "{}"}, req)
}

// TestFinishAuthenticationRequest_UsernameKeyIgnored verifies the removed
// "username" spelling is no longer read for the finish request either.
func TestFinishAuthenticationRequest_UsernameKeyIgnored(t *testing.T) {
	var req FinishAuthenticationRequest
	require.NoError(t, json.Unmarshal([]byte(`{"session_id":"s1","username":"alice@example.com","assertion_json":"{}"}`), &req))
	assert.Empty(t, req.Email)
	assert.Equal(t, "s1", req.SessionID)
}

// TestFinishAuthenticationRequest_EncodesEmailOnly verifies the finish
// request sends "email" alone and round-trips.
func TestFinishAuthenticationRequest_EncodesEmailOnly(t *testing.T) {
	in := FinishAuthenticationRequest{SessionID: "s1", Email: "alice@example.com", AssertionJSON: "{}"}
	data, err := json.Marshal(in)
	require.NoError(t, err)
	assert.JSONEq(t, `{"session_id":"s1","email":"alice@example.com","assertion_json":"{}"}`, string(data))

	var decoded FinishAuthenticationRequest
	require.NoError(t, json.Unmarshal(data, &decoded))
	assert.Equal(t, in, decoded)
}
