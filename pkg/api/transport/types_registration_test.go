package transport

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBeginRegistrationRequest_DecodesEmail verifies the login key is read
// from the "email" key, the field's only name on the wire.
func TestBeginRegistrationRequest_DecodesEmail(t *testing.T) {
	var req BeginRegistrationRequest
	require.NoError(t, json.Unmarshal([]byte(`{"email":"alice@example.com","display_name":"Alice"}`), &req))
	assert.Equal(t, "alice@example.com", req.Email)
	assert.Equal(t, "Alice", req.DisplayName)
}

// TestBeginRegistrationRequest_UsernameKeyIgnored verifies the removed
// "username" spelling is no longer read: a body that carries the login key
// only under that key decodes to an empty Email (owner rule 2026-09-22,
// PR 2 — no aliases for old names).
func TestBeginRegistrationRequest_UsernameKeyIgnored(t *testing.T) {
	var req BeginRegistrationRequest
	require.NoError(t, json.Unmarshal([]byte(`{"username":"alice@example.com","display_name":"Alice"}`), &req))
	assert.Empty(t, req.Email)
	assert.Equal(t, "Alice", req.DisplayName)
}

// TestBeginRegistrationRequest_MalformedBody verifies a body that is not an
// object is refused as a JSON error.
func TestBeginRegistrationRequest_MalformedBody(t *testing.T) {
	var req BeginRegistrationRequest
	err := json.Unmarshal([]byte(`["alice@example.com"]`), &req)
	require.Error(t, err)
	var syntax *json.UnmarshalTypeError
	assert.True(t, errors.As(err, &syntax))
}

// TestBeginRegistrationRequest_EncodesEmailOnly verifies the request is sent
// under "email" alone; the removed "username" key is never emitted.
func TestBeginRegistrationRequest_EncodesEmailOnly(t *testing.T) {
	data, err := json.Marshal(BeginRegistrationRequest{Email: "alice@example.com", DisplayName: "Alice"})
	require.NoError(t, err)
	assert.JSONEq(t, `{"email":"alice@example.com","display_name":"Alice"}`, string(data))
}

// TestBeginRegistrationRequest_RoundTrip verifies what this client encodes is
// what this server decodes.
func TestBeginRegistrationRequest_RoundTrip(t *testing.T) {
	data, err := json.Marshal(BeginRegistrationRequest{Email: "alice@example.com", DisplayName: "Alice"})
	require.NoError(t, err)
	var decoded BeginRegistrationRequest
	require.NoError(t, json.Unmarshal(data, &decoded))
	assert.Equal(t, BeginRegistrationRequest{Email: "alice@example.com", DisplayName: "Alice"}, decoded)
}
