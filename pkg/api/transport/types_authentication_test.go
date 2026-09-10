package transport

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBeginAuthenticationRequest_DecodesEitherKey verifies the login key is
// read from "email", from the legacy "username" key for the compatibility
// release, and from both when they agree.
func TestBeginAuthenticationRequest_DecodesEitherKey(t *testing.T) {
	for name, body := range map[string]string{
		"email":    `{"email":"alice@example.com"}`,
		"legacy":   `{"username":"alice@example.com"}`,
		"agreeing": `{"email":"alice@example.com","username":"alice@example.com"}`,
	} {
		t.Run(name, func(t *testing.T) {
			var req BeginAuthenticationRequest
			require.NoError(t, json.Unmarshal([]byte(body), &req))
			assert.Equal(t, "alice@example.com", req.Email)
		})
	}
}

// TestBeginAuthenticationRequest_RefusesConflictingKeys verifies different
// values under the two keys are refused with the typed error rather than one
// being chosen silently.
func TestBeginAuthenticationRequest_RefusesConflictingKeys(t *testing.T) {
	var req BeginAuthenticationRequest
	err := json.Unmarshal([]byte(`{"email":"alice@example.com","username":"alice"}`), &req)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrAuthenticationLoginKeyConflict))
	assert.Empty(t, req.Email)
}

// TestBeginAuthenticationRequest_EncodesBothKeys verifies the client sends
// the login key under both keys with one value for the compatibility release,
// and that what it sends decodes back to the same request.
func TestBeginAuthenticationRequest_EncodesBothKeys(t *testing.T) {
	data, err := json.Marshal(&BeginAuthenticationRequest{Email: "alice@example.com"})
	require.NoError(t, err)
	assert.JSONEq(t, `{"email":"alice@example.com","username":"alice@example.com"}`, string(data))

	var decoded BeginAuthenticationRequest
	require.NoError(t, json.Unmarshal(data, &decoded))
	assert.Equal(t, BeginAuthenticationRequest{Email: "alice@example.com"}, decoded)

	empty, err := json.Marshal(BeginAuthenticationRequest{})
	require.NoError(t, err)
	assert.JSONEq(t, `{"email":""}`, string(empty), "an empty login key is not duplicated")
}

// TestFinishAuthenticationRequest_DecodesEitherKey verifies the finish
// request resolves its login key the same way and keeps its other fields.
func TestFinishAuthenticationRequest_DecodesEitherKey(t *testing.T) {
	for name, body := range map[string]string{
		"email":  `{"session_id":"s1","email":"alice@example.com","assertion_json":"{}"}`,
		"legacy": `{"session_id":"s1","username":"alice@example.com","assertion_json":"{}"}`,
	} {
		t.Run(name, func(t *testing.T) {
			var req FinishAuthenticationRequest
			require.NoError(t, json.Unmarshal([]byte(body), &req))
			assert.Equal(t, FinishAuthenticationRequest{SessionID: "s1", Email: "alice@example.com", AssertionJSON: "{}"}, req)
		})
	}
}

// TestFinishAuthenticationRequest_RefusesConflictingKeys verifies the finish
// request refuses differing keys with the typed error.
func TestFinishAuthenticationRequest_RefusesConflictingKeys(t *testing.T) {
	var req FinishAuthenticationRequest
	err := json.Unmarshal([]byte(`{"session_id":"s1","email":"alice@example.com","username":"alice","assertion_json":"{}"}`), &req)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrAuthenticationLoginKeyConflict))
	assert.Empty(t, req.SessionID, "nothing is decoded from a refused body")
}

// TestFinishAuthenticationRequest_EncodesBothKeys verifies the finish request
// sends both keys with one value and round-trips.
func TestFinishAuthenticationRequest_EncodesBothKeys(t *testing.T) {
	in := FinishAuthenticationRequest{SessionID: "s1", Email: "alice@example.com", AssertionJSON: "{}"}
	data, err := json.Marshal(in)
	require.NoError(t, err)
	assert.JSONEq(t, `{"session_id":"s1","email":"alice@example.com","username":"alice@example.com","assertion_json":"{}"}`, string(data))

	var decoded FinishAuthenticationRequest
	require.NoError(t, json.Unmarshal(data, &decoded))
	assert.Equal(t, in, decoded)
}

// TestLoginKeyFromWire covers the shared resolution the three ceremony
// requests decode through.
func TestLoginKeyFromWire(t *testing.T) {
	conflict := errors.New("conflict")
	for name, tc := range map[string]struct {
		email, username, want string
		err                   error
	}{
		"email only":    {email: "a@x", want: "a@x"},
		"legacy only":   {username: "a@x", want: "a@x"},
		"both agree":    {email: "a@x", username: "a@x", want: "a@x"},
		"both differ":   {email: "a@x", username: "a", err: conflict},
		"neither given": {want: ""},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := loginKeyFromWire(tc.email, tc.username, conflict)
			assert.Equal(t, tc.want, got)
			assert.Equal(t, tc.err, err)
		})
	}
}
