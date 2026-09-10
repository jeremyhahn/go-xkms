package transport

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBeginRegistrationRequest_DecodesEmail verifies the login key is read
// from the "email" key, the field's name on the wire.
func TestBeginRegistrationRequest_DecodesEmail(t *testing.T) {
	var req BeginRegistrationRequest
	require.NoError(t, json.Unmarshal([]byte(`{"email":"alice@example.com","display_name":"Alice"}`), &req))
	assert.Equal(t, "alice@example.com", req.Email)
	assert.Equal(t, "Alice", req.DisplayName)
}

// TestBeginRegistrationRequest_AcceptsLegacyUsernameKey verifies a client
// built against the previous spelling, which sent the email under
// "username", keeps working for the compatibility release.
func TestBeginRegistrationRequest_AcceptsLegacyUsernameKey(t *testing.T) {
	var req BeginRegistrationRequest
	require.NoError(t, json.Unmarshal([]byte(`{"username":"alice@example.com","display_name":"Alice"}`), &req))
	assert.Equal(t, "alice@example.com", req.Email)
	assert.Equal(t, "Alice", req.DisplayName)
}

// TestBeginRegistrationRequest_AgreeingKeysAreAccepted verifies a body that
// sends the same login key under both spellings is not refused.
func TestBeginRegistrationRequest_AgreeingKeysAreAccepted(t *testing.T) {
	var req BeginRegistrationRequest
	require.NoError(t, json.Unmarshal([]byte(`{"email":"alice@example.com","username":"alice@example.com"}`), &req))
	assert.Equal(t, "alice@example.com", req.Email)
}

// TestBeginRegistrationRequest_RefusesConflictingKeys verifies a body that
// names different values under "email" and the legacy "username" key is
// refused with the typed error rather than one value being chosen silently:
// the wrong value would surface as "account not found" or as a credential
// enrolled against the wrong account.
func TestBeginRegistrationRequest_RefusesConflictingKeys(t *testing.T) {
	var req BeginRegistrationRequest
	err := json.Unmarshal([]byte(`{"email":"alice@example.com","username":"alice"}`), &req)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrRegistrationLoginKeyConflict))
	assert.Empty(t, req.Email, "nothing is decoded from a refused body")
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

// TestBeginRegistrationRequest_EncodesBothKeys verifies the request is sent
// under "email" and, for the compatibility release, under the legacy
// "username" key with the same value, so a server that still reads the
// legacy key does not receive an empty login key from this client.
func TestBeginRegistrationRequest_EncodesBothKeys(t *testing.T) {
	data, err := json.Marshal(BeginRegistrationRequest{Email: "alice@example.com", DisplayName: "Alice"})
	require.NoError(t, err)
	assert.JSONEq(t, `{"email":"alice@example.com","username":"alice@example.com","display_name":"Alice"}`, string(data))

	// A pointer encodes the same way.
	ptrData, err := json.Marshal(&BeginRegistrationRequest{Email: "alice@example.com", DisplayName: "Alice"})
	require.NoError(t, err)
	assert.JSONEq(t, string(data), string(ptrData))

	// An empty login key is not duplicated into the legacy key.
	empty, err := json.Marshal(BeginRegistrationRequest{DisplayName: "Alice"})
	require.NoError(t, err)
	assert.JSONEq(t, `{"email":"","display_name":"Alice"}`, string(empty))
}

// TestBeginRegistrationRequest_RoundTrip verifies what this client encodes
// is what this server decodes: the two agreeing keys yield one login key.
func TestBeginRegistrationRequest_RoundTrip(t *testing.T) {
	data, err := json.Marshal(BeginRegistrationRequest{Email: "alice@example.com", DisplayName: "Alice"})
	require.NoError(t, err)
	var decoded BeginRegistrationRequest
	require.NoError(t, json.Unmarshal(data, &decoded))
	assert.Equal(t, BeginRegistrationRequest{Email: "alice@example.com", DisplayName: "Alice"}, decoded)
}
