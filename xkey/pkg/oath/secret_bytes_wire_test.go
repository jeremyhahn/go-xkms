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

package oath

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCredential_JSONByteIdenticalToStringSecret proves the stored form is the
// bytes it was while the secret was exported as a string, so a store written
// by an earlier release still loads and an unchanged credential re-saves to
// the same bytes.
func TestCredential_JSONByteIdenticalToStringSecret(t *testing.T) {
	created := time.Unix(1700000000, 0).UTC()
	legacy, err := json.Marshal(struct {
		ID          string    `json:"id"`
		Name        string    `json:"name"`
		Issuer      string    `json:"issuer"`
		AccountName string    `json:"account_name"`
		Secret      string    `json:"secret"`
		Type        string    `json:"type"`
		Algorithm   string    `json:"algorithm"`
		Digits      int       `json:"digits"`
		Period      int       `json:"period"`
		Counter     uint64    `json:"counter"`
		CreatedAt   time.Time `json:"created_at"`
		BackendID   string    `json:"backend_id,omitempty"`
	}{"gh", "GitHub", "GitHub", "me", "JBSW<&>Y3DP", "totp", "SHA1", 6, 30, 0, created, ""})
	require.NoError(t, err)

	var cred Credential
	require.NoError(t, json.Unmarshal(legacy, &cred))
	t.Cleanup(func() { require.NoError(t, cred.SetSecret(nil)) })

	got, err := json.Marshal(&cred)
	require.NoError(t, err)
	assert.Equal(t, string(legacy), string(got))
}

func TestCredential_SecretAccessor(t *testing.T) {
	none, err := (&Credential{}).Secret()
	require.NoError(t, err)
	assert.Nil(t, none, "a credential without a secret yields nil, not an error")

	in := []byte("JBSWY3DP")
	var cred Credential
	require.NoError(t, cred.SetSecret(in))
	assert.Equal(t, []byte("JBSWY3DP"), in, "SetSecret must leave the caller's slice intact")

	got, err := cred.Secret()
	require.NoError(t, err)
	got[0] = 'X'
	assert.Equal(t, "JBSWY3DP", secretText(&cred), "a returned copy must not alias the protected original")
}

func TestCredential_ToURIEmbedsSecretAndReportsUnreadable(t *testing.T) {
	cred := &Credential{Name: "me", Issuer: "GitHub", Type: TypeTOTP, Algorithm: DefaultAlgorithm, Digits: DefaultDigits, Period: DefaultPeriod}
	require.NoError(t, cred.SetSecret([]byte("JBSWY3DP")))
	uri, err := cred.ToURI()
	require.NoError(t, err)
	assert.Contains(t, uri, "secret=JBSWY3DP")

	cred.secret.Destroy()
	_, err = cred.ToURI()
	require.ErrorIs(t, err, ErrInvalidSecret)
}
