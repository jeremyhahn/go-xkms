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

package sync

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDelta_EncodesByteIdenticalToStringSecrets proves the deltas encode to the
// bytes they did while the secret and password were Go strings. The peer
// compares a Checksum over that encoding (the status method), so a single
// differing byte would make every store look out of sync.
func TestDelta_EncodesByteIdenticalToStringSecrets(t *testing.T) {
	at := time.Unix(1700000000, 0).UTC()

	type legacyOATH struct {
		ID          string    `json:"id"`
		Name        string    `json:"name"`
		Issuer      string    `json:"issuer"`
		AccountName string    `json:"account_name"`
		Secret      string    `json:"secret"`
		Type        string    `json:"type"`
		Algorithm   string    `json:"algorithm"`
		Digits      int       `json:"digits"`
		Period      int       `json:"period"`
		Counter     int64     `json:"counter"`
		UpdatedAt   time.Time `json:"updated_at"`
	}
	legacy, err := json.Marshal(struct {
		Credentials []legacyOATH `json:"credentials"`
	}{[]legacyOATH{{ID: "a", Name: "n", Secret: "JB<&>\"\\SW", Type: "totp", UpdatedAt: at}}})
	require.NoError(t, err)

	delta := &OATHDelta{Credentials: []OATHCredentialSync{{ID: "a", Name: "n", Secret: mustSecretText("JB<&>\"\\SW"), Type: "totp", UpdatedAt: at}}}
	defer delta.Destroy()
	got, err := json.Marshal(delta)
	require.NoError(t, err)
	assert.Equal(t, string(legacy), string(got))
	assert.Equal(t, Checksum(legacy), Checksum(got))

	type legacyPassword struct {
		ID         string    `json:"id"`
		Name       string    `json:"name"`
		Title      string    `json:"title,omitempty"`
		Username   string    `json:"username,omitempty"`
		Password   string    `json:"password"`
		URL        string    `json:"url,omitempty"`
		Notes      string    `json:"notes,omitempty"`
		FolderPath string    `json:"folder_path,omitempty"`
		UpdatedAt  time.Time `json:"updated_at"`
	}
	legacyPW, err := json.Marshal(struct {
		Passwords []legacyPassword `json:"passwords"`
	}{[]legacyPassword{{ID: "p", Name: "n", Password: "p\tw é", UpdatedAt: at}}})
	require.NoError(t, err)

	pwDelta := &PasswordDelta{Passwords: []PasswordSync{{ID: "p", Name: "n", Password: mustSecretText("p\tw é"), UpdatedAt: at}}}
	defer pwDelta.Destroy()
	gotPW, err := json.Marshal(pwDelta)
	require.NoError(t, err)
	assert.Equal(t, string(legacyPW), string(gotPW))
}

func TestDelta_DestroyReleasesSecretsAndToleratesNil(t *testing.T) {
	secret := mustSecretText("JBSWY3DP")
	password := mustSecretText("hunter2")
	oathDelta := &OATHDelta{Credentials: []OATHCredentialSync{{Secret: secret}}}
	pwDelta := &PasswordDelta{Passwords: []PasswordSync{{Password: password}}}

	oathDelta.Destroy()
	pwDelta.Destroy()

	assert.True(t, oathDelta.Credentials[0].Secret.IsZero())
	assert.True(t, pwDelta.Passwords[0].Password.IsZero())
	_, err := secret.Copy()
	assert.Error(t, err, "a copy of a destroyed secret must not read back")
	_, err = password.Copy()
	assert.Error(t, err)

	assert.NotPanics(t, (*OATHDelta)(nil).Destroy)
	assert.NotPanics(t, (*PasswordDelta)(nil).Destroy)
}
