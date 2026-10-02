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

package backup

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// legacyArchive mirrors Archive as it was written while the OATH secret and
// the static password were Go strings. A backup sealed from it must still
// open, and what the current code writes must be byte-identical.
type legacyArchive struct {
	Manifest  Manifest `json:"manifest"`
	OATHCreds []struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Issuer      string `json:"issuer"`
		AccountName string `json:"account_name"`
		Secret      string `json:"secret"`
		Type        string `json:"type"`
		Algorithm   string `json:"algorithm"`
		Digits      int    `json:"digits"`
		Period      int    `json:"period"`
		Counter     int64  `json:"counter"`
	} `json:"oath_credentials,omitempty"`
	Passwords []struct {
		ID         string `json:"id"`
		Name       string `json:"name"`
		Title      string `json:"title,omitempty"`
		Username   string `json:"username,omitempty"`
		Password   string `json:"password"`
		URL        string `json:"url,omitempty"`
		Notes      string `json:"notes,omitempty"`
		FolderPath string `json:"folder_path,omitempty"`
	} `json:"passwords,omitempty"`
}

// sealLegacyArchive seals a legacy archive exactly as CreateBackup sealed one:
// hash with the checksum cleared, then re-marshal with it set.
func sealLegacyArchive(t *testing.T, key *Key, la *legacyArchive) *EncryptedBackup {
	t.Helper()
	la.Manifest.Checksum = ""
	payload, err := json.Marshal(la)
	require.NoError(t, err)
	sum := sha256.Sum256(payload)
	la.Manifest.Checksum = hex.EncodeToString(sum[:])
	plaintext, err := json.Marshal(la)
	require.NoError(t, err)

	eb := &EncryptedBackup{Magic: BackupMagic, Version: BackupVersion, KDF: key.kdf}
	aad, err := eb.headerAAD()
	require.NoError(t, err)
	eb.Ciphertext, eb.Nonce, err = encrypt(plaintext, key.material, aad)
	require.NoError(t, err)
	return eb
}

func newLegacyArchive() *legacyArchive {
	la := &legacyArchive{Manifest: Manifest{Version: BackupVersion, Created: time.Unix(1700000000, 0).UTC(), DeviceName: "laptop"}}
	la.OATHCreds = append(la.OATHCreds, struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Issuer      string `json:"issuer"`
		AccountName string `json:"account_name"`
		Secret      string `json:"secret"`
		Type        string `json:"type"`
		Algorithm   string `json:"algorithm"`
		Digits      int    `json:"digits"`
		Period      int    `json:"period"`
		Counter     int64  `json:"counter"`
	}{ID: "gh", Name: "GitHub", Secret: "JBSWY3DPEHPK3PXP", Type: "totp", Algorithm: "SHA1", Digits: 6, Period: 30})
	la.Passwords = append(la.Passwords, struct {
		ID         string `json:"id"`
		Name       string `json:"name"`
		Title      string `json:"title,omitempty"`
		Username   string `json:"username,omitempty"`
		Password   string `json:"password"`
		URL        string `json:"url,omitempty"`
		Notes      string `json:"notes,omitempty"`
		FolderPath string `json:"folder_path,omitempty"`
	}{ID: "p1", Name: "bank", Password: "p<a>&ss\"w\\o\trd é\U0001F600"})
	return la
}

func TestDecryptBackup_OpensArchiveWrittenWithStringSecrets(t *testing.T) {
	key, err := GenerateKey()
	require.NoError(t, err)
	svc, err := NewService(&Config{DeviceName: "laptop"})
	require.NoError(t, err)

	eb := sealLegacyArchive(t, key, newLegacyArchive())

	archive, err := svc.DecryptBackup(eb, key)
	require.NoError(t, err, "the checksum is over the bytes the old code wrote, so it only verifies if re-encoding is byte-identical")
	defer archive.Destroy()

	require.Len(t, archive.OATHCreds, 1)
	assert.Equal(t, "JBSWY3DPEHPK3PXP", textOf(archive.OATHCreds[0].Secret))
	require.Len(t, archive.Passwords, 1)
	assert.Equal(t, "p<a>&ss\"w\\o\trd é\U0001F600", textOf(archive.Passwords[0].Password))
}

func TestArchive_EncodesByteIdenticalToStringSecrets(t *testing.T) {
	la := newLegacyArchive()
	want, err := json.Marshal(la)
	require.NoError(t, err)

	var archive Archive
	require.NoError(t, json.Unmarshal(want, &archive))
	defer archive.Destroy()

	got, err := json.Marshal(&archive)
	require.NoError(t, err)
	assert.Equal(t, string(want), string(got))
}

func TestInfoJSON_ByteIdenticalToStringFields(t *testing.T) {
	oath := withSecret(&OATHCredentialInfo{ID: "gh", Name: "GitHub", Type: "totp", Algorithm: "SHA1", Digits: 6, Period: 30}, "JBSW<&>Y3DP")
	legacyOATH, err := json.Marshal(struct {
		ID, Name, Issuer, AccountName, Secret, Type, Algorithm string
		Digits, Period                                         int
		Counter                                                int64
	}{ID: "gh", Name: "GitHub", Secret: "JBSW<&>Y3DP", Type: "totp", Algorithm: "SHA1", Digits: 6, Period: 30})
	require.NoError(t, err)
	gotOATH, err := json.Marshal(oath)
	require.NoError(t, err)
	assert.Equal(t, string(legacyOATH), string(gotOATH))

	pw := withPassword(&PasswordInfo{ID: "p1", Name: "bank", Title: "Bank"}, "s3\"cr\\et")
	legacyPW, err := json.Marshal(struct {
		ID, Name, Title, Username, Password, URL, Notes, FolderPath string
	}{ID: "p1", Name: "bank", Title: "Bank", Password: "s3\"cr\\et"})
	require.NoError(t, err)
	gotPW, err := json.Marshal(pw)
	require.NoError(t, err)
	assert.Equal(t, string(legacyPW), string(gotPW))
}

func TestArchive_DestroyReleasesSecrets(t *testing.T) {
	var archive Archive
	require.NoError(t, json.Unmarshal([]byte(`{"oath_credentials":[{"id":"a","secret":"AAAA"}],"passwords":[{"id":"b","password":"hunter2"}]}`), &archive))
	require.False(t, archive.OATHCreds[0].Secret.IsZero())
	require.False(t, archive.Passwords[0].Password.IsZero())

	// A copy of the entry shares the protected buffer, so destroying the
	// archive empties it too.
	shared := archive.OATHCreds[0].Secret
	archive.Destroy()

	assert.True(t, archive.OATHCreds[0].Secret.IsZero())
	assert.True(t, archive.Passwords[0].Password.IsZero())
	_, err := shared.Copy()
	assert.Error(t, err, "a copy of a destroyed secret must not read back")

	var nilArchive *Archive
	assert.NotPanics(t, nilArchive.Destroy)
}

func TestInfoAccessors_ReturnIndependentCopiesAndNilWhenEmpty(t *testing.T) {
	cred := withSecret(&OATHCredentialInfo{}, "JBSWY3DP")
	first, err := cred.Secret()
	require.NoError(t, err)
	first[0] = 'X'
	assert.Equal(t, "JBSWY3DP", secretText(cred), "mutating a copy must not touch the protected original")

	empty, err := (&OATHCredentialInfo{}).Secret()
	require.NoError(t, err)
	assert.Nil(t, empty)
	none, err := (*PasswordInfo)(nil).Password()
	require.NoError(t, err)
	assert.Nil(t, none)
}

func TestSetSecret_LeavesCallerSliceIntact(t *testing.T) {
	in := []byte("JBSWY3DP")
	var cred OATHCredentialInfo
	require.NoError(t, cred.SetSecret(in))
	assert.Equal(t, []byte("JBSWY3DP"), in)
	require.NoError(t, cred.SetSecret(nil))
	assert.False(t, cred.HasSecret())
}

func TestInfoUnmarshal_RejectsNonStringSecret(t *testing.T) {
	var cred OATHCredentialInfo
	require.Error(t, json.Unmarshal([]byte(`{"Secret":12}`), &cred))
	var pw PasswordInfo
	require.Error(t, json.Unmarshal([]byte(`{"Password":[1]}`), &pw))
}
