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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// handedOutOATHReader returns fresh records on every call and remembers them,
// so a test can see what the service did with what it was handed.
type handedOutOATHReader struct {
	handedOut []*OATHCredentialInfo
}

func (r *handedOutOATHReader) List() ([]*OATHCredentialInfo, error) {
	info := withSecret(&OATHCredentialInfo{ID: "gh", Name: "GitHub", Type: "totp"}, "JBSWY3DP")
	r.handedOut = append(r.handedOut, info)
	return []*OATHCredentialInfo{info}, nil
}

type handedOutPasswordReader struct {
	handedOut []*PasswordInfo
}

func (r *handedOutPasswordReader) List() ([]*PasswordInfo, error) {
	info := withPassword(&PasswordInfo{ID: "p1", Name: "bank"}, "hunter2")
	r.handedOut = append(r.handedOut, info)
	return []*PasswordInfo{info}, nil
}

func TestCreateBackup_DestroysTheRecordsItWasHanded(t *testing.T) {
	oathReader := &handedOutOATHReader{}
	passwordReader := &handedOutPasswordReader{}
	svc, err := NewService(&Config{DeviceName: "laptop"}, WithOATH(oathReader), WithPasswords(passwordReader))
	require.NoError(t, err)

	_, err = svc.CreateBackup(testKey())
	require.NoError(t, err)

	require.Len(t, oathReader.handedOut, 1)
	require.Len(t, passwordReader.handedOut, 1)
	assert.False(t, oathReader.handedOut[0].HasSecret(), "the reader's record must be destroyed once the archive has its own copy")
	assert.False(t, passwordReader.handedOut[0].HasPassword())
}

// keepsWhatItIsGiven is a writer that breaks the contract by retaining the
// record, to prove the service destroys the record after Add returns.
type keepsWhatItIsGiven struct {
	oath []*OATHCredentialInfo
}

func (w *keepsWhatItIsGiven) Add(c *OATHCredentialInfo) error {
	w.oath = append(w.oath, c)
	return nil
}

type keepsPasswords struct{ kept []*PasswordInfo }

func (w *keepsPasswords) Add(p *PasswordInfo) error {
	w.kept = append(w.kept, p)
	return nil
}

func TestRestore_DestroysTheRecordItGaveTheWriter(t *testing.T) {
	var archive Archive
	require.NoError(t, jsonUnmarshal(`{"oath_credentials":[{"id":"a","secret":"AAAA"}],"passwords":[{"id":"b","password":"hunter2"}]}`, &archive))
	defer archive.Destroy()
	svc, err := NewService(&Config{DeviceName: "laptop"})
	require.NoError(t, err)

	oathWriter := &keepsWhatItIsGiven{}
	result, err := svc.RestoreOATH(&archive, oathWriter)
	require.NoError(t, err)
	assert.Equal(t, 1, result.Restored)
	require.Len(t, oathWriter.oath, 1)
	assert.False(t, oathWriter.oath[0].HasSecret())

	passwordWriter := &keepsPasswords{}
	result, err = svc.RestorePasswords(&archive, passwordWriter)
	require.NoError(t, err)
	assert.Equal(t, 1, result.Restored)
	require.Len(t, passwordWriter.kept, 1)
	assert.False(t, passwordWriter.kept[0].HasPassword())
}

func TestRestore_DestroysTheRecordWhenTheWriterFails(t *testing.T) {
	var archive Archive
	require.NoError(t, jsonUnmarshal(`{"oath_credentials":[{"id":"a","secret":"AAAA"}]}`, &archive))
	defer archive.Destroy()
	svc, err := NewService(&Config{DeviceName: "laptop"})
	require.NoError(t, err)

	failing := &failingOATHWriter{err: errors.New("disk full")}
	result, err := svc.RestoreOATH(&archive, failing)
	require.NoError(t, err)
	assert.Equal(t, 1, result.Skipped)
	require.NotNil(t, failing.seen)
	assert.False(t, failing.seen.HasSecret())
}

type failingOATHWriter struct {
	err  error
	seen *OATHCredentialInfo
}

func (w *failingOATHWriter) Add(c *OATHCredentialInfo) error {
	w.seen = c
	return w.err
}

func TestInfoClone_IsIndependent(t *testing.T) {
	original := withSecret(&OATHCredentialInfo{ID: "a", Name: "n"}, "JBSWY3DP")
	clone, err := original.Clone()
	require.NoError(t, err)
	original.Destroy()

	assert.False(t, original.HasSecret())
	assert.Equal(t, "JBSWY3DP", secretText(clone), "destroying the original must not touch the clone")
	assert.Equal(t, "n", clone.Name)
	clone.Destroy()

	pw := withPassword(&PasswordInfo{ID: "p"}, "hunter2")
	pwClone, err := pw.Clone()
	require.NoError(t, err)
	pw.Destroy()
	assert.Equal(t, "hunter2", passwordText(pwClone))
	pwClone.Destroy()

	var nilOATH *OATHCredentialInfo
	got, err := nilOATH.Clone()
	require.NoError(t, err)
	assert.Nil(t, got)
	var nilPW *PasswordInfo
	gotPW, err := nilPW.Clone()
	require.NoError(t, err)
	assert.Nil(t, gotPW)
}

func TestInfoDestroy_IsIdempotentAndNilSafe(t *testing.T) {
	info := withSecret(&OATHCredentialInfo{}, "JBSWY3DP")
	info.Destroy()
	info.Destroy()
	assert.False(t, info.HasSecret())

	var nilOATH *OATHCredentialInfo
	var nilPW *PasswordInfo
	assert.NotPanics(t, nilOATH.Destroy)
	assert.NotPanics(t, nilPW.Destroy)
}

func TestInfoText_RoundTripsThroughSecretText(t *testing.T) {
	info := withSecret(&OATHCredentialInfo{}, "JBSWY3DP")
	text, err := info.SecretText()
	require.NoError(t, err)
	defer text.Destroy()
	assert.Equal(t, "JBSWY3DP", textOf(text))

	var back OATHCredentialInfo
	require.NoError(t, back.SetSecretText(text))
	assert.Equal(t, "JBSWY3DP", secretText(&back))

	empty, err := (&PasswordInfo{}).PasswordText()
	require.NoError(t, err)
	assert.True(t, empty.IsZero(), "an unset password yields the zero SecretText")
}
