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

package pairingproto

import (
	"testing"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/stretchr/testify/assert"
)

// assertDestroyed fails unless each field was emptied and the protected
// buffer behind it wiped: the copy taken before Destroy shares the buffer and
// must no longer be readable.
func assertDestroyed(t *testing.T, fields []xkms.SecretText, before []xkms.SecretText) {
	t.Helper()
	for i := range fields {
		assert.True(t, fields[i].IsZero(), "secret %d was not emptied", i)
		_, err := before[i].Copy()
		assert.Error(t, err, "secret %d is still readable after Destroy", i)
	}
}

func TestLocalSyncOATH_DestroyWipesEverySecret(t *testing.T) {
	params := &LocalSyncOATHParams{Credentials: []SyncOATHCredential{
		{ID: "a", Secret: mustSecretText("JBSWY3DPEHPK3PXP")},
		{ID: "b", Secret: mustSecretText("GEZDGNBVGY3TQOJQ")},
	}}
	before := []xkms.SecretText{params.Credentials[0].Secret, params.Credentials[1].Secret}
	params.Destroy()
	assertDestroyed(t, []xkms.SecretText{params.Credentials[0].Secret, params.Credentials[1].Secret}, before)

	result := &LocalSyncOATHResult{Remote: []SyncOATHCredential{
		{ID: "c", Secret: mustSecretText("MFRGGZDFMZTWQ2LK")},
	}}
	before = []xkms.SecretText{result.Remote[0].Secret}
	result.Destroy()
	assertDestroyed(t, []xkms.SecretText{result.Remote[0].Secret}, before)
}

func TestLocalSyncPasswords_DestroyWipesEveryPassword(t *testing.T) {
	params := &LocalSyncPasswordsParams{Passwords: []SyncPassword{
		{ID: "a", Password: mustSecretText("hunter2")},
	}}
	before := []xkms.SecretText{params.Passwords[0].Password}
	params.Destroy()
	assertDestroyed(t, []xkms.SecretText{params.Passwords[0].Password}, before)

	result := &LocalSyncPasswordsResult{Remote: []SyncPassword{
		{ID: "b", Password: mustSecretText("correct horse")},
		{ID: "c", Password: mustSecretText("battery staple")},
	}}
	before = []xkms.SecretText{result.Remote[0].Password, result.Remote[1].Password}
	result.Destroy()
	assertDestroyed(t, []xkms.SecretText{result.Remote[0].Password, result.Remote[1].Password}, before)
}

func TestLocalSync_DestroyOnEmptyCollectionsIsSafe(t *testing.T) {
	// A sync with nothing to send still runs its deferred Destroy.
	assert.NotPanics(t, func() {
		(&LocalSyncOATHParams{}).Destroy()
		(&LocalSyncOATHResult{}).Destroy()
		(&LocalSyncPasswordsParams{}).Destroy()
		(&LocalSyncPasswordsResult{}).Destroy()
	})
}

func TestRemoteSyncParams_DestroyWipesEverySecret(t *testing.T) {
	oath := &RemoteSyncOATHParams{Credentials: []SyncOATHCredential{
		{ID: "a", Secret: mustSecretText("JBSWY3DPEHPK3PXP")},
	}}
	before := []xkms.SecretText{oath.Credentials[0].Secret}
	oath.Destroy()
	assertDestroyed(t, []xkms.SecretText{oath.Credentials[0].Secret}, before)

	passwords := &RemoteSyncPasswordsParams{Passwords: []SyncPassword{
		{ID: "b", Password: mustSecretText("hunter2")},
	}}
	before = []xkms.SecretText{passwords.Passwords[0].Password}
	passwords.Destroy()
	assertDestroyed(t, []xkms.SecretText{passwords.Passwords[0].Password}, before)
}

func TestRemoteResults_DestroyZeroesKeyMaterial(t *testing.T) {
	plaintext := []byte("plaintext")
	shared := []byte("shared secret")
	credential := []byte("credential")
	wrapped := []byte("wrapped key")

	(&RemoteDecryptResult{Plaintext: plaintext}).Destroy()
	(&RemoteDeriveKeyResult{SharedSecret: shared}).Destroy()
	(&RemoteActivateCredentialResult{DecryptedSecret: credential}).Destroy()
	(&RemoteImportSharedKeyResult{WrappedKey: wrapped}).Destroy()

	for name, buf := range map[string][]byte{
		"plaintext": plaintext, "shared secret": shared,
		"credential": credential, "wrapped key": wrapped,
	} {
		assert.Equal(t, make([]byte, len(buf)), buf, "%s was not zeroed", name)
	}
}

func TestRemoteResults_DestroyOnEmptyFieldsIsSafe(t *testing.T) {
	// An error path encodes no key material but still runs the deferred Destroy.
	assert.NotPanics(t, func() {
		(&RemoteDecryptResult{}).Destroy()
		(&RemoteDeriveKeyResult{}).Destroy()
		(&RemoteActivateCredentialResult{}).Destroy()
		(&RemoteImportSharedKeyResult{}).Destroy()
		(&RemoteSyncOATHParams{}).Destroy()
		(&RemoteSyncPasswordsParams{}).Destroy()
	})
}
