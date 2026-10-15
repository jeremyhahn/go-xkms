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
