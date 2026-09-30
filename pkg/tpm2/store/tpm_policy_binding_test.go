// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package store

import (
	"errors"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func validBinding() *TPMPolicyBinding {
	return &TPMPolicyBinding{
		Scope:           "tenant-a",
		Policy:          "boot",
		Index:           0x01500010,
		HashAlg:         0x000B,
		AuthValueBranch: true,
	}
}

// TestTPMPolicyBinding_RoundTrip proves every field survives encoding, for
// every valid combination of the auth-value flags, and that new records are
// written as version 2.
func TestTPMPolicyBinding_RoundTrip(t *testing.T) {
	for _, flags := range []struct{ branch, condition bool }{
		{true, false}, {false, false}, {false, true},
	} {
		want := validBinding()
		want.AuthValueBranch = flags.branch
		want.AuthValueCondition = flags.condition

		record, err := want.MarshalBinary()
		require.NoError(t, err)
		assert.Equal(t, tpmPolicyBindingMagic, string(record[:4]))
		assert.Equal(t, TPMPolicyBindingVersion, record[4])

		got, err := UnmarshalTPMPolicyBinding(record)
		require.NoError(t, err)
		assert.Equal(t, want, got)
	}
}

// v1BindingRecord is a version 1 record as the first writer produced it:
// scope "tenant-a", policy "boot", index 0x01500010, SHA-256, with an outer
// auth-value branch.
var v1BindingRecord = []byte{
	'X', 'T', 'P', 'B', 0x01,
	0x01, 0x50, 0x00, 0x10,
	0x00, 0x0B,
	0x01,
	0x00, 0x08, 't', 'e', 'n', 'a', 'n', 't', '-', 'a',
	0x00, 0x04, 'b', 'o', 'o', 't',
}

// TestUnmarshalTPMPolicyBinding_ReadsVersion1 proves records written before
// auth_value conditions existed still decode, as bindings to a policy
// without one, and that a version 1 record cannot claim the version 2 flag.
func TestUnmarshalTPMPolicyBinding_ReadsVersion1(t *testing.T) {
	got, err := UnmarshalTPMPolicyBinding(v1BindingRecord)
	require.NoError(t, err)
	assert.Equal(t, validBinding(), got)
	assert.False(t, got.AuthValueCondition)

	forged := append([]byte(nil), v1BindingRecord...)
	forged[11] = tpmPolicyBindingFlagAuthValueCondition
	_, err = UnmarshalTPMPolicyBinding(forged)
	var formatErr *TPMPolicyBindingFormatError
	require.ErrorAs(t, err, &formatErr)
}

// TestTPMPolicyBinding_MarshalRejectsInvalid proves a record that could not
// name a policy is never written.
func TestTPMPolicyBinding_MarshalRejectsInvalid(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*TPMPolicyBinding) *TPMPolicyBinding
	}{
		{"nil", func(*TPMPolicyBinding) *TPMPolicyBinding { return nil }},
		{"empty scope", func(b *TPMPolicyBinding) *TPMPolicyBinding { b.Scope = ""; return b }},
		{"empty policy", func(b *TPMPolicyBinding) *TPMPolicyBinding { b.Policy = ""; return b }},
		{"zero index", func(b *TPMPolicyBinding) *TPMPolicyBinding { b.Index = 0; return b }},
		{"zero hash", func(b *TPMPolicyBinding) *TPMPolicyBinding { b.HashAlg = 0; return b }},
		{"both auth value flags", func(b *TPMPolicyBinding) *TPMPolicyBinding { b.AuthValueCondition = true; return b }},
		{"long scope", func(b *TPMPolicyBinding) *TPMPolicyBinding {
			b.Scope = strings.Repeat("s", tpmPolicyBindingMaxName+1)
			return b
		}},
		{"long policy", func(b *TPMPolicyBinding) *TPMPolicyBinding {
			b.Policy = strings.Repeat("p", tpmPolicyBindingMaxName+1)
			return b
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.mutate(validBinding()).MarshalBinary()
			var formatErr *TPMPolicyBindingFormatError
			require.ErrorAs(t, err, &formatErr)
		})
	}
}

// TestUnmarshalTPMPolicyBinding_RejectsMalformed proves a damaged record is
// refused rather than decoded into a binding the object was not created with.
func TestUnmarshalTPMPolicyBinding_RejectsMalformed(t *testing.T) {
	good, err := validBinding().MarshalBinary()
	require.NoError(t, err)

	corrupt := func(f func([]byte) []byte) []byte {
		c := append([]byte(nil), good...)
		return f(c)
	}

	tests := []struct {
		name   string
		record []byte
	}{
		{"empty", nil},
		{"short header", good[:tpmPolicyBindingHeaderLen-1]},
		{"bad magic", corrupt(func(b []byte) []byte { b[0] = 'Y'; return b })},
		{"unknown flag", corrupt(func(b []byte) []byte { b[11] = 0x80; return b })},
		{"both auth value flags", corrupt(func(b []byte) []byte { b[11] = 0x03; return b })},
		{"truncated", good[:len(good)-1]},
		{"trailing bytes", append(append([]byte(nil), good...), 0)},
		{"zero scope length", corrupt(func(b []byte) []byte { b[12], b[13] = 0, 0; return b })},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := UnmarshalTPMPolicyBinding(tt.record)
			var formatErr *TPMPolicyBindingFormatError
			require.ErrorAs(t, err, &formatErr)
		})
	}
}

// TestUnmarshalTPMPolicyBinding_RejectsUnknownVersion proves a record from a
// newer writer is refused with a version error, not decoded by guesswork.
func TestUnmarshalTPMPolicyBinding_RejectsUnknownVersion(t *testing.T) {
	record, err := validBinding().MarshalBinary()
	require.NoError(t, err)
	record[4] = TPMPolicyBindingVersion + 1

	_, err = UnmarshalTPMPolicyBinding(record)
	var versionErr *TPMPolicyBindingVersionError
	require.ErrorAs(t, err, &versionErr)
	assert.Equal(t, TPMPolicyBindingVersion+1, versionErr.Version)
	assert.Contains(t, versionErr.Error(), "version")
}

// TestFileBackend_DeleteRemovesTPMPolicyBinding proves the binding follows its
// key's lifetime: deleting the key deletes the record beside it.
func TestFileBackend_DeleteRemovesTPMPolicyBinding(t *testing.T) {
	backend := NewFileBackend(testLogger(), storage.NewMemory())
	attrs := &types.KeyAttributes{CN: "bound-key"}

	record, err := validBinding().MarshalBinary()
	require.NoError(t, err)
	require.NoError(t, backend.Save(attrs, record, FSEXT_TPM_POLICY, false))
	require.NoError(t, backend.Save(attrs, []byte("pub"), FSEXT_PUBLIC_BLOB, false))

	require.NoError(t, backend.Delete(attrs))

	_, err = backend.Get(attrs, FSEXT_TPM_POLICY)
	require.True(t, errors.Is(err, storage.ErrNotFound), "the binding must be gone, got %v", err)
}
