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
	"strings"
	"testing"

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
		Authority:       []byte("authority public area"),
		Approvals:       [][]byte{[]byte("approval 0"), []byte("approval 1")},
	}
}

// TestTPMPolicyBinding_RoundTrip proves every flag combination, the
// authority and the approvals survive an encode/decode round trip, and that
// a record without approvals (written under a revoked policy) does too.
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

	revoked := validBinding()
	revoked.Authority, revoked.Approvals = nil, nil
	record, err := revoked.MarshalBinary()
	require.NoError(t, err)
	got, err := UnmarshalTPMPolicyBinding(record)
	require.NoError(t, err)
	assert.Equal(t, revoked, got)
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
		{"long authority", func(b *TPMPolicyBinding) *TPMPolicyBinding {
			b.Authority = make([]byte, tpmPolicyBindingMaxBlob+1)
			return b
		}},
		{"approvals without authority", func(b *TPMPolicyBinding) *TPMPolicyBinding { b.Authority = nil; return b }},
		{"empty approval", func(b *TPMPolicyBinding) *TPMPolicyBinding { b.Approvals[1] = nil; return b }},
		{"long approval", func(b *TPMPolicyBinding) *TPMPolicyBinding {
			b.Approvals[0] = make([]byte, tpmPolicyBindingMaxBlob+1)
			return b
		}},
		{"too many approvals", func(b *TPMPolicyBinding) *TPMPolicyBinding {
			b.Approvals = make([][]byte, tpmPolicyBindingMaxApprovals+1)
			for i := range b.Approvals {
				b.Approvals[i] = []byte{1}
			}
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
	unapproved := validBinding()
	unapproved.Authority, unapproved.Approvals = nil, nil
	revoked, err := unapproved.MarshalBinary()
	require.NoError(t, err)

	// approvalCount is the offset of good's approval count: the two
	// approvals, each with its length, end the record.
	approvalCount := len(good) - 1
	for _, approval := range validBinding().Approvals {
		approvalCount -= 2 + len(approval)
	}

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
		{"missing approval count", revoked[:len(revoked)-1]},
		{"missing authority", revoked[:len(revoked)-3]},
		{"approval count past the end", corrupt(func(b []byte) []byte { b[approvalCount]++; return b })},
		{"approvals without authority", corrupt(func(b []byte) []byte {
			// Zero the authority length and drop the authority's bytes.
			authority := approvalCount - len(validBinding().Authority) - 2
			b[authority], b[authority+1] = 0, 0
			return append(b[:authority+2], b[approvalCount:]...)
		})},
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

// TestBlobStore_DeleteRemovesTPMPolicyBinding proves the binding follows its
// key's lifetime: deleting the key deletes the record beside it.
func TestBlobStore_DeleteRemovesTPMPolicyBinding(t *testing.T) {
	backend := newTestBlobStore(t)
	attrs := &types.KeyAttributes{CN: "bound-key"}

	record, err := validBinding().MarshalBinary()
	require.NoError(t, err)
	require.NoError(t, backend.Save(attrs, record, FSEXT_TPM_POLICY, false))
	require.NoError(t, backend.Save(attrs, []byte("pub"), FSEXT_PUBLIC_BLOB, false))

	require.NoError(t, backend.Delete(attrs))

	_, err = backend.Get(attrs, FSEXT_TPM_POLICY)
	require.ErrorIs(t, err, ErrBlobNotFound, "the binding must be gone")
}
