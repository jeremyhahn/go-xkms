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

package tlog

import (
	"crypto/sha256"
	"math/big"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMarshalUnmarshal_RoundTrip(t *testing.T) {
	for _, e := range []Entry{
		CertIssued{CertSHA256: sha256.Sum256([]byte("cert")), Serial: big.NewInt(0x0102), Profile: "server", Tenant: "acme"},
		ImageSigned{ImageDigest: "sha256:aa", EnvelopeDigest: "sha256:bb", Signer: "ca"},
		Revoked{Serial: big.NewInt(7), Reason: 10},
	} {
		t.Run(e.Kind().String(), func(t *testing.T) {
			b, err := Marshal(e)
			require.NoError(t, err)
			assert.Equal(t, EncodingVersion, b[0])
			assert.Equal(t, byte(e.Kind()), b[1])

			got, err := Unmarshal(b)
			require.NoError(t, err)
			assert.Equal(t, e, got)
		})
	}
}

func TestMarshal_CanonicalBytes(t *testing.T) {
	b, err := Marshal(Revoked{Serial: big.NewInt(0x0102), Reason: 1})
	require.NoError(t, err)
	assert.Equal(t, []byte{1, 3, 0, 2, 1, 2, 0, 1, 1}, b,
		"version || kind || len(serial) || serial || len(reason) || reason")

	b, err = Marshal(ImageSigned{ImageDigest: "i", EnvelopeDigest: "e", Signer: "s"})
	require.NoError(t, err)
	assert.Equal(t, []byte{1, 2, 0, 1, 'i', 0, 1, 'e', 0, 1, 's'}, b)
}

func TestKind_String(t *testing.T) {
	assert.Equal(t, "cert-issued", KindCertIssued.String())
	assert.Equal(t, "image-signed", KindImageSigned.String())
	assert.Equal(t, "revoked", KindRevoked.String())
	assert.Equal(t, "kind(9)", Kind(9).String())
}

func TestMarshal_InvalidEntry(t *testing.T) {
	hash := sha256.Sum256([]byte("cert"))
	for name, e := range map[string]Entry{
		"nil":                nil,
		"cert nil serial":    CertIssued{CertSHA256: hash, Profile: "p", Tenant: "t"},
		"cert zero serial":   CertIssued{CertSHA256: hash, Serial: big.NewInt(0), Profile: "p", Tenant: "t"},
		"cert neg serial":    CertIssued{CertSHA256: hash, Serial: big.NewInt(-1), Profile: "p", Tenant: "t"},
		"cert empty hash":    CertIssued{Serial: big.NewInt(1), Profile: "p", Tenant: "t"},
		"cert empty profile": CertIssued{CertSHA256: hash, Serial: big.NewInt(1), Tenant: "t"},
		"cert empty tenant":  CertIssued{CertSHA256: hash, Serial: big.NewInt(1), Profile: "p"},
		"image empty digest": ImageSigned{EnvelopeDigest: "e", Signer: "s"},
		"image non-UTF-8":    ImageSigned{ImageDigest: "i", EnvelopeDigest: "\xff", Signer: "s"},
		"image empty signer": ImageSigned{ImageDigest: "i", EnvelopeDigest: "e"},
		"revoked no serial":  Revoked{Reason: 1},
		"revoked reason 7":   Revoked{Serial: big.NewInt(1), Reason: 7},
		"revoked reason 11":  Revoked{Serial: big.NewInt(1), Reason: 11},
		"field too long":     ImageSigned{ImageDigest: strings.Repeat("a", maxFieldLen+1), EnvelopeDigest: "e", Signer: "s"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Marshal(e)
			assert.ErrorIs(t, err, ErrInvalidEntry)
		})
	}
}

func TestUnmarshal_Refusals(t *testing.T) {
	valid, err := Marshal(Revoked{Serial: big.NewInt(1), Reason: 1})
	require.NoError(t, err)

	for name, tc := range map[string]struct {
		b    []byte
		want error
	}{
		"empty":               {nil, ErrMalformedEntry},
		"header only byte":    {[]byte{1}, ErrMalformedEntry},
		"version 2":           {[]byte{2, 3}, ErrUnsupportedVersion},
		"kind 4":              {[]byte{1, 4}, ErrUnknownKind},
		"kind 0":              {[]byte{1, 0}, ErrUnknownKind},
		"trailing bytes":      {append(append([]byte{}, valid...), 0, 0), ErrMalformedEntry},
		"truncated length":    {[]byte{1, 3, 0}, ErrMalformedEntry},
		"truncated field":     {[]byte{1, 3, 0, 2, 1}, ErrMalformedEntry},
		"missing fields":      {[]byte{1, 3, 0, 1, 1}, ErrMalformedEntry},
		"serial leading zero": {[]byte{1, 3, 0, 2, 0, 1, 0, 1, 1}, ErrMalformedEntry},
		"zero serial":         {[]byte{1, 3, 0, 0, 0, 1, 1}, ErrMalformedEntry},
		"reason two bytes":    {[]byte{1, 3, 0, 1, 1, 0, 2, 1, 1}, ErrMalformedEntry},
		"reason 7":            {[]byte{1, 3, 0, 1, 1, 0, 1, 7}, ErrMalformedEntry},
		"cert short hash":     {[]byte{1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 'p', 0, 1, 't'}, ErrMalformedEntry},
		"image empty signer":  {[]byte{1, 2, 0, 1, 'i', 0, 1, 'e', 0, 0}, ErrMalformedEntry},
	} {
		t.Run(name, func(t *testing.T) {
			e, err := Unmarshal(tc.b)
			assert.ErrorIs(t, err, tc.want)
			assert.Nil(t, e)
		})
	}
}
