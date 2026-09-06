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
	"bytes"
	"encoding/base32"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// referenceNormalizeSecret is the string-based normalization this package
// shipped before go-xkms#210, kept verbatim as the behavioural reference for
// the equivalence corpus below. It exists ONLY in this test: the production
// path must never regrow a string implementation.
func referenceNormalizeSecret(secret string) (string, error) {
	secret = strings.ToUpper(secret)
	secret = strings.Map(func(r rune) rune {
		switch r {
		case ' ', '-', '_', '\t', '\n', '\r':
			return -1
		case '0':
			return 'O'
		case '1':
			return 'I'
		case '8':
			return 'B'
		case '9':
			return -1
		default:
			return r
		}
	}, secret)
	secret = strings.TrimRight(secret, "=")

	if secret == "" {
		return "", ErrInvalidSecret
	}
	if _, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret); err != nil {
		return "", ErrInvalidSecret
	}
	return secret, nil
}

// TestNormalizeSecretBytes_EquivalentToStringImplementation proves the
// in-place byte normalization computes exactly what the removed string
// implementation computed, over a corpus covering case folds, padding,
// every separator, every typo correction, and invalid input.
//
// The one deliberate divergence — multi-byte runes whose UNICODE uppercase is
// an ASCII base32 character (e.g. U+017F) — is asserted explicitly at the
// end rather than smuggled into the corpus.
func TestNormalizeSecretBytes_EquivalentToStringImplementation(t *testing.T) {
	corpus := []string{
		"JBSWY3DPEHPK3PXP",
		"jbswy3dpehpk3pxp",
		"jBsWy3DpEhPk3pXp",
		"JBSWY3DPEHPK3PXP====",
		"jbswy3dpehpk3pxp==",
		"JBSW Y3DP EHPK 3PXP",
		"JBSW-Y3DP-EHPK-3PXP",
		"JBSW_Y3DP_EHPK_3PXP",
		"JBSW\tY3DP\nEHPK\r3PXP",
		"jbsw-Y3DP ehpk_3PXP====",
		"JBSWY0DPEHPK3PXP", // 0 -> O
		"JBSWY1DPEHPK3PXP", // 1 -> I
		"JBSWY8DPEHPK3PXP", // 8 -> B
		"JBSWY9DPEHPK3PXP", // 9 removed
		"0189",             // typo corrections only
		"",
		"   - _ ",
		"====",
		"INVALID!!!BASE32",
		"almost*valid",
		"J",                                // wrong base32 length
		"JBSWY3DP",                         // valid short secret
		"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", // RFC 4226 20-byte secret
		"MFRGG-ZDFMZ-TWQ2L-KNNWA",          // grouped entry
		"sécret",                           // non-ASCII rune, invalid either way
	}

	for _, input := range corpus {
		wantResult, wantErr := referenceNormalizeSecret(input)

		gotBytes, gotErr := normalizeSecretBytes([]byte(input))
		if wantErr != nil {
			require.Error(t, gotErr, "input %q: reference rejects, bytes accepted %q", input, gotBytes)
			continue
		}
		require.NoError(t, gotErr, "input %q: reference accepts %q, bytes rejected", input, wantResult)
		require.Equal(t, wantResult, string(gotBytes), "input %q", input)
	}

	// The known divergence: Unicode simple case folding maps U+017F LATIN
	// SMALL LETTER LONG S to 'S', so the string implementation accepted it as
	// base32; byte-wise ASCII folding rejects it. Rejection is the safer of
	// the two behaviours and is asserted so a future change is a decision,
	// not an accident.
	longS := "JBſWY3DPEHPK3PXP"
	if _, err := referenceNormalizeSecret(longS); err == nil {
		_, gotErr := normalizeSecretBytes([]byte(longS))
		require.ErrorIs(t, gotErr, ErrInvalidSecret)
	}
}

// TestCanonicalizeSecretBytes_InPlaceAndWipesTail proves the canonical form
// is a prefix of the caller's backing array (no hidden copy) and that the
// compaction's tail — which held shifted key material — is zeroed.
func TestCanonicalizeSecretBytes_InPlaceAndWipesTail(t *testing.T) {
	input := []byte("jbsw y3dp ehpk 3pxp")
	backing := input // same backing array

	got := canonicalizeSecretBytes(input)

	require.Equal(t, "JBSWY3DPEHPK3PXP", string(got))
	require.Equal(t, &backing[0], &got[0], "canonical form must reuse the caller's backing array")
	tail := backing[len(got):]
	require.Equal(t, make([]byte, len(tail)), tail, "compaction tail must be wiped")
}

func TestCredentialSetSecret(t *testing.T) {
	t.Run("stores the secret in protected memory verbatim", func(t *testing.T) {
		cred := &Credential{}
		require.NoError(t, cred.SetSecret("jbswy3dpehpk3pxp==")) // verbatim: no normalization
		require.True(t, cred.HasSecret())
		require.Equal(t, "jbswy3dpehpk3pxp==", cred.SecretString())
	})

	t.Run("replacing destroys the previous protected buffer", func(t *testing.T) {
		cred := &Credential{}
		require.NoError(t, cred.SetSecret("JBSWY3DPEHPK3PXP"))
		old := cred.secret
		require.NotNil(t, old.Bytes())

		require.NoError(t, cred.SetSecret("GEZDGNBVGY3TQOJQ"))
		require.Nil(t, old.Bytes(), "replaced secret buffer must be destroyed (wiped and unmapped)")
		require.Equal(t, "GEZDGNBVGY3TQOJQ", cred.SecretString())
	})

	t.Run("empty string clears and destroys the secret", func(t *testing.T) {
		cred := &Credential{}
		require.NoError(t, cred.SetSecret("JBSWY3DPEHPK3PXP"))
		old := cred.secret

		require.NoError(t, cred.SetSecret(""))
		require.False(t, cred.HasSecret())
		require.Nil(t, old.Bytes(), "cleared secret buffer must be destroyed")
		require.Equal(t, "", cred.SecretString())
	})
}

func TestCredentialSetSecretBytes(t *testing.T) {
	t.Run("adopts and wipes the source slice", func(t *testing.T) {
		cred := &Credential{}
		src := []byte("JBSWY3DPEHPK3PXP")
		require.NoError(t, cred.setSecretBytes(src))

		require.Equal(t, make([]byte, len(src)), src,
			"source slice must be wiped on adoption")
		require.Equal(t, "JBSWY3DPEHPK3PXP", cred.SecretString())
	})

	t.Run("empty slice clears the secret", func(t *testing.T) {
		cred := &Credential{}
		require.NoError(t, cred.SetSecret("JBSWY3DPEHPK3PXP"))
		require.NoError(t, cred.setSecretBytes(nil))
		require.False(t, cred.HasSecret())
	})
}

func TestCredentialSecretCopy(t *testing.T) {
	t.Run("returns an independent wipeable copy", func(t *testing.T) {
		cred := &Credential{}
		require.NoError(t, cred.SetSecret("JBSWY3DPEHPK3PXP"))

		b, err := cred.secretCopy()
		require.NoError(t, err)
		require.Equal(t, "JBSWY3DPEHPK3PXP", string(b))

		// Wiping the copy must not affect the stored secret.
		for i := range b {
			b[i] = 0
		}
		require.Equal(t, "JBSWY3DPEHPK3PXP", cred.SecretString())
	})

	t.Run("no secret returns ErrInvalidSecret", func(t *testing.T) {
		cred := &Credential{}
		b, err := cred.secretCopy()
		require.ErrorIs(t, err, ErrInvalidSecret)
		require.Nil(t, b)
	})

	t.Run("destroyed secret returns ErrInvalidSecret", func(t *testing.T) {
		cred := &Credential{}
		require.NoError(t, cred.SetSecret("JBSWY3DPEHPK3PXP"))
		cred.secret.Destroy()

		b, err := cred.secretCopy()
		require.ErrorIs(t, err, ErrInvalidSecret)
		require.Nil(t, b)
	})
}

// TestCredentialJSONRoundTripPreservesWireFormat pins the persisted JSON form
// to the historical wire format: the secret rides under the "secret" key as
// the plain Base32 string, so stores written before go-xkms#210 load
// unchanged and vice versa.
func TestCredentialJSONRoundTripPreservesWireFormat(t *testing.T) {
	cred, err := NewCredentialFromManualEntry("user@example.com", "GitHub", "jbsw y3dp ehpk 3pxp")
	require.NoError(t, err)

	data, err := cred.MarshalJSON()
	require.NoError(t, err)
	require.Contains(t, string(data), `"secret":"JBSWY3DPEHPK3PXP"`)

	var decoded Credential
	require.NoError(t, decoded.UnmarshalJSON(data))
	require.Equal(t, cred.SecretString(), decoded.SecretString())
	require.Equal(t, cred.ID, decoded.ID)
	require.Equal(t, cred.Algorithm, decoded.Algorithm)
}

// TestOATHProtectedSecretFlows_NoDeadlock drives every path that touches the
// protected secret — enrolment, validation, generation, JSON round-trip —
// repeatedly. The go-qrdb purge-lock nesting rule turns a purge-class call
// inside a borrow into a HANG, not an error, so this test's protection is the
// -timeout on the run: a nesting regression stalls here instead of passing.
func TestOATHProtectedSecretFlows_NoDeadlock(t *testing.T) {
	for i := 0; i < 25; i++ {
		cred, err := NewCredential("deadlock-probe", "Example", TypeTOTP)
		require.NoError(t, err)
		require.NoError(t, cred.Validate())

		gen, err := NewGenerator(cred)
		require.NoError(t, err)
		code, err := gen.Generate()
		require.NoError(t, err)
		require.Len(t, code, DefaultDigits)

		data, err := cred.MarshalJSON()
		require.NoError(t, err)
		var decoded Credential
		require.NoError(t, decoded.UnmarshalJSON(data))
		require.NoError(t, decoded.SetSecret(""))

		parsed, err := ParseURI(cred.ToURI())
		require.NoError(t, err)
		require.Equal(t, cred.SecretString(), parsed.SecretString())
	}
}

// TestGenerateCounterWipesScratch proves GenerateCounter succeeds from a
// protected secret and leaves the credential usable — the wipes bound the
// scratch copies, not the stored secret.
func TestGenerateCounterWipesScratch(t *testing.T) {
	cred, err := NewCredentialFromManualEntry("u", "I", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
	require.NoError(t, err)

	gen, err := NewGenerator(cred)
	require.NoError(t, err)

	code1, err := gen.GenerateCounter(0)
	require.NoError(t, err)
	code2, err := gen.GenerateCounter(0)
	require.NoError(t, err)
	require.Equal(t, code1, code2, "wipes must not corrupt the stored secret between calls")
	require.True(t, cred.HasSecret())
	require.False(t, bytes.Equal(nil, []byte(code1)))
}
