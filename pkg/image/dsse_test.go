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

package image

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPAE(t *testing.T) {
	// The DSSE protocol's test vector.
	assert.Equal(t,
		"DSSEv1 29 http://example.com/HelloWorld 11 hello world",
		string(PAE("http://example.com/HelloWorld", []byte("hello world"))))
	assert.Equal(t, "DSSEv1 0  0 ", string(PAE("", nil)))
}

func TestSignEnvelope(t *testing.T) {
	payload := []byte(`{"_type":"https://in-toto.io/Statement/v1"}`)
	for name, key := range signerKeys(t) {
		t.Run(name, func(t *testing.T) {
			env, err := signEnvelope(key, PayloadTypeInToto, payload)
			require.NoError(t, err)
			assert.Equal(t, PayloadTypeInToto, env.PayloadType)
			assert.Equal(t, payload, env.Payload)
			require.Len(t, env.Signatures, 1)
			require.NoError(t, verifyEnvelope(env, key.Public()))

			tampered := *env
			tampered.Payload = []byte(`{"_type":"tampered"}`)
			require.ErrorIs(t, verifyEnvelope(&tampered, key.Public()), ErrSignatureInvalid)

			retyped := *env
			retyped.PayloadType = "application/json"
			require.ErrorIs(t, verifyEnvelope(&retyped, key.Public()), ErrSignatureInvalid,
				"the payload type is signed")
		})
	}
}

func TestSignEnvelope_Errors(t *testing.T) {
	x25519, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)

	env, err := signEnvelope(failingSigner{public: x25519.PublicKey()}, PayloadTypeInToto, []byte("{}"))
	require.ErrorIs(t, err, ErrUnsupportedKey)
	assert.Nil(t, env)

	env, err = signEnvelope(failingSigner{public: newECDSAKey(t).Public()}, PayloadTypeInToto, []byte("{}"))
	require.ErrorIs(t, err, ErrSigningFailed)
	require.ErrorIs(t, err, errTestSigner)
	assert.Nil(t, env)
}

func TestVerifyEnvelope_Errors(t *testing.T) {
	key := newECDSAKey(t)
	env, err := signEnvelope(key, PayloadTypeInToto, []byte("{}"))
	require.NoError(t, err)

	require.ErrorIs(t, verifyEnvelope(env, newECDSAKey(t).Public()), ErrSignatureInvalid, "wrong key")
	require.ErrorIs(t, verifyEnvelope(env, newRSAKey(t).Public()), ErrSignatureInvalid, "wrong key type")
	require.ErrorIs(t, verifyEnvelope(env, "not a key"), ErrUnsupportedKey)

	unsigned := *env
	unsigned.Signatures = nil
	require.ErrorIs(t, verifyEnvelope(&unsigned, key.Public()), ErrInvalidEnvelope)
}

func TestVerifyEnvelope_AnySignature(t *testing.T) {
	key := newEd25519Key(t)
	env, err := signEnvelope(key, PayloadTypeInToto, []byte("{}"))
	require.NoError(t, err)

	env.Signatures = append([]EnvelopeSignature{{KeyID: "other", Sig: []byte("garbage")}}, env.Signatures...)
	require.NoError(t, verifyEnvelope(env, key.Public()), "one valid signature suffices")

	env.Signatures = env.Signatures[:1]
	require.ErrorIs(t, verifyEnvelope(env, key.Public()), ErrSignatureInvalid)
}

func TestParseEnvelope(t *testing.T) {
	env, err := signEnvelope(newECDSAKey(t), PayloadTypeInToto, []byte(`{"a":1}`))
	require.NoError(t, err)
	data, err := json.Marshal(env)
	require.NoError(t, err)

	parsed, err := parseEnvelope(data)
	require.NoError(t, err)
	assert.Equal(t, env, parsed)
}

func TestParseEnvelope_Invalid(t *testing.T) {
	tests := map[string]string{
		"not json":           "{",
		"bad base64 payload": `{"payloadType":"application/vnd.in-toto+json","payload":"!!"}`,
		"wrong payload type": `{"payloadType":"application/json","payload":"e30="}`,
		"no payload type":    `{"payload":"e30="}`,
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			env, err := parseEnvelope([]byte(data))
			require.ErrorIs(t, err, ErrInvalidEnvelope)
			assert.Nil(t, env)
		})
	}
}

func TestNewStatement(t *testing.T) {
	statement, err := newStatement("gcr.io/image", testSHA256, PredicateTypeCosign, json.RawMessage(`{"Data":""}`))
	require.NoError(t, err)
	assert.Equal(t, StatementTypeV1, statement.Type)
	assert.Equal(t, []Subject{{Name: "gcr.io/image", Digest: map[string]string{"sha256": strings.Repeat("ab", 32)}}}, statement.Subject)
	assert.Equal(t, PredicateTypeCosign, statement.PredicateType)
	assert.True(t, statement.names(testSHA256))

	data, err := json.Marshal(statement)
	require.NoError(t, err)
	parsed, err := parseStatement(data)
	require.NoError(t, err)
	assert.Equal(t, statement, parsed)
}

func TestNewStatement_InvalidDigest(t *testing.T) {
	statement, err := newStatement("gcr.io/image", "sha256:abc", PredicateTypeCosign, nil)
	require.ErrorIs(t, err, ErrInvalidDigest)
	assert.Nil(t, statement)
}

func TestParseStatement(t *testing.T) {
	// Older cosign releases write in-toto v0.1 statements.
	statement, err := parseStatement([]byte(`{
		"_type": "https://in-toto.io/Statement/v0.1",
		"subject": [{"name": "gcr.io/image", "digest": {"sha256": "` + strings.Repeat("ab", 32) + `"}}],
		"predicateType": "https://slsa.dev/provenance/v0.2",
		"predicate": {}
	}`))
	require.NoError(t, err)
	assert.Equal(t, "https://slsa.dev/provenance/v0.2", statement.PredicateType)
	assert.True(t, statement.names(testSHA256))
}

func TestParseStatement_Invalid(t *testing.T) {
	subject := `"subject":[{"name":"image","digest":{"sha256":"` + strings.Repeat("ab", 32) + `"}}]`
	tests := map[string]string{
		"not json":          "[",
		"unknown type":      `{"_type":"https://in-toto.io/Statement/v2",` + subject + `,"predicateType":"p"}`,
		"no type":           `{` + subject + `,"predicateType":"p"}`,
		"no subject":        `{"_type":"https://in-toto.io/Statement/v1","subject":[],"predicateType":"p"}`,
		"no predicate type": `{"_type":"https://in-toto.io/Statement/v1",` + subject + `}`,
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			statement, err := parseStatement([]byte(data))
			require.ErrorIs(t, err, ErrInvalidStatement)
			assert.Nil(t, statement)
		})
	}
}

func TestStatement_Names(t *testing.T) {
	statement := &Statement{Subject: []Subject{
		{Name: "a", Digest: map[string]string{"sha512": strings.Repeat("cd", 64)}},
		{Name: "b", Digest: map[string]string{"sha256": strings.Repeat("ab", 32)}},
	}}
	assert.True(t, statement.names(testSHA256))
	assert.True(t, statement.names(testSHA512))
	assert.False(t, statement.names("sha256:"+strings.Repeat("ef", 32)))
	assert.False(t, statement.names("sha256:abc"))
}
