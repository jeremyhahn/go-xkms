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
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/ca/checkpoint"
)

// checkpointBody is a tree head as go-qrdb renders it for signing.
var checkpointBody = []byte(testOrigin + "\n1\n" + base64.StdEncoding.EncodeToString(make([]byte, sha256.Size)) + "\n")

// caKeySignatureTypes is the head signature type each CA key type maps to.
var caKeySignatureTypes = map[string]qrdbsdk.HeadSignatureType{
	"ed25519":    qrdbsdk.HeadSignatureEd25519,
	"ecdsa-p256": qrdbsdk.HeadSignatureECDSAP256SHA256,
}

// failingCAKeys is a CA key provider whose Signer answers signer and err.
func failingCAKeys(signer crypto.Signer, err error) qrdbsdk.CAKeyProvider {
	return qrdbsdk.CAKeyAdapter{
		SignerFunc:      func(context.Context) (crypto.Signer, error) { return signer, err },
		CertificateFunc: func(context.Context) (*x509.Certificate, error) { return nil, err },
	}
}

func TestNewHeadSignerProvider(t *testing.T) {
	p, err := NewHeadSignerProvider(newCAKeys(t, newEd25519(t)), testKeyName)
	require.NoError(t, err)
	assert.Equal(t, testKeyName, p.KeyName())

	_, err = NewHeadSignerProvider(nil, testKeyName)
	assert.ErrorIs(t, err, ErrNoKeyProvider)

	_, err = NewHeadSignerProvider(newCAKeys(t, newEd25519(t)), "")
	assert.ErrorIs(t, err, checkpoint.ErrInvalidKeyName)
}

func TestHeadSignerProvider_SignsUnderTheCAKey(t *testing.T) {
	for name, newKey := range caKeyTypes {
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()
			key := newKey(t)
			p := newProvider(t, key)
			sigType := caKeySignatureTypes[name]

			created, err := p.CreateKey(ctx, qrdbsdk.HeadSignerCreateKeyRequest{Log: "certs", Type: sigType, Version: 1})
			require.NoError(t, err)
			spki, err := x509.MarshalPKIXPublicKey(key.Public())
			require.NoError(t, err)
			sum := sha256.Sum256(spki)
			assert.Equal(t, hex.EncodeToString(sum[:]), created.Ref)
			assert.Equal(t, key.Public(), created.Public)

			hs, err := p.HeadSigner(ctx, qrdbsdk.HeadSignerRequest{Log: "certs", KeyRef: created.Ref, KeyVersion: 3})
			require.NoError(t, err)
			wantHash, err := qrdbsdk.HeadKeyHash(testKeyName, key.Public())
			require.NoError(t, err)
			assert.Equal(t, wantHash, hs.KeyHash(), "the key hash is go-qrdb's")
			assert.Equal(t, testKeyName, hs.Name())
			assert.Equal(t, uint32(3), hs.KeyVersion())
			assert.Equal(t, sigType, hs.SignatureType())
			assert.Equal(t, key.Public(), hs.Public())

			sig, err := hs.Sign(ctx, checkpointBody)
			require.NoError(t, err)
			v, err := p.Verifier(ctx)
			require.NoError(t, err)
			_, err = checkpoint.Open(signedNote(testKeyName, hs.KeyHash(), sig), v)
			assert.NoError(t, err, "the signature verifies as the signature line go-qrdb renders")
		})
	}
}

func TestHeadSignerProvider_Refusals(t *testing.T) {
	ctx := t.Context()
	p := newProvider(t, newEd25519(t))

	_, err := p.CreateKey(ctx, qrdbsdk.HeadSignerCreateKeyRequest{Type: qrdbsdk.HeadSignatureECDSAP256SHA256})
	assert.ErrorIs(t, err, ErrKeyTypeMismatch)

	_, err = p.HeadSigner(ctx, qrdbsdk.HeadSignerRequest{KeyRef: "another key"})
	assert.ErrorIs(t, err, ErrKeyRefMismatch)

	created, err := p.CreateKey(ctx, qrdbsdk.HeadSignerCreateKeyRequest{Type: qrdbsdk.HeadSignatureEd25519})
	require.NoError(t, err)
	hs, err := p.HeadSigner(ctx, qrdbsdk.HeadSignerRequest{KeyRef: created.Ref})
	require.NoError(t, err)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	_, err = hs.Sign(cancelled, checkpointBody)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestHeadSignerProvider_UnsupportedCAKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	p := newProvider(t, key)

	_, err = p.CreateKey(t.Context(), qrdbsdk.HeadSignerCreateKeyRequest{Type: qrdbsdk.HeadSignatureECDSAP256SHA256})
	assert.ErrorIs(t, err, ErrUnsupportedCAKey)
	_, err = p.Verifier(t.Context())
	assert.ErrorIs(t, err, ErrUnsupportedCAKey)
}

func TestHeadSignerProvider_CAKeyUnavailable(t *testing.T) {
	for name, keys := range map[string]qrdbsdk.CAKeyProvider{
		"not initialized": failingCAKeys(nil, &qrdbsdk.CAKeyNotInitializedError{}),
		"nil signer":      failingCAKeys(nil, nil),
	} {
		t.Run(name, func(t *testing.T) {
			p, err := NewHeadSignerProvider(keys, testKeyName)
			require.NoError(t, err)

			_, err = p.CreateKey(t.Context(), qrdbsdk.HeadSignerCreateKeyRequest{Type: qrdbsdk.HeadSignatureEd25519})
			assert.ErrorIs(t, err, ErrCAKeyUnavailable)
			_, err = p.HeadSigner(t.Context(), qrdbsdk.HeadSignerRequest{})
			assert.ErrorIs(t, err, ErrCAKeyUnavailable)
			_, err = p.Verifier(t.Context())
			assert.ErrorIs(t, err, ErrCAKeyUnavailable)
		})
	}
}

func TestCreateAndOpen_Refusals(t *testing.T) {
	cfg := Config{Name: "certs", Origin: testOrigin}

	_, err := Create(t.Context(), nil, cfg, nil)
	assert.ErrorIs(t, err, ErrNoKeyProvider)

	p, err := NewHeadSignerProvider(failingCAKeys(nil, &qrdbsdk.CAKeyNotInitializedError{}), testKeyName)
	require.NoError(t, err)
	_, err = Create(t.Context(), nil, cfg, p)
	assert.ErrorIs(t, err, ErrCAKeyUnavailable, "the CA key is checked before any log request")

	_, err = Create(t.Context(), nil, cfg, newProvider(t, newEd25519(t)))
	assert.ErrorIs(t, err, ErrNoClient)

	v, err := newProvider(t, newEd25519(t)).Verifier(t.Context())
	require.NoError(t, err)
	_, err = Open(nil, cfg, v)
	assert.ErrorIs(t, err, ErrNoClient)
}

// signedNote renders checkpointBody with the signature line go-qrdb puts
// back on it: the key name, then base64 of the key hash and the signature
// (c2sp.org/signed-note §Signatures).
func signedNote(name string, keyHash uint32, sig []byte) []byte {
	line := binary.BigEndian.AppendUint32(nil, keyHash)
	line = append(line, sig...)
	note := append([]byte{}, checkpointBody...)
	note = append(note, "\n— "+name+" "+base64.StdEncoding.EncodeToString(line)+"\n"...)
	return note
}
