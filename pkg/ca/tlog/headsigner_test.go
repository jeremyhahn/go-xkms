package tlog

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeCA struct{ signer crypto.Signer }

func (f fakeCA) Signer(context.Context) (crypto.Signer, error) { return f.signer, nil }

func createReq(t qrdbsdk.HeadSignatureType) qrdbsdk.HeadSignerCreateKeyRequest {
	return qrdbsdk.HeadSignerCreateKeyRequest{TenantID: "t1", Database: "system", Log: "issuance", Type: t, Version: 1}
}

func TestHeadSignerProvider_ECDSAUsesCAKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	p := NewHeadSignerProvider()
	require.NoError(t, p.Bind(fakeCA{signer: key}))
	ctx := context.Background()

	req := createReq(qrdbsdk.HeadSignatureECDSAP256SHA256)
	created, err := p.CreateKey(ctx, req)
	require.NoError(t, err)
	assert.Nil(t, created.Record, "the CA key never leaves the CA")
	assert.True(t, key.PublicKey.Equal(created.Public), "checkpoint key is the CA key")
	_, err = created.HeadKey(req)
	require.NoError(t, err)

	hs, err := p.HeadSigner(ctx, qrdbsdk.HeadSignerRequest{
		TenantID: "t1", Database: "system", Log: "issuance", KeyRef: created.Ref, KeyVersion: 1,
	})
	require.NoError(t, err)
	assert.Equal(t, "t1/system/issuance", hs.Name())
	assert.Equal(t, uint32(1), hs.KeyVersion())
	assert.Equal(t, qrdbsdk.HeadSignatureECDSAP256SHA256, hs.SignatureType())
	wantHash, err := qrdbsdk.HeadKeyHash(hs.Name(), &key.PublicKey)
	require.NoError(t, err)
	assert.Equal(t, wantHash, hs.KeyHash())

	body := []byte("t1/system/issuance\n1\nroot\n")
	sig, err := hs.Sign(ctx, body)
	require.NoError(t, err)
	digest := sha256.Sum256(body)
	assert.True(t, ecdsa.VerifyASN1(&key.PublicKey, digest[:], sig), "checkpoint verifies under the CA key")
}

func TestHeadSignerProvider_Ed25519UsesCAKey(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	p := NewHeadSignerProvider()
	require.NoError(t, p.Bind(fakeCA{signer: priv}))
	ctx := context.Background()

	created, err := p.CreateKey(ctx, createReq(qrdbsdk.HeadSignatureEd25519))
	require.NoError(t, err)
	hs, err := p.HeadSigner(ctx, qrdbsdk.HeadSignerRequest{
		TenantID: "t1", Database: "system", Log: "issuance", KeyRef: created.Ref, KeyVersion: 1,
	})
	require.NoError(t, err)
	body := []byte("checkpoint body\n")
	sig, err := hs.Sign(ctx, body)
	require.NoError(t, err)
	assert.True(t, ed25519.Verify(pub, body, sig))
}

func TestHeadSignerProvider_Refusals(t *testing.T) {
	ctx := context.Background()
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	t.Run("unbound", func(t *testing.T) {
		_, err := NewHeadSignerProvider().CreateKey(ctx, createReq(qrdbsdk.HeadSignatureECDSAP256SHA256))
		assert.ErrorIs(t, err, ErrCANotBound)
	})
	t.Run("nil CA", func(t *testing.T) {
		assert.ErrorIs(t, NewHeadSignerProvider().Bind(nil), ErrCANotBound)
	})
	t.Run("RSA CA key", func(t *testing.T) {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		p := NewHeadSignerProvider()
		require.NoError(t, p.Bind(fakeCA{signer: rsaKey}))
		_, err = p.CreateKey(ctx, createReq(qrdbsdk.HeadSignatureECDSAP256SHA256))
		var unsupported *UnsupportedKeyError
		assert.True(t, errors.As(err, &unsupported))
	})
	t.Run("type mismatch", func(t *testing.T) {
		p := NewHeadSignerProvider()
		require.NoError(t, p.Bind(fakeCA{signer: ecKey}))
		_, err := p.CreateKey(ctx, createReq(qrdbsdk.HeadSignatureEd25519))
		var mismatch *KeyTypeMismatchError
		assert.True(t, errors.As(err, &mismatch))
	})
	t.Run("foreign key ref", func(t *testing.T) {
		p := NewHeadSignerProvider()
		require.NoError(t, p.Bind(fakeCA{signer: ecKey}))
		_, err := p.HeadSigner(ctx, qrdbsdk.HeadSignerRequest{TenantID: "t1", Database: "system", Log: "issuance", KeyRef: "k/1", KeyVersion: 1})
		var ref *KeyRefError
		assert.True(t, errors.As(err, &ref))
	})
}
