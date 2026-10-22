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

package services

// These tests drive every PKCS#11 operation end to end: the module-side
// IPCTransport, a real ipc.Server on a unix socket, the real PKCS11IPCHandler
// and a real EmbeddedTransport over the in-memory software backend. The xkms
// service is a process singleton, so none of them run in parallel.

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/testing/fipstest"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/ipc"
	pkcs11svc "github.com/jeremyhahn/go-xkms/xkey/pkg/pkcs11"
)

const roundTripBackend = "software"

// ipcTestHandler is the minimal ipc.Handler the GUI provides around the
// PKCS#11 handler: only the PKCS#11 surface is under test.
type ipcTestHandler struct {
	*PKCS11IPCHandler
}

func (ipcTestHandler) HandleTouch() (*ipc.Response, error) {
	return ipc.OKResponse(ipc.ActionDaemonReady), nil
}

func (ipcTestHandler) HandleTypePassword(string) (*ipc.Response, error) {
	return ipc.OKResponse(ipc.ActionDaemonReady), nil
}

func (ipcTestHandler) HandleStatus() (*ipc.Response, error) {
	return ipc.OKResponse(ipc.ActionDaemonReady), nil
}

// ipcRoundTrip is one running xkey IPC endpoint and the clients that reach it.
type ipcRoundTrip struct {
	client   *pkcs11svc.IPCTransport
	embedded *pkcs11svc.EmbeddedTransport
	sealed   *atomic.Bool
}

// newIPCRoundTrip brings up the xkms service with in-memory storage, serves a
// real PKCS11IPCHandler on a socket in a private temporary directory and
// returns an IPCTransport dialing it.
func newIPCRoundTrip(t *testing.T) *ipcRoundTrip {
	t.Helper()

	xkms.Reset()
	require.NoError(t, xkms.AutoInitialize(&xkms.AutoConfig{}))
	t.Cleanup(xkms.Reset)
	embedded, err := pkcs11svc.NewEmbeddedTransport()
	require.NoError(t, err)

	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o700))
	socketPath := filepath.Join(dir, "xkey.sock")

	sealed := &atomic.Bool{}
	handler := NewPKCS11IPCHandler(embedded, testLogger(), sealed.Load)
	srv, err := ipc.NewServer(socketPath, ipcTestHandler{handler}, testLogger())
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		srv.Close()
	})
	go srv.Serve(ctx)

	return &ipcRoundTrip{client: pkcs11svc.NewIPCTransport(socketPath), embedded: embedded, sealed: sealed}
}

// generateKey creates an asymmetric key through the socket.
func (rt *ipcRoundTrip) generateKey(t *testing.T, keyID, algorithm string) *transport.GenerateKeyResponse {
	t.Helper()
	resp, err := rt.client.GenerateKey(context.Background(), &transport.GenerateKeyRequest{
		Backend: roundTripBackend, KeyID: keyID, Algorithm: algorithm, KeyType: algorithm,
	})
	require.NoError(t, err)
	return resp
}

// newAESKey creates an AES-256 key through the socket with the request the
// PKCS#11 module sends for CKM_AES_KEY_GEN.
func (rt *ipcRoundTrip) newAESKey(t *testing.T, keyID string, exportable bool) {
	t.Helper()
	resp, err := rt.client.GenerateKey(context.Background(), &transport.GenerateKeyRequest{
		Backend: roundTripBackend, KeyID: keyID, KeyType: "Symmetric", Algorithm: "Symmetric",
		KeySize: 256, Exportable: exportable,
	})
	require.NoError(t, err)
	require.Equal(t, keyID, resp.KeyID)
	require.Empty(t, resp.PublicKeyPEM, "a secret key has no public half")
}

func TestPKCS11IPCRoundTrip_GenerateSignVerify(t *testing.T) {
	rt := newIPCRoundTrip(t)
	ctx := context.Background()

	generated := rt.generateKey(t, "rt-ecdsa", "ECDSA")
	assert.Equal(t, "rt-ecdsa", generated.KeyID)
	assert.Contains(t, generated.PublicKeyPEM, "PUBLIC KEY")

	data := []byte("signed over the xkey socket")
	signed, err := rt.client.Sign(ctx, &transport.SignRequest{Backend: roundTripBackend, KeyID: "rt-ecdsa", Data: data, Hash: "SHA-256"})
	require.NoError(t, err)
	require.NotEmpty(t, signed.Signature)

	verified, err := rt.client.Verify(ctx, &transport.VerifyRequest{
		Backend: roundTripBackend, KeyID: "rt-ecdsa", Data: data, Signature: signed.Signature, Hash: "SHA-256",
	})
	require.NoError(t, err)
	assert.True(t, verified.Valid)

	tampered, err := rt.client.Verify(ctx, &transport.VerifyRequest{
		Backend: roundTripBackend, KeyID: "rt-ecdsa", Data: []byte("other data"), Signature: signed.Signature, Hash: "SHA-256",
	})
	require.NoError(t, err)
	assert.False(t, tampered.Valid)
}

func TestPKCS11IPCRoundTrip_GenerateKey_UnsupportedAlgorithm(t *testing.T) {
	rt := newIPCRoundTrip(t)

	_, err := rt.client.GenerateKey(context.Background(), &transport.GenerateKeyRequest{
		Backend: roundTripBackend, KeyID: "rt-bad", Algorithm: "DSA",
	})
	assert.ErrorIs(t, err, ipc.ErrPKCS11Operation)
}

func TestPKCS11IPCRoundTrip_GenerateKey_SymmetricSizeNotAES(t *testing.T) {
	rt := newIPCRoundTrip(t)

	_, err := rt.client.GenerateKey(context.Background(), &transport.GenerateKeyRequest{
		Backend: roundTripBackend, KeyID: "rt-bad-aes", KeyType: "Symmetric", Algorithm: "Symmetric", KeySize: 512,
	})
	assert.ErrorIs(t, err, ipc.ErrPKCS11Operation)
}

func TestPKCS11IPCRoundTrip_Sign_UnknownKey(t *testing.T) {
	rt := newIPCRoundTrip(t)

	_, err := rt.client.Sign(context.Background(), &transport.SignRequest{
		Backend: roundTripBackend, KeyID: "no-such-key", Data: []byte("d"), Hash: "SHA-256",
	})
	assert.ErrorIs(t, err, pkcs11svc.ErrSigningFailed)
}

func TestPKCS11IPCRoundTrip_EncryptDecrypt(t *testing.T) {
	rt := newIPCRoundTrip(t)
	ctx := context.Background()
	rt.newAESKey(t, "rt-aes", false)

	plaintext := []byte("sealed over the xkey socket")
	encrypted, err := rt.client.Encrypt(ctx, &transport.EncryptRequest{Backend: roundTripBackend, KeyID: "rt-aes", Plaintext: plaintext})
	require.NoError(t, err)
	assert.NotEqual(t, plaintext, encrypted.Ciphertext)

	decrypted, err := rt.client.Decrypt(ctx, &transport.DecryptRequest{
		Backend: roundTripBackend, KeyID: "rt-aes",
		Ciphertext: encrypted.Ciphertext, Nonce: encrypted.Nonce, Tag: encrypted.Tag,
		GCMNonceMode: encrypted.GCMNonceMode,
	})
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted.Plaintext)
}

func TestPKCS11IPCRoundTrip_Decrypt_TamperedCiphertext(t *testing.T) {
	rt := newIPCRoundTrip(t)
	ctx := context.Background()
	rt.newAESKey(t, "rt-aes", false)

	encrypted, err := rt.client.Encrypt(ctx, &transport.EncryptRequest{Backend: roundTripBackend, KeyID: "rt-aes", Plaintext: []byte("p")})
	require.NoError(t, err)
	encrypted.Ciphertext[0] ^= 0xff

	_, err = rt.client.Decrypt(ctx, &transport.DecryptRequest{
		Backend: roundTripBackend, KeyID: "rt-aes",
		Ciphertext: encrypted.Ciphertext, Nonce: encrypted.Nonce, Tag: encrypted.Tag,
		GCMNonceMode: encrypted.GCMNonceMode,
	})
	assert.ErrorIs(t, err, pkcs11svc.ErrDecryptionFailed)
}

func TestPKCS11IPCRoundTrip_EncryptAsym(t *testing.T) {
	rt := newIPCRoundTrip(t)
	rt.generateKey(t, "rt-rsa", "RSA")

	encrypted, err := rt.client.EncryptAsym(context.Background(), &transport.EncryptAsymRequest{
		Backend: roundTripBackend, KeyID: "rt-rsa", Plaintext: []byte("oaep"), Hash: "SHA-256",
	})
	require.NoError(t, err)
	assert.Len(t, encrypted.Ciphertext, 256, "RSA-2048 OAEP ciphertext is one modulus long")
}

func TestPKCS11IPCRoundTrip_EncryptAsym_NonRSAKey(t *testing.T) {
	rt := newIPCRoundTrip(t)
	rt.generateKey(t, "rt-ecdsa", "ECDSA")

	_, err := rt.client.EncryptAsym(context.Background(), &transport.EncryptAsymRequest{
		Backend: roundTripBackend, KeyID: "rt-ecdsa", Plaintext: []byte("oaep"), Hash: "SHA-256",
	})
	assert.ErrorIs(t, err, pkcs11svc.ErrEncryptionFailed)
}

func TestPKCS11IPCRoundTrip_EncryptDecrypt_CBCWithCallerIV(t *testing.T) {
	rt := newIPCRoundTrip(t)
	ctx := context.Background()
	rt.newAESKey(t, "rt-aes", false)
	iv := []byte("0123456789abcdef")

	for mode, plaintext := range map[string][]byte{
		"cbc":     []byte("exactly 32 bytes of block input!"),
		"cbc-pad": []byte("not block aligned"),
	} {
		encrypted, err := rt.client.Encrypt(ctx, &transport.EncryptRequest{
			Backend: roundTripBackend, KeyID: "rt-aes", Plaintext: plaintext, Mode: mode, IV: iv,
		})
		require.NoError(t, err, mode)
		assert.Equal(t, iv, encrypted.IV, "%s must run under the caller's IV", mode)
		assert.Empty(t, encrypted.Tag, "%s produces no tag", mode)

		decrypted, err := rt.client.Decrypt(ctx, &transport.DecryptRequest{
			Backend: roundTripBackend, KeyID: "rt-aes", Ciphertext: encrypted.Ciphertext,
			Mode: mode, IV: encrypted.IV, KeyVersion: encrypted.KeyVersion,
		})
		require.NoError(t, err, mode)
		assert.Equal(t, plaintext, decrypted.Plaintext, mode)
	}
}

func TestPKCS11IPCRoundTrip_Encrypt_CBCRefusesAdditionalData(t *testing.T) {
	rt := newIPCRoundTrip(t)
	rt.newAESKey(t, "rt-aes", false)

	_, err := rt.client.Encrypt(context.Background(), &transport.EncryptRequest{
		Backend: roundTripBackend, KeyID: "rt-aes", Plaintext: []byte("p"), Mode: "cbc-pad", AdditionalData: []byte("aad"),
	})
	assert.ErrorIs(t, err, pkcs11svc.ErrEncryptionFailed, "AES-CBC authenticates nothing, so AAD must be refused, not dropped")
}

func TestPKCS11IPCRoundTrip_EncryptDecrypt_GCMAdditionalDataAndTagSize(t *testing.T) {
	rt := newIPCRoundTrip(t)
	ctx := context.Background()
	rt.newAESKey(t, "rt-aes", false)
	plaintext := []byte("bound to its context")
	aad := []byte("record-17")

	encrypted, err := rt.client.Encrypt(ctx, &transport.EncryptRequest{
		Backend: roundTripBackend, KeyID: "rt-aes", Plaintext: plaintext, AdditionalData: aad, TagSize: 12,
	})
	// A truncated tag needs the arbitrary-IV GCM construction, which the
	// FIPS 140-3 module refuses.
	if !fipstest.OutsideFIPSAfterRefusal(t, err, pkcs11svc.ErrEncryptionFailed) {
		return
	}
	require.NoError(t, err)
	assert.Len(t, encrypted.Tag, 12, "the caller's tag size must reach the cipher")

	decrypt := &transport.DecryptRequest{
		Backend: roundTripBackend, KeyID: "rt-aes", Ciphertext: encrypted.Ciphertext, Nonce: encrypted.Nonce,
		Tag: encrypted.Tag, GCMNonceMode: encrypted.GCMNonceMode, AdditionalData: aad, TagSize: 12,
	}
	decrypted, err := rt.client.Decrypt(ctx, decrypt)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted.Plaintext)

	decrypt.AdditionalData = []byte("record-18")
	_, err = rt.client.Decrypt(ctx, decrypt)
	assert.ErrorIs(t, err, pkcs11svc.ErrDecryptionFailed, "a different AAD must fail authentication")
}

func TestPKCS11IPCRoundTrip_EncryptAsymDecrypt_OAEPLabel(t *testing.T) {
	rt := newIPCRoundTrip(t)
	ctx := context.Background()
	rt.generateKey(t, "rt-rsa", "RSA")
	plaintext := []byte("labelled oaep")
	label := []byte("session-42")

	encrypted, err := rt.client.EncryptAsym(ctx, &transport.EncryptAsymRequest{
		Backend: roundTripBackend, KeyID: "rt-rsa", Plaintext: plaintext, Hash: "SHA-256", Label: label,
	})
	require.NoError(t, err)

	decrypt := &transport.DecryptRequest{
		Backend: roundTripBackend, KeyID: "rt-rsa", Ciphertext: encrypted.Ciphertext,
		Padding: "oaep", Hash: "SHA-256", Label: label,
	}
	decrypted, err := rt.client.Decrypt(ctx, decrypt)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted.Plaintext)

	decrypt.Label = []byte("session-43")
	_, err = rt.client.Decrypt(ctx, decrypt)
	assert.ErrorIs(t, err, pkcs11svc.ErrDecryptionFailed, "a different OAEP label must fail decryption")
}

func TestPKCS11IPCRoundTrip_Decrypt_RSAPKCS1v15Refused(t *testing.T) {
	rt := newIPCRoundTrip(t)
	ctx := context.Background()
	rt.generateKey(t, "rt-rsa", "RSA")
	encrypted, err := rt.client.EncryptAsym(ctx, &transport.EncryptAsymRequest{
		Backend: roundTripBackend, KeyID: "rt-rsa", Plaintext: []byte("p"), Hash: "SHA-256",
	})
	require.NoError(t, err)

	_, err = rt.client.Decrypt(ctx, &transport.DecryptRequest{
		Backend: roundTripBackend, KeyID: "rt-rsa", Ciphertext: encrypted.Ciphertext, Padding: "pkcs1v15",
	})
	assert.ErrorIs(t, err, pkcs11svc.ErrDecryptionFailed, "PKCS#1 v1.5 decryption stays refused unless legacy key wrap is enabled")
}

func TestPKCS11IPCRoundTrip_Encrypt_RSAPKCS1v15Refused(t *testing.T) {
	rt := newIPCRoundTrip(t)
	rt.generateKey(t, "rt-rsa", "RSA")

	_, err := rt.client.Encrypt(context.Background(), &transport.EncryptRequest{
		Backend: roundTripBackend, KeyID: "rt-rsa", Plaintext: []byte("p"),
	})
	assert.ErrorIs(t, err, pkcs11svc.ErrEncryptionFailed, "PKCS#1 v1.5 encryption stays refused unless legacy key wrap is enabled")
}

func TestPKCS11IPCRoundTrip_EncryptDecrypt_GCMCallerNonce(t *testing.T) {
	rt := newIPCRoundTrip(t)
	ctx := context.Background()
	rt.newAESKey(t, "rt-aes", false)
	plaintext := []byte("under the caller's nonce")
	nonce := []byte("0123456789ab")
	aad := []byte("record-17")

	encrypted, err := rt.client.Encrypt(ctx, &transport.EncryptRequest{
		Backend: roundTripBackend, KeyID: "rt-aes", Plaintext: plaintext, Nonce: nonce, AdditionalData: aad,
	})
	// The FIPS 140-3 module seals AES-GCM only under its own nonce.
	if !fipstest.OutsideFIPSAfterRefusal(t, err, pkcs11svc.ErrEncryptionFailed) {
		return
	}
	require.NoError(t, err)
	assert.Equal(t, nonce, encrypted.Nonce, "the caller's nonce must reach the cipher")

	decrypted, err := rt.client.Decrypt(ctx, &transport.DecryptRequest{
		Backend: roundTripBackend, KeyID: "rt-aes", Ciphertext: encrypted.Ciphertext, Nonce: encrypted.Nonce,
		Tag: encrypted.Tag, GCMNonceMode: encrypted.GCMNonceMode, AdditionalData: aad,
	})
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted.Plaintext)
}

func TestPKCS11IPCRoundTrip_CanceledContext_NeverDispatched(t *testing.T) {
	rt := newIPCRoundTrip(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := rt.client.GenerateKey(ctx, &transport.GenerateKeyRequest{
		Backend: roundTripBackend, KeyID: "rt-canceled", Algorithm: "ECDSA", KeyType: "ECDSA",
	})
	require.ErrorIs(t, err, pkcs11svc.ErrIPCRequestCanceled)
	assert.ErrorIs(t, err, context.Canceled)

	_, err = rt.embedded.Sign(context.Background(), &transport.SignRequest{
		Backend: roundTripBackend, KeyID: "rt-canceled", Data: []byte("d"), Hash: "SHA-256",
	})
	assert.ErrorIs(t, err, pkcs11svc.ErrKeyNotFound, "a canceled request must not create the key")
}

func TestPKCS11IPCRoundTrip_EveryOperation_CanceledContextNeverDials(t *testing.T) {
	// Nothing listens on the socket, so any dial would fail as a connection
	// error: a cancellation error proves the request never left the caller.
	client := pkcs11svc.NewIPCTransport(filepath.Join(t.TempDir(), "absent.sock"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	for action, op := range clientOps() {
		err := op(ctx, client)
		assert.ErrorIs(t, err, pkcs11svc.ErrIPCRequestCanceled, action)
		assert.NotErrorIs(t, err, pkcs11svc.ErrIPCConnectionFailed, action)
	}
}

func TestPKCS11IPCRoundTrip_DeriveKey_MatchesEmbedded(t *testing.T) {
	rt := newIPCRoundTrip(t)
	req := &transport.DeriveKeyRequest{
		Backend: roundTripBackend, Algorithm: "HKDF", Hash: "SHA-256", KeyLength: 32,
		InputKeyMaterial: []byte("0123456789abcdef0123456789abcdef"), Salt: []byte("salt"), Info: []byte("info"),
	}

	overSocket, err := rt.client.DeriveKey(context.Background(), req)
	require.NoError(t, err)
	direct, err := rt.embedded.DeriveKey(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, direct, overSocket)
}

func TestPKCS11IPCRoundTrip_DeriveKey_UnknownAlgorithm(t *testing.T) {
	rt := newIPCRoundTrip(t)

	_, err := rt.client.DeriveKey(context.Background(), &transport.DeriveKeyRequest{
		Backend: roundTripBackend, Algorithm: "NO-SUCH-KDF", KeyLength: 32, InputKeyMaterial: []byte("ikm"),
	})
	assert.ErrorIs(t, err, pkcs11svc.ErrDerivationFailed)
}

func TestPKCS11IPCRoundTrip_DeriveKeyECDH_MatchesEmbedded(t *testing.T) {
	rt := newIPCRoundTrip(t)
	rt.generateKey(t, "rt-ecdh", "ECDSA")
	peer, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	peerDER, err := x509.MarshalPKIXPublicKey(peer.PublicKey())
	require.NoError(t, err)
	req := &transport.DeriveKeyECDHRequest{Backend: roundTripBackend, KeyID: "rt-ecdh", PeerPublicKey: peerDER, KeyLength: 32}

	overSocket, err := rt.client.DeriveKeyECDH(context.Background(), req)
	require.NoError(t, err)
	require.Len(t, overSocket.DerivedKey, 32)
	direct, err := rt.embedded.DeriveKeyECDH(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, direct.DerivedKey, overSocket.DerivedKey)
}

func TestPKCS11IPCRoundTrip_DeriveKeyECDH_BadPeerKey(t *testing.T) {
	rt := newIPCRoundTrip(t)
	rt.generateKey(t, "rt-ecdh", "ECDSA")

	_, err := rt.client.DeriveKeyECDH(context.Background(), &transport.DeriveKeyECDHRequest{
		Backend: roundTripBackend, KeyID: "rt-ecdh", PeerPublicKey: []byte("not a public key"),
	})
	assert.ErrorIs(t, err, pkcs11svc.ErrDerivationFailed)
}

func TestPKCS11IPCRoundTrip_WrapUnwrapExport(t *testing.T) {
	rt := newIPCRoundTrip(t)
	ctx := context.Background()
	rt.newAESKey(t, "rt-kek", false)
	rt.newAESKey(t, "rt-target", true)

	wrapped, err := rt.client.WrapKeyByID(ctx, &transport.WrapKeyByIDRequest{
		WrappingKeyBackend: roundTripBackend, WrappingKeyID: "rt-kek",
		TargetKeyBackend: roundTripBackend, TargetKeyID: "rt-target", Algorithm: "AES_KW",
	})
	require.NoError(t, err)
	require.NotEmpty(t, wrapped.WrappedKey)

	_, err = rt.client.UnwrapKeyByID(ctx, &transport.UnwrapKeyByIDRequest{
		WrappedKey: wrapped.WrappedKey, Algorithm: "AES_KW",
		UnwrappingKeyBackend: roundTripBackend, UnwrappingKeyID: "rt-kek",
		TargetKeyBackend: roundTripBackend, TargetKeyID: "rt-unwrapped",
		TargetKeyType: "symmetric", TargetKeySize: 256, TargetExportable: true,
	})
	require.NoError(t, err)

	original, err := rt.client.ExportKeyMaterial(ctx, &transport.ExportKeyMaterialRequest{Backend: roundTripBackend, KeyID: "rt-target"})
	require.NoError(t, err)
	unwrapped, err := rt.client.ExportKeyMaterial(ctx, &transport.ExportKeyMaterialRequest{Backend: roundTripBackend, KeyID: "rt-unwrapped"})
	require.NoError(t, err)
	assert.Len(t, original.KeyMaterial, 32)
	assert.Equal(t, original.KeyMaterial, unwrapped.KeyMaterial, "unwrapping must restore the wrapped key")
}

func TestPKCS11IPCRoundTrip_UnwrapKeyByID_CorruptBlob(t *testing.T) {
	rt := newIPCRoundTrip(t)
	rt.newAESKey(t, "rt-kek", false)

	_, err := rt.client.UnwrapKeyByID(context.Background(), &transport.UnwrapKeyByIDRequest{
		WrappedKey: []byte("0123456789abcdef01234567"), Algorithm: "AES_KW",
		UnwrappingKeyBackend: roundTripBackend, UnwrappingKeyID: "rt-kek",
		TargetKeyBackend: roundTripBackend, TargetKeyID: "rt-unwrapped", TargetKeyType: "symmetric", TargetKeySize: 256,
	})
	assert.ErrorIs(t, err, pkcs11svc.ErrWrappingFailed)
}

func TestPKCS11IPCRoundTrip_WrapKeyByID_UnknownTarget(t *testing.T) {
	rt := newIPCRoundTrip(t)
	rt.newAESKey(t, "rt-kek", false)

	_, err := rt.client.WrapKeyByID(context.Background(), &transport.WrapKeyByIDRequest{
		WrappingKeyBackend: roundTripBackend, WrappingKeyID: "rt-kek",
		TargetKeyBackend: roundTripBackend, TargetKeyID: "no-such-key", Algorithm: "AES_KW",
	})
	assert.ErrorIs(t, err, pkcs11svc.ErrWrappingFailed)
}

func TestPKCS11IPCRoundTrip_ExportKeyMaterial_NonExportableRefused(t *testing.T) {
	// The socket adds no export path: a key the backend will not release
	// stays inside it however it is asked for.
	rt := newIPCRoundTrip(t)
	rt.newAESKey(t, "rt-sealed", false)

	resp, err := rt.client.ExportKeyMaterial(context.Background(), &transport.ExportKeyMaterialRequest{Backend: roundTripBackend, KeyID: "rt-sealed"})
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, pkcs11svc.ErrExportFailed)
}

func TestPKCS11IPCRoundTrip_GetImportParameters(t *testing.T) {
	rt := newIPCRoundTrip(t)

	params, err := rt.client.GetImportParameters(context.Background(), &transport.GetImportParametersRequest{
		Backend: roundTripBackend, KeyID: "rt-import", Algorithm: "RSA_AES_KEY_WRAP_SHA_256", KeyType: "ECDSA",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, params.WrappingPublicKey)
	assert.Equal(t, "RSA_AES_KEY_WRAP_SHA_256", params.Algorithm)
}

func TestPKCS11IPCRoundTrip_GetImportParameters_SecretKeyTemplate(t *testing.T) {
	// The service negotiates an import ceremony for a secret key as well as
	// for a key pair.
	rt := newIPCRoundTrip(t)

	params, err := rt.client.GetImportParameters(context.Background(), &transport.GetImportParametersRequest{
		Backend: roundTripBackend, KeyID: "rt-import", Algorithm: "RSA_AES_KEY_WRAP_SHA_256", KeyType: "AES", KeySize: 256,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, params.WrappingPublicKey)
}

func TestPKCS11IPCRoundTrip_GetImportParameters_UnsupportedTemplate(t *testing.T) {
	rt := newIPCRoundTrip(t)

	_, err := rt.client.GetImportParameters(context.Background(), &transport.GetImportParametersRequest{
		Backend: roundTripBackend, KeyID: "rt-import", Algorithm: "RSA_AES_KEY_WRAP_SHA_256", KeyType: "not-an-algorithm",
	})
	assert.ErrorIs(t, err, pkcs11svc.ErrGetImportParamsFailed)
}

func TestPKCS11IPCRoundTrip_ImportKey_CorruptMaterial(t *testing.T) {
	rt := newIPCRoundTrip(t)
	params, err := rt.client.GetImportParameters(context.Background(), &transport.GetImportParametersRequest{
		Backend: roundTripBackend, KeyID: "rt-import", Algorithm: "RSA_AES_KEY_WRAP_SHA_256", KeyType: "ECDSA",
	})
	require.NoError(t, err)

	_, err = rt.client.ImportKey(context.Background(), &transport.ImportKeyRequest{
		Backend: roundTripBackend, KeyID: "rt-import", KeyType: "ECDSA",
		Algorithm: params.Algorithm, ImportToken: params.ImportToken, WrappedKeyMaterial: []byte("not wrapped key material"),
	})
	assert.ErrorIs(t, err, pkcs11svc.ErrImportFailed)
}

// clientOp calls one IPCTransport operation and returns only the error.
type clientOp func(ctx context.Context, tr *pkcs11svc.IPCTransport) error

func clientOpOf[Req, Resp any](call func(*pkcs11svc.IPCTransport, context.Context, *Req) (*Resp, error), req *Req) clientOp {
	return func(ctx context.Context, tr *pkcs11svc.IPCTransport) error {
		_, err := call(tr, ctx, req)
		return err
	}
}

func clientNoResultOpOf[Req any](call func(*pkcs11svc.IPCTransport, context.Context, *Req) error, req *Req) clientOp {
	return func(ctx context.Context, tr *pkcs11svc.IPCTransport) error {
		return call(tr, ctx, req)
	}
}

// clientOps holds every IPCTransport operation with a request that passes
// the protocol's validation.
func clientOps() map[string]clientOp {
	type T = pkcs11svc.IPCTransport
	return map[string]clientOp{
		ipc.ActionGenerateKey: clientOpOf((*T).GenerateKey,
			&transport.GenerateKeyRequest{Backend: roundTripBackend, KeyID: "k", Algorithm: "ECDSA"}),
		ipc.ActionSign: clientOpOf((*T).Sign,
			&transport.SignRequest{Backend: roundTripBackend, KeyID: "k", Data: []byte("d")}),
		ipc.ActionVerify: clientOpOf((*T).Verify,
			&transport.VerifyRequest{Backend: roundTripBackend, KeyID: "k"}),
		ipc.ActionEncrypt: clientOpOf((*T).Encrypt,
			&transport.EncryptRequest{Backend: roundTripBackend, KeyID: "k"}),
		ipc.ActionEncryptAsym: clientOpOf((*T).EncryptAsym,
			&transport.EncryptAsymRequest{Backend: roundTripBackend, KeyID: "k"}),
		ipc.ActionDecrypt: clientOpOf((*T).Decrypt,
			&transport.DecryptRequest{Backend: roundTripBackend, KeyID: "k"}),
		ipc.ActionDeriveKey: clientOpOf((*T).DeriveKey,
			&transport.DeriveKeyRequest{Backend: roundTripBackend, Algorithm: "HKDF", KeyLength: 32}),
		ipc.ActionDeriveKeyECDH: clientOpOf((*T).DeriveKeyECDH,
			&transport.DeriveKeyECDHRequest{Backend: roundTripBackend, KeyID: "k"}),
		ipc.ActionWrapKeyByID: clientOpOf((*T).WrapKeyByID,
			&transport.WrapKeyByIDRequest{WrappingKeyBackend: roundTripBackend, WrappingKeyID: "w"}),
		ipc.ActionUnwrapKeyByID: clientOpOf((*T).UnwrapKeyByID,
			&transport.UnwrapKeyByIDRequest{UnwrappingKeyBackend: roundTripBackend, UnwrappingKeyID: "w"}),
		ipc.ActionExportKeyMaterial: clientOpOf((*T).ExportKeyMaterial,
			&transport.ExportKeyMaterialRequest{Backend: roundTripBackend, KeyID: "k"}),
		ipc.ActionGetImportParameters: clientOpOf((*T).GetImportParameters,
			&transport.GetImportParametersRequest{Backend: roundTripBackend, KeyID: "k"}),
		ipc.ActionImportKey: clientOpOf((*T).ImportKey,
			&transport.ImportKeyRequest{Backend: roundTripBackend, KeyID: "k"}),
		ipc.ActionListPIVSlots: clientOpOf((*T).ListPIVSlots,
			&transport.ListPIVSlotsRequest{Backend: roundTripBackend}),
		ipc.ActionGetPIVCertificate: clientOpOf((*T).GetPIVCertificate,
			&transport.GetPIVCertificateRequest{Backend: roundTripBackend, Slot: "9a"}),
		ipc.ActionGeneratePIVKey: clientOpOf((*T).GeneratePIVKey,
			&transport.GeneratePIVKeyRequest{Backend: roundTripBackend, Slot: "9a"}),
		ipc.ActionStorePIVCertificate: clientNoResultOpOf((*T).StorePIVCertificate,
			&transport.StorePIVCertificateRequest{Backend: roundTripBackend, Slot: "9a", Certificate: []byte("c")}),
		ipc.ActionDeletePIVCertificate: clientNoResultOpOf((*T).DeletePIVCertificate,
			&transport.DeletePIVCertificateRequest{Backend: roundTripBackend, Slot: "9a"}),
		ipc.ActionImportPIVCertificate: clientNoResultOpOf((*T).ImportPIVCertificate,
			&transport.StorePIVCertificateRequest{Backend: roundTripBackend, Slot: "9a", Certificate: []byte("c")}),
		ipc.ActionExportPIVCertificate: clientOpOf((*T).ExportPIVCertificate,
			&transport.GetPIVCertificateRequest{Backend: roundTripBackend, Slot: "9a"}),
		ipc.ActionGeneratePIVCSR: clientOpOf((*T).GeneratePIVCSR,
			&transport.GeneratePIVCSRRequest{Backend: roundTripBackend, Slot: "9a"}),
	}
}

func TestPKCS11IPCRoundTrip_ClientOpsCoverEveryOperation(t *testing.T) {
	assert.Len(t, clientOps(), len(handlerOps()))
}

func TestPKCS11IPCRoundTrip_PIVOperations_ReachTheHandler(t *testing.T) {
	// The software backend has no PIV card behind it, so every PIV operation
	// fails inside the embedded transport. That failure must come back over
	// the socket as the operation error, with the embedded detail withheld.
	rt := newIPCRoundTrip(t)
	ops := clientOps()
	for _, action := range []string{
		ipc.ActionListPIVSlots, ipc.ActionGetPIVCertificate, ipc.ActionGeneratePIVKey,
		ipc.ActionStorePIVCertificate, ipc.ActionDeletePIVCertificate, ipc.ActionImportPIVCertificate,
		ipc.ActionExportPIVCertificate, ipc.ActionGeneratePIVCSR,
	} {
		err := ops[action](context.Background(), rt.client)
		require.ErrorIs(t, err, ipc.ErrPKCS11Operation, action)
		assert.Contains(t, err.Error(), ipc.ErrHandlerFailed.Error(), action)
		assert.NotContains(t, err.Error(), "piv manager", action)
	}
}

func TestPKCS11IPCRoundTrip_EveryOperation_BarrierSealed(t *testing.T) {
	rt := newIPCRoundTrip(t)
	rt.sealed.Store(true)

	for action, op := range clientOps() {
		err := op(context.Background(), rt.client)
		require.ErrorIs(t, err, ipc.ErrPKCS11Operation, action)
		assert.Contains(t, err.Error(), ipc.ErrBarrierSealed.Error(), action)
	}
}

func TestPKCS11IPCRoundTrip_EveryOperation_NoGUIAnswering(t *testing.T) {
	client := pkcs11svc.NewIPCTransport(filepath.Join(t.TempDir(), "absent.sock"))

	for action, op := range clientOps() {
		assert.ErrorIs(t, op(context.Background(), client), pkcs11svc.ErrIPCConnectionFailed, action)
	}
}

func TestPKCS11IPCRoundTrip_InvalidRequest_RejectedByServer(t *testing.T) {
	rt := newIPCRoundTrip(t)

	_, err := rt.client.Sign(context.Background(), &transport.SignRequest{Backend: roundTripBackend, KeyID: "k"})
	require.ErrorIs(t, err, pkcs11svc.ErrSigningFailed)
	assert.Contains(t, err.Error(), ipc.ErrInvalidMessage.Error())

	err = rt.client.DeletePIVCertificate(context.Background(), &transport.DeletePIVCertificateRequest{Backend: roundTripBackend})
	require.ErrorIs(t, err, ipc.ErrPKCS11Operation)
	assert.Contains(t, err.Error(), ipc.ErrInvalidMessage.Error())
}
