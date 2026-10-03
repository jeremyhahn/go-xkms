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

//go:build pkcs11

package pkcs11

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/miekg/pkcs11"
	"github.com/stretchr/testify/require"
)

var pkcs11SealAuthAAD = []byte("tenant=acme,purpose=barrier")

// cloneSealedData deep-copies sealed so a case can mutate it freely.
func cloneSealedData(sealed *types.SealedData) *types.SealedData {
	c := *sealed
	c.Ciphertext = bytes.Clone(sealed.Ciphertext)
	c.Nonce = bytes.Clone(sealed.Nonce)
	c.Tag = bytes.Clone(sealed.Tag)
	return &c
}

// secondSealingKey generates another AES-256-GCM key on b's token.
func secondSealingKey(t *testing.T, b *Backend, cn string) *types.KeyAttributes {
	t.Helper()
	attrs := &types.KeyAttributes{
		CN:                 cn,
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_PKCS11,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}
	require.NoError(t, attrs.Validate())
	_, err := b.GenerateSymmetricKey(context.Background(), attrs)
	require.NoError(t, err)
	return attrs
}

// TestUnseal_SealedDataAuthentication proves, on a real token (SoftHSM),
// that sealed data the backend can judge without the token -- another
// backend's, another key's by its KeyID, a nonce or tag of the wrong length
// -- is reported as types.ErrSealedDataAuthentication. A ciphertext the token
// itself refuses is a rejection only when the token says so unambiguously;
// see TestDecryptGCM_Classification and
// TestUnseal_TokenRefusalClassifiedByItsOwnCode.
func TestUnseal_SealedDataAuthentication(t *testing.T) {
	b, keyA := newSealingBackend(t, "seal-auth", "seal-auth-a")
	keyB := secondSealingKey(t, b, "seal-auth-b")
	ctx := context.Background()

	sealed, err := b.Seal(ctx, []byte("hsm sealed root key"), &types.SealOptions{KeyAttributes: keyA, AAD: pkcs11SealAuthAAD})
	require.NoError(t, err)

	cases := []struct {
		name   string
		mutate func(s *types.SealedData) *types.UnsealOptions
		reason error
	}{
		{"foreign key named by sealed KeyID", func(s *types.SealedData) *types.UnsealOptions {
			return &types.UnsealOptions{KeyAttributes: keyB, AAD: pkcs11SealAuthAAD}
		}, nil},
		{"wrong backend", func(s *types.SealedData) *types.UnsealOptions {
			s.Backend = types.BackendTypeTPM2
			return &types.UnsealOptions{KeyAttributes: keyA, AAD: pkcs11SealAuthAAD}
		}, nil},
		{"malformed: nonce missing", func(s *types.SealedData) *types.UnsealOptions {
			s.Nonce = nil
			return &types.UnsealOptions{KeyAttributes: keyA, AAD: pkcs11SealAuthAAD}
		}, ErrInvalidNonceLength},
		{"malformed: nonce short", func(s *types.SealedData) *types.UnsealOptions {
			s.Nonce = s.Nonce[:8]
			return &types.UnsealOptions{KeyAttributes: keyA, AAD: pkcs11SealAuthAAD}
		}, ErrInvalidNonceLength},
		{"malformed: tag missing", func(s *types.SealedData) *types.UnsealOptions {
			s.Tag = nil
			return &types.UnsealOptions{KeyAttributes: keyA, AAD: pkcs11SealAuthAAD}
		}, ErrInvalidTagLength},
		{"malformed: tag short", func(s *types.SealedData) *types.UnsealOptions {
			s.Tag = s.Tag[:12]
			return &types.UnsealOptions{KeyAttributes: keyA, AAD: pkcs11SealAuthAAD}
		}, ErrInvalidTagLength},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mutated := cloneSealedData(sealed)
			opts := tc.mutate(mutated)

			out, err := b.Unseal(ctx, mutated, opts)
			require.Nil(t, out, "bad sealed data must not produce plaintext")
			require.ErrorIs(t, err, types.ErrSealedDataAuthentication)
			if tc.reason != nil {
				require.ErrorIs(t, err, tc.reason)
			}
		})
	}

	got, err := b.Unseal(ctx, sealed, &types.UnsealOptions{KeyAttributes: keyA, AAD: pkcs11SealAuthAAD})
	require.NoError(t, err, "the untouched envelope must still unseal")
	require.Equal(t, []byte("hsm sealed root key"), got)
}

// TestUnseal_EnvironmentFailuresAreNotAuthentication proves a cancelled
// context, a closed backend and a key missing from the token are never
// reported as sealed-data authentication failures, even when the sealed data
// handed in would itself fail authentication.
func TestUnseal_EnvironmentFailuresAreNotAuthentication(t *testing.T) {
	t.Run("cancelled context with tampered data", func(t *testing.T) {
		b, attrs := newSealingBackend(t, "seal-env-ctx", "seal-env-ctx-key")
		sealed, err := b.Seal(context.Background(), []byte("payload"), &types.SealOptions{KeyAttributes: attrs})
		require.NoError(t, err)
		sealed.Ciphertext[0] ^= 0x01
		sealed.Backend = types.BackendTypeAWSKMS

		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err = b.Unseal(ctx, sealed, &types.UnsealOptions{KeyAttributes: attrs})
		require.ErrorIs(t, err, context.Canceled)
		require.NotErrorIs(t, err, types.ErrSealedDataAuthentication)
	})

	t.Run("uninitialized backend with tampered data", func(t *testing.T) {
		tempLib := filepath.Join(t.TempDir(), "libtest.so")
		require.NoError(t, os.WriteFile(tempLib, []byte("test"), 0o600))
		b, err := NewBackend(&Config{Library: tempLib, TokenLabel: "test", KeyStorage: storage.New(), CertStorage: storage.New()})
		require.NoError(t, err)

		attrs := &types.KeyAttributes{
			CN: "seal-env-uninit", KeyType: backend.KEY_TYPE_SECRET, StoreType: backend.STORE_PKCS11, SymmetricAlgorithm: types.SymmetricAES256GCM,
		}
		sealed := &types.SealedData{Backend: types.BackendTypePKCS11, Ciphertext: []byte("x"), Nonce: []byte{1}, Tag: []byte{2}}
		_, err = b.Unseal(context.Background(), sealed, &types.UnsealOptions{KeyAttributes: attrs})
		require.ErrorIs(t, err, ErrNotInitialized)
		require.NotErrorIs(t, err, types.ErrSealedDataAuthentication)
	})

	t.Run("sealing key missing from the token", func(t *testing.T) {
		b, attrs := newSealingBackend(t, "seal-env-missing", "seal-env-missing-key")
		sealed, err := b.Seal(context.Background(), []byte("payload"), &types.SealOptions{KeyAttributes: attrs})
		require.NoError(t, err)
		sealed.KeyID = ""

		never := &types.KeyAttributes{
			CN:                 "seal-env-never-generated",
			KeyType:            backend.KEY_TYPE_SECRET,
			StoreType:          backend.STORE_PKCS11,
			SymmetricAlgorithm: types.SymmetricAES256GCM,
		}
		_, err = b.Unseal(context.Background(), sealed, &types.UnsealOptions{KeyAttributes: never})
		require.Error(t, err)
		require.NotErrorIs(t, err, types.ErrSealedDataAuthentication)
	})
}

// TestRejectsCiphertext pins the C_Decrypt classification: only the return
// values that name the ciphertext are rejections. CKR_GENERAL_ERROR -- the
// specification's unrecoverable token error, which SoftHSM also uses for a
// GCM tag mismatch -- never is.
func TestRejectsCiphertext(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"encrypted data invalid", pkcs11.Error(pkcs11.CKR_ENCRYPTED_DATA_INVALID), true},
		{"encrypted data length range", pkcs11.Error(pkcs11.CKR_ENCRYPTED_DATA_LEN_RANGE), true},
		{"AEAD decrypt failed", pkcs11.Error(ckrAEADDecryptFailed), true},
		{"wrapped encrypted data invalid", &errs.Wrapped{Msg: "decrypt", Err: pkcs11.Error(pkcs11.CKR_ENCRYPTED_DATA_INVALID)}, true},
		{"general error", pkcs11.Error(pkcs11.CKR_GENERAL_ERROR), false},
		{"function failed", pkcs11.Error(pkcs11.CKR_FUNCTION_FAILED), false},
		{"device error", pkcs11.Error(pkcs11.CKR_DEVICE_ERROR), false},
		{"device removed", pkcs11.Error(pkcs11.CKR_DEVICE_REMOVED), false},
		{"device memory", pkcs11.Error(pkcs11.CKR_DEVICE_MEMORY), false},
		{"session closed", pkcs11.Error(pkcs11.CKR_SESSION_CLOSED), false},
		{"not logged in", pkcs11.Error(pkcs11.CKR_USER_NOT_LOGGED_IN), false},
		{"key handle invalid", pkcs11.Error(pkcs11.CKR_KEY_HANDLE_INVALID), false},
		{"not a PKCS#11 error", errors.New("transport"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, rejectsCiphertext(tc.err))
		})
	}
}

// TestRejectsSealedData pins which Decrypt errors Unseal reports as
// sealed-data authentication.
func TestRejectsSealedData(t *testing.T) {
	general := &errs.Wrapped{Msg: "decryption failed (authentication error)", Err: pkcs11.Error(pkcs11.CKR_GENERAL_ERROR)}
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"token rejected the ciphertext", &errs.Joined{Lead: ErrCiphertextRejected, Cause: general}, true},
		{"nonce length", &errs.Detail{Err: ErrInvalidNonceLength, Detail: "nonce is 0 bytes, want 12"}, true},
		{"tag length", &errs.Detail{Err: ErrInvalidTagLength, Detail: "tag is 0 bytes, want 16"}, true},
		{"decrypt init failed", &errs.Joined{Lead: ErrDecryptInit, Cause: pkcs11.Error(pkcs11.CKR_KEY_HANDLE_INVALID)}, false},
		{"general error", general, false},
		{"not initialized", ErrNotInitialized, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, rejectsSealedData(tc.err))
		})
	}
}

// TestUnseal_TokenRefusalClassifiedByItsOwnCode proves, end to end on the
// real token, that a ciphertext the token refuses is reported by the token's
// own return value: it matches types.ErrSealedDataAuthentication exactly
// when that value is one that names the ciphertext (ciphertextRejections),
// and never when it is the ambiguous CKR_GENERAL_ERROR. SoftHSM before 2.7.0
// answers every case below with CKR_GENERAL_ERROR, so there the failures are
// pinned as not promoted; SoftHSM 2.7.0 answers CKR_ENCRYPTED_DATA_INVALID,
// and the same assertions then require the sentinel. Either way no refused
// ciphertext yields plaintext and the native code stays reachable.
func TestUnseal_TokenRefusalClassifiedByItsOwnCode(t *testing.T) {
	b, keyA := newSealingBackend(t, "seal-token-refusal", "seal-token-refusal-a")
	keyB := secondSealingKey(t, b, "seal-token-refusal-b")
	ctx := context.Background()

	sealed, err := b.Seal(ctx, []byte("hsm sealed root key"), &types.SealOptions{KeyAttributes: keyA, AAD: pkcs11SealAuthAAD})
	require.NoError(t, err)

	for name, mutate := range map[string]func(s *types.SealedData) *types.UnsealOptions{
		"ciphertext bit flipped": func(s *types.SealedData) *types.UnsealOptions {
			s.Ciphertext[0] ^= 0x01
			return &types.UnsealOptions{KeyAttributes: keyA, AAD: pkcs11SealAuthAAD}
		},
		"tag bit flipped": func(s *types.SealedData) *types.UnsealOptions {
			s.Tag[len(s.Tag)-1] ^= 0x80
			return &types.UnsealOptions{KeyAttributes: keyA, AAD: pkcs11SealAuthAAD}
		},
		"nonce bit flipped": func(s *types.SealedData) *types.UnsealOptions {
			s.Nonce[0] ^= 0x01
			return &types.UnsealOptions{KeyAttributes: keyA, AAD: pkcs11SealAuthAAD}
		},
		"truncated": func(s *types.SealedData) *types.UnsealOptions {
			s.Ciphertext = s.Ciphertext[:len(s.Ciphertext)-1]
			return &types.UnsealOptions{KeyAttributes: keyA, AAD: pkcs11SealAuthAAD}
		},
		"extended": func(s *types.SealedData) *types.UnsealOptions {
			s.Ciphertext = append(s.Ciphertext, 0x00)
			return &types.UnsealOptions{KeyAttributes: keyA, AAD: pkcs11SealAuthAAD}
		},
		"AAD omitted": func(s *types.SealedData) *types.UnsealOptions {
			return &types.UnsealOptions{KeyAttributes: keyA}
		},
		"AAD mismatch": func(s *types.SealedData) *types.UnsealOptions {
			return &types.UnsealOptions{KeyAttributes: keyA, AAD: []byte("tenant=evil")}
		},
		"foreign key reaching the token": func(s *types.SealedData) *types.UnsealOptions {
			s.KeyID = ""
			return &types.UnsealOptions{KeyAttributes: keyB, AAD: pkcs11SealAuthAAD}
		},
	} {
		t.Run(name, func(t *testing.T) {
			mutated := cloneSealedData(sealed)
			opts := mutate(mutated)

			out, err := b.Unseal(ctx, mutated, opts)
			require.Nil(t, out, "a refused ciphertext must not produce plaintext")
			require.Error(t, err)

			var native pkcs11.Error
			require.True(t, errors.As(err, &native), "the token's own answer must stay reachable: %v", err)
			_, namesCiphertext := ciphertextRejections[native]
			require.Equal(t, namesCiphertext, errors.Is(err, types.ErrSealedDataAuthentication),
				"the sentinel must follow the token's own code (%v)", native)
			if native == pkcs11.Error(pkcs11.CKR_GENERAL_ERROR) {
				require.NotErrorIs(t, err, types.ErrSealedDataAuthentication,
					"an ambiguous token error is never promoted to sealed-data authentication")
			}
		})
	}
}

// conformantToken drives SoftHSM but answers a C_Decrypt that SoftHSM
// refuses with the return value a specification-conformant module uses
// (rejectAs), so the classification of those codes is exercised against a
// real token and a real tampered ciphertext. failInit fails C_DecryptInit.
type conformantToken struct {
	*pkcs11.Ctx
	rejectAs pkcs11.Error
	failInit bool
}

func (c *conformantToken) DecryptInit(s pkcs11.SessionHandle, m []*pkcs11.Mechanism, o pkcs11.ObjectHandle) error {
	if c.failInit {
		return pkcs11.Error(pkcs11.CKR_KEY_HANDLE_INVALID)
	}
	return c.Ctx.DecryptInit(s, m, o)
}

func (c *conformantToken) Decrypt(s pkcs11.SessionHandle, data []byte) ([]byte, error) {
	out, err := c.Ctx.Decrypt(s, data)
	if err != nil && c.rejectAs != 0 {
		return nil, c.rejectAs
	}
	return out, err
}

// gcmDecryptFixture is a SoftHSM token with a sealing key, the key's handle
// in an open session, and one genuine AES-GCM ciphertext under it.
type gcmDecryptFixture struct {
	backend    *Backend
	session    pkcs11.SessionHandle
	key        pkcs11.ObjectHandle
	mechanism  []*pkcs11.Mechanism
	ciphertext []byte
	plaintext  []byte
}

func newGCMDecryptFixture(t *testing.T, label string) *gcmDecryptFixture {
	t.Helper()
	b, attrs := newSealingBackend(t, label, label+"-key")
	encrypter, err := b.SymmetricEncrypter(context.Background(), attrs)
	require.NoError(t, err)
	plaintext := []byte("gcm decrypt fixture payload")
	encrypted, err := encrypter.Encrypt(plaintext, &types.EncryptOptions{})
	require.NoError(t, err)

	session := openIntrospectionSession(t, b)
	key := findSingleObject(t, b, session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, createKeyID(attrs)),
	})
	params := pkcs11.NewGCMParams(encrypted.Nonce, nil, gcmTagSize*8)
	t.Cleanup(params.Free)
	return &gcmDecryptFixture{
		backend:    b,
		session:    session,
		key:        key,
		mechanism:  []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, params)},
		ciphertext: concatCiphertextAndTag(encrypted.Ciphertext, encrypted.Tag),
		plaintext:  plaintext,
	}
}

// TestDecryptGCM_Classification proves, on SoftHSM with a real tampered
// ciphertext, that decryptGCM reports ErrCiphertextRejected exactly when the
// module answers with a code that names the ciphertext, never for
// CKR_GENERAL_ERROR or a device error, and never for a C_DecryptInit
// failure; an untouched ciphertext decrypts.
func TestDecryptGCM_Classification(t *testing.T) {
	f := newGCMDecryptFixture(t, "gcm-classify")
	tampered := bytes.Clone(f.ciphertext)
	tampered[len(tampered)-1] ^= 0x01

	for _, code := range []pkcs11.Error{pkcs11.CKR_ENCRYPTED_DATA_INVALID, pkcs11.CKR_ENCRYPTED_DATA_LEN_RANGE, ckrAEADDecryptFailed} {
		t.Run(code.Error(), func(t *testing.T) {
			_, err := decryptGCM(&conformantToken{Ctx: f.backend.p11ctx, rejectAs: code}, f.session, f.mechanism, f.key, tampered)
			require.ErrorIs(t, err, ErrCiphertextRejected)
			require.ErrorIs(t, err, code)
		})
	}

	for _, code := range []pkcs11.Error{pkcs11.CKR_GENERAL_ERROR, pkcs11.CKR_DEVICE_ERROR} {
		t.Run(code.Error()+" is not a rejection", func(t *testing.T) {
			_, err := decryptGCM(&conformantToken{Ctx: f.backend.p11ctx, rejectAs: code}, f.session, f.mechanism, f.key, tampered)
			require.ErrorIs(t, err, code)
			require.NotErrorIs(t, err, ErrCiphertextRejected)
		})
	}

	t.Run("decrypt init failure", func(t *testing.T) {
		_, err := decryptGCM(&conformantToken{Ctx: f.backend.p11ctx, failInit: true}, f.session, f.mechanism, f.key, tampered)
		require.ErrorIs(t, err, ErrDecryptInit)
		require.NotErrorIs(t, err, ErrCiphertextRejected)
	})

	t.Run("untouched ciphertext decrypts", func(t *testing.T) {
		got, err := decryptGCM(&conformantToken{Ctx: f.backend.p11ctx, rejectAs: ckrAEADDecryptFailed}, f.session, f.mechanism, f.key, f.ciphertext)
		require.NoError(t, err)
		require.Equal(t, f.plaintext, got)
	})
}
