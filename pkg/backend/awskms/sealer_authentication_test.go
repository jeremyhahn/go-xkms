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

//go:build awskms

package awskms

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// kmsDouble is an in-process stand-in for AWS KMS Encrypt/Decrypt over
// symmetric keys. It performs real AES-256-GCM, binds the encryption context
// as additional authenticated data, and embeds the key ID in the blob the way
// KMS's opaque ciphertext does, so it answers a tampered blob with
// InvalidCiphertextException and a blob under another key with
// IncorrectKeyException exactly as the service does. decryptFault, when set,
// replaces every Decrypt answer, standing in for an outage.
type kmsDouble struct {
	mu           sync.Mutex
	keys         map[string][]byte
	decryptFault error
}

func newKMSDouble(keyIDs ...string) *kmsDouble {
	d := &kmsDouble{keys: make(map[string][]byte)}
	for _, id := range keyIDs {
		material := make([]byte, 32)
		if _, err := rand.Read(material); err != nil {
			panic(err)
		}
		d.keys[id] = material
	}
	return d
}

// aead returns an AES-GCM AEAD that generates its own nonce and carries it
// in the ciphertext (NewGCMWithRandomNonce), the only GCM construction a
// fips140=only process may build.
func (d *kmsDouble) aead(keyID string) (cipher.AEAD, error) {
	d.mu.Lock()
	material, ok := d.keys[keyID]
	d.mu.Unlock()
	if !ok {
		return nil, &kmstypes.NotFoundException{Message: aws.String("key not found")}
	}
	block, err := aes.NewCipher(material)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(block)
}

// contextAAD canonicalizes an encryption context into AEAD associated data.
func contextAAD(ec map[string]string) []byte {
	if len(ec) == 0 {
		return nil
	}
	encoded, err := json.Marshal(ec)
	if err != nil {
		panic(err)
	}
	return encoded
}

// blob layout: len(keyID) || keyID || nonce || sealed.
func (d *kmsDouble) encrypt(_ context.Context, in *kms.EncryptInput, _ ...func(*kms.Options)) (*kms.EncryptOutput, error) {
	keyID := aws.ToString(in.KeyId)
	gcm, err := d.aead(keyID)
	if err != nil {
		return nil, err
	}
	blob := append([]byte{byte(len(keyID))}, keyID...)
	blob = gcm.Seal(blob, nil, in.Plaintext, contextAAD(in.EncryptionContext))
	return &kms.EncryptOutput{CiphertextBlob: blob, KeyId: aws.String(keyID)}, nil
}

func (d *kmsDouble) decrypt(_ context.Context, in *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	if d.decryptFault != nil {
		return nil, d.decryptFault
	}
	invalid := &kmstypes.InvalidCiphertextException{Message: aws.String("invalid ciphertext")}
	blob := in.CiphertextBlob
	if len(blob) < 1 || len(blob) < 1+int(blob[0]) {
		return nil, invalid
	}
	blobKeyID := string(blob[1 : 1+int(blob[0])])
	if requested := aws.ToString(in.KeyId); requested != "" && requested != blobKeyID {
		return nil, &kmstypes.IncorrectKeyException{Message: aws.String("incorrect key")}
	}
	gcm, err := d.aead(blobKeyID)
	if err != nil {
		return nil, invalid
	}
	plaintext, err := gcm.Open(nil, nil, blob[1+int(blob[0]):], contextAAD(in.EncryptionContext))
	if err != nil {
		return nil, invalid
	}
	return &kms.DecryptOutput{Plaintext: plaintext, KeyId: aws.String(blobKeyID)}, nil
}

// sealAuthFixture is a backend over a kmsDouble with two sealing keys.
type sealAuthFixture struct {
	backend *Backend
	double  *kmsDouble
	keyA    *types.KeyAttributes
	keyB    *types.KeyAttributes
}

func newSealAuthFixture(t *testing.T) *sealAuthFixture {
	t.Helper()
	double := newKMSDouble("kms-key-a", "kms-key-b")
	client := &MockKMSClient{EncryptFunc: double.encrypt, DecryptFunc: double.decrypt}
	config := &Config{Region: "us-east-1", KeyStorage: storage.New(), CertStorage: storage.New()}
	b, err := NewBackendWithClient(config, client)
	if err != nil {
		t.Fatalf("NewBackendWithClient: %v", err)
	}
	attrs := func(cn, kmsID string) *types.KeyAttributes {
		a := &types.KeyAttributes{
			CN:                 cn,
			KeyType:            backend.KEY_TYPE_SECRET,
			StoreType:          backend.STORE_AWSKMS,
			SymmetricAlgorithm: types.SymmetricAES256GCM,
		}
		metadata, err := json.Marshal(map[string]interface{}{
			"key_id":    kmsID,
			"alias":     "alias/" + cn,
			"algorithm": string(types.SymmetricAES256GCM),
		})
		if err != nil {
			t.Fatalf("marshal metadata: %v", err)
		}
		if err := storage.SaveKey(context.Background(), config.KeyStorage, cn, metadata); err != nil {
			t.Fatalf("seed metadata: %v", err)
		}
		return a
	}
	return &sealAuthFixture{
		backend: b,
		double:  double,
		keyA:    attrs("seal-auth-a", "kms-key-a"),
		keyB:    attrs("seal-auth-b", "kms-key-b"),
	}
}

// cloneSealed deep-copies sealed so a case can mutate it freely.
func cloneSealed(sealed *types.SealedData) *types.SealedData {
	c := *sealed
	c.Ciphertext = bytes.Clone(sealed.Ciphertext)
	c.Metadata = make(map[string][]byte, len(sealed.Metadata))
	for k, v := range sealed.Metadata {
		c.Metadata[k] = bytes.Clone(v)
	}
	return &c
}

var sealAuthAAD = []byte("tenant=acme,purpose=barrier")

// TestUnseal_SealedDataAuthentication proves every way the sealed data itself
// can be wrong is reported as types.ErrSealedDataAuthentication, with the KMS
// cause still reachable where KMS produced one.
func TestUnseal_SealedDataAuthentication(t *testing.T) {
	cases := []struct {
		name      string
		mutate    func(f *sealAuthFixture, s *types.SealedData) (*types.SealedData, *types.UnsealOptions)
		kmsReason any
	}{
		{
			name: "bit flipped",
			mutate: func(f *sealAuthFixture, s *types.SealedData) (*types.SealedData, *types.UnsealOptions) {
				s.Ciphertext[len(s.Ciphertext)-1] ^= 0x01
				return s, &types.UnsealOptions{KeyAttributes: f.keyA, AAD: sealAuthAAD}
			},
			kmsReason: new(*kmstypes.InvalidCiphertextException),
		},
		{
			name: "truncated",
			mutate: func(f *sealAuthFixture, s *types.SealedData) (*types.SealedData, *types.UnsealOptions) {
				s.Ciphertext = s.Ciphertext[:len(s.Ciphertext)-1]
				return s, &types.UnsealOptions{KeyAttributes: f.keyA, AAD: sealAuthAAD}
			},
			kmsReason: new(*kmstypes.InvalidCiphertextException),
		},
		{
			name: "extended",
			mutate: func(f *sealAuthFixture, s *types.SealedData) (*types.SealedData, *types.UnsealOptions) {
				s.Ciphertext = append(s.Ciphertext, 0x00)
				return s, &types.UnsealOptions{KeyAttributes: f.keyA, AAD: sealAuthAAD}
			},
			kmsReason: new(*kmstypes.InvalidCiphertextException),
		},
		{
			name: "extended beyond the largest blob KMS accepts",
			mutate: func(f *sealAuthFixture, s *types.SealedData) (*types.SealedData, *types.UnsealOptions) {
				s.Ciphertext = append(s.Ciphertext, make([]byte, maxCiphertextBlobSize)...)
				return s, &types.UnsealOptions{KeyAttributes: f.keyA, AAD: sealAuthAAD}
			},
		},
		{
			name: "AAD mismatch",
			mutate: func(f *sealAuthFixture, s *types.SealedData) (*types.SealedData, *types.UnsealOptions) {
				return s, &types.UnsealOptions{KeyAttributes: f.keyA, AAD: []byte("tenant=evil")}
			},
			kmsReason: new(*kmstypes.InvalidCiphertextException),
		},
		{
			name: "AAD omitted",
			mutate: func(f *sealAuthFixture, s *types.SealedData) (*types.SealedData, *types.UnsealOptions) {
				return s, &types.UnsealOptions{KeyAttributes: f.keyA}
			},
			kmsReason: new(*kmstypes.InvalidCiphertextException),
		},
		{
			name: "foreign key named by sealed KeyID",
			mutate: func(f *sealAuthFixture, s *types.SealedData) (*types.SealedData, *types.UnsealOptions) {
				return s, &types.UnsealOptions{KeyAttributes: f.keyB, AAD: sealAuthAAD}
			},
		},
		{
			name: "foreign key detected by KMS",
			mutate: func(f *sealAuthFixture, s *types.SealedData) (*types.SealedData, *types.UnsealOptions) {
				s.KeyID = ""
				return s, &types.UnsealOptions{KeyAttributes: f.keyB, AAD: sealAuthAAD}
			},
			kmsReason: new(*kmstypes.IncorrectKeyException),
		},
		{
			name: "wrong backend",
			mutate: func(f *sealAuthFixture, s *types.SealedData) (*types.SealedData, *types.UnsealOptions) {
				s.Backend = types.BackendTypeGCPKMS
				return s, &types.UnsealOptions{KeyAttributes: f.keyA, AAD: sealAuthAAD}
			},
		},
		{
			name: "malformed: ciphertext missing",
			mutate: func(f *sealAuthFixture, s *types.SealedData) (*types.SealedData, *types.UnsealOptions) {
				s.Ciphertext = nil
				return s, &types.UnsealOptions{KeyAttributes: f.keyA, AAD: sealAuthAAD}
			},
		},
		{
			name: "malformed: garbage blob",
			mutate: func(f *sealAuthFixture, s *types.SealedData) (*types.SealedData, *types.UnsealOptions) {
				s.Ciphertext = []byte{0xff}
				return s, &types.UnsealOptions{KeyAttributes: f.keyA, AAD: sealAuthAAD}
			},
			kmsReason: new(*kmstypes.InvalidCiphertextException),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newSealAuthFixture(t)
			ctx := context.Background()
			sealed, err := f.backend.Seal(ctx, []byte("root key"), &types.SealOptions{KeyAttributes: f.keyA, AAD: sealAuthAAD})
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}
			mutated, opts := tc.mutate(f, cloneSealed(sealed))

			out, err := f.backend.Unseal(ctx, mutated, opts)
			if out != nil {
				t.Fatalf("Unseal returned plaintext %q for bad sealed data", out)
			}
			if !errors.Is(err, types.ErrSealedDataAuthentication) {
				t.Fatalf("Unseal error %v does not match ErrSealedDataAuthentication", err)
			}
			if tc.kmsReason != nil && !errors.As(err, tc.kmsReason) {
				t.Fatalf("Unseal error %v lost the KMS cause %T", err, tc.kmsReason)
			}
		})
	}
}

// TestUnseal_EnvironmentFailuresAreNotAuthentication proves an outage, a
// permission or key-state failure, and a cancelled context are never
// reported as sealed-data authentication failures, even when the sealed data
// handed in would itself fail authentication.
func TestUnseal_EnvironmentFailuresAreNotAuthentication(t *testing.T) {
	faults := []struct {
		name  string
		fault error
	}{
		{"KMS internal error", &kmstypes.KMSInternalException{Message: aws.String("internal")}},
		{"dependency timeout", &kmstypes.DependencyTimeoutException{Message: aws.String("timeout")}},
		{"throttled", &kmstypes.LimitExceededException{Message: aws.String("rate exceeded")}},
		{"key disabled", &kmstypes.DisabledException{Message: aws.String("disabled")}},
		{"key pending deletion", &kmstypes.KMSInvalidStateException{Message: aws.String("pending deletion")}},
		{"key not found", &kmstypes.NotFoundException{Message: aws.String("not found")}},
		{"access denied", errors.New("AccessDeniedException: not authorized to perform kms:Decrypt")},
		{"deadline exceeded in transport", context.DeadlineExceeded},
	}
	for _, tc := range faults {
		t.Run(tc.name, func(t *testing.T) {
			f := newSealAuthFixture(t)
			ctx := context.Background()
			sealed, err := f.backend.Seal(ctx, []byte("root key"), &types.SealOptions{KeyAttributes: f.keyA})
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}
			f.double.decryptFault = tc.fault

			_, err = f.backend.Unseal(ctx, sealed, &types.UnsealOptions{KeyAttributes: f.keyA})
			if err == nil {
				t.Fatal("Unseal must fail when KMS fails")
			}
			if errors.Is(err, types.ErrSealedDataAuthentication) {
				t.Fatalf("environment failure %v reported as sealed-data authentication", err)
			}
			if !errors.Is(err, tc.fault) {
				t.Fatalf("Unseal error %v lost the KMS cause", err)
			}
		})
	}

	t.Run("cancelled context with tampered data", func(t *testing.T) {
		f := newSealAuthFixture(t)
		sealed, err := f.backend.Seal(context.Background(), []byte("root key"), &types.SealOptions{KeyAttributes: f.keyA})
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		sealed.Ciphertext[0] ^= 0x01
		sealed.Backend = types.BackendTypeVault

		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err = f.backend.Unseal(ctx, sealed, &types.UnsealOptions{KeyAttributes: f.keyA})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Unseal error %v, want context.Canceled", err)
		}
		if errors.Is(err, types.ErrSealedDataAuthentication) {
			t.Fatal("a cancelled context must not be reported as sealed-data authentication")
		}
	})

	t.Run("sealing key metadata missing", func(t *testing.T) {
		f := newSealAuthFixture(t)
		sealed, err := f.backend.Seal(context.Background(), []byte("root key"), &types.SealOptions{KeyAttributes: f.keyA})
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		unknown := &types.KeyAttributes{
			CN:                 "seal-auth-never-created",
			KeyType:            backend.KEY_TYPE_SECRET,
			StoreType:          backend.STORE_AWSKMS,
			SymmetricAlgorithm: types.SymmetricAES256GCM,
		}
		sealed.KeyID = ""
		_, err = f.backend.Unseal(context.Background(), sealed, &types.UnsealOptions{KeyAttributes: unknown})
		if err == nil {
			t.Fatal("Unseal must fail without the sealing key")
		}
		if errors.Is(err, types.ErrSealedDataAuthentication) {
			t.Fatalf("a missing key %v reported as sealed-data authentication", err)
		}
	})
}

// TestUnseal_SealedDataAuthentication_RoundTripStillWorks pins the positive
// half of the fixture: an untouched blob with its AAD unseals.
func TestUnseal_SealedDataAuthentication_RoundTripStillWorks(t *testing.T) {
	f := newSealAuthFixture(t)
	ctx := context.Background()
	sealed, err := f.backend.Seal(ctx, []byte("root key"), &types.SealOptions{KeyAttributes: f.keyA, AAD: sealAuthAAD})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	got, err := f.backend.Unseal(ctx, sealed, &types.UnsealOptions{KeyAttributes: f.keyA, AAD: sealAuthAAD})
	if err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if !bytes.Equal(got, []byte("root key")) {
		t.Fatalf("Unseal = %q", got)
	}
}
