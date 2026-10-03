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

//go:build gcpkms

package gcpkms

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"sync"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// cloudKMSDouble is an in-process stand-in for Cloud KMS Encrypt/Decrypt on
// ENCRYPT_DECRYPT CryptoKeys. It performs real AES-256-GCM with the request's
// additional_authenticated_data as AEAD associated data, keyed per CryptoKey
// name, and answers every ciphertext it cannot authenticate with
// codes.InvalidArgument the way the service does. decryptFault, when set,
// replaces every Decrypt answer, standing in for an outage.
type cloudKMSDouble struct {
	mu           sync.Mutex
	keys         map[string][]byte
	decryptFault error
}

func (d *cloudKMSDouble) aead(name string) (cipher.AEAD, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	material, ok := d.keys[name]
	if !ok {
		material = make([]byte, 32)
		if _, err := rand.Read(material); err != nil {
			return nil, err
		}
		d.keys[name] = material
	}
	block, err := aes.NewCipher(material)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (d *cloudKMSDouble) encrypt(_ context.Context, req *kmspb.EncryptRequest, _ ...interface{}) (*kmspb.EncryptResponse, error) {
	gcm, err := d.aead(req.Name)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(bytes.Clone(nonce), nonce, req.Plaintext, req.AdditionalAuthenticatedData)
	return &kmspb.EncryptResponse{
		Name:             req.Name,
		Ciphertext:       ciphertext,
		CiphertextCrc32C: wrapperspb.Int64(int64(crc32c(ciphertext))),
	}, nil
}

func (d *cloudKMSDouble) decrypt(_ context.Context, req *kmspb.DecryptRequest, _ ...interface{}) (*kmspb.DecryptResponse, error) {
	if d.decryptFault != nil {
		return nil, d.decryptFault
	}
	invalid := status.Error(codes.InvalidArgument, "Decryption failed: the ciphertext is invalid.")
	gcm, err := d.aead(req.Name)
	if err != nil {
		return nil, err
	}
	if len(req.Ciphertext) < gcm.NonceSize() {
		return nil, invalid
	}
	nonce := req.Ciphertext[:gcm.NonceSize()]
	plaintext, err := gcm.Open(nil, nonce, req.Ciphertext[gcm.NonceSize():], req.AdditionalAuthenticatedData)
	if err != nil {
		return nil, invalid
	}
	return &kmspb.DecryptResponse{
		Plaintext:       plaintext,
		PlaintextCrc32C: wrapperspb.Int64(int64(crc32c(plaintext))),
	}, nil
}

// gcpSealAuthFixture is a backend over a cloudKMSDouble with two keys.
type gcpSealAuthFixture struct {
	backend *Backend
	double  *cloudKMSDouble
	keyA    *types.KeyAttributes
	keyB    *types.KeyAttributes
}

func newGCPSealAuthFixture(t *testing.T) *gcpSealAuthFixture {
	t.Helper()
	b, keyA := newSealTestBackend(t, "seal-auth-a")
	keyB := &types.KeyAttributes{
		CN:                 "seal-auth-b",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_GCPKMS,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}
	if _, err := b.GenerateSymmetricKey(context.Background(), keyB); err != nil {
		t.Fatalf("GenerateSymmetricKey: %v", err)
	}
	double := &cloudKMSDouble{keys: make(map[string][]byte)}
	mock, ok := b.client.(*MockKMSClient)
	if !ok {
		t.Fatalf("backend client is %T, want *MockKMSClient", b.client)
	}
	mock.EncryptFunc = double.encrypt
	mock.DecryptFunc = double.decrypt
	return &gcpSealAuthFixture{backend: b, double: double, keyA: keyA, keyB: keyB}
}

func cloneSealedData(sealed *types.SealedData) *types.SealedData {
	c := *sealed
	c.Ciphertext = bytes.Clone(sealed.Ciphertext)
	c.Metadata = make(map[string][]byte, len(sealed.Metadata))
	for k, v := range sealed.Metadata {
		c.Metadata[k] = bytes.Clone(v)
	}
	return &c
}

var gcpSealAuthAAD = []byte("tenant=acme,purpose=barrier")

// TestUnseal_SealedDataAuthentication proves every way the sealed data itself
// can be wrong is reported as types.ErrSealedDataAuthentication, with the
// Cloud KMS status still reachable where the service produced one.
func TestUnseal_SealedDataAuthentication(t *testing.T) {
	cases := []struct {
		name      string
		mutate    func(f *gcpSealAuthFixture, s *types.SealedData) (*types.SealedData, *types.UnsealOptions)
		fromCloud bool
	}{
		{"bit flipped", func(f *gcpSealAuthFixture, s *types.SealedData) (*types.SealedData, *types.UnsealOptions) {
			s.Ciphertext[len(s.Ciphertext)-1] ^= 0x01
			return s, &types.UnsealOptions{KeyAttributes: f.keyA, AAD: gcpSealAuthAAD}
		}, true},
		{"truncated", func(f *gcpSealAuthFixture, s *types.SealedData) (*types.SealedData, *types.UnsealOptions) {
			s.Ciphertext = s.Ciphertext[:len(s.Ciphertext)-1]
			return s, &types.UnsealOptions{KeyAttributes: f.keyA, AAD: gcpSealAuthAAD}
		}, true},
		{"extended", func(f *gcpSealAuthFixture, s *types.SealedData) (*types.SealedData, *types.UnsealOptions) {
			s.Ciphertext = append(s.Ciphertext, 0x00)
			return s, &types.UnsealOptions{KeyAttributes: f.keyA, AAD: gcpSealAuthAAD}
		}, true},
		{"AAD mismatch", func(f *gcpSealAuthFixture, s *types.SealedData) (*types.SealedData, *types.UnsealOptions) {
			return s, &types.UnsealOptions{KeyAttributes: f.keyA, AAD: []byte("tenant=evil")}
		}, true},
		{"AAD omitted", func(f *gcpSealAuthFixture, s *types.SealedData) (*types.SealedData, *types.UnsealOptions) {
			return s, &types.UnsealOptions{KeyAttributes: f.keyA}
		}, true},
		{"foreign key named by sealed KeyID", func(f *gcpSealAuthFixture, s *types.SealedData) (*types.SealedData, *types.UnsealOptions) {
			return s, &types.UnsealOptions{KeyAttributes: f.keyB, AAD: gcpSealAuthAAD}
		}, false},
		{"foreign key detected by Cloud KMS", func(f *gcpSealAuthFixture, s *types.SealedData) (*types.SealedData, *types.UnsealOptions) {
			s.KeyID = ""
			return s, &types.UnsealOptions{KeyAttributes: f.keyB, AAD: gcpSealAuthAAD}
		}, true},
		{"wrong backend", func(f *gcpSealAuthFixture, s *types.SealedData) (*types.SealedData, *types.UnsealOptions) {
			s.Backend = types.BackendTypeAWSKMS
			return s, &types.UnsealOptions{KeyAttributes: f.keyA, AAD: gcpSealAuthAAD}
		}, false},
		{"malformed: ciphertext missing", func(f *gcpSealAuthFixture, s *types.SealedData) (*types.SealedData, *types.UnsealOptions) {
			s.Ciphertext = nil
			return s, &types.UnsealOptions{KeyAttributes: f.keyA, AAD: gcpSealAuthAAD}
		}, false},
		{"malformed: shorter than a nonce", func(f *gcpSealAuthFixture, s *types.SealedData) (*types.SealedData, *types.UnsealOptions) {
			s.Ciphertext = s.Ciphertext[:3]
			return s, &types.UnsealOptions{KeyAttributes: f.keyA, AAD: gcpSealAuthAAD}
		}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newGCPSealAuthFixture(t)
			ctx := context.Background()
			sealed, err := f.backend.Seal(ctx, []byte("root key"), &types.SealOptions{KeyAttributes: f.keyA, AAD: gcpSealAuthAAD})
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}
			mutated, opts := tc.mutate(f, cloneSealedData(sealed))

			out, err := f.backend.Unseal(ctx, mutated, opts)
			if out != nil {
				t.Fatalf("Unseal returned plaintext %q for bad sealed data", out)
			}
			if !errors.Is(err, types.ErrSealedDataAuthentication) {
				t.Fatalf("Unseal error %v does not match ErrSealedDataAuthentication", err)
			}
			if tc.fromCloud && status.Code(err) != codes.InvalidArgument {
				t.Fatalf("Unseal error %v lost the Cloud KMS status", err)
			}
		})
	}
}

// TestUnseal_EnvironmentFailuresAreNotAuthentication proves outages,
// permission and key-state failures, a corrupted response and a cancelled
// context are never reported as sealed-data authentication failures.
func TestUnseal_EnvironmentFailuresAreNotAuthentication(t *testing.T) {
	faults := []struct {
		name string
		code codes.Code
	}{
		{"unavailable", codes.Unavailable},
		{"deadline exceeded", codes.DeadlineExceeded},
		{"throttled", codes.ResourceExhausted},
		{"permission denied", codes.PermissionDenied},
		{"unauthenticated", codes.Unauthenticated},
		{"key version disabled", codes.FailedPrecondition},
		{"key not found", codes.NotFound},
		{"internal", codes.Internal},
	}
	for _, tc := range faults {
		t.Run(tc.name, func(t *testing.T) {
			f := newGCPSealAuthFixture(t)
			ctx := context.Background()
			sealed, err := f.backend.Seal(ctx, []byte("root key"), &types.SealOptions{KeyAttributes: f.keyA})
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}
			f.double.decryptFault = status.Error(tc.code, tc.name)

			_, err = f.backend.Unseal(ctx, sealed, &types.UnsealOptions{KeyAttributes: f.keyA})
			if err == nil {
				t.Fatal("Unseal must fail when Cloud KMS fails")
			}
			if errors.Is(err, types.ErrSealedDataAuthentication) {
				t.Fatalf("environment failure %v reported as sealed-data authentication", err)
			}
			if status.Code(err) != tc.code {
				t.Fatalf("Unseal error %v lost the Cloud KMS status", err)
			}
		})
	}

	t.Run("request checksum mismatch in transit", func(t *testing.T) {
		f := newGCPSealAuthFixture(t)
		ctx := context.Background()
		sealed, err := f.backend.Seal(ctx, []byte("root key"), &types.SealOptions{KeyAttributes: f.keyA})
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		f.double.decryptFault = status.Error(codes.InvalidArgument,
			"The checksum in field ciphertext_crc32c did not match the data in field ciphertext.")

		_, err = f.backend.Unseal(ctx, sealed, &types.UnsealOptions{KeyAttributes: f.keyA})
		if err == nil {
			t.Fatal("Unseal must fail when Cloud KMS reports a request checksum mismatch")
		}
		if errors.Is(err, types.ErrSealedDataAuthentication) {
			t.Fatalf("corruption in transit %v reported as sealed-data authentication", err)
		}
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("Unseal error %v lost the Cloud KMS status", err)
		}
	})

	t.Run("corrupted response checksum", func(t *testing.T) {
		f := newGCPSealAuthFixture(t)
		ctx := context.Background()
		sealed, err := f.backend.Seal(ctx, []byte("root key"), &types.SealOptions{KeyAttributes: f.keyA})
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		mock := f.backend.client.(*MockKMSClient)
		mock.DecryptFunc = func(ctx context.Context, req *kmspb.DecryptRequest, opts ...interface{}) (*kmspb.DecryptResponse, error) {
			resp, err := f.double.decrypt(ctx, req, opts...)
			if err != nil {
				return nil, err
			}
			resp.PlaintextCrc32C = wrapperspb.Int64(resp.PlaintextCrc32C.Value + 1)
			return resp, nil
		}
		_, err = f.backend.Unseal(ctx, sealed, &types.UnsealOptions{KeyAttributes: f.keyA})
		if err == nil {
			t.Fatal("a response failing its checksum must not unseal")
		}
		if errors.Is(err, types.ErrSealedDataAuthentication) {
			t.Fatalf("a corrupted response %v reported as sealed-data authentication", err)
		}
	})

	t.Run("cancelled context with tampered data", func(t *testing.T) {
		f := newGCPSealAuthFixture(t)
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

	t.Run("sealing key cannot be resolved", func(t *testing.T) {
		f := newGCPSealAuthFixture(t)
		sealed, err := f.backend.Seal(context.Background(), []byte("root key"), &types.SealOptions{KeyAttributes: f.keyA})
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		mock := f.backend.client.(*MockKMSClient)
		mock.GetCryptoKeyFunc = func(ctx context.Context, req *kmspb.GetCryptoKeyRequest, opts ...interface{}) (*kmspb.CryptoKey, error) {
			return nil, status.Error(codes.Unavailable, "kms unreachable")
		}
		_, err = f.backend.Unseal(context.Background(), sealed, &types.UnsealOptions{KeyAttributes: f.keyA})
		if err == nil {
			t.Fatal("Unseal must fail when the key cannot be resolved")
		}
		if errors.Is(err, types.ErrSealedDataAuthentication) {
			t.Fatalf("an unresolvable key %v reported as sealed-data authentication", err)
		}
	})
}

// TestUnseal_SealedDataAuthentication_RoundTripStillWorks pins the positive
// half of the fixture: an untouched ciphertext with its AAD unseals.
func TestUnseal_SealedDataAuthentication_RoundTripStillWorks(t *testing.T) {
	f := newGCPSealAuthFixture(t)
	ctx := context.Background()
	sealed, err := f.backend.Seal(ctx, []byte("root key"), &types.SealOptions{KeyAttributes: f.keyA, AAD: gcpSealAuthAAD})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	got, err := f.backend.Unseal(ctx, sealed, &types.UnsealOptions{KeyAttributes: f.keyA, AAD: gcpSealAuthAAD})
	if err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if !bytes.Equal(got, []byte("root key")) {
		t.Fatalf("Unseal = %q", got)
	}
}

// TestRejectsSealedData pins the Decrypt classification.
func TestRejectsSealedData(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"invalid ciphertext", status.Error(codes.InvalidArgument, "Decryption failed: the ciphertext is invalid."), true},
		{"wrapped invalid ciphertext", &wrappedStatus{status.Error(codes.InvalidArgument, "Decryption failed")}, true},
		{"request CRC32C mismatch", status.Error(codes.InvalidArgument, "The checksum in field ciphertext_crc32c did not match the data in field ciphertext."), false},
		{"AAD CRC32C mismatch", status.Error(codes.InvalidArgument, "additional_authenticated_data_crc32c mismatch"), false},
		{"failed precondition", status.Error(codes.FailedPrecondition, "key version is disabled"), false},
		{"not a gRPC status", errors.New("Decryption failed: the ciphertext is invalid."), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := rejectsSealedData(tc.err); got != tc.want {
				t.Fatalf("rejectsSealedData(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// wrappedStatus wraps a gRPC status error the way the SDK's callers do.
type wrappedStatus struct{ err error }

func (w *wrappedStatus) Error() string { return "kms: " + w.err.Error() }
func (w *wrappedStatus) Unwrap() error { return w.err }
