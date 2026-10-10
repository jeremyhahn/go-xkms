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

package file

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/dao"
	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
)

// errKV is the failure failingKV injects.
var errKV = errors.New("kv failure")

// failingKV is an atomic KV store that fails the operations it is told to.
type failingKV struct {
	qrdbsdk.AtomicKVStore

	// getErr fails every read.
	getErr error

	// writeErr fails every write and delete.
	writeErr error

	// deleteMisses makes every guarded delete report that the stored value
	// changed, as a concurrent writer would.
	deleteMisses bool
}

func (f *failingKV) Get(ctx context.Context, key string) ([]byte, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.AtomicKVStore.Get(ctx, key)
}

func (f *failingKV) Put(ctx context.Context, key string, value []byte) error {
	if f.writeErr != nil {
		return f.writeErr
	}
	return f.AtomicKVStore.Put(ctx, key, value)
}

func (f *failingKV) PutIfAbsent(ctx context.Context, key string, value []byte) (bool, error) {
	if f.writeErr != nil {
		return false, f.writeErr
	}
	return f.AtomicKVStore.PutIfAbsent(ctx, key, value)
}

func (f *failingKV) CompareAndSwap(ctx context.Context, key string, expected, next []byte) (bool, error) {
	if f.writeErr != nil {
		return false, f.writeErr
	}
	return f.AtomicKVStore.CompareAndSwap(ctx, key, expected, next)
}

func (f *failingKV) CompareAndDelete(ctx context.Context, key string, expected []byte) (bool, error) {
	if f.writeErr != nil {
		return false, f.writeErr
	}
	if f.deleteMisses {
		return false, nil
	}
	return f.AtomicKVStore.CompareAndDelete(ctx, key, expected)
}

func (f *failingKV) Delete(ctx context.Context, key string) error {
	if f.writeErr != nil {
		return f.writeErr
	}
	return f.AtomicKVStore.Delete(ctx, key)
}

// newMemoryKV returns an empty in-memory atomic KV store.
func newMemoryKV(t *testing.T) qrdbsdk.AtomicKVStore {
	t.Helper()
	return qrdbsdk.NewMemoryKVStore()
}

// newStore returns a store over kv.
func newStore(t *testing.T, kv qrdbsdk.KVStore) *FileBackend {
	t.Helper()
	fb, err := NewFileBackend(&pivcert.FileStorageConfig{DAOs: dao.NewStoreFactory(kv)})
	require.NoError(t, err)
	return fb
}

// newTestStore returns a store over a fresh in-memory KV store.
func newTestStore(t *testing.T) *FileBackend {
	t.Helper()
	return newStore(t, newMemoryKV(t))
}

// newCertificate returns a self-signed certificate for key.
func newCertificate(t *testing.T, subject string, key crypto.Signer, extensions ...pkix.Extension) *x509.Certificate {
	t.Helper()

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: subject, Organization: []string{"Test Organization"}},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		ExtraExtensions:       extensions,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// generateTestCertificate returns a self-signed ECDSA P-256 certificate.
func generateTestCertificate(t *testing.T, subject string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return newCertificate(t, subject, key)
}

// generateRSACertificate returns a self-signed RSA-2048 certificate.
func generateRSACertificate(t *testing.T, subject string) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return newCertificate(t, subject, key)
}

// generateEd25519Certificate returns a self-signed Ed25519 certificate.
func generateEd25519Certificate(t *testing.T, subject string) *x509.Certificate {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return newCertificate(t, subject, key)
}

// generateLargeCertificate returns a certificate larger than
// pivcert.MaxCertSizeFile.
func generateLargeCertificate(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	padding := pkix.Extension{
		Id:    []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
		Value: make([]byte, pivcert.MaxCertSizeFile+1024),
	}
	return newCertificate(t, "large-cert", key, padding)
}

func TestNewFileBackend(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		fb := newTestStore(t)
		assert.Equal(t, pivcert.StorageTypeFile, fb.Type())
	})

	t.Run("nil config", func(t *testing.T) {
		_, err := NewFileBackend(nil)
		assert.ErrorIs(t, err, pivcert.ErrInvalidConfig)
	})

	t.Run("missing DAO factory", func(t *testing.T) {
		_, err := NewFileBackend(&pivcert.FileStorageConfig{})
		assert.ErrorIs(t, err, pivcert.ErrMissingDAOFactory)
	})

	t.Run("unavailable database", func(t *testing.T) {
		_, err := NewFileBackend(&pivcert.FileStorageConfig{DAOs: dao.NewStoreFactory(nil)})
		var unavailable *dao.DatabaseUnavailableError
		assert.ErrorAs(t, err, &unavailable)
		assert.ErrorContains(t, err, DatabaseName)
	})
}

func TestFileBackend_StoreRetrieve(t *testing.T) {
	fb := newTestStore(t)
	cert := generateTestCertificate(t, "round-trip")

	require.NoError(t, fb.Store(pivcert.PIVSlotAuthentication, cert))

	got, err := fb.Retrieve(pivcert.PIVSlotAuthentication)
	require.NoError(t, err)
	assert.Equal(t, cert.Raw, got.Raw)
}

// TestFileBackend_PersistsAcrossStores verifies the certificate lives in the
// DAO factory, not in the store: a second store over the same factory reads
// what the first wrote.
func TestFileBackend_PersistsAcrossStores(t *testing.T) {
	daos := dao.NewStoreFactory(newMemoryKV(t))
	cert := generateTestCertificate(t, "persisted")

	first, err := NewFileBackend(&pivcert.FileStorageConfig{DAOs: daos})
	require.NoError(t, err)
	require.NoError(t, first.Store(pivcert.PIVSlotDigitalSignature, cert))
	require.NoError(t, first.Close())

	second, err := NewFileBackend(&pivcert.FileStorageConfig{DAOs: daos})
	require.NoError(t, err)
	got, err := second.Retrieve(pivcert.PIVSlotDigitalSignature)
	require.NoError(t, err)
	assert.Equal(t, cert.Raw, got.Raw)
}

func TestFileBackend_Store_Errors(t *testing.T) {
	cert := generateTestCertificate(t, "store-errors")

	t.Run("invalid slot", func(t *testing.T) {
		err := newTestStore(t).Store(pivcert.PIVSlot("invalid"), cert)
		assert.ErrorIs(t, err, pivcert.ErrInvalidSlot)
	})

	t.Run("nil certificate", func(t *testing.T) {
		err := newTestStore(t).Store(pivcert.PIVSlotAuthentication, nil)
		assert.ErrorIs(t, err, pivcert.ErrInvalidCertificate)
	})

	t.Run("certificate too large", func(t *testing.T) {
		err := newTestStore(t).Store(pivcert.PIVSlotAuthentication, generateLargeCertificate(t))
		assert.ErrorIs(t, err, pivcert.ErrCertificateTooLarge)
	})

	t.Run("closed", func(t *testing.T) {
		fb := newTestStore(t)
		require.NoError(t, fb.Close())
		assert.ErrorIs(t, fb.Store(pivcert.PIVSlotAuthentication, cert), pivcert.ErrStorageClosed)
	})

	t.Run("write failure", func(t *testing.T) {
		fb := newStore(t, &failingKV{AtomicKVStore: newMemoryKV(t), writeErr: errKV})
		err := fb.Store(pivcert.PIVSlotAuthentication, cert)
		assert.ErrorIs(t, err, errKV)
		var storageErr *pivcert.PIVStorageError
		assert.ErrorAs(t, err, &storageErr)
	})
}

func TestFileBackend_Retrieve_Errors(t *testing.T) {
	t.Run("not found", func(t *testing.T) {
		_, err := newTestStore(t).Retrieve(pivcert.PIVSlotAuthentication)
		assert.ErrorIs(t, err, pivcert.ErrCertificateNotFound)
	})

	t.Run("invalid slot", func(t *testing.T) {
		_, err := newTestStore(t).Retrieve(pivcert.PIVSlot("invalid"))
		assert.ErrorIs(t, err, pivcert.ErrInvalidSlot)
	})

	t.Run("closed", func(t *testing.T) {
		fb := newTestStore(t)
		require.NoError(t, fb.Store(pivcert.PIVSlotAuthentication, generateTestCertificate(t, "closed")))
		require.NoError(t, fb.Close())
		_, err := fb.Retrieve(pivcert.PIVSlotAuthentication)
		assert.ErrorIs(t, err, pivcert.ErrStorageClosed)
	})

	t.Run("corrupt record", func(t *testing.T) {
		fb := newTestStore(t)
		require.NoError(t, fb.certs.Save(context.Background(), &certEntity{Slot: string(pivcert.PIVSlotAuthentication), DER: []byte("not DER")}))
		_, err := fb.Retrieve(pivcert.PIVSlotAuthentication)
		assert.ErrorIs(t, err, pivcert.ErrInvalidCertificate)
	})

	t.Run("read failure", func(t *testing.T) {
		fb := newStore(t, &failingKV{AtomicKVStore: newMemoryKV(t), getErr: errKV})
		_, err := fb.Retrieve(pivcert.PIVSlotAuthentication)
		assert.ErrorIs(t, err, errKV)
		assert.NotErrorIs(t, err, pivcert.ErrCertificateNotFound)
	})
}

func TestFileBackend_Delete(t *testing.T) {
	fb := newTestStore(t)
	require.NoError(t, fb.Store(pivcert.PIVSlotAuthentication, generateTestCertificate(t, "delete")))

	require.NoError(t, fb.Delete(pivcert.PIVSlotAuthentication))

	_, err := fb.Retrieve(pivcert.PIVSlotAuthentication)
	assert.ErrorIs(t, err, pivcert.ErrCertificateNotFound)
	assert.ErrorIs(t, fb.Delete(pivcert.PIVSlotAuthentication), pivcert.ErrCertificateNotFound)
}

func TestFileBackend_Delete_Errors(t *testing.T) {
	cert := generateTestCertificate(t, "delete-errors")

	// seeded returns a store over a KV holding cert in the authentication
	// slot, with kv's failures switched on after seeding.
	seeded := func(t *testing.T, kv *failingKV) *FileBackend {
		t.Helper()
		mem := newMemoryKV(t)
		require.NoError(t, newStore(t, mem).Store(pivcert.PIVSlotAuthentication, cert))
		kv.AtomicKVStore = mem
		return newStore(t, kv)
	}

	t.Run("invalid slot", func(t *testing.T) {
		assert.ErrorIs(t, newTestStore(t).Delete(pivcert.PIVSlot("invalid")), pivcert.ErrInvalidSlot)
	})

	t.Run("closed", func(t *testing.T) {
		fb := newTestStore(t)
		require.NoError(t, fb.Close())
		assert.ErrorIs(t, fb.Delete(pivcert.PIVSlotAuthentication), pivcert.ErrStorageClosed)
	})

	t.Run("concurrent replacement", func(t *testing.T) {
		fb := seeded(t, &failingKV{deleteMisses: true})
		assert.ErrorIs(t, fb.Delete(pivcert.PIVSlotAuthentication), pivcert.ErrConflict)
	})

	t.Run("delete failure", func(t *testing.T) {
		fb := seeded(t, &failingKV{writeErr: errKV})
		assert.ErrorIs(t, fb.Delete(pivcert.PIVSlotAuthentication), errKV)
	})

	t.Run("read failure", func(t *testing.T) {
		fb := seeded(t, &failingKV{getErr: errKV})
		assert.ErrorIs(t, fb.Delete(pivcert.PIVSlotAuthentication), errKV)
	})
}

func TestFileBackend_List(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		infos, err := newTestStore(t).List()
		require.NoError(t, err)
		assert.Empty(t, infos)
	})

	t.Run("derives slot info from each certificate, sorted by slot", func(t *testing.T) {
		fb := newTestStore(t)
		signature := generateRSACertificate(t, "signature")
		authentication := generateTestCertificate(t, "authentication")
		before := time.Now().UTC().Add(-time.Second)
		require.NoError(t, fb.Store(pivcert.PIVSlotDigitalSignature, signature))
		require.NoError(t, fb.Store(pivcert.PIVSlotAuthentication, authentication))

		infos, err := fb.List()
		require.NoError(t, err)
		require.Len(t, infos, 2)

		assert.Equal(t, pivcert.PIVSlotAuthentication, infos[0].Slot)
		assert.Equal(t, "ECDSA", infos[0].Algorithm)
		assert.Equal(t, 256, infos[0].KeySize)
		assert.Equal(t, authentication.Subject.String(), infos[0].Subject)
		assert.Equal(t, pivcert.ThumbprintSHA256(authentication), infos[0].Fingerprint)
		assert.True(t, infos[0].StoredAt.After(before))

		assert.Equal(t, pivcert.PIVSlotDigitalSignature, infos[1].Slot)
		assert.Equal(t, "RSA", infos[1].Algorithm)
		assert.Equal(t, 2048, infos[1].KeySize)
	})

	t.Run("closed", func(t *testing.T) {
		fb := newTestStore(t)
		require.NoError(t, fb.Close())
		_, err := fb.List()
		assert.ErrorIs(t, err, pivcert.ErrStorageClosed)
	})

	t.Run("corrupt record", func(t *testing.T) {
		fb := newTestStore(t)
		require.NoError(t, fb.certs.Save(context.Background(), &certEntity{Slot: string(pivcert.PIVSlotDigitalSignature), DER: []byte("not DER")}))
		_, err := fb.List()
		assert.ErrorIs(t, err, pivcert.ErrInvalidCertificate)
	})
}

func TestFileBackend_OverwriteCertificate(t *testing.T) {
	fb := newTestStore(t)
	first := generateTestCertificate(t, "first")
	second := generateTestCertificate(t, "second")

	require.NoError(t, fb.Store(pivcert.PIVSlotAuthentication, first))
	require.NoError(t, fb.Store(pivcert.PIVSlotAuthentication, second))

	got, err := fb.Retrieve(pivcert.PIVSlotAuthentication)
	require.NoError(t, err)
	assert.Equal(t, second.Raw, got.Raw)

	infos, err := fb.List()
	require.NoError(t, err)
	require.Len(t, infos, 1)
	assert.Equal(t, second.Subject.String(), infos[0].Subject)
}

func TestFileBackend_AllSlots(t *testing.T) {
	fb := newTestStore(t)
	cert := generateEd25519Certificate(t, "all-slots")
	slots := pivcert.AllSlots()

	for _, slot := range slots {
		require.NoError(t, fb.Store(slot, cert), "slot %s", slot)
	}

	infos, err := fb.List()
	require.NoError(t, err)
	assert.Len(t, infos, len(slots))
	for _, slot := range slots {
		got, err := fb.Retrieve(slot)
		require.NoError(t, err, "slot %s", slot)
		assert.Equal(t, cert.Raw, got.Raw)
	}
}

func TestFileBackend_ImportExport(t *testing.T) {
	cert := generateTestCertificate(t, "import-export")
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	t.Run("DER", func(t *testing.T) {
		fb := newTestStore(t)
		require.NoError(t, fb.Import(pivcert.PIVSlotAuthentication, cert.Raw, pivcert.FormatDER))
		got, err := fb.Export(pivcert.PIVSlotAuthentication, pivcert.FormatDER)
		require.NoError(t, err)
		assert.Equal(t, cert.Raw, got)
	})

	t.Run("PEM", func(t *testing.T) {
		fb := newTestStore(t)
		require.NoError(t, fb.Import(pivcert.PIVSlotAuthentication, pemData, pivcert.FormatPEM))
		got, err := fb.Export(pivcert.PIVSlotAuthentication, pivcert.FormatPEM)
		require.NoError(t, err)
		assert.Equal(t, pemData, got)
	})

	t.Run("import refusals", func(t *testing.T) {
		fb := newTestStore(t)
		wrongBlock := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: cert.Raw})
		badPEMBody := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not DER")})

		assert.ErrorIs(t, fb.Import(pivcert.PIVSlotAuthentication, nil, pivcert.FormatDER), pivcert.ErrInvalidCertificate)
		assert.ErrorIs(t, fb.Import(pivcert.PIVSlotAuthentication, []byte("not DER"), pivcert.FormatDER), pivcert.ErrInvalidCertificate)
		assert.ErrorIs(t, fb.Import(pivcert.PIVSlotAuthentication, []byte("not PEM"), pivcert.FormatPEM), pivcert.ErrInvalidFormat)
		assert.ErrorIs(t, fb.Import(pivcert.PIVSlotAuthentication, wrongBlock, pivcert.FormatPEM), pivcert.ErrInvalidFormat)
		assert.ErrorIs(t, fb.Import(pivcert.PIVSlotAuthentication, badPEMBody, pivcert.FormatPEM), pivcert.ErrInvalidCertificate)
		assert.ErrorIs(t, fb.Import(pivcert.PIVSlotAuthentication, cert.Raw, pivcert.CertFormat(99)), pivcert.ErrInvalidFormat)
	})

	t.Run("export refusals", func(t *testing.T) {
		fb := newTestStore(t)
		_, err := fb.Export(pivcert.PIVSlotAuthentication, pivcert.FormatDER)
		assert.ErrorIs(t, err, pivcert.ErrCertificateNotFound)

		require.NoError(t, fb.Store(pivcert.PIVSlotAuthentication, cert))
		_, err = fb.Export(pivcert.PIVSlotAuthentication, pivcert.CertFormat(99))
		assert.ErrorIs(t, err, pivcert.ErrInvalidFormat)
	})
}

// TestFileBackend_Close verifies Close leaves the injected factory usable:
// the factory belongs to the composition root.
func TestFileBackend_Close(t *testing.T) {
	daos := dao.NewStoreFactory(newMemoryKV(t))
	cert := generateTestCertificate(t, "close")

	fb, err := NewFileBackend(&pivcert.FileStorageConfig{DAOs: daos})
	require.NoError(t, err)
	require.NoError(t, fb.Close())
	require.NoError(t, fb.Close(), "Close is idempotent")

	other, err := NewFileBackend(&pivcert.FileStorageConfig{DAOs: daos})
	require.NoError(t, err)
	assert.NoError(t, other.Store(pivcert.PIVSlotAuthentication, cert))
}

func TestFileBackend_ConcurrentAccess(t *testing.T) {
	fb := newTestStore(t)
	cert := generateTestCertificate(t, "concurrent")
	slots := []pivcert.PIVSlot{
		pivcert.PIVSlotAuthentication,
		pivcert.PIVSlotDigitalSignature,
		pivcert.PIVSlotKeyManagement,
		pivcert.PIVSlotCardAuthentication,
	}

	var wg sync.WaitGroup
	errs := make(chan error, len(slots)*2)
	for _, slot := range slots {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := fb.Store(slot, cert); err != nil {
				errs <- err
				return
			}
			if _, err := fb.Retrieve(slot); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		assert.NoError(t, err)
	}
	infos, err := fb.List()
	require.NoError(t, err)
	assert.Len(t, infos, len(slots))
}

func TestKeyAlgorithmName_DSA(t *testing.T) {
	cert := &x509.Certificate{PublicKeyAlgorithm: x509.DSA}
	assert.Equal(t, "DSA", pivcert.KeyAlgorithmName(cert))
}

func TestKeyAlgorithmName_Unknown(t *testing.T) {
	cert := &x509.Certificate{PublicKeyAlgorithm: x509.PublicKeyAlgorithm(99)}
	assert.Equal(t, "Unknown", pivcert.KeyAlgorithmName(cert))
}

func TestKeySize_UnknownAlgorithm(t *testing.T) {
	cert := &x509.Certificate{
		PublicKeyAlgorithm: x509.PublicKeyAlgorithm(99),
		PublicKey:          "not-a-real-key", // string has no Size() or Params() method
	}
	assert.Equal(t, 0, pivcert.KeySize(cert))
}

func TestKeySize_Ed25519(t *testing.T) {
	assert.Equal(t, 256, pivcert.KeySize(generateEd25519Certificate(t, "ed25519-keysize")))
}

func TestKeySize_RSA(t *testing.T) {
	assert.Equal(t, 2048, pivcert.KeySize(generateRSACertificate(t, "rsa-keysize")))
}

// TestKeySize_ECDSA verifies a real standard-library ECDSA certificate reports
// its curve size. A former backend-local keySize matched *ecdsa.PublicKey
// against a method signature it cannot satisfy and recorded every ECDSA
// certificate with KeySize 0.
func TestKeySize_ECDSA(t *testing.T) {
	assert.Equal(t, 256, pivcert.KeySize(generateTestCertificate(t, "ecdsa-keysize")))
}

// TestKeySize_ECDSA_P384 covers a second curve so the result tracks the actual
// curve rather than a constant.
func TestKeySize_ECDSA_P384(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	cert := &x509.Certificate{PublicKeyAlgorithm: x509.ECDSA, PublicKey: &key.PublicKey}
	assert.Equal(t, 384, pivcert.KeySize(cert))
}

// TestKeySize_ECDSA_NilCurve verifies a malformed ECDSA key with no curve
// reports 0 rather than panicking.
func TestKeySize_ECDSA_NilCurve(t *testing.T) {
	cert := &x509.Certificate{PublicKeyAlgorithm: x509.ECDSA, PublicKey: &ecdsa.PublicKey{}}
	assert.Equal(t, 0, pivcert.KeySize(cert))
}
