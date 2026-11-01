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

//go:build pkcs11

package hardware_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/internal/softhsmtest"
	backend "github.com/jeremyhahn/go-xkms/pkg/backend/pkcs11"
	"github.com/jeremyhahn/go-xkms/pkg/storage/hardware"
	"github.com/miekg/pkcs11"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// poolSize matches the session pool the PKCS#11 integration suite hands the
// store, so the concurrency below contends for sessions the same way.
const poolSize = 8

// newPooledCertStorage provisions an isolated SoftHSM2 token and wraps a real
// backend.SessionPool of size sessions in a PKCS11CertStorage -- the provider
// production and the integration suite use, and the one whose WithSearch the
// store dispatches through.
func newPooledCertStorage(t *testing.T, label string, size int) (hardware.HardwareCertStorage, *backend.SessionPool) {
	t.Helper()

	tok := softhsmtest.Provision(t, label)

	ctx := pkcs11.New(tok.Library)
	require.NotNil(t, ctx, "SoftHSM2 library must load")
	require.NoError(t, ctx.Initialize())
	t.Cleanup(func() {
		ctx.Finalize()
		ctx.Destroy()
	})

	pool, err := backend.NewSessionPool(ctx, tok.Slot(t, ctx), tok.UserPIN, size)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, pool.Close()) })

	s, err := hardware.NewPKCS11CertStorageWithSO(pool, tok.Label, "", "", false)
	require.NoError(t, err)
	return s, pool
}

// newPoolTestCert returns a self-signed P-256 certificate for cn.
func newPoolTestCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// TestPKCS11CertStorage_Pool_ConcurrentReadsSucceed proves concurrent reads on
// a pooled store all succeed: each holds its own session, so none can collide
// with another's search.
func TestPKCS11CertStorage_Pool_ConcurrentReadsSucceed(t *testing.T) {
	s, _ := newPooledCertStorage(t, "pool-concurrent-reads", poolSize)

	cert := newPoolTestCert(t, "concurrent-read")
	require.NoError(t, s.SaveCert("concurrent-read", cert))

	const readers = 20
	var wg sync.WaitGroup
	for i := range readers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := s.GetCert("concurrent-read")
			if assert.NoError(t, err, "reader %d", i) {
				assert.True(t, got.Equal(cert), "reader %d read a different certificate", i)
			}
		}()
	}
	wg.Wait()
}

// TestPKCS11CertStorage_Pool_MixedLoadLeavesTokenReadable drives concurrent
// saves and reads through the pool, then reads sequentially through every
// session. Unserialized, SoftHSM2 fails some of those calls CKR_GENERAL_ERROR,
// leaves a failed search active on the session (CKR_OPERATION_ACTIVE on every
// later read of it), and can persist an object no later search can read; the
// integration suite's renewal read failed on exactly that.
func TestPKCS11CertStorage_Pool_MixedLoadLeavesTokenReadable(t *testing.T) {
	s, _ := newPooledCertStorage(t, "pool-mixed-load", poolSize)

	cert := newPoolTestCert(t, "renewal")
	require.NoError(t, s.SaveCert("renewal", cert))

	const workers = 16
	saveErrs := make([]error, workers)
	readErrs := make([]error, workers)
	var wg sync.WaitGroup
	for i := range workers {
		wg.Add(2)
		go func() {
			defer wg.Done()
			saveErrs[i] = s.SaveCert(fmt.Sprintf("mixed-%d", i), newPoolTestCert(t, "mixed"))
		}()
		go func() {
			defer wg.Done()
			_, readErrs[i] = s.GetCert("renewal")
		}()
	}
	wg.Wait()

	for i := range workers {
		assert.NoError(t, saveErrs[i], "concurrent save %d", i)
		assert.NoError(t, readErrs[i], "concurrent read %d", i)
	}

	ids, err := s.ListCerts()
	require.NoError(t, err)
	assert.Len(t, ids, workers+1)

	// Sequential reads check out every session in turn.
	for i := range 2 * poolSize {
		got, err := s.GetCert("renewal")
		require.NoError(t, err, "sequential read %d", i)
		assert.True(t, got.Equal(cert))
	}
}

// TestPKCS11CertStorage_Pool_ClearsSearchLeftByFailedInit leaves a search
// active on the pool's only session, as a C_FindObjectsInit that fails part
// way through does, and proves the store's next read reports the failure and
// clears it rather than passing it to every read after.
func TestPKCS11CertStorage_Pool_ClearsSearchLeftByFailedInit(t *testing.T) {
	s, pool := newPooledCertStorage(t, "pool-stale-search", 1)

	cert := newPoolTestCert(t, "stale")
	require.NoError(t, s.SaveCert("stale", cert))

	require.NoError(t, pool.WithSession(func(session pkcs11.SessionHandle) error {
		return pool.Ctx().FindObjectsInit(session, nil)
	}))

	_, err := s.GetCert("stale")
	require.ErrorIs(t, err, pkcs11.Error(pkcs11.CKR_OPERATION_ACTIVE))

	got, err := s.GetCert("stale")
	require.NoError(t, err, "the failed read must not leave the session searching")
	assert.True(t, got.Equal(cert))
}
