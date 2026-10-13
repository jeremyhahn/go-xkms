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

package storage_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/jeremyhahn/go-xkms/pkg/acme/storage"
	"github.com/jeremyhahn/go-xkms/pkg/acme/storage/objstore"
	xkmsstorage "github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/kvadapter"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

// BenchmarkSaveAccount benchmarks saving an account
func BenchmarkSaveAccount(b *testing.B) {
	factory := setupBenchmarkStorage(b)
	ctx := context.Background()

	dao, err := factory.AccountDAO()
	if err != nil {
		b.Fatalf("failed to create account DAO: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		account := createBenchmarkAccountEntity(b, uint64(i))
		if err := dao.Save(ctx, account); err != nil {
			b.Fatalf("failed to save account: %v", err)
		}
	}
}

// BenchmarkGetAccount benchmarks retrieving an account
func BenchmarkGetAccount(b *testing.B) {
	factory := setupBenchmarkStorage(b)
	ctx := context.Background()

	dao, err := factory.AccountDAO()
	if err != nil {
		b.Fatalf("failed to create account DAO: %v", err)
	}

	// Pre-create account
	account := createBenchmarkAccountEntity(b, 1)
	if err := dao.Save(ctx, account); err != nil {
		b.Fatalf("failed to save account: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := dao.Get(ctx, account.ID)
		if err != nil {
			b.Fatalf("failed to get account: %v", err)
		}
	}
}

// BenchmarkSaveOrder benchmarks saving an order
func BenchmarkSaveOrder(b *testing.B) {
	factory := setupBenchmarkStorage(b)
	ctx := context.Background()
	accountID := uint64(1)

	dao, err := factory.OrderDAO(accountID)
	if err != nil {
		b.Fatalf("failed to create order DAO: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		order := createBenchmarkOrderEntity(b, uint64(i), accountID)
		if err := dao.Save(ctx, order); err != nil {
			b.Fatalf("failed to save order: %v", err)
		}
	}
}

// BenchmarkGetOrder benchmarks retrieving an order
func BenchmarkGetOrder(b *testing.B) {
	factory := setupBenchmarkStorage(b)
	ctx := context.Background()
	accountID := uint64(1)

	dao, err := factory.OrderDAO(accountID)
	if err != nil {
		b.Fatalf("failed to create order DAO: %v", err)
	}

	// Pre-create order
	order := createBenchmarkOrderEntity(b, 1, accountID)
	if err := dao.Save(ctx, order); err != nil {
		b.Fatalf("failed to save order: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := dao.Get(ctx, order.ID)
		if err != nil {
			b.Fatalf("failed to get order: %v", err)
		}
	}
}

// BenchmarkListOrders benchmarks listing orders for an account
func BenchmarkListOrders(b *testing.B) {
	factory := setupBenchmarkStorage(b)
	ctx := context.Background()
	accountID := uint64(1)

	dao, err := factory.OrderDAO(accountID)
	if err != nil {
		b.Fatalf("failed to create order DAO: %v", err)
	}

	// Pre-create 100 orders
	for i := 0; i < 100; i++ {
		order := createBenchmarkOrderEntity(b, uint64(i), accountID)
		if err := dao.Save(ctx, order); err != nil {
			b.Fatalf("failed to save order: %v", err)
		}
	}

	b.ReportAllocs()
	b.ResetTimer()

	// The order DAO is partitioned per account, so listing an account's
	// orders is a paged walk of its DAO, as the admin service does it.
	for i := 0; i < b.N; i++ {
		listed := 0
		err := dao.ForEachPage(ctx, qrdbsdk.PageQuery{PageSize: 1000}, func(page qrdbsdk.PageResult[*entities.ACMEOrder]) error {
			listed += len(page.Entities)
			return nil
		})
		if err != nil {
			b.Fatalf("failed to list orders: %v", err)
		}
		if listed != 100 {
			b.Fatalf("listed %d orders, want 100", listed)
		}
	}
}

// BenchmarkSaveAuthorization benchmarks saving an authorization
func BenchmarkSaveAuthorization(b *testing.B) {
	factory := setupBenchmarkStorage(b)
	ctx := context.Background()
	accountID := uint64(1)

	dao, err := factory.AuthorizationDAO(accountID)
	if err != nil {
		b.Fatalf("failed to create authorization DAO: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		authz := createBenchmarkAuthorizationEntity(b, uint64(i), accountID)
		if err := dao.Save(ctx, authz); err != nil {
			b.Fatalf("failed to save authorization: %v", err)
		}
	}
}

// BenchmarkGetAuthorization benchmarks retrieving an authorization
func BenchmarkGetAuthorization(b *testing.B) {
	factory := setupBenchmarkStorage(b)
	ctx := context.Background()
	accountID := uint64(1)

	dao, err := factory.AuthorizationDAO(accountID)
	if err != nil {
		b.Fatalf("failed to create authorization DAO: %v", err)
	}

	// Pre-create authorization
	authz := createBenchmarkAuthorizationEntity(b, 1, accountID)
	if err := dao.Save(ctx, authz); err != nil {
		b.Fatalf("failed to save authorization: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := dao.Get(ctx, authz.ID)
		if err != nil {
			b.Fatalf("failed to get authorization: %v", err)
		}
	}
}

// BenchmarkSaveChallenge benchmarks saving a challenge
func BenchmarkSaveChallenge(b *testing.B) {
	factory := setupBenchmarkStorage(b)
	ctx := context.Background()
	accountID := uint64(1)

	dao, err := factory.ChallengeDAO(accountID)
	if err != nil {
		b.Fatalf("failed to create challenge DAO: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		challenge := createBenchmarkChallengeEntity(b, uint64(i), accountID)
		if err := dao.Save(ctx, challenge); err != nil {
			b.Fatalf("failed to save challenge: %v", err)
		}
	}
}

// BenchmarkGetChallenge benchmarks retrieving a challenge
func BenchmarkGetChallenge(b *testing.B) {
	factory := setupBenchmarkStorage(b)
	ctx := context.Background()
	accountID := uint64(1)

	dao, err := factory.ChallengeDAO(accountID)
	if err != nil {
		b.Fatalf("failed to create challenge DAO: %v", err)
	}

	// Pre-create challenge
	challenge := createBenchmarkChallengeEntity(b, 1, accountID)
	if err := dao.Save(ctx, challenge); err != nil {
		b.Fatalf("failed to save challenge: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := dao.Get(ctx, challenge.ID)
		if err != nil {
			b.Fatalf("failed to get challenge: %v", err)
		}
	}
}

// BenchmarkSaveCertificate benchmarks saving a certificate
func BenchmarkSaveCertificate(b *testing.B) {
	factory := setupBenchmarkStorage(b)
	ctx := context.Background()

	dao, err := factory.CertificateDAO()
	if err != nil {
		b.Fatalf("failed to create certificate DAO: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		cert := createBenchmarkCertificateEntity(b, uint64(i))
		if err := dao.Save(ctx, cert); err != nil {
			b.Fatalf("failed to save certificate: %v", err)
		}
	}
}

// BenchmarkGetCertificate benchmarks retrieving a certificate
func BenchmarkGetCertificate(b *testing.B) {
	factory := setupBenchmarkStorage(b)
	ctx := context.Background()

	dao, err := factory.CertificateDAO()
	if err != nil {
		b.Fatalf("failed to create certificate DAO: %v", err)
	}

	// Pre-create certificate
	cert := createBenchmarkCertificateEntity(b, 1)
	if err := dao.Save(ctx, cert); err != nil {
		b.Fatalf("failed to save certificate: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := dao.Get(ctx, cert.EntityID())
		if err != nil {
			b.Fatalf("failed to get certificate: %v", err)
		}
	}
}

// Parallel benchmarks

// BenchmarkSaveOrder_Parallel benchmarks concurrent order saves
func BenchmarkSaveOrder_Parallel(b *testing.B) {
	factory := setupBenchmarkStorage(b)
	ctx := context.Background()
	accountID := uint64(1)

	dao, err := factory.OrderDAO(accountID)
	if err != nil {
		b.Fatalf("failed to create order DAO: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			order := createBenchmarkOrderEntity(b, uint64(i), accountID)
			if err := dao.Save(ctx, order); err != nil {
				b.Fatalf("failed to save order: %v", err)
			}
			i++
		}
	})
}

// BenchmarkGetOrder_Parallel benchmarks concurrent order retrievals
func BenchmarkGetOrder_Parallel(b *testing.B) {
	factory := setupBenchmarkStorage(b)
	ctx := context.Background()
	accountID := uint64(1)

	dao, err := factory.OrderDAO(accountID)
	if err != nil {
		b.Fatalf("failed to create order DAO: %v", err)
	}

	// Pre-create order
	order := createBenchmarkOrderEntity(b, 1, accountID)
	if err := dao.Save(ctx, order); err != nil {
		b.Fatalf("failed to save order: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := dao.Get(ctx, order.ID)
			if err != nil {
				b.Fatalf("failed to get order: %v", err)
			}
		}
	})
}

// Helper functions

// setupBenchmarkStorage creates a storage factory for benchmarking
func setupBenchmarkStorage(b *testing.B) storage.Factory {
	b.Helper()

	kv, err := kvadapter.New(xkmsstorage.NewMemory())
	if err != nil {
		b.Fatalf("failed to create kvadapter: %v", err)
	}

	factory, err := objstore.NewFactoryFromKVStore(kv)
	if err != nil {
		b.Fatalf("failed to create storage factory: %v", err)
	}

	return factory
}

// createBenchmarkAccountEntity creates a test account entity
func createBenchmarkAccountEntity(b *testing.B, id uint64) *entities.ACMEAccount {
	b.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatalf("failed to generate key: %v", err)
	}

	keyPEM, err := xkmssdk.EncodePublicKeyPEM(&key.PublicKey)
	if err != nil {
		b.Fatalf("failed to encode public key: %v", err)
	}

	return &entities.ACMEAccount{
		ID:      id,
		Key:     string(keyPEM),
		Contact: []string{fmt.Sprintf("mailto:benchmark%d@example.com", id)},
		Status:  common.StatusValid,
		Orders:  fmt.Sprintf("/acme/account/%d/orders", id),
	}
}

// createBenchmarkOrderEntity creates a test order entity
func createBenchmarkOrderEntity(b *testing.B, id uint64, accountID uint64) *entities.ACMEOrder {
	b.Helper()

	return &entities.ACMEOrder{
		ID:        id,
		AccountID: accountID,
		Status:    common.StatusPending,
		Identifiers: []entities.ACMEIdentifier{
			{
				Type:  "dns",
				Value: fmt.Sprintf("benchmark%d.example.com", id),
			},
		},
		Authorizations: []string{fmt.Sprintf("/acme/authz/%d", id)},
		Finalize:       fmt.Sprintf("/acme/finalize/%d", id),
		Expires:        time.Now().Add(24 * time.Hour).Format(time.RFC3339),
	}
}

// createBenchmarkAuthorizationEntity creates a test authorization entity
func createBenchmarkAuthorizationEntity(b *testing.B, id uint64, accountID uint64) *entities.ACMEAuthorization {
	b.Helper()

	return &entities.ACMEAuthorization{
		ID:        id,
		AccountID: accountID,
		Status:    common.StatusPending,
		Identifier: entities.ACMEIdentifier{
			Type:  "dns",
			Value: fmt.Sprintf("benchmark%d.example.com", id),
		},
		Challenges: []entities.ACMEChallenge{
			{
				ID:              id,
				Type:            "http-01",
				URL:             fmt.Sprintf("/acme/challenge/%d", id),
				Status:          common.StatusPending,
				Token:           fmt.Sprintf("benchmark-token-%d", id),
				AccountID:       accountID,
				AuthorizationID: id,
			},
		},
		Expires: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
	}
}

// createBenchmarkChallengeEntity creates a test challenge entity
func createBenchmarkChallengeEntity(b *testing.B, id uint64, accountID uint64) *entities.ACMEChallenge {
	b.Helper()

	return &entities.ACMEChallenge{
		ID:              id,
		AccountID:       accountID,
		AuthorizationID: id,
		Type:            "http-01",
		URL:             fmt.Sprintf("/acme/challenge/%d", id),
		Status:          common.StatusPending,
		Token:           fmt.Sprintf("benchmark-token-%d", id),
	}
}

// createBenchmarkCertificateEntity creates a test certificate entity
func createBenchmarkCertificateEntity(b *testing.B, id uint64) *entities.ACMECertificate {
	b.Helper()

	// Generate a simple self-signed certificate for benchmarking
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(int64(id)),
		Subject: pkix.Name{
			CommonName: fmt.Sprintf("benchmark%d.example.com", id),
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		b.Fatalf("failed to create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	serial := template.SerialNumber.Text(16)
	return &entities.ACMECertificate{
		Serial:    serial,
		CertURL:   fmt.Sprintf("/acme/cert/%s", serial),
		PEM:       string(certPEM),
		Status:    common.StatusValid,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(365 * 24 * time.Hour),
	}
}
