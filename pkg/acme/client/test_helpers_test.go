// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package client

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/require"

	qrdbdao "github.com/jeremyhahn/go-qrdb/pkg/dao"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
)

var errNotFound = errors.New("not found")

// mockStorage implements GenericDAO[*entities.ACMEAccount] for testing
type mockStorage struct {
	accounts     map[uint64]*entities.ACMEAccount
	certificates map[uint64]*entities.ACMECertificate
	orders       map[uint64]*entities.ACMEOrder
	saveError    error // Optional error to return from Save
}

func newMockStorage() *mockStorage {
	return &mockStorage{
		accounts:     make(map[uint64]*entities.ACMEAccount),
		certificates: make(map[uint64]*entities.ACMECertificate),
		orders:       make(map[uint64]*entities.ACMEOrder),
	}
}

func (m *mockStorage) Save(_ context.Context, account *entities.ACMEAccount) error {
	if m.saveError != nil {
		return m.saveError
	}
	m.accounts[1] = account
	return nil
}

func (m *mockStorage) SaveWithCondition(_ context.Context, _ *entities.ACMEAccount, _ qrdbdao.Condition) error {
	panic("not implemented")
}

func (m *mockStorage) Get(_ context.Context, id uint64) (*entities.ACMEAccount, error) {
	if acc, ok := m.accounts[id]; ok {
		return acc, nil
	}
	return nil, errNotFound
}

func (m *mockStorage) Delete(_ context.Context, account *entities.ACMEAccount) error {
	delete(m.accounts, account.ID)
	return nil
}

func (m *mockStorage) Count(_ context.Context) (int, error) {
	return len(m.accounts), nil
}

func (m *mockStorage) Page(_ context.Context, _ qrdbsdk.PageQuery) (qrdbsdk.PageResult[*entities.ACMEAccount], error) {
	panic("not implemented")
}

func (m *mockStorage) ForEachPage(_ context.Context, _ qrdbsdk.PageQuery, _ qrdbdao.PagerFunc[*entities.ACMEAccount]) error {
	panic("not implemented")
}

func (m *mockStorage) EntityType() string {
	return "accounts"
}

func (m *mockStorage) QueryByIndex(_ context.Context, _ string, _ interface{}) ([]*entities.ACMEAccount, error) {
	panic("not implemented")
}

func (m *mockStorage) QueryByCompoundIndex(_ context.Context, _ string, _ []interface{}) ([]*entities.ACMEAccount, error) {
	panic("not implemented")
}

func (m *mockStorage) ScanByCompoundIndex(_ context.Context, _ string, _ []interface{}, _, _ interface{}) ([]*entities.ACMEAccount, error) {
	panic("not implemented")
}

func (m *mockStorage) QueryOneByIndex(_ context.Context, _ string, _ interface{}) (*entities.ACMEAccount, error) {
	panic("not implemented")
}

func (m *mockStorage) ScanByIndex(_ context.Context, _ string, _, _ interface{}) ([]*entities.ACMEAccount, error) {
	panic("not implemented")
}

func (m *mockStorage) PageByIndex(_ context.Context, _ string, _ interface{}, _ qrdbsdk.PageQuery) (qrdbsdk.PageResult[*entities.ACMEAccount], error) {
	panic("not implemented")
}

func (m *mockStorage) CountByIndex(_ context.Context, _ string, _ interface{}) (int, error) {
	panic("not implemented")
}

func (m *mockStorage) Find(_ context.Context) *qrdbdao.QueryBuilder[*entities.ACMEAccount] {
	panic("not implemented")
}

// mockCertStorage implements GenericDAO[*entities.ACMECertificate]
type mockCertStorage struct {
	certificates map[uint64]*entities.ACMECertificate
}

func newMockCertStorage() *mockCertStorage {
	return &mockCertStorage{
		certificates: make(map[uint64]*entities.ACMECertificate),
	}
}

func (m *mockCertStorage) Save(_ context.Context, cert *entities.ACMECertificate) error {
	m.certificates[1] = cert
	return nil
}

func (m *mockCertStorage) SaveWithCondition(_ context.Context, _ *entities.ACMECertificate, _ qrdbdao.Condition) error {
	panic("not implemented")
}

func (m *mockCertStorage) Get(_ context.Context, id uint64) (*entities.ACMECertificate, error) {
	if cert, ok := m.certificates[id]; ok {
		return cert, nil
	}
	return nil, errNotFound
}

func (m *mockCertStorage) Delete(_ context.Context, _ *entities.ACMECertificate) error {
	return nil
}

func (m *mockCertStorage) Count(_ context.Context) (int, error) {
	return len(m.certificates), nil
}

func (m *mockCertStorage) Page(_ context.Context, _ qrdbsdk.PageQuery) (qrdbsdk.PageResult[*entities.ACMECertificate], error) {
	panic("not implemented")
}

func (m *mockCertStorage) ForEachPage(_ context.Context, _ qrdbsdk.PageQuery, _ qrdbdao.PagerFunc[*entities.ACMECertificate]) error {
	panic("not implemented")
}

func (m *mockCertStorage) EntityType() string {
	return "certificates"
}

func (m *mockCertStorage) QueryByIndex(_ context.Context, _ string, _ interface{}) ([]*entities.ACMECertificate, error) {
	panic("not implemented")
}

func (m *mockCertStorage) QueryByCompoundIndex(_ context.Context, _ string, _ []interface{}) ([]*entities.ACMECertificate, error) {
	panic("not implemented")
}

func (m *mockCertStorage) ScanByCompoundIndex(_ context.Context, _ string, _ []interface{}, _, _ interface{}) ([]*entities.ACMECertificate, error) {
	panic("not implemented")
}

func (m *mockCertStorage) QueryOneByIndex(_ context.Context, _ string, _ interface{}) (*entities.ACMECertificate, error) {
	panic("not implemented")
}

func (m *mockCertStorage) ScanByIndex(_ context.Context, _ string, _, _ interface{}) ([]*entities.ACMECertificate, error) {
	panic("not implemented")
}

func (m *mockCertStorage) PageByIndex(_ context.Context, _ string, _ interface{}, _ qrdbsdk.PageQuery) (qrdbsdk.PageResult[*entities.ACMECertificate], error) {
	panic("not implemented")
}

func (m *mockCertStorage) CountByIndex(_ context.Context, _ string, _ interface{}) (int, error) {
	panic("not implemented")
}

func (m *mockCertStorage) Find(_ context.Context) *qrdbdao.QueryBuilder[*entities.ACMECertificate] {
	panic("not implemented")
}

// mockOrderStorage implements GenericDAO[*entities.ACMEOrder]
type mockOrderStorage struct {
	orders map[uint64]*entities.ACMEOrder
}

func newMockOrderStorage() *mockOrderStorage {
	return &mockOrderStorage{
		orders: make(map[uint64]*entities.ACMEOrder),
	}
}

func (m *mockOrderStorage) Save(_ context.Context, order *entities.ACMEOrder) error {
	m.orders[1] = order
	return nil
}

func (m *mockOrderStorage) SaveWithCondition(_ context.Context, _ *entities.ACMEOrder, _ qrdbdao.Condition) error {
	panic("not implemented")
}

func (m *mockOrderStorage) Get(_ context.Context, id uint64) (*entities.ACMEOrder, error) {
	if order, ok := m.orders[id]; ok {
		return order, nil
	}
	return nil, errNotFound
}

func (m *mockOrderStorage) Delete(_ context.Context, _ *entities.ACMEOrder) error {
	return nil
}

func (m *mockOrderStorage) Count(_ context.Context) (int, error) {
	return len(m.orders), nil
}

func (m *mockOrderStorage) Page(_ context.Context, _ qrdbsdk.PageQuery) (qrdbsdk.PageResult[*entities.ACMEOrder], error) {
	panic("not implemented")
}

func (m *mockOrderStorage) ForEachPage(_ context.Context, _ qrdbsdk.PageQuery, _ qrdbdao.PagerFunc[*entities.ACMEOrder]) error {
	panic("not implemented")
}

func (m *mockOrderStorage) EntityType() string {
	return "orders"
}

func (m *mockOrderStorage) QueryByIndex(_ context.Context, _ string, _ interface{}) ([]*entities.ACMEOrder, error) {
	panic("not implemented")
}

func (m *mockOrderStorage) QueryByCompoundIndex(_ context.Context, _ string, _ []interface{}) ([]*entities.ACMEOrder, error) {
	panic("not implemented")
}

func (m *mockOrderStorage) ScanByCompoundIndex(_ context.Context, _ string, _ []interface{}, _, _ interface{}) ([]*entities.ACMEOrder, error) {
	panic("not implemented")
}

func (m *mockOrderStorage) QueryOneByIndex(_ context.Context, _ string, _ interface{}) (*entities.ACMEOrder, error) {
	panic("not implemented")
}

func (m *mockOrderStorage) ScanByIndex(_ context.Context, _ string, _, _ interface{}) ([]*entities.ACMEOrder, error) {
	panic("not implemented")
}

func (m *mockOrderStorage) PageByIndex(_ context.Context, _ string, _ interface{}, _ qrdbsdk.PageQuery) (qrdbsdk.PageResult[*entities.ACMEOrder], error) {
	panic("not implemented")
}

func (m *mockOrderStorage) CountByIndex(_ context.Context, _ string, _ interface{}) (int, error) {
	panic("not implemented")
}

func (m *mockOrderStorage) Find(_ context.Context) *qrdbdao.QueryBuilder[*entities.ACMEOrder] {
	panic("not implemented")
}

// generateTestCertificate generates a self-signed certificate for testing
func generateTestCertificate(t *testing.T, commonName string) (*x509.Certificate, crypto.Signer) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert, privateKey
}

// generateSerial generates a random serial number for certificates
func generateSerial(t *testing.T) *big.Int {
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)
	return serialNumber
}
