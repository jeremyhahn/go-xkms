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

package mocks

import (
	"context"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/jeremyhahn/go-xkms/pkg/acme/storage"
	"github.com/stretchr/testify/mock"
)

// ========================================================================
// Mock DAO implementations for each entity type
// ========================================================================

// MockAccountDAO is a testify mock implementation of qrdbsdk.GenericDAO[*entities.ACMEAccount].
type MockAccountDAO struct {
	mock.Mock
}

// Compile-time interface check.
var _ qrdbsdk.GenericDAO[*entities.ACMEAccount] = (*MockAccountDAO)(nil)

// Save mocks the Save method.
func (m *MockAccountDAO) Save(ctx context.Context, entity *entities.ACMEAccount) error {
	args := m.Called(ctx, entity)
	return args.Error(0)
}

// SaveWithCondition mocks the SaveWithCondition method.
func (m *MockAccountDAO) SaveWithCondition(ctx context.Context, entity *entities.ACMEAccount, cond qrdbsdk.Condition) error {
	args := m.Called(ctx, entity, cond)
	return args.Error(0)
}

// Get mocks the Get method.
func (m *MockAccountDAO) Get(ctx context.Context, id uint64) (*entities.ACMEAccount, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.ACMEAccount), args.Error(1)
}

// Delete mocks the Delete method.
func (m *MockAccountDAO) Delete(ctx context.Context, entity *entities.ACMEAccount) error {
	args := m.Called(ctx, entity)
	return args.Error(0)
}

// Count mocks the Count method.
func (m *MockAccountDAO) Count(ctx context.Context) (int, error) {
	args := m.Called(ctx)
	return args.Int(0), args.Error(1)
}

// Page mocks the Page method.
func (m *MockAccountDAO) Page(ctx context.Context, query qrdbsdk.PageQuery) (qrdbsdk.PageResult[*entities.ACMEAccount], error) {
	args := m.Called(ctx, query)
	return args.Get(0).(qrdbsdk.PageResult[*entities.ACMEAccount]), args.Error(1)
}

// ForEachPage mocks the ForEachPage method.
func (m *MockAccountDAO) ForEachPage(ctx context.Context, query qrdbsdk.PageQuery, fn qrdbsdk.PagerFunc[*entities.ACMEAccount]) error {
	args := m.Called(ctx, query, fn)
	return args.Error(0)
}

// EntityType mocks the EntityType method.
func (m *MockAccountDAO) EntityType() string {
	args := m.Called()
	return args.String(0)
}

// QueryByIndex mocks the QueryByIndex method.
func (m *MockAccountDAO) QueryByIndex(ctx context.Context, fieldName string, value interface{}) ([]*entities.ACMEAccount, error) {
	args := m.Called(ctx, fieldName, value)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*entities.ACMEAccount), args.Error(1)
}

// QueryByCompoundIndex mocks the QueryByCompoundIndex method.
func (m *MockAccountDAO) QueryByCompoundIndex(ctx context.Context, indexName string, fieldValues []interface{}) ([]*entities.ACMEAccount, error) {
	args := m.Called(ctx, indexName, fieldValues)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*entities.ACMEAccount), args.Error(1)
}

// QueryOneByIndex mocks the QueryOneByIndex method.
func (m *MockAccountDAO) QueryOneByIndex(ctx context.Context, fieldName string, value interface{}) (*entities.ACMEAccount, error) {
	args := m.Called(ctx, fieldName, value)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.ACMEAccount), args.Error(1)
}

// ScanByIndex mocks the ScanByIndex method.
func (m *MockAccountDAO) ScanByIndex(ctx context.Context, fieldName string, start, end interface{}) ([]*entities.ACMEAccount, error) {
	args := m.Called(ctx, fieldName, start, end)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*entities.ACMEAccount), args.Error(1)
}

// ScanByCompoundIndex mocks the ScanByCompoundIndex method.
func (m *MockAccountDAO) ScanByCompoundIndex(ctx context.Context, indexName string, prefixValues []interface{}, rangeStart, rangeEnd interface{}) ([]*entities.ACMEAccount, error) {
	args := m.Called(ctx, indexName, prefixValues, rangeStart, rangeEnd)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*entities.ACMEAccount), args.Error(1)
}

// PageByIndex mocks the PageByIndex method.
func (m *MockAccountDAO) PageByIndex(ctx context.Context, fieldName string, value interface{}, query qrdbsdk.PageQuery) (qrdbsdk.PageResult[*entities.ACMEAccount], error) {
	args := m.Called(ctx, fieldName, value, query)
	return args.Get(0).(qrdbsdk.PageResult[*entities.ACMEAccount]), args.Error(1)
}

// CountByIndex mocks the CountByIndex method.
func (m *MockAccountDAO) CountByIndex(ctx context.Context, fieldName string, value interface{}) (int, error) {
	args := m.Called(ctx, fieldName, value)
	return args.Int(0), args.Error(1)
}

// Find mocks the Find method.
func (m *MockAccountDAO) Find(ctx context.Context) *qrdbsdk.QueryBuilder[*entities.ACMEAccount] {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*qrdbsdk.QueryBuilder[*entities.ACMEAccount])
}

// ========================================================================
// MockOrderDAO
// ========================================================================

// MockOrderDAO is a testify mock implementation of qrdbsdk.GenericDAO[*entities.ACMEOrder].
type MockOrderDAO struct {
	mock.Mock
}

// Compile-time interface check.
var _ qrdbsdk.GenericDAO[*entities.ACMEOrder] = (*MockOrderDAO)(nil)

// Save mocks the Save method.
func (m *MockOrderDAO) Save(ctx context.Context, entity *entities.ACMEOrder) error {
	args := m.Called(ctx, entity)
	return args.Error(0)
}

// SaveWithCondition mocks the SaveWithCondition method.
func (m *MockOrderDAO) SaveWithCondition(ctx context.Context, entity *entities.ACMEOrder, cond qrdbsdk.Condition) error {
	args := m.Called(ctx, entity, cond)
	return args.Error(0)
}

// Get mocks the Get method.
func (m *MockOrderDAO) Get(ctx context.Context, id uint64) (*entities.ACMEOrder, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.ACMEOrder), args.Error(1)
}

// Delete mocks the Delete method.
func (m *MockOrderDAO) Delete(ctx context.Context, entity *entities.ACMEOrder) error {
	args := m.Called(ctx, entity)
	return args.Error(0)
}

// Count mocks the Count method.
func (m *MockOrderDAO) Count(ctx context.Context) (int, error) {
	args := m.Called(ctx)
	return args.Int(0), args.Error(1)
}

// Page mocks the Page method.
func (m *MockOrderDAO) Page(ctx context.Context, query qrdbsdk.PageQuery) (qrdbsdk.PageResult[*entities.ACMEOrder], error) {
	args := m.Called(ctx, query)
	return args.Get(0).(qrdbsdk.PageResult[*entities.ACMEOrder]), args.Error(1)
}

// ForEachPage mocks the ForEachPage method.
func (m *MockOrderDAO) ForEachPage(ctx context.Context, query qrdbsdk.PageQuery, fn qrdbsdk.PagerFunc[*entities.ACMEOrder]) error {
	args := m.Called(ctx, query, fn)
	return args.Error(0)
}

// EntityType mocks the EntityType method.
func (m *MockOrderDAO) EntityType() string {
	args := m.Called()
	return args.String(0)
}

// QueryByIndex mocks the QueryByIndex method.
func (m *MockOrderDAO) QueryByIndex(ctx context.Context, fieldName string, value interface{}) ([]*entities.ACMEOrder, error) {
	args := m.Called(ctx, fieldName, value)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*entities.ACMEOrder), args.Error(1)
}

// QueryByCompoundIndex mocks the QueryByCompoundIndex method.
func (m *MockOrderDAO) QueryByCompoundIndex(ctx context.Context, indexName string, fieldValues []interface{}) ([]*entities.ACMEOrder, error) {
	args := m.Called(ctx, indexName, fieldValues)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*entities.ACMEOrder), args.Error(1)
}

// QueryOneByIndex mocks the QueryOneByIndex method.
func (m *MockOrderDAO) QueryOneByIndex(ctx context.Context, fieldName string, value interface{}) (*entities.ACMEOrder, error) {
	args := m.Called(ctx, fieldName, value)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.ACMEOrder), args.Error(1)
}

// ScanByIndex mocks the ScanByIndex method.
func (m *MockOrderDAO) ScanByIndex(ctx context.Context, fieldName string, start, end interface{}) ([]*entities.ACMEOrder, error) {
	args := m.Called(ctx, fieldName, start, end)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*entities.ACMEOrder), args.Error(1)
}

// ScanByCompoundIndex mocks the ScanByCompoundIndex method.
func (m *MockOrderDAO) ScanByCompoundIndex(ctx context.Context, indexName string, prefixValues []interface{}, rangeStart, rangeEnd interface{}) ([]*entities.ACMEOrder, error) {
	args := m.Called(ctx, indexName, prefixValues, rangeStart, rangeEnd)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*entities.ACMEOrder), args.Error(1)
}

// PageByIndex mocks the PageByIndex method.
func (m *MockOrderDAO) PageByIndex(ctx context.Context, fieldName string, value interface{}, query qrdbsdk.PageQuery) (qrdbsdk.PageResult[*entities.ACMEOrder], error) {
	args := m.Called(ctx, fieldName, value, query)
	return args.Get(0).(qrdbsdk.PageResult[*entities.ACMEOrder]), args.Error(1)
}

// CountByIndex mocks the CountByIndex method.
func (m *MockOrderDAO) CountByIndex(ctx context.Context, fieldName string, value interface{}) (int, error) {
	args := m.Called(ctx, fieldName, value)
	return args.Int(0), args.Error(1)
}

// Find mocks the Find method.
func (m *MockOrderDAO) Find(ctx context.Context) *qrdbsdk.QueryBuilder[*entities.ACMEOrder] {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*qrdbsdk.QueryBuilder[*entities.ACMEOrder])
}

// ========================================================================
// MockAuthorizationDAO
// ========================================================================

// MockAuthorizationDAO is a testify mock implementation of qrdbsdk.GenericDAO[*entities.ACMEAuthorization].
type MockAuthorizationDAO struct {
	mock.Mock
}

// Compile-time interface check.
var _ qrdbsdk.GenericDAO[*entities.ACMEAuthorization] = (*MockAuthorizationDAO)(nil)

// Save mocks the Save method.
func (m *MockAuthorizationDAO) Save(ctx context.Context, entity *entities.ACMEAuthorization) error {
	args := m.Called(ctx, entity)
	return args.Error(0)
}

// SaveWithCondition mocks the SaveWithCondition method.
func (m *MockAuthorizationDAO) SaveWithCondition(ctx context.Context, entity *entities.ACMEAuthorization, cond qrdbsdk.Condition) error {
	args := m.Called(ctx, entity, cond)
	return args.Error(0)
}

// Get mocks the Get method.
func (m *MockAuthorizationDAO) Get(ctx context.Context, id uint64) (*entities.ACMEAuthorization, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.ACMEAuthorization), args.Error(1)
}

// Delete mocks the Delete method.
func (m *MockAuthorizationDAO) Delete(ctx context.Context, entity *entities.ACMEAuthorization) error {
	args := m.Called(ctx, entity)
	return args.Error(0)
}

// Count mocks the Count method.
func (m *MockAuthorizationDAO) Count(ctx context.Context) (int, error) {
	args := m.Called(ctx)
	return args.Int(0), args.Error(1)
}

// Page mocks the Page method.
func (m *MockAuthorizationDAO) Page(ctx context.Context, query qrdbsdk.PageQuery) (qrdbsdk.PageResult[*entities.ACMEAuthorization], error) {
	args := m.Called(ctx, query)
	return args.Get(0).(qrdbsdk.PageResult[*entities.ACMEAuthorization]), args.Error(1)
}

// ForEachPage mocks the ForEachPage method.
func (m *MockAuthorizationDAO) ForEachPage(ctx context.Context, query qrdbsdk.PageQuery, fn qrdbsdk.PagerFunc[*entities.ACMEAuthorization]) error {
	args := m.Called(ctx, query, fn)
	return args.Error(0)
}

// EntityType mocks the EntityType method.
func (m *MockAuthorizationDAO) EntityType() string {
	args := m.Called()
	return args.String(0)
}

// QueryByIndex mocks the QueryByIndex method.
func (m *MockAuthorizationDAO) QueryByIndex(ctx context.Context, fieldName string, value interface{}) ([]*entities.ACMEAuthorization, error) {
	args := m.Called(ctx, fieldName, value)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*entities.ACMEAuthorization), args.Error(1)
}

// QueryByCompoundIndex mocks the QueryByCompoundIndex method.
func (m *MockAuthorizationDAO) QueryByCompoundIndex(ctx context.Context, indexName string, fieldValues []interface{}) ([]*entities.ACMEAuthorization, error) {
	args := m.Called(ctx, indexName, fieldValues)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*entities.ACMEAuthorization), args.Error(1)
}

// QueryOneByIndex mocks the QueryOneByIndex method.
func (m *MockAuthorizationDAO) QueryOneByIndex(ctx context.Context, fieldName string, value interface{}) (*entities.ACMEAuthorization, error) {
	args := m.Called(ctx, fieldName, value)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.ACMEAuthorization), args.Error(1)
}

// ScanByIndex mocks the ScanByIndex method.
func (m *MockAuthorizationDAO) ScanByIndex(ctx context.Context, fieldName string, start, end interface{}) ([]*entities.ACMEAuthorization, error) {
	args := m.Called(ctx, fieldName, start, end)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*entities.ACMEAuthorization), args.Error(1)
}

// ScanByCompoundIndex mocks the ScanByCompoundIndex method.
func (m *MockAuthorizationDAO) ScanByCompoundIndex(ctx context.Context, indexName string, prefixValues []interface{}, rangeStart, rangeEnd interface{}) ([]*entities.ACMEAuthorization, error) {
	args := m.Called(ctx, indexName, prefixValues, rangeStart, rangeEnd)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*entities.ACMEAuthorization), args.Error(1)
}

// PageByIndex mocks the PageByIndex method.
func (m *MockAuthorizationDAO) PageByIndex(ctx context.Context, fieldName string, value interface{}, query qrdbsdk.PageQuery) (qrdbsdk.PageResult[*entities.ACMEAuthorization], error) {
	args := m.Called(ctx, fieldName, value, query)
	return args.Get(0).(qrdbsdk.PageResult[*entities.ACMEAuthorization]), args.Error(1)
}

// CountByIndex mocks the CountByIndex method.
func (m *MockAuthorizationDAO) CountByIndex(ctx context.Context, fieldName string, value interface{}) (int, error) {
	args := m.Called(ctx, fieldName, value)
	return args.Int(0), args.Error(1)
}

// Find mocks the Find method.
func (m *MockAuthorizationDAO) Find(ctx context.Context) *qrdbsdk.QueryBuilder[*entities.ACMEAuthorization] {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*qrdbsdk.QueryBuilder[*entities.ACMEAuthorization])
}

// ========================================================================
// MockChallengeDAO
// ========================================================================

// MockChallengeDAO is a testify mock implementation of qrdbsdk.GenericDAO[*entities.ACMEChallenge].
type MockChallengeDAO struct {
	mock.Mock
}

// Compile-time interface check.
var _ qrdbsdk.GenericDAO[*entities.ACMEChallenge] = (*MockChallengeDAO)(nil)

// Save mocks the Save method.
func (m *MockChallengeDAO) Save(ctx context.Context, entity *entities.ACMEChallenge) error {
	args := m.Called(ctx, entity)
	return args.Error(0)
}

// SaveWithCondition mocks the SaveWithCondition method.
func (m *MockChallengeDAO) SaveWithCondition(ctx context.Context, entity *entities.ACMEChallenge, cond qrdbsdk.Condition) error {
	args := m.Called(ctx, entity, cond)
	return args.Error(0)
}

// Get mocks the Get method.
func (m *MockChallengeDAO) Get(ctx context.Context, id uint64) (*entities.ACMEChallenge, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.ACMEChallenge), args.Error(1)
}

// Delete mocks the Delete method.
func (m *MockChallengeDAO) Delete(ctx context.Context, entity *entities.ACMEChallenge) error {
	args := m.Called(ctx, entity)
	return args.Error(0)
}

// Count mocks the Count method.
func (m *MockChallengeDAO) Count(ctx context.Context) (int, error) {
	args := m.Called(ctx)
	return args.Int(0), args.Error(1)
}

// Page mocks the Page method.
func (m *MockChallengeDAO) Page(ctx context.Context, query qrdbsdk.PageQuery) (qrdbsdk.PageResult[*entities.ACMEChallenge], error) {
	args := m.Called(ctx, query)
	return args.Get(0).(qrdbsdk.PageResult[*entities.ACMEChallenge]), args.Error(1)
}

// ForEachPage mocks the ForEachPage method.
func (m *MockChallengeDAO) ForEachPage(ctx context.Context, query qrdbsdk.PageQuery, fn qrdbsdk.PagerFunc[*entities.ACMEChallenge]) error {
	args := m.Called(ctx, query, fn)
	return args.Error(0)
}

// EntityType mocks the EntityType method.
func (m *MockChallengeDAO) EntityType() string {
	args := m.Called()
	return args.String(0)
}

// QueryByIndex mocks the QueryByIndex method.
func (m *MockChallengeDAO) QueryByIndex(ctx context.Context, fieldName string, value interface{}) ([]*entities.ACMEChallenge, error) {
	args := m.Called(ctx, fieldName, value)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*entities.ACMEChallenge), args.Error(1)
}

// QueryByCompoundIndex mocks the QueryByCompoundIndex method.
func (m *MockChallengeDAO) QueryByCompoundIndex(ctx context.Context, indexName string, fieldValues []interface{}) ([]*entities.ACMEChallenge, error) {
	args := m.Called(ctx, indexName, fieldValues)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*entities.ACMEChallenge), args.Error(1)
}

// QueryOneByIndex mocks the QueryOneByIndex method.
func (m *MockChallengeDAO) QueryOneByIndex(ctx context.Context, fieldName string, value interface{}) (*entities.ACMEChallenge, error) {
	args := m.Called(ctx, fieldName, value)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.ACMEChallenge), args.Error(1)
}

// ScanByIndex mocks the ScanByIndex method.
func (m *MockChallengeDAO) ScanByIndex(ctx context.Context, fieldName string, start, end interface{}) ([]*entities.ACMEChallenge, error) {
	args := m.Called(ctx, fieldName, start, end)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*entities.ACMEChallenge), args.Error(1)
}

// ScanByCompoundIndex mocks the ScanByCompoundIndex method.
func (m *MockChallengeDAO) ScanByCompoundIndex(ctx context.Context, indexName string, prefixValues []interface{}, rangeStart, rangeEnd interface{}) ([]*entities.ACMEChallenge, error) {
	args := m.Called(ctx, indexName, prefixValues, rangeStart, rangeEnd)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*entities.ACMEChallenge), args.Error(1)
}

// PageByIndex mocks the PageByIndex method.
func (m *MockChallengeDAO) PageByIndex(ctx context.Context, fieldName string, value interface{}, query qrdbsdk.PageQuery) (qrdbsdk.PageResult[*entities.ACMEChallenge], error) {
	args := m.Called(ctx, fieldName, value, query)
	return args.Get(0).(qrdbsdk.PageResult[*entities.ACMEChallenge]), args.Error(1)
}

// CountByIndex mocks the CountByIndex method.
func (m *MockChallengeDAO) CountByIndex(ctx context.Context, fieldName string, value interface{}) (int, error) {
	args := m.Called(ctx, fieldName, value)
	return args.Int(0), args.Error(1)
}

// Find mocks the Find method.
func (m *MockChallengeDAO) Find(ctx context.Context) *qrdbsdk.QueryBuilder[*entities.ACMEChallenge] {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*qrdbsdk.QueryBuilder[*entities.ACMEChallenge])
}

// ========================================================================
// MockCertificateDAO
// ========================================================================

// MockCertificateDAO is a testify mock implementation of qrdbsdk.GenericDAO[*entities.ACMECertificate].
type MockCertificateDAO struct {
	mock.Mock
}

// Compile-time interface check.
var _ qrdbsdk.GenericDAO[*entities.ACMECertificate] = (*MockCertificateDAO)(nil)

// Save mocks the Save method.
func (m *MockCertificateDAO) Save(ctx context.Context, entity *entities.ACMECertificate) error {
	args := m.Called(ctx, entity)
	return args.Error(0)
}

// SaveWithCondition mocks the SaveWithCondition method.
func (m *MockCertificateDAO) SaveWithCondition(ctx context.Context, entity *entities.ACMECertificate, cond qrdbsdk.Condition) error {
	args := m.Called(ctx, entity, cond)
	return args.Error(0)
}

// Get mocks the Get method.
func (m *MockCertificateDAO) Get(ctx context.Context, id uint64) (*entities.ACMECertificate, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.ACMECertificate), args.Error(1)
}

// Delete mocks the Delete method.
func (m *MockCertificateDAO) Delete(ctx context.Context, entity *entities.ACMECertificate) error {
	args := m.Called(ctx, entity)
	return args.Error(0)
}

// Count mocks the Count method.
func (m *MockCertificateDAO) Count(ctx context.Context) (int, error) {
	args := m.Called(ctx)
	return args.Int(0), args.Error(1)
}

// Page mocks the Page method.
func (m *MockCertificateDAO) Page(ctx context.Context, query qrdbsdk.PageQuery) (qrdbsdk.PageResult[*entities.ACMECertificate], error) {
	args := m.Called(ctx, query)
	return args.Get(0).(qrdbsdk.PageResult[*entities.ACMECertificate]), args.Error(1)
}

// ForEachPage mocks the ForEachPage method.
func (m *MockCertificateDAO) ForEachPage(ctx context.Context, query qrdbsdk.PageQuery, fn qrdbsdk.PagerFunc[*entities.ACMECertificate]) error {
	args := m.Called(ctx, query, fn)
	return args.Error(0)
}

// EntityType mocks the EntityType method.
func (m *MockCertificateDAO) EntityType() string {
	args := m.Called()
	return args.String(0)
}

// QueryByIndex mocks the QueryByIndex method.
func (m *MockCertificateDAO) QueryByIndex(ctx context.Context, fieldName string, value interface{}) ([]*entities.ACMECertificate, error) {
	args := m.Called(ctx, fieldName, value)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*entities.ACMECertificate), args.Error(1)
}

// QueryByCompoundIndex mocks the QueryByCompoundIndex method.
func (m *MockCertificateDAO) QueryByCompoundIndex(ctx context.Context, indexName string, fieldValues []interface{}) ([]*entities.ACMECertificate, error) {
	args := m.Called(ctx, indexName, fieldValues)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*entities.ACMECertificate), args.Error(1)
}

// QueryOneByIndex mocks the QueryOneByIndex method.
func (m *MockCertificateDAO) QueryOneByIndex(ctx context.Context, fieldName string, value interface{}) (*entities.ACMECertificate, error) {
	args := m.Called(ctx, fieldName, value)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.ACMECertificate), args.Error(1)
}

// ScanByIndex mocks the ScanByIndex method.
func (m *MockCertificateDAO) ScanByIndex(ctx context.Context, fieldName string, start, end interface{}) ([]*entities.ACMECertificate, error) {
	args := m.Called(ctx, fieldName, start, end)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*entities.ACMECertificate), args.Error(1)
}

// ScanByCompoundIndex mocks the ScanByCompoundIndex method.
func (m *MockCertificateDAO) ScanByCompoundIndex(ctx context.Context, indexName string, prefixValues []interface{}, rangeStart, rangeEnd interface{}) ([]*entities.ACMECertificate, error) {
	args := m.Called(ctx, indexName, prefixValues, rangeStart, rangeEnd)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*entities.ACMECertificate), args.Error(1)
}

// PageByIndex mocks the PageByIndex method.
func (m *MockCertificateDAO) PageByIndex(ctx context.Context, fieldName string, value interface{}, query qrdbsdk.PageQuery) (qrdbsdk.PageResult[*entities.ACMECertificate], error) {
	args := m.Called(ctx, fieldName, value, query)
	return args.Get(0).(qrdbsdk.PageResult[*entities.ACMECertificate]), args.Error(1)
}

// CountByIndex mocks the CountByIndex method.
func (m *MockCertificateDAO) CountByIndex(ctx context.Context, fieldName string, value interface{}) (int, error) {
	args := m.Called(ctx, fieldName, value)
	return args.Int(0), args.Error(1)
}

// Find mocks the Find method.
func (m *MockCertificateDAO) Find(ctx context.Context) *qrdbsdk.QueryBuilder[*entities.ACMECertificate] {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*qrdbsdk.QueryBuilder[*entities.ACMECertificate])
}

// ========================================================================
// MockNonceDAO
// ========================================================================

// MockNonceDAO is a testify mock implementation of qrdbsdk.GenericDAO[*entities.ACMENonce].
type MockNonceDAO struct {
	mock.Mock
}

// Compile-time interface check.
var _ qrdbsdk.GenericDAO[*entities.ACMENonce] = (*MockNonceDAO)(nil)

// Save mocks the Save method.
func (m *MockNonceDAO) Save(ctx context.Context, entity *entities.ACMENonce) error {
	args := m.Called(ctx, entity)
	return args.Error(0)
}

// SaveWithCondition mocks the SaveWithCondition method.
func (m *MockNonceDAO) SaveWithCondition(ctx context.Context, entity *entities.ACMENonce, cond qrdbsdk.Condition) error {
	args := m.Called(ctx, entity, cond)
	return args.Error(0)
}

// Get mocks the Get method.
func (m *MockNonceDAO) Get(ctx context.Context, id uint64) (*entities.ACMENonce, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.ACMENonce), args.Error(1)
}

// Delete mocks the Delete method.
func (m *MockNonceDAO) Delete(ctx context.Context, entity *entities.ACMENonce) error {
	args := m.Called(ctx, entity)
	return args.Error(0)
}

// Count mocks the Count method.
func (m *MockNonceDAO) Count(ctx context.Context) (int, error) {
	args := m.Called(ctx)
	return args.Int(0), args.Error(1)
}

// Page mocks the Page method.
func (m *MockNonceDAO) Page(ctx context.Context, query qrdbsdk.PageQuery) (qrdbsdk.PageResult[*entities.ACMENonce], error) {
	args := m.Called(ctx, query)
	return args.Get(0).(qrdbsdk.PageResult[*entities.ACMENonce]), args.Error(1)
}

// ForEachPage mocks the ForEachPage method.
func (m *MockNonceDAO) ForEachPage(ctx context.Context, query qrdbsdk.PageQuery, fn qrdbsdk.PagerFunc[*entities.ACMENonce]) error {
	args := m.Called(ctx, query, fn)
	return args.Error(0)
}

// EntityType mocks the EntityType method.
func (m *MockNonceDAO) EntityType() string {
	args := m.Called()
	return args.String(0)
}

// QueryByIndex mocks the QueryByIndex method.
func (m *MockNonceDAO) QueryByIndex(ctx context.Context, fieldName string, value interface{}) ([]*entities.ACMENonce, error) {
	args := m.Called(ctx, fieldName, value)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*entities.ACMENonce), args.Error(1)
}

// QueryByCompoundIndex mocks the QueryByCompoundIndex method.
func (m *MockNonceDAO) QueryByCompoundIndex(ctx context.Context, indexName string, fieldValues []interface{}) ([]*entities.ACMENonce, error) {
	args := m.Called(ctx, indexName, fieldValues)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*entities.ACMENonce), args.Error(1)
}

// QueryOneByIndex mocks the QueryOneByIndex method.
func (m *MockNonceDAO) QueryOneByIndex(ctx context.Context, fieldName string, value interface{}) (*entities.ACMENonce, error) {
	args := m.Called(ctx, fieldName, value)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.ACMENonce), args.Error(1)
}

// ScanByIndex mocks the ScanByIndex method.
func (m *MockNonceDAO) ScanByIndex(ctx context.Context, fieldName string, start, end interface{}) ([]*entities.ACMENonce, error) {
	args := m.Called(ctx, fieldName, start, end)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*entities.ACMENonce), args.Error(1)
}

// ScanByCompoundIndex mocks the ScanByCompoundIndex method.
func (m *MockNonceDAO) ScanByCompoundIndex(ctx context.Context, indexName string, prefixValues []interface{}, rangeStart, rangeEnd interface{}) ([]*entities.ACMENonce, error) {
	args := m.Called(ctx, indexName, prefixValues, rangeStart, rangeEnd)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*entities.ACMENonce), args.Error(1)
}

// PageByIndex mocks the PageByIndex method.
func (m *MockNonceDAO) PageByIndex(ctx context.Context, fieldName string, value interface{}, query qrdbsdk.PageQuery) (qrdbsdk.PageResult[*entities.ACMENonce], error) {
	args := m.Called(ctx, fieldName, value, query)
	return args.Get(0).(qrdbsdk.PageResult[*entities.ACMENonce]), args.Error(1)
}

// CountByIndex mocks the CountByIndex method.
func (m *MockNonceDAO) CountByIndex(ctx context.Context, fieldName string, value interface{}) (int, error) {
	args := m.Called(ctx, fieldName, value)
	return args.Int(0), args.Error(1)
}

// Find mocks the Find method.
func (m *MockNonceDAO) Find(ctx context.Context) *qrdbsdk.QueryBuilder[*entities.ACMENonce] {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*qrdbsdk.QueryBuilder[*entities.ACMENonce])
}

// ========================================================================
// MockExternalAccountBindingDAO
// ========================================================================

// MockExternalAccountBindingDAO is a testify mock implementation of
// qrdbsdk.GenericDAO[*entities.ExternalAccountBinding].
type MockExternalAccountBindingDAO struct {
	mock.Mock
}

// Compile-time interface check.
var _ qrdbsdk.GenericDAO[*entities.ExternalAccountBinding] = (*MockExternalAccountBindingDAO)(nil)

// Save mocks the Save method.
func (m *MockExternalAccountBindingDAO) Save(ctx context.Context, entity *entities.ExternalAccountBinding) error {
	args := m.Called(ctx, entity)
	return args.Error(0)
}

// SaveWithCondition mocks the SaveWithCondition method.
func (m *MockExternalAccountBindingDAO) SaveWithCondition(ctx context.Context, entity *entities.ExternalAccountBinding, cond qrdbsdk.Condition) error {
	args := m.Called(ctx, entity, cond)
	return args.Error(0)
}

// Get mocks the Get method.
func (m *MockExternalAccountBindingDAO) Get(ctx context.Context, id uint64) (*entities.ExternalAccountBinding, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.ExternalAccountBinding), args.Error(1)
}

// Delete mocks the Delete method.
func (m *MockExternalAccountBindingDAO) Delete(ctx context.Context, entity *entities.ExternalAccountBinding) error {
	args := m.Called(ctx, entity)
	return args.Error(0)
}

// Count mocks the Count method.
func (m *MockExternalAccountBindingDAO) Count(ctx context.Context) (int, error) {
	args := m.Called(ctx)
	return args.Int(0), args.Error(1)
}

// Page mocks the Page method.
func (m *MockExternalAccountBindingDAO) Page(ctx context.Context, query qrdbsdk.PageQuery) (qrdbsdk.PageResult[*entities.ExternalAccountBinding], error) {
	args := m.Called(ctx, query)
	return args.Get(0).(qrdbsdk.PageResult[*entities.ExternalAccountBinding]), args.Error(1)
}

// ForEachPage mocks the ForEachPage method.
func (m *MockExternalAccountBindingDAO) ForEachPage(ctx context.Context, query qrdbsdk.PageQuery, fn qrdbsdk.PagerFunc[*entities.ExternalAccountBinding]) error {
	args := m.Called(ctx, query, fn)
	return args.Error(0)
}

// EntityType mocks the EntityType method.
func (m *MockExternalAccountBindingDAO) EntityType() string {
	args := m.Called()
	return args.String(0)
}

// QueryByIndex mocks the QueryByIndex method.
func (m *MockExternalAccountBindingDAO) QueryByIndex(ctx context.Context, fieldName string, value interface{}) ([]*entities.ExternalAccountBinding, error) {
	args := m.Called(ctx, fieldName, value)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*entities.ExternalAccountBinding), args.Error(1)
}

// QueryByCompoundIndex mocks the QueryByCompoundIndex method.
func (m *MockExternalAccountBindingDAO) QueryByCompoundIndex(ctx context.Context, indexName string, fieldValues []interface{}) ([]*entities.ExternalAccountBinding, error) {
	args := m.Called(ctx, indexName, fieldValues)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*entities.ExternalAccountBinding), args.Error(1)
}

// QueryOneByIndex mocks the QueryOneByIndex method.
func (m *MockExternalAccountBindingDAO) QueryOneByIndex(ctx context.Context, fieldName string, value interface{}) (*entities.ExternalAccountBinding, error) {
	args := m.Called(ctx, fieldName, value)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.ExternalAccountBinding), args.Error(1)
}

// ScanByIndex mocks the ScanByIndex method.
func (m *MockExternalAccountBindingDAO) ScanByIndex(ctx context.Context, fieldName string, start, end interface{}) ([]*entities.ExternalAccountBinding, error) {
	args := m.Called(ctx, fieldName, start, end)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*entities.ExternalAccountBinding), args.Error(1)
}

// ScanByCompoundIndex mocks the ScanByCompoundIndex method.
func (m *MockExternalAccountBindingDAO) ScanByCompoundIndex(ctx context.Context, indexName string, prefixValues []interface{}, rangeStart, rangeEnd interface{}) ([]*entities.ExternalAccountBinding, error) {
	args := m.Called(ctx, indexName, prefixValues, rangeStart, rangeEnd)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*entities.ExternalAccountBinding), args.Error(1)
}

// PageByIndex mocks the PageByIndex method.
func (m *MockExternalAccountBindingDAO) PageByIndex(ctx context.Context, fieldName string, value interface{}, query qrdbsdk.PageQuery) (qrdbsdk.PageResult[*entities.ExternalAccountBinding], error) {
	args := m.Called(ctx, fieldName, value, query)
	return args.Get(0).(qrdbsdk.PageResult[*entities.ExternalAccountBinding]), args.Error(1)
}

// CountByIndex mocks the CountByIndex method.
func (m *MockExternalAccountBindingDAO) CountByIndex(ctx context.Context, fieldName string, value interface{}) (int, error) {
	args := m.Called(ctx, fieldName, value)
	return args.Int(0), args.Error(1)
}

// Find mocks the Find method.
func (m *MockExternalAccountBindingDAO) Find(ctx context.Context) *qrdbsdk.QueryBuilder[*entities.ExternalAccountBinding] {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*qrdbsdk.QueryBuilder[*entities.ExternalAccountBinding])
}

// ========================================================================
// MockTenantDAO
// ========================================================================

// MockTenantDAO is a testify mock implementation of qrdbsdk.GenericDAO[*entities.Tenant].
type MockTenantDAO struct {
	mock.Mock
}

// Compile-time interface check.
var _ qrdbsdk.GenericDAO[*entities.Tenant] = (*MockTenantDAO)(nil)

// Save mocks the Save method.
func (m *MockTenantDAO) Save(ctx context.Context, entity *entities.Tenant) error {
	args := m.Called(ctx, entity)
	return args.Error(0)
}

// SaveWithCondition mocks the SaveWithCondition method.
func (m *MockTenantDAO) SaveWithCondition(ctx context.Context, entity *entities.Tenant, cond qrdbsdk.Condition) error {
	args := m.Called(ctx, entity, cond)
	return args.Error(0)
}

// Get mocks the Get method.
func (m *MockTenantDAO) Get(ctx context.Context, id uint64) (*entities.Tenant, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.Tenant), args.Error(1)
}

// Delete mocks the Delete method.
func (m *MockTenantDAO) Delete(ctx context.Context, entity *entities.Tenant) error {
	args := m.Called(ctx, entity)
	return args.Error(0)
}

// Count mocks the Count method.
func (m *MockTenantDAO) Count(ctx context.Context) (int, error) {
	args := m.Called(ctx)
	return args.Int(0), args.Error(1)
}

// Page mocks the Page method.
func (m *MockTenantDAO) Page(ctx context.Context, query qrdbsdk.PageQuery) (qrdbsdk.PageResult[*entities.Tenant], error) {
	args := m.Called(ctx, query)
	return args.Get(0).(qrdbsdk.PageResult[*entities.Tenant]), args.Error(1)
}

// ForEachPage mocks the ForEachPage method.
func (m *MockTenantDAO) ForEachPage(ctx context.Context, query qrdbsdk.PageQuery, fn qrdbsdk.PagerFunc[*entities.Tenant]) error {
	args := m.Called(ctx, query, fn)
	return args.Error(0)
}

// EntityType mocks the EntityType method.
func (m *MockTenantDAO) EntityType() string {
	args := m.Called()
	return args.String(0)
}

// QueryByIndex mocks the QueryByIndex method.
func (m *MockTenantDAO) QueryByIndex(ctx context.Context, fieldName string, value interface{}) ([]*entities.Tenant, error) {
	args := m.Called(ctx, fieldName, value)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*entities.Tenant), args.Error(1)
}

// QueryByCompoundIndex mocks the QueryByCompoundIndex method.
func (m *MockTenantDAO) QueryByCompoundIndex(ctx context.Context, indexName string, fieldValues []interface{}) ([]*entities.Tenant, error) {
	args := m.Called(ctx, indexName, fieldValues)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*entities.Tenant), args.Error(1)
}

// QueryOneByIndex mocks the QueryOneByIndex method.
func (m *MockTenantDAO) QueryOneByIndex(ctx context.Context, fieldName string, value interface{}) (*entities.Tenant, error) {
	args := m.Called(ctx, fieldName, value)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.Tenant), args.Error(1)
}

// ScanByIndex mocks the ScanByIndex method.
func (m *MockTenantDAO) ScanByIndex(ctx context.Context, fieldName string, start, end interface{}) ([]*entities.Tenant, error) {
	args := m.Called(ctx, fieldName, start, end)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*entities.Tenant), args.Error(1)
}

// ScanByCompoundIndex mocks the ScanByCompoundIndex method.
func (m *MockTenantDAO) ScanByCompoundIndex(ctx context.Context, indexName string, prefixValues []interface{}, rangeStart, rangeEnd interface{}) ([]*entities.Tenant, error) {
	args := m.Called(ctx, indexName, prefixValues, rangeStart, rangeEnd)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*entities.Tenant), args.Error(1)
}

// PageByIndex mocks the PageByIndex method.
func (m *MockTenantDAO) PageByIndex(ctx context.Context, fieldName string, value interface{}, query qrdbsdk.PageQuery) (qrdbsdk.PageResult[*entities.Tenant], error) {
	args := m.Called(ctx, fieldName, value, query)
	return args.Get(0).(qrdbsdk.PageResult[*entities.Tenant]), args.Error(1)
}

// CountByIndex mocks the CountByIndex method.
func (m *MockTenantDAO) CountByIndex(ctx context.Context, fieldName string, value interface{}) (int, error) {
	args := m.Called(ctx, fieldName, value)
	return args.Int(0), args.Error(1)
}

// Find mocks the Find method.
func (m *MockTenantDAO) Find(ctx context.Context) *qrdbsdk.QueryBuilder[*entities.Tenant] {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*qrdbsdk.QueryBuilder[*entities.Tenant])
}

// ========================================================================
// MockStorageFactory
// ========================================================================

// MockStorageFactory is a testify mock implementation of storage.Factory.
type MockStorageFactory struct {
	mock.Mock
}

// Compile-time interface check.
var _ storage.Factory = (*MockStorageFactory)(nil)

// AccountDAO mocks the AccountDAO method.
func (m *MockStorageFactory) AccountDAO() (qrdbsdk.GenericDAO[*entities.ACMEAccount], error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(qrdbsdk.GenericDAO[*entities.ACMEAccount]), args.Error(1)
}

// OrderDAO mocks the OrderDAO method.
func (m *MockStorageFactory) OrderDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEOrder], error) {
	args := m.Called(accountID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(qrdbsdk.GenericDAO[*entities.ACMEOrder]), args.Error(1)
}

// AuthorizationDAO mocks the AuthorizationDAO method.
func (m *MockStorageFactory) AuthorizationDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEAuthorization], error) {
	args := m.Called(accountID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(qrdbsdk.GenericDAO[*entities.ACMEAuthorization]), args.Error(1)
}

// ChallengeDAO mocks the ChallengeDAO method.
func (m *MockStorageFactory) ChallengeDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEChallenge], error) {
	args := m.Called(accountID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(qrdbsdk.GenericDAO[*entities.ACMEChallenge]), args.Error(1)
}

// CertificateDAO mocks the CertificateDAO method.
func (m *MockStorageFactory) CertificateDAO() (qrdbsdk.GenericDAO[*entities.ACMECertificate], error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(qrdbsdk.GenericDAO[*entities.ACMECertificate]), args.Error(1)
}

// NonceDAO mocks the NonceDAO method.
func (m *MockStorageFactory) NonceDAO() (qrdbsdk.GenericDAO[*entities.ACMENonce], error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(qrdbsdk.GenericDAO[*entities.ACMENonce]), args.Error(1)
}

// ExternalAccountBindingDAO mocks the ExternalAccountBindingDAO method.
func (m *MockStorageFactory) ExternalAccountBindingDAO() (qrdbsdk.GenericDAO[*entities.ExternalAccountBinding], error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(qrdbsdk.GenericDAO[*entities.ExternalAccountBinding]), args.Error(1)
}

// ========================================================================
// MockTenantAwareStorageFactory
// ========================================================================

// MockTenantAwareStorageFactory is a testify mock implementation of storage.TenantAwareFactory.
type MockTenantAwareStorageFactory struct {
	MockStorageFactory
}

// Compile-time interface check.
var _ storage.TenantAwareFactory = (*MockTenantAwareStorageFactory)(nil)

// TenantDAO mocks the TenantDAO method.
func (m *MockTenantAwareStorageFactory) TenantDAO() (qrdbsdk.GenericDAO[*entities.Tenant], error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(qrdbsdk.GenericDAO[*entities.Tenant]), args.Error(1)
}

// ForTenant mocks the ForTenant method.
func (m *MockTenantAwareStorageFactory) ForTenant(tenantID string) (storage.Factory, error) {
	args := m.Called(tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(storage.Factory), args.Error(1)
}

// GetTenantID mocks the GetTenantID method.
func (m *MockTenantAwareStorageFactory) GetTenantID() string {
	args := m.Called()
	return args.String(0)
}
