//go:build codec_json

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

package handlers

import (
	"context"
	"errors"

	qrdbdao "github.com/jeremyhahn/go-qrdb/pkg/dao"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
)

// mockEABDAO is a mock implementation of GenericDAO[*entities.ExternalAccountBinding].
type mockEABDAO struct {
	bindings map[string]*entities.ExternalAccountBinding
	err      error
}

func newMockEABDAO() *mockEABDAO {
	return &mockEABDAO{
		bindings: make(map[string]*entities.ExternalAccountBinding),
	}
}

func (m *mockEABDAO) Save(_ context.Context, binding *entities.ExternalAccountBinding) error {
	if m.err != nil {
		return m.err
	}
	m.bindings[binding.ID] = binding
	return nil
}

func (m *mockEABDAO) SaveWithCondition(_ context.Context, _ *entities.ExternalAccountBinding, _ qrdbdao.Condition) error {
	panic("not implemented")
}

func (m *mockEABDAO) Get(_ context.Context, id uint64) (*entities.ExternalAccountBinding, error) {
	if m.err != nil {
		return nil, m.err
	}
	for _, b := range m.bindings {
		if b.EntityID() == id {
			return b, nil
		}
	}
	return nil, errors.New("external account binding not found")
}

func (m *mockEABDAO) Delete(_ context.Context, binding *entities.ExternalAccountBinding) error {
	if m.err != nil {
		return m.err
	}
	delete(m.bindings, binding.ID)
	return nil
}

func (m *mockEABDAO) Count(_ context.Context) (int, error) {
	return len(m.bindings), nil
}

func (m *mockEABDAO) Page(_ context.Context, _ qrdbsdk.PageQuery) (qrdbsdk.PageResult[*entities.ExternalAccountBinding], error) {
	panic("not implemented")
}

func (m *mockEABDAO) ForEachPage(_ context.Context, _ qrdbsdk.PageQuery, _ qrdbdao.PagerFunc[*entities.ExternalAccountBinding]) error {
	panic("not implemented")
}

func (m *mockEABDAO) EntityType() string {
	return "eab"
}

func (m *mockEABDAO) QueryByIndex(_ context.Context, fieldName string, value interface{}) ([]*entities.ExternalAccountBinding, error) {
	if m.err != nil {
		return nil, m.err
	}
	if fieldName == "ID" {
		kid, ok := value.(string)
		if ok {
			if b, found := m.bindings[kid]; found {
				return []*entities.ExternalAccountBinding{b}, nil
			}
		}
	}
	return nil, nil
}

func (m *mockEABDAO) QueryByCompoundIndex(_ context.Context, _ string, _ []interface{}) ([]*entities.ExternalAccountBinding, error) {
	return nil, nil
}

func (m *mockEABDAO) ScanByCompoundIndex(_ context.Context, _ string, _ []interface{}, _, _ interface{}) ([]*entities.ExternalAccountBinding, error) {
	return nil, nil
}

func (m *mockEABDAO) QueryOneByIndex(_ context.Context, fieldName string, value interface{}) (*entities.ExternalAccountBinding, error) {
	if m.err != nil {
		return nil, m.err
	}
	if fieldName == "ID" {
		kid, ok := value.(string)
		if ok {
			if b, found := m.bindings[kid]; found {
				return b, nil
			}
		}
	}
	return nil, errors.New("external account binding not found")
}

func (m *mockEABDAO) ScanByIndex(_ context.Context, _ string, _, _ interface{}) ([]*entities.ExternalAccountBinding, error) {
	panic("not implemented")
}

func (m *mockEABDAO) PageByIndex(_ context.Context, _ string, _ interface{}, _ qrdbsdk.PageQuery) (qrdbsdk.PageResult[*entities.ExternalAccountBinding], error) {
	panic("not implemented")
}

func (m *mockEABDAO) CountByIndex(_ context.Context, _ string, _ interface{}) (int, error) {
	panic("not implemented")
}

func (m *mockEABDAO) Find(_ context.Context) *qrdbdao.QueryBuilder[*entities.ExternalAccountBinding] {
	panic("not implemented")
}
