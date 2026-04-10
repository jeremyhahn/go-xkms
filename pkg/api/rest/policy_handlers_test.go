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

package rest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jeremyhahn/go-xkms/pkg/seal/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockPCRReader implements policy.PCRReader for testing.
type mockPCRReader struct {
	values map[int][]byte
	err    error
}

func (m *mockPCRReader) ReadPCRs(_ string, indices []int) (map[int][]byte, error) {
	if m.err != nil {
		return nil, m.err
	}
	result := make(map[int][]byte, len(indices))
	for _, idx := range indices {
		if val, ok := m.values[idx]; ok {
			result[idx] = val
		} else {
			result[idx] = make([]byte, 32) // zero-filled
		}
	}
	return result, nil
}

// mockPolicyStore implements policy.PolicyStore for testing.
type mockPolicyStore struct {
	policies map[string]*policy.PolicyDefinition
}

func newMockPolicyStore() *mockPolicyStore {
	return &mockPolicyStore{policies: make(map[string]*policy.PolicyDefinition)}
}

func (m *mockPolicyStore) SavePolicy(name string, def *policy.PolicyDefinition) error {
	m.policies[name] = def
	return nil
}

func (m *mockPolicyStore) LoadPolicy(name string) (*policy.PolicyDefinition, error) {
	def, ok := m.policies[name]
	if !ok {
		return nil, policy.ErrPolicyNotFound
	}
	return def, nil
}

func (m *mockPolicyStore) DeletePolicy(name string) error {
	if _, ok := m.policies[name]; !ok {
		return policy.ErrPolicyNotFound
	}
	delete(m.policies, name)
	return nil
}

func (m *mockPolicyStore) ListPolicies() ([]*policy.PolicyDefinition, error) {
	defs := make([]*policy.PolicyDefinition, 0, len(m.policies))
	for _, def := range m.policies {
		defs = append(defs, def)
	}
	return defs, nil
}

func newTestPolicyHandlers(t *testing.T) (*PolicyHandlers, *mockPolicyStore) {
	t.Helper()
	store := newMockPolicyStore()
	reader := &mockPCRReader{
		values: map[int][]byte{
			0: make([]byte, 32),
			1: make([]byte, 32),
			7: make([]byte, 32),
		},
	}
	mgr, err := policy.NewManager(reader, store)
	require.NoError(t, err)
	return NewPolicyHandlers(mgr), store
}

func policyRouter(h *PolicyHandlers) *chi.Mux {
	r := chi.NewRouter()
	r.Post("/api/v1/policies", h.CreatePolicyHandler)
	r.Get("/api/v1/policies", h.ListPoliciesHandler)
	r.Get("/api/v1/policies/{name}", h.GetPolicyHandler)
	r.Delete("/api/v1/policies/{name}", h.DeletePolicyHandler)
	r.Post("/api/v1/policies/{name}/refresh", h.RefreshPolicyHandler)
	r.Post("/api/v1/policies/{name}/verify", h.VerifyPolicyHandler)
	r.Get("/api/v1/policies/{name}/export", h.ExportPolicyHandler)
	return r
}

// --- CreatePolicyHandler ---

func TestPolicy_CreatePolicy_Success(t *testing.T) {
	h, _ := newTestPolicyHandlers(t)
	r := policyRouter(h)

	body := `{"name":"boot","bank":"sha256","pcr_indices":[0,1,7]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies",
		strings.NewReader(body))
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	var resp PolicyCreateResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "boot", resp.Name)
	assert.Equal(t, "sha256", resp.Bank)
}

func TestPolicy_CreatePolicy_InvalidJSON(t *testing.T) {
	h, _ := newTestPolicyHandlers(t)
	r := policyRouter(h)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies",
		strings.NewReader(`{bad`))
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPolicy_CreatePolicy_EmptyName(t *testing.T) {
	h, _ := newTestPolicyHandlers(t)
	r := policyRouter(h)

	body := `{"name":"","bank":"sha256","pcr_indices":[0]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies",
		strings.NewReader(body))
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPolicy_CreatePolicy_EmptyBank(t *testing.T) {
	h, _ := newTestPolicyHandlers(t)
	r := policyRouter(h)

	body := `{"name":"boot","bank":"","pcr_indices":[0]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies",
		strings.NewReader(body))
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPolicy_CreatePolicy_UnsupportedBank(t *testing.T) {
	h, _ := newTestPolicyHandlers(t)
	r := policyRouter(h)

	body := `{"name":"boot","bank":"md5","pcr_indices":[0]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies",
		strings.NewReader(body))
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPolicy_CreatePolicy_NoPCRs(t *testing.T) {
	h, _ := newTestPolicyHandlers(t)
	r := policyRouter(h)

	body := `{"name":"boot","bank":"sha256","pcr_indices":[]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies",
		strings.NewReader(body))
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPolicy_CreatePolicy_PCROutOfRange(t *testing.T) {
	h, _ := newTestPolicyHandlers(t)
	r := policyRouter(h)

	body := `{"name":"boot","bank":"sha256","pcr_indices":[99]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies",
		strings.NewReader(body))
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPolicy_CreatePolicy_DuplicatePCR(t *testing.T) {
	h, _ := newTestPolicyHandlers(t)
	r := policyRouter(h)

	body := `{"name":"boot","bank":"sha256","pcr_indices":[0,0]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies",
		strings.NewReader(body))
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPolicy_CreatePolicy_Duplicate(t *testing.T) {
	h, _ := newTestPolicyHandlers(t)
	r := policyRouter(h)

	body := `{"name":"boot","bank":"sha256","pcr_indices":[0]}`

	// First create.
	req1 := httptest.NewRequest(http.MethodPost, "/api/v1/policies",
		strings.NewReader(body))
	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, req1)
	require.Equal(t, http.StatusCreated, w1.Code)

	// Duplicate.
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/policies",
		strings.NewReader(body))
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)

	assert.Equal(t, http.StatusConflict, w2.Code)
}

// --- ListPoliciesHandler ---

func TestPolicy_ListPolicies_Success(t *testing.T) {
	h, _ := newTestPolicyHandlers(t)
	r := policyRouter(h)

	// Create two policies.
	for _, name := range []string{"pol1", "pol2"} {
		body := `{"name":"` + name + `","bank":"sha256","pcr_indices":[0]}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/policies",
			strings.NewReader(body))
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		require.Equal(t, http.StatusCreated, w.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/policies", nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp PolicyListResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, 2, resp.Total)
}

// --- GetPolicyHandler ---

func TestPolicy_GetPolicy_Success(t *testing.T) {
	h, store := newTestPolicyHandlers(t)
	r := policyRouter(h)

	store.policies["boot"] = &policy.PolicyDefinition{
		Name:       "boot",
		Bank:       "sha256",
		PCRIndices: []int{0, 1},
		PCRValues:  map[int][]byte{0: {1}, 1: {2}},
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/policies/boot", nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp PolicyGetResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "boot", resp.Name)
}

func TestPolicy_GetPolicy_NotFound(t *testing.T) {
	h, _ := newTestPolicyHandlers(t)
	r := policyRouter(h)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/policies/ghost", nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestPolicy_GetPolicy_MissingName(t *testing.T) {
	h, _ := newTestPolicyHandlers(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/policies/", nil)
	w := httptest.NewRecorder()

	h.GetPolicyHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// --- DeletePolicyHandler ---

func TestPolicy_DeletePolicy_Success(t *testing.T) {
	h, store := newTestPolicyHandlers(t)
	r := policyRouter(h)

	store.policies["temp"] = &policy.PolicyDefinition{Name: "temp"}

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/policies/temp", nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestPolicy_DeletePolicy_NotFound(t *testing.T) {
	h, _ := newTestPolicyHandlers(t)
	r := policyRouter(h)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/policies/ghost", nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestPolicy_DeletePolicy_MissingName(t *testing.T) {
	h, _ := newTestPolicyHandlers(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/policies/", nil)
	w := httptest.NewRecorder()

	h.DeletePolicyHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// --- RefreshPolicyHandler ---

func TestPolicy_RefreshPolicy_Success(t *testing.T) {
	h, store := newTestPolicyHandlers(t)
	r := policyRouter(h)

	store.policies["boot"] = &policy.PolicyDefinition{
		Name:       "boot",
		Bank:       "sha256",
		PCRIndices: []int{0},
		PCRValues:  map[int][]byte{0: {1}},
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies/boot/refresh", nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp PolicyRefreshResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "boot", resp.Name)
}

func TestPolicy_RefreshPolicy_NotFound(t *testing.T) {
	h, _ := newTestPolicyHandlers(t)
	r := policyRouter(h)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies/ghost/refresh", nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestPolicy_RefreshPolicy_MissingName(t *testing.T) {
	h, _ := newTestPolicyHandlers(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies//refresh", nil)
	w := httptest.NewRecorder()

	h.RefreshPolicyHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// --- VerifyPolicyHandler ---

func TestPolicy_VerifyPolicy_Success(t *testing.T) {
	h, store := newTestPolicyHandlers(t)
	r := policyRouter(h)

	store.policies["boot"] = &policy.PolicyDefinition{
		Name:       "boot",
		Bank:       "sha256",
		PCRIndices: []int{0},
		PCRValues:  map[int][]byte{0: make([]byte, 32)},
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies/boot/verify", nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp PolicyVerifyResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Valid)
}

func TestPolicy_VerifyPolicy_Mismatch(t *testing.T) {
	h, store := newTestPolicyHandlers(t)
	r := policyRouter(h)

	store.policies["boot"] = &policy.PolicyDefinition{
		Name:       "boot",
		Bank:       "sha256",
		PCRIndices: []int{0},
		PCRValues:  map[int][]byte{0: {0xff, 0xfe}}, // Mismatched values.
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies/boot/verify", nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp PolicyVerifyResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.False(t, resp.Valid)
}

func TestPolicy_VerifyPolicy_NotFound(t *testing.T) {
	h, _ := newTestPolicyHandlers(t)
	r := policyRouter(h)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies/ghost/verify", nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestPolicy_VerifyPolicy_MissingName(t *testing.T) {
	h, _ := newTestPolicyHandlers(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies//verify", nil)
	w := httptest.NewRecorder()

	h.VerifyPolicyHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// --- ExportPolicyHandler ---

func TestPolicy_ExportPolicy_Success(t *testing.T) {
	h, store := newTestPolicyHandlers(t)
	r := policyRouter(h)

	store.policies["boot"] = &policy.PolicyDefinition{
		Name:       "boot",
		Bank:       "sha256",
		PCRIndices: []int{0},
		PCRValues:  map[int][]byte{0: {1}},
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/policies/boot/export", nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp PolicyExportResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "boot", resp.Name)
	assert.NotEmpty(t, resp.PolicyJSON)
}

func TestPolicy_ExportPolicy_NotFound(t *testing.T) {
	h, _ := newTestPolicyHandlers(t)
	r := policyRouter(h)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/policies/ghost/export", nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestPolicy_ExportPolicy_MissingName(t *testing.T) {
	h, _ := newTestPolicyHandlers(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/policies//export", nil)
	w := httptest.NewRecorder()

	h.ExportPolicyHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// --- policyWriteJSONError ---

func TestPolicyWriteJSONError(t *testing.T) {
	w := httptest.NewRecorder()
	policyWriteJSONError(w, "test error", http.StatusBadRequest)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "test error")
}
