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
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/custodian"
)

// Custodian handler typed errors.
var (
	ErrCustodianNotConfigured = errors.New("rest: custodian service not configured")
	ErrMissingGroupID         = errors.New("rest: missing group_id")
	ErrMissingGroupName       = errors.New("rest: missing group name")
	ErrMissingUserID          = errors.New("rest: missing user_id")
	ErrInvalidThreshold       = errors.New("rest: threshold must be positive")
	ErrInvalidTotal           = errors.New("rest: total must be >= threshold")
)

// createCustodianGroupRequest represents the request body for creating a
// custodian group.
type createCustodianGroupRequest struct {
	ID        string `json:"id"`
	TenantID  string `json:"tenant_id,omitempty"`
	Name      string `json:"name"`
	Purpose   string `json:"purpose"`
	Threshold int    `json:"threshold"`
	Total     int    `json:"total"`
}

// addCustodianMemberRequest represents the request body for adding a member
// to a custodian group.
type addCustodianMemberRequest struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	Method   string `json:"method"`
}

// createCustodianGroupResponse wraps the created group for the SDK contract.
type createCustodianGroupResponse struct {
	Group *custodian.CustodianGroup `json:"group"`
}

// getCustodianGroupResponse wraps a single group for the SDK contract.
type getCustodianGroupResponse struct {
	Group *custodian.CustodianGroup `json:"group"`
}

// listCustodianGroupsResponse wraps the groups list for the SDK contract.
type listCustodianGroupsResponse struct {
	Groups     []*custodian.CustodianGroup `json:"groups"`
	Pagination transport.PageResponse      `json:"pagination"`
}

// addCustodianMemberResponse wraps the added member for the SDK contract.
type addCustodianMemberResponse struct {
	Member *custodian.CustodianMember `json:"member"`
}

// distributeSharesResponse represents the response for share distribution.
type distributeSharesResponse struct {
	Distributed int `json:"distributed"`
}

// CustodianHandlers holds the custodian service dependency for REST handlers.
type CustodianHandlers struct {
	service *custodian.Service
}

// NewCustodianHandlers creates a new CustodianHandlers with the given service.
func NewCustodianHandlers(service *custodian.Service) *CustodianHandlers {
	return &CustodianHandlers{service: service}
}

// CreateGroupHandler handles POST /custodian/groups requests.
// Creates a new custodian group with the specified M-of-N threshold parameters.
//
// Request body (JSON):
//
//	{
//	  "id": "string",
//	  "tenant_id": "string (optional)",
//	  "name": "string",
//	  "purpose": "string",
//	  "threshold": int,
//	  "total": int
//	}
func (h *CustodianHandlers) CreateGroupHandler(w http.ResponseWriter, r *http.Request) {
	if h.service == nil {
		writeError(w, ErrCustodianNotConfigured, http.StatusServiceUnavailable)
		return
	}

	var req createCustodianGroupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	if req.Name == "" {
		writeError(w, ErrMissingGroupName, http.StatusBadRequest)
		return
	}

	if req.Threshold < 1 {
		writeError(w, ErrInvalidThreshold, http.StatusBadRequest)
		return
	}

	if req.Total < req.Threshold {
		writeError(w, ErrInvalidTotal, http.StatusBadRequest)
		return
	}

	group, err := h.service.CreateGroup(r.Context(), req.ID, req.TenantID, req.Name, req.Purpose, req.Threshold, req.Total)
	if err != nil {
		handleCustodianError(w, err)
		return
	}

	writeJSON(w, createCustodianGroupResponse{Group: group}, http.StatusCreated)
}

// ListGroupsHandler handles GET /custodian/groups requests.
// Returns all custodian groups wrapped in a groups envelope.
func (h *CustodianHandlers) ListGroupsHandler(w http.ResponseWriter, r *http.Request) {
	if h.service == nil {
		writeError(w, ErrCustodianNotConfigured, http.StatusServiceUnavailable)
		return
	}

	groups, err := h.service.ListGroups(r.Context())
	if err != nil {
		handleCustodianError(w, err)
		return
	}

	pageReq := parsePageRequest(r)
	paged, pageResp := applyPagination(groups, pageReq)

	writeJSON(w, listCustodianGroupsResponse{Groups: paged, Pagination: pageResp}, http.StatusOK)
}

// GetGroupHandler handles GET /custodian/groups/{id} requests.
// Returns a single custodian group by its ID wrapped in a group envelope.
//
// URL parameters:
//   - id: custodian group identifier (required)
func (h *CustodianHandlers) GetGroupHandler(w http.ResponseWriter, r *http.Request) {
	if h.service == nil {
		writeError(w, ErrCustodianNotConfigured, http.StatusServiceUnavailable)
		return
	}

	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, ErrMissingGroupID, http.StatusBadRequest)
		return
	}

	group, err := h.service.GetGroup(r.Context(), id)
	if err != nil {
		handleCustodianError(w, err)
		return
	}

	writeJSON(w, getCustodianGroupResponse{Group: group}, http.StatusOK)
}

// DeleteGroupHandler handles DELETE /custodian/groups/{id} requests.
// Deletes a custodian group by its ID.
//
// URL parameters:
//   - id: custodian group identifier (required)
func (h *CustodianHandlers) DeleteGroupHandler(w http.ResponseWriter, r *http.Request) {
	if h.service == nil {
		writeError(w, ErrCustodianNotConfigured, http.StatusServiceUnavailable)
		return
	}

	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, ErrMissingGroupID, http.StatusBadRequest)
		return
	}

	if err := h.service.DeleteGroup(r.Context(), id); err != nil {
		handleCustodianError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// AddMemberHandler handles POST /custodian/groups/{id}/members requests.
// Adds a new member to a custodian group.
//
// URL parameters:
//   - id: custodian group identifier (required)
//
// Request body (JSON):
//
//	{
//	  "user_id": "string",
//	  "username": "string",
//	  "method": "string"
//	}
func (h *CustodianHandlers) AddMemberHandler(w http.ResponseWriter, r *http.Request) {
	if h.service == nil {
		writeError(w, ErrCustodianNotConfigured, http.StatusServiceUnavailable)
		return
	}

	groupID := chi.URLParam(r, "id")
	if groupID == "" {
		writeError(w, ErrMissingGroupID, http.StatusBadRequest)
		return
	}

	var req addCustodianMemberRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	if req.UserID == "" {
		writeError(w, ErrMissingUserID, http.StatusBadRequest)
		return
	}

	member, err := h.service.AddMember(r.Context(), groupID, req.UserID, req.Username, req.Method)
	if err != nil {
		handleCustodianError(w, err)
		return
	}

	writeJSON(w, addCustodianMemberResponse{Member: member}, http.StatusCreated)
}

// RemoveMemberHandler handles DELETE /custodian/groups/{id}/members/{userID} requests.
// Removes a member from a custodian group.
//
// URL parameters:
//   - id: custodian group identifier (required)
//   - uid: user identifier of the member to remove (required)
func (h *CustodianHandlers) RemoveMemberHandler(w http.ResponseWriter, r *http.Request) {
	if h.service == nil {
		writeError(w, ErrCustodianNotConfigured, http.StatusServiceUnavailable)
		return
	}

	groupID := chi.URLParam(r, "id")
	if groupID == "" {
		writeError(w, ErrMissingGroupID, http.StatusBadRequest)
		return
	}

	uid := chi.URLParam(r, "userID")
	if uid == "" {
		writeError(w, ErrMissingUserID, http.StatusBadRequest)
		return
	}

	if err := h.service.RemoveMember(r.Context(), groupID, uid); err != nil {
		handleCustodianError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// DistributeSharesHandler handles POST /custodian/groups/{id}/distribute requests.
// It triggers share distribution for the specified custodian group.
//
// URL parameters:
//   - id: custodian group identifier (required)
func (h *CustodianHandlers) DistributeSharesHandler(w http.ResponseWriter, r *http.Request) {
	if h.service == nil {
		writeError(w, ErrCustodianNotConfigured, http.StatusServiceUnavailable)
		return
	}

	groupID := chi.URLParam(r, "id")
	if groupID == "" {
		writeError(w, ErrMissingGroupID, http.StatusBadRequest)
		return
	}

	count, err := h.service.DistributeShares(r.Context(), groupID)
	if err != nil {
		handleCustodianError(w, err)
		return
	}

	writeJSON(w, distributeSharesResponse{Distributed: count}, http.StatusOK)
}

// handleCustodianError maps custodian-specific errors to HTTP status codes
// and writes the error response.
func handleCustodianError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, custodian.ErrGroupNotFound):
		writeError(w, err, http.StatusNotFound)
	case errors.Is(err, custodian.ErrGroupAlreadyExists):
		writeError(w, err, http.StatusConflict)
	case errors.Is(err, custodian.ErrGroupFull):
		writeError(w, err, http.StatusConflict)
	case errors.Is(err, custodian.ErrMemberAlreadyExists):
		writeError(w, err, http.StatusConflict)
	case errors.Is(err, custodian.ErrMemberNotFound):
		writeError(w, err, http.StatusNotFound)
	case errors.Is(err, custodian.ErrEmptyGroupID),
		errors.Is(err, custodian.ErrEmptyGroupName),
		errors.Is(err, custodian.ErrEmptyUserID),
		errors.Is(err, custodian.ErrInvalidThreshold),
		errors.Is(err, custodian.ErrInvalidTotalShares),
		errors.Is(err, custodian.ErrInvalidPurpose),
		errors.Is(err, custodian.ErrGroupEmpty):
		writeError(w, err, http.StatusBadRequest)
	default:
		writeError(w, ErrInternalError, http.StatusInternalServerError)
	}
}
