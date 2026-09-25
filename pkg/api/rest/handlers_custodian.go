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
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
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
	Group transport.CustodianGroupInfo `json:"group"`
}

// getCustodianGroupResponse wraps a single group for the SDK contract.
type getCustodianGroupResponse struct {
	Group transport.CustodianGroupInfo `json:"group"`
}

// listCustodianGroupsResponse wraps the groups list for the SDK contract.
type listCustodianGroupsResponse struct {
	Groups     []transport.CustodianGroupInfo `json:"groups"`
	Pagination transport.PageResponse         `json:"pagination"`
}

// addCustodianMemberResponse wraps the added member for the SDK contract.
type addCustodianMemberResponse struct {
	Member transport.CustodianMemberInfo `json:"member"`
}

// distributeSharesResponse represents the response for share distribution.
type distributeSharesResponse struct {
	Distributed int `json:"distributed"`
}

// CustodianHandlers serves the custodian group REST endpoints. Custodian state
// is owned by the embedded go-qrdb node; the handlers delegate to the unified
// XKMSService servicer, which passes calls through to the node's custodian
// group client.
type CustodianHandlers struct {
	xkmsService *xkms.XKMSService
}

// NewCustodianHandlers creates a new CustodianHandlers with the provided XKMS service.
func NewCustodianHandlers(svc *xkms.XKMSService) *CustodianHandlers {
	return &CustodianHandlers{xkmsService: svc}
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
	if h.xkmsService == nil {
		writeError(w, ErrCustodianNotConfigured, http.StatusServiceUnavailable)
		return
	}
	svc := h.xkmsService

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

	resp, err := svc.CreateCustodianGroup(r.Context(), &qrdbtransport.CreateCustodianGroupRequest{
		ID:        req.ID,
		TenantID:  req.TenantID,
		Name:      req.Name,
		Purpose:   req.Purpose,
		Threshold: req.Threshold,
		Total:     req.Total,
	})
	if err != nil {
		handleCustodianError(w, err)
		return
	}

	writeJSON(w, createCustodianGroupResponse{Group: resp.Group}, http.StatusCreated)
}

// ListGroupsHandler handles GET /custodian/groups requests.
// Returns all custodian groups wrapped in a groups envelope.
func (h *CustodianHandlers) ListGroupsHandler(w http.ResponseWriter, r *http.Request) {
	if h.xkmsService == nil {
		writeError(w, ErrCustodianNotConfigured, http.StatusServiceUnavailable)
		return
	}
	svc := h.xkmsService

	resp, err := svc.ListCustodianGroups(r.Context())
	if err != nil {
		handleCustodianError(w, err)
		return
	}

	pageReq, err := parsePageRequest(r)
	if err != nil {
		writeError(w, err, http.StatusBadRequest)
		return
	}
	paged, pageResp := applyPagination(resp.Groups, pageReq)

	writeJSON(w, listCustodianGroupsResponse{Groups: paged, Pagination: pageResp}, http.StatusOK)
}

// GetGroupHandler handles GET /custodian/groups/{id} requests.
// Returns a single custodian group by its ID wrapped in a group envelope.
//
// URL parameters:
//   - id: custodian group identifier (required)
func (h *CustodianHandlers) GetGroupHandler(w http.ResponseWriter, r *http.Request) {
	if h.xkmsService == nil {
		writeError(w, ErrCustodianNotConfigured, http.StatusServiceUnavailable)
		return
	}
	svc := h.xkmsService

	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, ErrMissingGroupID, http.StatusBadRequest)
		return
	}

	resp, err := svc.GetCustodianGroup(r.Context(), id)
	if err != nil {
		handleCustodianError(w, err)
		return
	}

	writeJSON(w, getCustodianGroupResponse{Group: resp.Group}, http.StatusOK)
}

// DeleteGroupHandler handles DELETE /custodian/groups/{id} requests.
// Deletes a custodian group by its ID.
//
// URL parameters:
//   - id: custodian group identifier (required)
func (h *CustodianHandlers) DeleteGroupHandler(w http.ResponseWriter, r *http.Request) {
	if h.xkmsService == nil {
		writeError(w, ErrCustodianNotConfigured, http.StatusServiceUnavailable)
		return
	}
	svc := h.xkmsService

	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, ErrMissingGroupID, http.StatusBadRequest)
		return
	}

	if err := svc.DeleteCustodianGroup(r.Context(), id); err != nil {
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
	if h.xkmsService == nil {
		writeError(w, ErrCustodianNotConfigured, http.StatusServiceUnavailable)
		return
	}
	svc := h.xkmsService

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

	resp, err := svc.AddCustodianMember(r.Context(), &qrdbtransport.AddCustodianMemberRequest{
		GroupID:  groupID,
		UserID:   req.UserID,
		Username: req.Username,
		Method:   req.Method,
	})
	if err != nil {
		handleCustodianError(w, err)
		return
	}

	writeJSON(w, addCustodianMemberResponse{Member: resp.Member}, http.StatusCreated)
}

// RemoveMemberHandler handles DELETE /custodian/groups/{id}/members/{userID} requests.
// Removes a member from a custodian group.
//
// URL parameters:
//   - id: custodian group identifier (required)
//   - userID: user identifier of the member to remove (required)
func (h *CustodianHandlers) RemoveMemberHandler(w http.ResponseWriter, r *http.Request) {
	if h.xkmsService == nil {
		writeError(w, ErrCustodianNotConfigured, http.StatusServiceUnavailable)
		return
	}
	svc := h.xkmsService

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

	if err := svc.RemoveCustodianMember(r.Context(), &qrdbtransport.RemoveCustodianMemberRequest{
		GroupID: groupID,
		UserID:  uid,
	}); err != nil {
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
	if h.xkmsService == nil {
		writeError(w, ErrCustodianNotConfigured, http.StatusServiceUnavailable)
		return
	}
	svc := h.xkmsService

	groupID := chi.URLParam(r, "id")
	if groupID == "" {
		writeError(w, ErrMissingGroupID, http.StatusBadRequest)
		return
	}

	resp, err := svc.DistributeShares(r.Context(), &qrdbtransport.DistributeSharesRequest{
		GroupID: groupID,
	})
	if err != nil {
		handleCustodianError(w, err)
		return
	}

	writeJSON(w, distributeSharesResponse{Distributed: resp.Distributed}, http.StatusOK)
}

// handleCustodianError maps custodian domain errors (surfaced by the go-qrdb
// node's custodian client) to HTTP status codes and writes the error response.
func handleCustodianError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, xkms.ErrNotConfigured):
		writeError(w, ErrCustodianNotConfigured, http.StatusServiceUnavailable)
	case errors.Is(err, qrdbsdk.ErrCeremonyGroupNotFound),
		errors.Is(err, qrdbsdk.ErrCeremonyMemberNotFound),
		errors.Is(err, qrdbsdk.ErrCeremonyUserNotFound):
		writeError(w, err, http.StatusNotFound)
	case errors.Is(err, qrdbsdk.ErrCeremonyGroupAlreadyExists),
		errors.Is(err, qrdbsdk.ErrCeremonyGroupFull),
		errors.Is(err, qrdbsdk.ErrCeremonyMemberAlreadyExists):
		writeError(w, err, http.StatusConflict)
	case errors.Is(err, qrdbsdk.ErrCeremonyEmptyGroupID),
		errors.Is(err, qrdbsdk.ErrCeremonyEmptyGroupName),
		errors.Is(err, qrdbsdk.ErrCeremonyInvalidThreshold),
		errors.Is(err, qrdbsdk.ErrCeremonyInvalidTotal),
		errors.Is(err, qrdbsdk.ErrCeremonyInsufficientMembers):
		writeError(w, err, http.StatusBadRequest)
	default:
		// An unexpected error from the custodian subsystem must never be silently
		// collapsed into a bare 500 — log the underlying cause for diagnosis.
		slog.Default().Error("custodian operation failed", "error", err)
		writeError(w, ErrInternalError, http.StatusInternalServerError)
	}
}
