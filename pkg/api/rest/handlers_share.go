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
	"net/url"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// Share handler typed errors.
var (
	ErrShareNotConfigured    = errors.New("rest: share service not configured")
	ErrMissingShareGroupID   = errors.New("rest: missing group_id for share")
	ErrMissingShareData      = errors.New("rest: missing share data")
	ErrMissingShareServerURL = errors.New("rest: missing server_url for share")
	ErrMissingShareIndex     = errors.New("rest: missing or invalid share_index for share")
	ErrMissingStatusGroupID  = errors.New("rest: missing group_id for share collection status")
)

// submitShareRequest represents the request body for submitting a Shamir share.
type submitShareRequest struct {
	ServerURL  string `json:"server_url"`
	GroupID    string `json:"group_id"`
	GroupName  string `json:"group_name,omitempty"`
	ShareIndex int    `json:"share_index"`
	ShareData  []byte `json:"share_data"`
	Purpose    string `json:"purpose,omitempty"`
	TenantID   string `json:"tenant_id,omitempty"`
}

// shareStatusResponse represents a share entry without the sensitive share data.
type shareStatusResponse struct {
	ServerURL  string `json:"server_url"`
	GroupID    string `json:"group_id"`
	GroupName  string `json:"group_name,omitempty"`
	ShareIndex int    `json:"share_index"`
	Purpose    string `json:"purpose,omitempty"`
	ReceivedAt string `json:"received_at"`
	TenantID   string `json:"tenant_id,omitempty"`
}

// listSharesResponse wraps a list of share status responses.
type listSharesResponse struct {
	Shares     []shareStatusResponse  `json:"shares"`
	Pagination transport.PageResponse `json:"pagination"`
}

// shareCollectionStatusResponse represents the status of share collection for a group.
type shareCollectionStatusResponse struct {
	GroupID   string `json:"group_id"`
	Collected int    `json:"collected"`
}

// shareInfoToStatus converts a transport.ShareInfo to a shareStatusResponse,
// omitting the sensitive share data.
func shareInfoToStatus(info *transport.ShareInfo) shareStatusResponse {
	return shareStatusResponse{
		ServerURL:  info.ServerURL,
		GroupID:    info.GroupID,
		GroupName:  info.GroupName,
		ShareIndex: info.ShareIndex,
		Purpose:    info.Purpose,
		ReceivedAt: info.ReceivedAt.Format(time.RFC3339),
		TenantID:   info.TenantID,
	}
}

// ShareHandlers serves the Shamir share REST endpoints. Share state is owned by
// the embedded go-qrdb node; the handlers delegate to the unified XKMSService
// servicer, which passes calls through to the node's share client.
type ShareHandlers struct {
	xkmsService *xkms.XKMSService
}

// NewShareHandlers creates a new ShareHandlers with the provided XKMS service.
func NewShareHandlers(svc *xkms.XKMSService) *ShareHandlers {
	return &ShareHandlers{xkmsService: svc}
}

// SubmitShareHandler handles POST /shares/submit requests.
// It submits a Shamir share to the embedded go-qrdb node's share client.
//
// Request body (JSON):
//
//	{
//	  "server_url": "string",
//	  "group_id": "string",
//	  "group_name": "string (optional)",
//	  "share_index": int,
//	  "share_data": "base64-encoded bytes",
//	  "purpose": "string (optional)",
//	  "tenant_id": "string (optional)"
//	}
func (h *ShareHandlers) SubmitShareHandler(w http.ResponseWriter, r *http.Request) {
	if h.xkmsService == nil {
		writeError(w, ErrShareNotConfigured, http.StatusServiceUnavailable)
		return
	}
	svc := h.xkmsService

	var req submitShareRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	if req.ServerURL == "" {
		writeError(w, ErrMissingShareServerURL, http.StatusBadRequest)
		return
	}

	if req.GroupID == "" {
		writeError(w, ErrMissingShareGroupID, http.StatusBadRequest)
		return
	}

	if len(req.ShareData) == 0 {
		writeError(w, ErrMissingShareData, http.StatusBadRequest)
		return
	}

	if _, err := svc.SubmitShare(r.Context(), &transport.SubmitShareRequest{
		ServerURL:  req.ServerURL,
		GroupID:    req.GroupID,
		GroupName:  req.GroupName,
		ShareIndex: req.ShareIndex,
		ShareData:  req.ShareData,
		Purpose:    req.Purpose,
		TenantID:   req.TenantID,
	}); err != nil {
		handleShareError(w, err)
		return
	}

	resp := shareStatusResponse{
		ServerURL:  req.ServerURL,
		GroupID:    req.GroupID,
		GroupName:  req.GroupName,
		ShareIndex: req.ShareIndex,
		Purpose:    req.Purpose,
		ReceivedAt: time.Now().UTC().Format(time.RFC3339),
		TenantID:   req.TenantID,
	}
	writeJSON(w, resp, http.StatusCreated)
}

// ListSharesHandler handles GET /shares requests.
// Returns all stored shares without exposing the sensitive share data.
func (h *ShareHandlers) ListSharesHandler(w http.ResponseWriter, r *http.Request) {
	if h.xkmsService == nil {
		writeError(w, ErrShareNotConfigured, http.StatusServiceUnavailable)
		return
	}
	svc := h.xkmsService

	resp, err := svc.ListShares(r.Context())
	if err != nil {
		handleShareError(w, err)
		return
	}

	shares := make([]shareStatusResponse, 0, len(resp.Shares))
	for i := range resp.Shares {
		shares = append(shares, shareInfoToStatus(&resp.Shares[i]))
	}

	pageReq := parsePageRequest(r)
	paged, pageResp := applyPagination(shares, pageReq)

	writeJSON(w, listSharesResponse{Shares: paged, Pagination: pageResp}, http.StatusOK)
}

// GetShareHandler handles GET /shares/{serverURL}/{groupID}/{shareIndex} requests.
// Returns the share status for a specific server URL, group ID, and share index.
// The sensitive share data is intentionally omitted from the response.
//
// URL parameters:
//   - serverURL: URL-encoded server URL (required)
//   - groupID: custodian group identifier (required)
//   - shareIndex: 1-based share index within the group (required)
func (h *ShareHandlers) GetShareHandler(w http.ResponseWriter, r *http.Request) {
	if h.xkmsService == nil {
		writeError(w, ErrShareNotConfigured, http.StatusServiceUnavailable)
		return
	}
	svc := h.xkmsService

	rawServerURL := chi.URLParam(r, "serverURL")
	if rawServerURL == "" {
		writeError(w, ErrMissingShareServerURL, http.StatusBadRequest)
		return
	}

	serverURL, err := url.PathUnescape(rawServerURL)
	if err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	groupID := chi.URLParam(r, "groupID")
	if groupID == "" {
		writeError(w, ErrMissingShareGroupID, http.StatusBadRequest)
		return
	}

	shareIndexStr := chi.URLParam(r, "shareIndex")
	shareIndex, err := strconv.Atoi(shareIndexStr)
	if err != nil {
		writeError(w, ErrMissingShareIndex, http.StatusBadRequest)
		return
	}

	info, err := svc.GetShare(r.Context(), serverURL, groupID, shareIndex)
	if err != nil {
		handleShareError(w, err)
		return
	}

	writeJSON(w, shareInfoToStatus(info), http.StatusOK)
}

// DeleteShareHandler handles DELETE /shares/{serverURL}/{groupID}/{shareIndex} requests.
// Deletes a share by server URL, group ID, and share index.
//
// URL parameters:
//   - serverURL: URL-encoded server URL (required)
//   - groupID: custodian group identifier (required)
//   - shareIndex: 1-based share index within the group (required)
func (h *ShareHandlers) DeleteShareHandler(w http.ResponseWriter, r *http.Request) {
	if h.xkmsService == nil {
		writeError(w, ErrShareNotConfigured, http.StatusServiceUnavailable)
		return
	}
	svc := h.xkmsService

	rawServerURL := chi.URLParam(r, "serverURL")
	if rawServerURL == "" {
		writeError(w, ErrMissingShareServerURL, http.StatusBadRequest)
		return
	}

	serverURL, err := url.PathUnescape(rawServerURL)
	if err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	groupID := chi.URLParam(r, "groupID")
	if groupID == "" {
		writeError(w, ErrMissingShareGroupID, http.StatusBadRequest)
		return
	}

	shareIndexStr := chi.URLParam(r, "shareIndex")
	shareIndex, err := strconv.Atoi(shareIndexStr)
	if err != nil {
		writeError(w, ErrMissingShareIndex, http.StatusBadRequest)
		return
	}

	if err := svc.DeleteShare(r.Context(), serverURL, groupID, shareIndex); err != nil {
		handleShareError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GetShareCollectionStatusHandler handles GET /shares/status/{groupID} requests.
// It reports the number of shares submitted for a given group.
//
// URL parameters:
//   - groupID: custodian group identifier (required)
func (h *ShareHandlers) GetShareCollectionStatusHandler(w http.ResponseWriter, r *http.Request) {
	if h.xkmsService == nil {
		writeError(w, ErrShareNotConfigured, http.StatusServiceUnavailable)
		return
	}
	svc := h.xkmsService

	groupID := chi.URLParam(r, "groupID")
	if groupID == "" {
		writeError(w, ErrMissingStatusGroupID, http.StatusBadRequest)
		return
	}

	status, err := svc.GetShareCollectionStatus(r.Context(), groupID)
	if err != nil {
		handleShareError(w, err)
		return
	}

	writeJSON(w, shareCollectionStatusResponse{
		GroupID:   status.GroupID,
		Collected: status.Collected,
	}, http.StatusOK)
}

// handleShareError maps share domain errors (surfaced by the go-qrdb node's
// share client through the XKMSService servicer) to HTTP status codes and
// writes the appropriate error response.
func handleShareError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, xkms.ErrNotConfigured):
		writeError(w, ErrShareNotConfigured, http.StatusServiceUnavailable)
	case errors.Is(err, qrdbsdk.ErrCeremonyShareNotFound):
		writeError(w, err, http.StatusNotFound)
	default:
		slog.Default().Error("share operation failed", "error", err)
		writeError(w, ErrInternalError, http.StatusInternalServerError)
	}
}
