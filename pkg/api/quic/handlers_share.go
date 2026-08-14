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

package quic

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// sharePathPrefix is the common prefix for every share endpoint.
const sharePathPrefix = "/api/v1/shares"

// setupShareRoutes registers the Shamir share endpoints on mux. Share state
// is owned by the embedded go-qrdb node; the handlers delegate to the
// unified XKMSService servicer, exactly as the REST handlers do.
func (s *Server) setupShareRoutes(mux *http.ServeMux) {
	// Exact match handles list (GET); the prefix dispatcher handles
	// submit, status, and the per-share get/delete triple.
	mux.HandleFunc(sharePathPrefix, s.handleShares)
	mux.HandleFunc(sharePathPrefix+"/", s.handleShareOperations)
}

// handleShares dispatches GET (list) on /api/v1/shares.
func (s *Server) handleShares(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	s.handleListShares(w, r)
}

// handleShareOperations is the prefix dispatcher for /api/v1/shares/*:
//
//   - "submit"                              → POST (submit a share)
//   - "status/{groupID}"                    → GET  (collection status)
//   - "{serverURL}/{groupID}/{shareIndex}"  → GET (get) or DELETE (delete)
//
// The server URL is itself a URL, so the client escapes it as a single path
// segment. Splitting therefore happens on the raw (still-escaped) path and
// each segment is unescaped afterwards — splitting the decoded path would
// break apart the scheme and host of the server URL.
func (s *Server) handleShareOperations(w http.ResponseWriter, r *http.Request) {
	tail := strings.TrimPrefix(rawRequestPath(r), sharePathPrefix+"/")
	if tail == "" {
		s.sendError(w, http.StatusNotFound, "not found")
		return
	}

	if tail == "submit" {
		if r.Method != http.MethodPost {
			s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		s.handleSubmitShare(w, r)
		return
	}

	parts := strings.Split(tail, "/")
	if parts[0] == "status" {
		if len(parts) != 2 {
			s.sendError(w, http.StatusNotFound, "not found")
			return
		}
		if r.Method != http.MethodGet {
			s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		groupID, err := url.PathUnescape(parts[1])
		if err != nil {
			s.sendError(w, http.StatusBadRequest, "invalid group_id")
			return
		}
		s.handleShareCollectionStatus(w, r, groupID)
		return
	}

	if len(parts) != 3 {
		s.sendError(w, http.StatusNotFound, "not found")
		return
	}

	serverURL, err := url.PathUnescape(parts[0])
	if err != nil || serverURL == "" {
		s.sendError(w, http.StatusBadRequest, "invalid server_url")
		return
	}
	groupID, err := url.PathUnescape(parts[1])
	if err != nil || groupID == "" {
		s.sendError(w, http.StatusBadRequest, "invalid group_id")
		return
	}
	shareIndex, err := strconv.Atoi(parts[2])
	if err != nil {
		s.sendError(w, http.StatusBadRequest, "invalid share_index")
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.handleGetShare(w, r, serverURL, groupID, shareIndex)
	case http.MethodDelete:
		s.handleDeleteShare(w, r, serverURL, groupID, shareIndex)
	default:
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// rawRequestPath returns the request path with percent-escapes intact when
// the URL carries them, so path segments that legitimately contain "/" stay
// in one piece.
func rawRequestPath(r *http.Request) string {
	if r.URL.RawPath != "" {
		return r.URL.RawPath
	}
	return r.URL.Path
}

// handleSubmitShare handles POST /api/v1/shares/submit.
func (s *Server) handleSubmitShare(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, auth.ResourceBarrier, auth.ActionUnsealShare) {
		return
	}
	if s.xkmsService == nil {
		s.sendError(w, http.StatusServiceUnavailable, "share service not configured")
		return
	}

	var req transport.SubmitShareRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.GroupID == "" {
		s.sendError(w, http.StatusBadRequest, "group_id is required")
		return
	}
	if len(req.ShareData) == 0 {
		s.sendError(w, http.StatusBadRequest, "share_data is required")
		return
	}

	resp, err := s.xkmsService.SubmitShare(r.Context(), &req)
	if err != nil {
		s.sendShareError(w, err)
		return
	}

	s.sendJSON(w, http.StatusOK, resp)
}

// handleListShares handles GET /api/v1/shares. Sensitive share material is
// stripped before the response is written.
func (s *Server) handleListShares(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, auth.ResourceCeremony, auth.ActionStatus) {
		return
	}
	if s.xkmsService == nil {
		s.sendError(w, http.StatusServiceUnavailable, "share service not configured")
		return
	}

	resp, err := s.xkmsService.ListShares(r.Context())
	if err != nil {
		s.sendShareError(w, err)
		return
	}

	shares := make([]transport.ShareInfo, len(resp.Shares))
	for i := range resp.Shares {
		shares[i] = withoutShareData(resp.Shares[i])
	}

	s.sendJSON(w, http.StatusOK, transport.ListSharesResponse{Shares: shares})
}

// handleGetShare handles GET /api/v1/shares/{serverURL}/{groupID}/{shareIndex}.
// Sensitive share material is stripped before the response is written.
func (s *Server) handleGetShare(w http.ResponseWriter, r *http.Request, serverURL, groupID string, shareIndex int) {
	if !s.authorize(w, r, auth.ResourceCeremony, auth.ActionStatus) {
		return
	}
	if s.xkmsService == nil {
		s.sendError(w, http.StatusServiceUnavailable, "share service not configured")
		return
	}

	info, err := s.xkmsService.GetShare(r.Context(), serverURL, groupID, shareIndex)
	if err != nil {
		s.sendShareError(w, err)
		return
	}

	s.sendJSON(w, http.StatusOK, withoutShareData(*info))
}

// handleDeleteShare handles DELETE /api/v1/shares/{serverURL}/{groupID}/{shareIndex}.
func (s *Server) handleDeleteShare(w http.ResponseWriter, r *http.Request, serverURL, groupID string, shareIndex int) {
	if !s.authorize(w, r, auth.ResourceBarrier, auth.ActionUnsealShare) {
		return
	}
	if s.xkmsService == nil {
		s.sendError(w, http.StatusServiceUnavailable, "share service not configured")
		return
	}

	if err := s.xkmsService.DeleteShare(r.Context(), serverURL, groupID, shareIndex); err != nil {
		s.sendShareError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleShareCollectionStatus handles GET /api/v1/shares/status/{groupID}.
func (s *Server) handleShareCollectionStatus(w http.ResponseWriter, r *http.Request, groupID string) {
	if !s.authorize(w, r, auth.ResourceCeremony, auth.ActionStatus) {
		return
	}
	if s.xkmsService == nil {
		s.sendError(w, http.StatusServiceUnavailable, "share service not configured")
		return
	}

	status, err := s.xkmsService.GetShareCollectionStatus(r.Context(), groupID)
	if err != nil {
		s.sendShareError(w, err)
		return
	}

	s.sendJSON(w, http.StatusOK, status)
}

// withoutShareData returns a copy of info with the sensitive share material
// cleared. Share bytes are write-only over the API: they go in through
// submit and are only ever read by the barrier's unseal quorum.
func withoutShareData(info transport.ShareInfo) transport.ShareInfo {
	info.ShareData = nil
	return info
}

// sendShareError maps share domain errors surfaced by the go-qrdb node's
// share client to HTTP status codes.
func (s *Server) sendShareError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, xkms.ErrNotConfigured):
		s.sendError(w, http.StatusServiceUnavailable, "share service not configured")
	case errors.Is(err, qrdbsdk.ErrCeremonyShareNotFound):
		s.sendError(w, http.StatusNotFound, err.Error())
	default:
		s.sendError(w, http.StatusInternalServerError, "share operation failed")
	}
}
