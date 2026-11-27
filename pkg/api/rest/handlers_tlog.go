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

package rest

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/jeremyhahn/go-xkms/pkg/api/apierrors"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// TransparencyLogHandlers serves the CA transparency log's read verbs over
// REST, the server side of the REST and QUIC transports' transparency-log
// clients (transport.TransparencyLog*Path). The routes gate on the vlog
// resource (routes.go), matching the gRPC/MCP/Unix handlers.
type TransparencyLogHandlers struct {
	servicer transport.TransparencyLogServicer
}

// NewTransparencyLogHandlers returns the transparency-log handlers over
// servicer.
func NewTransparencyLogHandlers(servicer transport.TransparencyLogServicer) *TransparencyLogHandlers {
	return &TransparencyLogHandlers{servicer: servicer}
}

// transparencyLogClassOf classifies a transparency-log read error through
// apierrors.TransparencyLogSentinelClasses, the table every transport shares.
func transparencyLogClassOf(err error) (apierrors.Class, bool) {
	return apierrors.ClassOf(apierrors.TransparencyLogSentinelClasses, err)
}

// HeadHandler handles GET /ca/transparency-log/head.
func (h *TransparencyLogHandlers) HeadHandler(w http.ResponseWriter, r *http.Request) {
	resp, err := h.servicer.GetTransparencyLogHead(r.Context(), &transport.GetTransparencyLogHeadRequest{})
	respondClassified(w, resp, err, http.StatusOK, transparencyLogClassOf)
}

// EntryHandler handles GET /ca/transparency-log/entries/{index}.
func (h *TransparencyLogHandlers) EntryHandler(w http.ResponseWriter, r *http.Request) {
	index, ok := parseUint(w, chi.URLParam(r, "index"))
	if !ok {
		return
	}
	resp, err := h.servicer.GetTransparencyLogEntry(r.Context(), &transport.GetTransparencyLogEntryRequest{Index: index})
	respondClassified(w, resp, err, http.StatusOK, transparencyLogClassOf)
}

// InclusionProofHandler handles
// GET /ca/transparency-log/proofs/inclusion?index=&tree_size=.
func (h *TransparencyLogHandlers) InclusionProofHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	index, ok := parseUintQuery(w, query, "index")
	if !ok {
		return
	}
	treeSize, ok := parseUintQuery(w, query, "tree_size")
	if !ok {
		return
	}
	req := transport.GetTransparencyLogInclusionProofRequest{Index: index, TreeSize: treeSize}
	resp, err := h.servicer.GetTransparencyLogInclusionProof(r.Context(), &req)
	respondClassified(w, resp, err, http.StatusOK, transparencyLogClassOf)
}

// ConsistencyProofHandler handles
// GET /ca/transparency-log/proofs/consistency?first_size=&second_size=.
func (h *TransparencyLogHandlers) ConsistencyProofHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	firstSize, ok := parseUintQuery(w, query, "first_size")
	if !ok {
		return
	}
	secondSize, ok := parseUintQuery(w, query, "second_size")
	if !ok {
		return
	}
	req := transport.GetTransparencyLogConsistencyProofRequest{FirstSize: firstSize, SecondSize: secondSize}
	resp, err := h.servicer.GetTransparencyLogConsistencyProof(r.Context(), &req)
	respondClassified(w, resp, err, http.StatusOK, transparencyLogClassOf)
}

// AppendExternalHandler appends an external entry under the caller's SPIFFE
// ID, which the service reads from the connection's verified TLS client
// certificate. POST /ca/transparency-log/entries.
func (h *TransparencyLogHandlers) AppendExternalHandler(w http.ResponseWriter, r *http.Request) {
	var req transport.AppendTransparencyLogExternalRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}
	resp, err := h.servicer.AppendTransparencyLogExternal(peerTLSContext(r), &req)
	respondClassified(w, resp, err, http.StatusCreated, transparencyLogClassOf)
}

// parseUint parses s, a required path or query parameter, as a uint64,
// writing 400 and returning false when it is missing or not one.
func parseUint(w http.ResponseWriter, s string) (uint64, bool) {
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return 0, false
	}
	return n, true
}

// parseUintQuery parses the required query parameter name as a uint64,
// writing 400 and returning false when it is missing or not one.
func parseUintQuery(w http.ResponseWriter, query url.Values, name string) (uint64, bool) {
	return parseUint(w, query.Get(name))
}
