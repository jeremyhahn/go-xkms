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
	"net/http"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// setupPKCS11StateRoutes registers the remote-mode PKCS#11 state endpoints. They
// gate on the keys resource — the records are a token's key/object state — and
// forward opaque records to the XKMSService servicer. Every route is POST with a
// JSON body so a binary value never rides in a URL.
func (s *Server) setupPKCS11StateRoutes(mux *http.ServeMux) {
	post := func(path, action string, handle func(w http.ResponseWriter, r *http.Request)) {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
				return
			}
			if !s.authorize(w, r, auth.ResourceKeys, action) {
				return
			}
			if s.xkmsService == nil {
				s.sendError(w, http.StatusServiceUnavailable, "xkms service not initialized")
				return
			}
			handle(w, r)
		})
	}

	post("/api/v1/pkcs11state/put", auth.ActionWrite, func(w http.ResponseWriter, r *http.Request) {
		var req transport.PKCS11StatePutRequest
		if !s.decodePKCS11StateBody(w, r, &req) {
			return
		}
		resp, err := s.xkmsService.PKCS11StatePut(r.Context(), &req)
		s.respondPKCS11State(w, resp, err)
	})

	post("/api/v1/pkcs11state/put-if-absent", auth.ActionWrite, func(w http.ResponseWriter, r *http.Request) {
		var req transport.PKCS11StatePutIfAbsentRequest
		if !s.decodePKCS11StateBody(w, r, &req) {
			return
		}
		resp, err := s.xkmsService.PKCS11StatePutIfAbsent(r.Context(), &req)
		s.respondPKCS11State(w, resp, err)
	})

	post("/api/v1/pkcs11state/compare-and-swap", auth.ActionWrite, func(w http.ResponseWriter, r *http.Request) {
		var req transport.PKCS11StateCASRequest
		if !s.decodePKCS11StateBody(w, r, &req) {
			return
		}
		resp, err := s.xkmsService.PKCS11StateCAS(r.Context(), &req)
		s.respondPKCS11State(w, resp, err)
	})

	post("/api/v1/pkcs11state/get", auth.ActionRead, func(w http.ResponseWriter, r *http.Request) {
		var req transport.PKCS11StateGetRequest
		if !s.decodePKCS11StateBody(w, r, &req) {
			return
		}
		resp, err := s.xkmsService.PKCS11StateGet(r.Context(), &req)
		s.respondPKCS11State(w, resp, err)
	})

	post("/api/v1/pkcs11state/delete", auth.ActionWrite, func(w http.ResponseWriter, r *http.Request) {
		var req transport.PKCS11StateDeleteRequest
		if !s.decodePKCS11StateBody(w, r, &req) {
			return
		}
		resp, err := s.xkmsService.PKCS11StateDelete(r.Context(), &req)
		s.respondPKCS11State(w, resp, err)
	})

	post("/api/v1/pkcs11state/list", auth.ActionRead, func(w http.ResponseWriter, r *http.Request) {
		var req transport.PKCS11StateListRequest
		if !s.decodePKCS11StateBody(w, r, &req) {
			return
		}
		resp, err := s.xkmsService.PKCS11StateList(r.Context(), &req)
		s.respondPKCS11State(w, resp, err)
	})
}

// decodePKCS11StateBody decodes the JSON request body, writing a 400 and
// returning false on failure.
func (s *Server) decodePKCS11StateBody(w http.ResponseWriter, r *http.Request, dst interface{}) bool {
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		s.sendError(w, http.StatusBadRequest, "invalid request body")
		return false
	}
	return true
}

// respondPKCS11State writes the servicer result: a 500 on error, else the
// response as JSON.
func (s *Server) respondPKCS11State(w http.ResponseWriter, resp interface{}, err error) {
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.sendJSON(w, http.StatusOK, resp)
}
