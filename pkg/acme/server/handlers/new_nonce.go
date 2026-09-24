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

package handlers

import (
	"fmt"
	"net/http"

	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
)

// NewNonceHandler responds to /acme/new-nonce requests per RFC 8555 Section 7.2.
// It generates and returns a new nonce for replay protection.
// Supports both HEAD and GET methods.
func (s *RestService) NewNonceHandler(w http.ResponseWriter, r *http.Request) {
	s.logger.Debug("NewNonceHandler", "method", r.Method, "url", r.URL.String())

	nonce, err := s.generateNonce()
	if err != nil {
		writeError(w, common.ServerInternal("Unable to generate nonce"))
		return
	}

	w.Header().Set("Replay-Nonce", nonce)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Link", fmt.Sprintf("%s/acme/directory>;rel=\"index\"", s.baseRESTURI))

	switch r.Method {
	case http.MethodHead:
		w.WriteHeader(http.StatusOK)
	case http.MethodGet:
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
