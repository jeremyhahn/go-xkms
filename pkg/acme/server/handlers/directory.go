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
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
)

// DirectoryHandler responds to /acme/directory requests per RFC 8555 Section 7.1.1.
// It provides the ACME server's directory of resources, allowing clients to discover
// available endpoints.
//
// The directory is built entirely from server configuration and has no
// dependency of its own that can fail, so it is not run through the storage
// breaker (that would make trivial, always-succeeding directory requests
// contend for the breaker's half-open probe budget with CABundleHandler's
// real dependency). Instead it peeks at the storage breaker's state: while
// open -- signaling CA-bundle storage access is unavailable -- it serves the
// last computed directory from cache instead of recomputing, so a client
// polling both endpoints during an incident sees the server behave
// consistently.
func (s *RestService) DirectoryHandler(w http.ResponseWriter, r *http.Request) {
	const cacheKey = "default"
	body, degraded := s.serveCachedWhenOpen(s.storageBreaker, s.directoryCache, cacheKey, func() []byte {
		directory := common.Directory{
			NewNonce:   fmt.Sprintf("%s/acme/new-nonce", s.baseRESTURI),
			NewAccount: fmt.Sprintf("%s/acme/new-account", s.baseRESTURI),
			NewOrder:   fmt.Sprintf("%s/acme/new-order", s.baseRESTURI),
			RevokeCert: fmt.Sprintf("%s/acme/revoke-cert", s.baseRESTURI),
			KeyChange:  fmt.Sprintf("%s/acme/key-change", s.baseRESTURI),
			Meta: common.Meta{
				TermsOfService:     s.termsOfService,
				Website:            s.baseRESTURI,
				CAAIdentities:      s.caaIdentities,
				ExternalAccountReq: s.externalAccountRequired,
			},
		}
		body, err := json.Marshal(directory)
		if err != nil {
			s.logger.Error("failed to encode directory response", "error", err.Error())
			return nil
		}
		return body
	})

	w.Header().Set("Content-Type", "application/json")
	setDegradedHeader(w, degraded)
	if body == nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}
