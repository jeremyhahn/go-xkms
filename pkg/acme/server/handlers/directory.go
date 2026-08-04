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

// DirectoryHandler responds to /acme/directory requests per RFC 8555 Section 7.1.1.
// It provides the ACME server's directory of resources, allowing clients to discover
// available endpoints.
func (s *RestService) DirectoryHandler(w http.ResponseWriter, r *http.Request) {
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
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	s.encodeJSON(w, directory)
}
