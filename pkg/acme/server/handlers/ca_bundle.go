// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package handlers

import (
	"crypto/x509"
	"net/http"

	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

func (s *RestService) CABundleHandler(w http.ResponseWriter, r *http.Request) {

	s.logger.Debug("CABundleHandler", "method", r.Method, "url", r.URL)

	// Serve the default CA bundle using software store and RSA algorithm
	// These are reasonable defaults for ACME client compatibility
	bundle, err := s.ca.CABundleFiltered(xkmssdk.StoreSoftware, x509.RSA)
	if err != nil {
		writeError(w, common.ServerInternal("Failed to get CA bundle"))
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(bundle)
}
