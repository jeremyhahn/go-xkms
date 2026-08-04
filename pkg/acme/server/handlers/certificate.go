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
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
)

func (s *RestService) CertificateHandler(w http.ResponseWriter, r *http.Request) {

	s.logger.Debug("CertificateHandler", "method", r.Method, "url", r.URL)
	ctx := r.Context()

	strCertID := mux.Vars(r)["id"]
	certID, err := strconv.ParseUint(strCertID, 10, 64)
	if err != nil {
		writeError(w, common.MalformedError("Invalid certificate ID", nil))
		return
	}
	certificateDAO, err := s.storageFactory.CertificateDAO()
	if err != nil {
		writeError(w, common.ServerInternal("Failed to create certificate DAO"))
		return
	}
	certificate, err := certificateDAO.Get(ctx, certID)
	if err != nil {
		writeError(w, common.MalformedError("Certificate not found", nil))
		return
	}

	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(certificate.PEM))
}
