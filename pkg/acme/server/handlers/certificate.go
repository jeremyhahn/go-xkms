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

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
)

func (s *RestService) CertificateHandler(w http.ResponseWriter, r *http.Request) {

	s.logger.Debug("CertificateHandler", "method", r.Method, "url", r.URL)
	ctx := r.Context()

	// The "id" path segment is the certificate's full serial number,
	// hex-encoded (see entities.ACMECertificate.Serial). NormalizeSerial
	// rejects anything that isn't a valid positive hex integer with a typed
	// error rather than letting a malformed value reach the DAO lookup.
	serial, err := entities.NormalizeSerial(mux.Vars(r)["id"])
	if err != nil {
		writeError(w, common.MalformedError("Invalid certificate ID", nil))
		return
	}
	certificateDAO, err := s.storageFactory.CertificateDAO()
	if err != nil {
		writeError(w, common.ServerInternal("Failed to create certificate DAO"))
		return
	}
	certificate, err := certificateDAO.Get(ctx, entities.StringToEntityID(serial))
	if err != nil {
		writeError(w, common.MalformedError("Certificate not found", nil))
		return
	}

	// The DAO row is keyed by a 64-bit hash of Serial (entities.StringToEntityID),
	// not Serial itself, so an astronomically unlikely hash collision between
	// two different certificates would otherwise return the WRONG certificate
	// here instead of a not-found. Verify the row actually holds the
	// certificate that was asked for before serving it.
	if certificate.Serial != serial {
		s.logger.Error("Certificate storage row collision on fetch",
			"requested_serial", serial,
			"stored_serial", certificate.Serial)
		writeError(w, common.MalformedError("Certificate not found", nil))
		return
	}

	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(certificate.PEM)); err != nil {
		s.logger.Error("failed to write certificate response", "error", err.Error())
	}
}
