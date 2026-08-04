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

package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gorilla/mux"

	svc "github.com/jeremyhahn/go-xkms/pkg/acme/client/service"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/workflow"
)

// registerRequest is the JSON request body for account registration.
type registerRequest struct {
	Email string `json:"email"`
}

// registerResponse is the JSON response body for account registration.
type registerResponse struct {
	AccountURL string   `json:"accountUrl,omitempty"`
	Status     string   `json:"status"`
	Contact    []string `json:"contact"`
}

// register handles POST /api/v1/account/register.
// When the SDK workflow is available it uses the workflow's Register method,
// otherwise it falls back to the service layer.
func (h *handlers) register(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, (&ErrInvalidRequestBody{Detail: err.Error()}).Error())
		return
	}

	if h.wf != nil {
		h.registerViaWorkflow(w, r, &req)
		return
	}

	h.registerViaService(w, r, &req)
}

// registerViaWorkflow performs account registration through the SDK workflow.
func (h *handlers) registerViaWorkflow(w http.ResponseWriter, r *http.Request, req *registerRequest) {
	resp, err := h.wf.Register(r.Context(), &workflow.RegisterRequest{
		Email:                req.Email,
		TermsOfServiceAgreed: true,
	})
	if err != nil {
		h.logger.Error("register account via workflow failed", "error", err.Error())
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, &registerResponse{
		AccountURL: resp.AccountURL,
		Status:     resp.Status,
		Contact:    resp.Contact,
	})
}

// registerViaService performs account registration through the direct service layer.
// The legacy register endpoint only provides {email}, which is insufficient for
// multi-account configuration. Callers should use POST /api/v1/accounts instead.
func (h *handlers) registerViaService(w http.ResponseWriter, _ *http.Request, _ *registerRequest) {
	writeError(w, http.StatusBadRequest, (&ErrMissingField{Field: "name, directory"}).Error())
}

// addAccountRequest is the JSON request body for adding a new account via the service layer.
type addAccountRequest struct {
	Name                string         `json:"name"`
	Email               string         `json:"email"`
	Directory           string         `json:"directory"`
	Key                 *svc.KeyConfig `json:"key,omitempty"`
	Transport           string         `json:"transport,omitempty"`
	ServerAddr          string         `json:"server_addr,omitempty"`
	EAB                 *svc.EABConfig `json:"eab,omitempty"`
	TrustedRoots        []string       `json:"trusted_roots,omitempty"`
	RequestServerBundle bool           `json:"request_server_bundle,omitempty"`
}

// addAccount handles POST /api/v1/accounts.
func (h *handlers) addAccount(w http.ResponseWriter, r *http.Request) {
	var req addAccountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, (&ErrInvalidRequestBody{Detail: err.Error()}).Error())
		return
	}

	if req.Name == "" {
		writeError(w, http.StatusBadRequest, (&ErrMissingField{Field: "name"}).Error())
		return
	}
	if req.Directory == "" {
		writeError(w, http.StatusBadRequest, (&ErrMissingField{Field: "directory"}).Error())
		return
	}
	if req.Email == "" {
		writeError(w, http.StatusBadRequest, (&ErrMissingField{Field: "email"}).Error())
		return
	}

	cfg := &svc.AccountConfig{
		DirectoryURL:        req.Directory,
		Email:               req.Email,
		Key:                 req.Key,
		Transport:           req.Transport,
		ServerAddr:          req.ServerAddr,
		EAB:                 req.EAB,
		TrustedRoots:        req.TrustedRoots,
		RequestServerBundle: req.RequestServerBundle,
	}

	if err := h.service.Accounts().Add(r.Context(), req.Name, cfg); err != nil {
		h.logger.Error("add account failed", "error", err.Error(), "name", req.Name)
		writeError(w, http.StatusConflict, (&ErrServiceCall{Operation: "add account", Detail: err.Error()}).Error())
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{"status": "created", "name": req.Name})
}

// listAccounts handles GET /api/v1/accounts.
func (h *handlers) listAccounts(w http.ResponseWriter, _ *http.Request) {
	accounts := h.service.Accounts().List()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"accounts": accounts,
	})
}

// getAccount handles GET /api/v1/accounts/{name}.
func (h *handlers) getAccount(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]

	acct, err := h.service.Accounts().Get(name)
	if err != nil {
		writeError(w, http.StatusNotFound, (&ErrServiceCall{Operation: "get account", Detail: err.Error()}).Error())
		return
	}

	writeJSON(w, http.StatusOK, acct)
}

// removeAccount handles DELETE /api/v1/accounts/{name}.
func (h *handlers) removeAccount(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]

	if err := h.service.Accounts().Remove(r.Context(), name); err != nil {
		h.logger.Error("remove account failed", "error", err.Error(), "name", name)
		writeError(w, http.StatusConflict, (&ErrServiceCall{Operation: "remove account", Detail: err.Error()}).Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "removed", "name": name})
}

// certResponseBody is the JSON response body for certificate operations.
type certResponseBody struct {
	Subject   string `json:"subject"`
	NotBefore string `json:"notBefore,omitempty"`
	NotAfter  string `json:"notAfter,omitempty"`
}

// certNameRequest is the JSON request body for spec-based certificate operations.
type certNameRequest struct {
	Name string `json:"name"`
}

// requestCert handles POST /api/v1/certificate/request.
func (h *handlers) requestCert(w http.ResponseWriter, r *http.Request) {
	var req certNameRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, (&ErrInvalidRequestBody{Detail: err.Error()}).Error())
		return
	}

	if req.Name == "" {
		writeError(w, http.StatusBadRequest, (&ErrMissingField{Field: "name"}).Error())
		return
	}

	result, err := h.service.Certificates().Request(r.Context(), req.Name)
	if err != nil {
		h.logger.Error("certificate request failed", "error", err.Error(), "name", req.Name)
		writeError(w, http.StatusInternalServerError, (&ErrServiceCall{Operation: "request certificate", Detail: err.Error()}).Error())
		return
	}

	writeJSON(w, http.StatusOK, &certResponseBody{
		Subject:   result.Certificate.Subject.CommonName,
		NotBefore: result.Certificate.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:  result.Certificate.NotAfter.UTC().Format(time.RFC3339),
	})
}

// renewCert handles POST /api/v1/certificate/renew.
func (h *handlers) renewCert(w http.ResponseWriter, r *http.Request) {
	var req certNameRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, (&ErrInvalidRequestBody{Detail: err.Error()}).Error())
		return
	}

	if req.Name == "" {
		writeError(w, http.StatusBadRequest, (&ErrMissingField{Field: "name"}).Error())
		return
	}

	result, err := h.service.Certificates().Renew(r.Context(), req.Name)
	if err != nil {
		h.logger.Error("certificate renewal failed", "error", err.Error(), "name", req.Name)
		writeError(w, http.StatusInternalServerError, (&ErrServiceCall{Operation: "renew certificate", Detail: err.Error()}).Error())
		return
	}

	writeJSON(w, http.StatusOK, &certResponseBody{
		Subject:   result.Certificate.Subject.CommonName,
		NotBefore: result.Certificate.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:  result.Certificate.NotAfter.UTC().Format(time.RFC3339),
	})
}

// revokeRequestBody is the JSON request body for certificate revocation.
type revokeRequestBody struct {
	CertFile    string `json:"certFile"`
	Certificate string `json:"certificate"`
	Name        string `json:"name"`
	Reason      int    `json:"reason"`
}

// revokeCert handles POST /api/v1/certificate/revoke.
// When the SDK workflow is available it uses the workflow's RevokeCertificate
// method, otherwise it falls back to the service layer.
func (h *handlers) revokeCert(w http.ResponseWriter, r *http.Request) {
	var req revokeRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, (&ErrInvalidRequestBody{Detail: err.Error()}).Error())
		return
	}

	if h.wf != nil && req.Certificate != "" {
		h.revokeViaWorkflow(w, r, &req)
		return
	}

	h.revokeViaService(w, r, &req)
}

// revokeViaWorkflow performs certificate revocation through the SDK workflow.
func (h *handlers) revokeViaWorkflow(w http.ResponseWriter, r *http.Request, req *revokeRequestBody) {
	err := h.wf.RevokeCertificate(r.Context(), &workflow.RevokeRequest{
		Certificate: req.Certificate,
		Reason:      req.Reason,
	})
	if err != nil {
		h.logger.Error("revoke certificate via workflow failed", "error", err.Error())
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

// revokeViaService performs certificate revocation through the direct service layer.
func (h *handlers) revokeViaService(w http.ResponseWriter, r *http.Request, req *revokeRequestBody) {
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, (&ErrMissingField{Field: "name"}).Error())
		return
	}

	if err := h.service.Certificates().Revoke(r.Context(), req.Name, req.Reason); err != nil {
		h.logger.Error("revoke certificate via service failed", "error", err.Error(), "name", req.Name)
		writeError(w, http.StatusInternalServerError, (&ErrServiceCall{Operation: "revoke certificate", Detail: err.Error()}).Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked", "name": req.Name})
}

// listCertificates handles GET /api/v1/certificates.
func (h *handlers) listCertificates(w http.ResponseWriter, r *http.Request) {
	accountFilter := r.URL.Query().Get("account")
	certs := h.service.Certificates().List(accountFilter)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"certificates": certs,
	})
}

// certInfoResponse is the JSON response for certificate metadata.
type certInfoResponse struct {
	Name       string `json:"name"`
	Subject    string `json:"subject"`
	Account    string `json:"account"`
	IssuedAt   string `json:"issuedAt"`
	ExpiresAt  string `json:"expiresAt"`
	DeployedAt string `json:"deployedAt,omitempty"`
}

// getCertificate handles GET /api/v1/certificates/{name}.
func (h *handlers) getCertificate(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]

	info, err := h.service.Certificates().Show(name)
	if err != nil {
		// Fall back to returning the spec if the cert is not yet managed.
		specs := h.service.Certificates().List("")
		if spec, ok := specs[name]; ok {
			writeJSON(w, http.StatusOK, spec)
			return
		}
		writeError(w, http.StatusNotFound, (&ErrServiceCall{Operation: "show certificate", Detail: err.Error()}).Error())
		return
	}

	resp := &certInfoResponse{
		Name:      info.Name,
		Subject:   info.Spec.Subject.CN,
		Account:   info.Spec.Account,
		IssuedAt:  info.IssuedAt.UTC().Format(time.RFC3339),
		ExpiresAt: info.ExpiresAt.UTC().Format(time.RFC3339),
	}
	if info.DeployedAt != nil {
		resp.DeployedAt = info.DeployedAt.UTC().Format(time.RFC3339)
	}

	writeJSON(w, http.StatusOK, resp)
}

// deployCertificate handles POST /api/v1/certificates/{name}/deploy.
func (h *handlers) deployCertificate(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]

	if err := h.service.Certificates().Deploy(r.Context(), name); err != nil {
		h.logger.Error("certificate deployment failed", "error", err.Error(), "name", name)
		writeError(w, http.StatusInternalServerError, (&ErrServiceCall{Operation: "deploy certificate", Detail: err.Error()}).Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "deployed", "name": name})
}
