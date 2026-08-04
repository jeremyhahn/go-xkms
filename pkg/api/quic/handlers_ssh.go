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
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	gossh "golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-xkms/pkg/api/rest/secureio"
	pkgauthorized "github.com/jeremyhahn/go-xkms/pkg/ssh/authorized"
	pkgkeys "github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	pkgknownhosts "github.com/jeremyhahn/go-xkms/pkg/ssh/known_hosts"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// setupSSHRoutes registers SSH key, known-hosts, and authorized-keys
// routes on mux. Called from setupRoutes only when sshClient is non-nil.
func (s *Server) setupSSHRoutes(mux *http.ServeMux) {
	// Keys — exact match handles list (GET) and generate (POST);
	// prefix match handles import, get, delete, export-public, sign.
	mux.HandleFunc("/xkms/v1/ssh/keys", s.handleSSHKeys)
	mux.HandleFunc("/xkms/v1/ssh/keys/", s.handleSSHKeyOps)

	// Known hosts — exact handles list and add; prefix handles
	// per-host remove and verify.
	mux.HandleFunc("/xkms/v1/ssh/known-hosts", s.handleSSHKnownHosts)
	mux.HandleFunc("/xkms/v1/ssh/known-hosts/", s.handleSSHKnownHostOps)

	// Authorized keys — exact handles list and add; prefix handles
	// emit, verify, get, and remove.
	mux.HandleFunc("/xkms/v1/ssh/authorized-keys", s.handleSSHAuthorizedKeys)
	mux.HandleFunc("/xkms/v1/ssh/authorized-keys/", s.handleSSHAuthorizedKeyOps)
}

// ------------------------------------------------------------------ //
// Keys                                                                //
// ------------------------------------------------------------------ //

// handleSSHKeys dispatches GET (list) and POST (generate) on the
// /xkms/v1/ssh/keys endpoint.
func (s *Server) handleSSHKeys(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleSSHListKeys(w, r)
	case http.MethodPost:
		s.handleSSHGenerate(w, r)
	default:
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// handleSSHKeyOps is the prefix dispatcher for /xkms/v1/ssh/keys/*.
// It parses the trailing path to determine the operation:
//
//   - "import"                    → POST /keys/import
//   - "{scope}/{owner}/{name}"    → GET (get) or DELETE (delete)
//   - "{scope}/{owner}/{name}/public" → GET (export public)
//   - "{scope}/{owner}/{name}/sign"   → POST (sign)
func (s *Server) handleSSHKeyOps(w http.ResponseWriter, r *http.Request) {
	tail := strings.TrimPrefix(r.URL.Path, "/xkms/v1/ssh/keys/")
	if tail == "" {
		s.sendError(w, http.StatusNotFound, "not found")
		return
	}

	if tail == "import" {
		if r.Method != http.MethodPost {
			s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		s.handleSSHImport(w, r)
		return
	}

	parts := strings.Split(tail, "/")
	if len(parts) == 3 {
		scope, owner, name := parts[0], parts[1], parts[2]
		switch r.Method {
		case http.MethodGet:
			s.handleSSHGetKey(w, r, scope, owner, name)
		case http.MethodDelete:
			s.handleSSHDeleteKey(w, r, scope, owner, name)
		default:
			s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
		return
	}

	if len(parts) == 4 {
		scope, owner, name, op := parts[0], parts[1], parts[2], parts[3]

		type keyOpHandler func(http.ResponseWriter, *http.Request, string, string, string)
		handlers := map[string]keyOpHandler{
			"public": s.handleSSHExportPublic,
			"sign":   s.handleSSHSign,
		}
		handler, ok := handlers[op]
		if !ok {
			s.sendError(w, http.StatusNotFound, "unknown key operation: "+op)
			return
		}
		handler(w, r, scope, owner, name)
		return
	}

	s.sendError(w, http.StatusNotFound, "not found")
}

// handleSSHGenerate handles POST /xkms/v1/ssh/keys.
func (s *Server) handleSSHGenerate(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, "ssh", "write") {
		return
	}
	var req sdkssh.GenerateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendSSHError(w, &sshBadBodyError{err: err})
		return
	}
	out, err := s.sshClient.Keys().Generate(r.Context(), req)
	if err != nil {
		s.sendSSHError(w, err)
		return
	}
	s.sendJSON(w, http.StatusCreated, out)
}

// handleSSHImport handles POST /xkms/v1/ssh/keys/import. The passphrase
// (if present) is decoded directly into a memguard-backed *secure.Buffer
// via secureio.PasswordField — plaintext never occupies a Go string.
func (s *Server) handleSSHImport(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, "ssh", "write") {
		return
	}
	var dto sshImportDTO
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&dto); err != nil {
		dto.Passphrase.Destroy()
		s.sendSSHError(w, &sshBadBodyError{err: err})
		return
	}
	defer dto.Passphrase.Destroy()

	var provider secure.PassphraseProvider
	if buf := dto.Passphrase.Buffer(); buf != nil && buf.Size() > 0 {
		provider = &sshBuffersProvider{buf: buf}
	}

	importReq := sdkssh.ImportRequest{
		Scope:   dto.Scope,
		Owner:   dto.Owner,
		Name:    dto.Name,
		Comment: dto.Comment,
		PEM:     dto.PEM,
	}
	out, err := s.sshClient.Keys().Import(r.Context(), importReq, provider)
	if err != nil {
		s.sendSSHError(w, err)
		return
	}
	s.sendJSON(w, http.StatusCreated, out)
}

// handleSSHListKeys handles GET /xkms/v1/ssh/keys.
func (s *Server) handleSSHListKeys(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, "ssh", "read") {
		return
	}
	list, err := s.sshClient.Keys().List(r.Context(), sdkssh.ListKeysRequest{
		Scope: r.URL.Query().Get("scope"),
		Owner: r.URL.Query().Get("owner"),
	})
	if err != nil {
		s.sendSSHError(w, err)
		return
	}
	s.sendJSON(w, http.StatusOK, sshKeyListResp{Items: list})
}

// handleSSHGetKey handles GET /xkms/v1/ssh/keys/{scope}/{owner}/{name}.
func (s *Server) handleSSHGetKey(w http.ResponseWriter, r *http.Request, scope, owner, name string) {
	if !s.authorize(w, r, "ssh", "read") {
		return
	}
	out, err := s.sshClient.Keys().Get(r.Context(), sdkssh.GetKeyRequest{
		Scope: scope,
		Owner: owner,
		Name:  name,
	})
	if err != nil {
		s.sendSSHError(w, err)
		return
	}
	s.sendJSON(w, http.StatusOK, out)
}

// handleSSHDeleteKey handles DELETE /xkms/v1/ssh/keys/{scope}/{owner}/{name}.
func (s *Server) handleSSHDeleteKey(w http.ResponseWriter, r *http.Request, scope, owner, name string) {
	if !s.authorize(w, r, "ssh", "delete") {
		return
	}
	if err := s.sshClient.Keys().Delete(r.Context(), sdkssh.DeleteKeyRequest{
		Scope: scope,
		Owner: owner,
		Name:  name,
	}); err != nil {
		s.sendSSHError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleSSHExportPublic handles GET /xkms/v1/ssh/keys/{scope}/{owner}/{name}/public.
func (s *Server) handleSSHExportPublic(w http.ResponseWriter, r *http.Request, scope, owner, name string) {
	if r.Method != http.MethodGet {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.authorize(w, r, "ssh", "read") {
		return
	}
	out, err := s.sshClient.Keys().ExportPublic(r.Context(), sdkssh.ExportRequest{
		Scope: scope,
		Owner: owner,
		Name:  name,
	})
	if err != nil {
		s.sendSSHError(w, err)
		return
	}
	s.sendJSON(w, http.StatusOK, out)
}

// handleSSHSign handles POST /xkms/v1/ssh/keys/{scope}/{owner}/{name}/sign.
// It acquires an enclave-backed signer, signs the supplied digest, and
// returns the signature in the same JSON shape the REST client expects.
func (s *Server) handleSSHSign(w http.ResponseWriter, r *http.Request, scope, owner, name string) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.authorize(w, r, "ssh", "write") {
		return
	}
	var req sshSignReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendSSHError(w, &sshBadBodyError{err: err})
		return
	}
	if len(req.Digest) == 0 {
		s.sendSSHError(w, &sshBadBodyError{err: errors.New("digest is required")})
		return
	}

	signer, err := s.sshClient.Keys().Signer(r.Context(), sdkssh.GetKeyRequest{
		Scope: scope,
		Owner: owner,
		Name:  name,
	})
	if err != nil {
		s.sendSSHError(w, err)
		return
	}

	sig, err := signer.Sign(rand.Reader, req.Digest)
	if err != nil {
		s.sendSSHError(w, err)
		return
	}
	s.sendJSON(w, http.StatusOK, sshSignResp{
		Format: sig.Format,
		Blob:   sig.Blob,
		Rest:   sig.Rest,
	})
}

// ------------------------------------------------------------------ //
// Known hosts                                                         //
// ------------------------------------------------------------------ //

// handleSSHKnownHosts dispatches GET (list) and POST (add) on
// /xkms/v1/ssh/known-hosts.
func (s *Server) handleSSHKnownHosts(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleSSHListKnownHosts(w, r)
	case http.MethodPost:
		s.handleSSHAddKnownHost(w, r)
	default:
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// handleSSHKnownHostOps is the prefix dispatcher for
// /xkms/v1/ssh/known-hosts/*. It parses the host from the path and
// routes to remove (DELETE) or verify (POST .../verify).
func (s *Server) handleSSHKnownHostOps(w http.ResponseWriter, r *http.Request) {
	tail := strings.TrimPrefix(r.URL.Path, "/xkms/v1/ssh/known-hosts/")
	if tail == "" {
		s.sendError(w, http.StatusNotFound, "not found")
		return
	}

	parts := strings.SplitN(tail, "/", 2)
	host := parts[0]

	if len(parts) == 1 {
		if r.Method != http.MethodDelete {
			s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		s.handleSSHRemoveKnownHost(w, r, host)
		return
	}

	if parts[1] == "verify" {
		if r.Method != http.MethodPost {
			s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		s.handleSSHVerifyKnownHost(w, r, host)
		return
	}

	s.sendError(w, http.StatusNotFound, "not found")
}

// handleSSHAddKnownHost handles POST /xkms/v1/ssh/known-hosts.
func (s *Server) handleSSHAddKnownHost(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, "ssh", "write") {
		return
	}
	var req sdkssh.AddKnownHostRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendSSHError(w, &sshBadBodyError{err: err})
		return
	}
	if err := s.sshClient.KnownHosts().Add(r.Context(), req); err != nil {
		s.sendSSHError(w, err)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

// handleSSHListKnownHosts handles GET /xkms/v1/ssh/known-hosts.
func (s *Server) handleSSHListKnownHosts(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, "ssh", "read") {
		return
	}
	list, err := s.sshClient.KnownHosts().List(r.Context(), sdkssh.ListKnownHostsRequest{
		Scope: r.URL.Query().Get("scope"),
		Owner: r.URL.Query().Get("owner"),
	})
	if err != nil {
		s.sendSSHError(w, err)
		return
	}
	s.sendJSON(w, http.StatusOK, sshPinListResp{Items: list})
}

// handleSSHRemoveKnownHost handles DELETE /xkms/v1/ssh/known-hosts/{host}.
func (s *Server) handleSSHRemoveKnownHost(w http.ResponseWriter, r *http.Request, host string) {
	if !s.authorize(w, r, "ssh", "delete") {
		return
	}
	err := s.sshClient.KnownHosts().Remove(r.Context(), sdkssh.RemoveKnownHostRequest{
		Scope: r.URL.Query().Get("scope"),
		Owner: r.URL.Query().Get("owner"),
		Host:  host,
	})
	if err != nil {
		s.sendSSHError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleSSHVerifyKnownHost handles POST /xkms/v1/ssh/known-hosts/{host}/verify.
// It compares the supplied fingerprint against the pin stored for host,
// returning 204 on match and 409 on mismatch — the same semantics as
// the REST transport.
func (s *Server) handleSSHVerifyKnownHost(w http.ResponseWriter, r *http.Request, host string) {
	if !s.authorize(w, r, "ssh", "read") {
		return
	}
	var req sshVerifyReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendSSHError(w, &sshBadBodyError{err: err})
		return
	}

	pins, err := s.sshClient.KnownHosts().List(r.Context(), sdkssh.ListKnownHostsRequest{
		Scope: req.Scope,
		Owner: req.Owner,
	})
	if err != nil {
		s.sendSSHError(w, err)
		return
	}

	var pin *sdkssh.Pin
	for _, p := range pins {
		if p.Host == host {
			pin = p
			break
		}
	}
	if pin == nil {
		s.sendSSHError(w, &pkgknownhosts.NotFoundError{
			Scope: req.Scope,
			Owner: req.Owner,
			Host:  host,
		})
		return
	}
	if pin.Fingerprint != req.Fingerprint {
		s.sendSSHMismatch(w, host, pin.Fingerprint, req.Fingerprint)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ------------------------------------------------------------------ //
// Authorized keys                                                     //
// ------------------------------------------------------------------ //

// handleSSHAuthorizedKeys dispatches GET (list) and POST (add) on
// /xkms/v1/ssh/authorized-keys.
func (s *Server) handleSSHAuthorizedKeys(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleSSHListAuthorized(w, r)
	case http.MethodPost:
		s.handleSSHAddAuthorized(w, r)
	default:
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// handleSSHAuthorizedKeyOps is the prefix dispatcher for
// /xkms/v1/ssh/authorized-keys/*. It routes:
//
//   - "emit"                    → POST /emit
//   - "verify"                  → POST /verify
//   - "{scope}/{owner}/{name}"  → GET (get) or DELETE (remove)
func (s *Server) handleSSHAuthorizedKeyOps(w http.ResponseWriter, r *http.Request) {
	tail := strings.TrimPrefix(r.URL.Path, "/xkms/v1/ssh/authorized-keys/")
	if tail == "" {
		s.sendError(w, http.StatusNotFound, "not found")
		return
	}

	// Fixed named operations take precedence over parameterised paths.
	switch tail {
	case "emit":
		if r.Method != http.MethodPost {
			s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		s.handleSSHEmit(w, r)
		return
	case "verify":
		if r.Method != http.MethodPost {
			s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		s.handleSSHVerifyAuthorized(w, r)
		return
	}

	// {scope}/{owner}/{name}
	parts := strings.Split(tail, "/")
	if len(parts) != 3 {
		s.sendError(w, http.StatusNotFound, "not found")
		return
	}
	scope, owner, name := parts[0], parts[1], parts[2]
	switch r.Method {
	case http.MethodGet:
		s.handleSSHGetAuthorized(w, r, scope, owner, name)
	case http.MethodDelete:
		s.handleSSHRemoveAuthorized(w, r, scope, owner, name)
	default:
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// handleSSHAddAuthorized handles POST /xkms/v1/ssh/authorized-keys.
func (s *Server) handleSSHAddAuthorized(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, "ssh", "write") {
		return
	}
	var req sdkssh.AddAuthorizedKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendSSHError(w, &sshBadBodyError{err: err})
		return
	}
	if err := s.sshClient.AuthorizedKeys().Add(r.Context(), req); err != nil {
		s.sendSSHError(w, err)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

// handleSSHListAuthorized handles GET /xkms/v1/ssh/authorized-keys.
func (s *Server) handleSSHListAuthorized(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, "ssh", "read") {
		return
	}
	list, err := s.sshClient.AuthorizedKeys().List(r.Context(), sdkssh.ListAuthorizedKeysRequest{
		Scope: r.URL.Query().Get("scope"),
		Owner: r.URL.Query().Get("owner"),
	})
	if err != nil {
		s.sendSSHError(w, err)
		return
	}
	s.sendJSON(w, http.StatusOK, sshAuthorizedListResp{Items: list})
}

// handleSSHGetAuthorized handles GET /xkms/v1/ssh/authorized-keys/{scope}/{owner}/{name}.
func (s *Server) handleSSHGetAuthorized(w http.ResponseWriter, r *http.Request, scope, owner, name string) {
	if !s.authorize(w, r, "ssh", "read") {
		return
	}
	out, err := s.sshClient.AuthorizedKeys().Get(r.Context(), scope, owner, name)
	if err != nil {
		s.sendSSHError(w, err)
		return
	}
	s.sendJSON(w, http.StatusOK, out)
}

// handleSSHRemoveAuthorized handles DELETE /xkms/v1/ssh/authorized-keys/{scope}/{owner}/{name}.
func (s *Server) handleSSHRemoveAuthorized(w http.ResponseWriter, r *http.Request, scope, owner, name string) {
	if !s.authorize(w, r, "ssh", "delete") {
		return
	}
	if err := s.sshClient.AuthorizedKeys().Remove(r.Context(), scope, owner, name); err != nil {
		s.sendSSHError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleSSHEmit handles POST /xkms/v1/ssh/authorized-keys/emit.
func (s *Server) handleSSHEmit(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, "ssh", "read") {
		return
	}
	var req sdkssh.EmitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendSSHError(w, &sshBadBodyError{err: err})
		return
	}
	line, err := s.sshClient.AuthorizedKeys().Emit(r.Context(), req)
	if err != nil {
		s.sendSSHError(w, err)
		return
	}
	s.sendJSON(w, http.StatusOK, sshEmitResp{Line: line})
}

// handleSSHVerifyAuthorized handles POST /xkms/v1/ssh/authorized-keys/verify.
// It lists the authorized entries for (scope, owner), parses each entry's
// public key, and compares the SHA-256 fingerprint against the supplied
// value — matching the REST handler's fingerprint-comparison semantics.
func (s *Server) handleSSHVerifyAuthorized(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, "ssh", "read") {
		return
	}
	var req sshVerifyReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendSSHError(w, &sshBadBodyError{err: err})
		return
	}

	list, err := s.sshClient.AuthorizedKeys().List(r.Context(), sdkssh.ListAuthorizedKeysRequest{
		Scope: req.Scope,
		Owner: req.Owner,
	})
	if err != nil {
		s.sendSSHError(w, err)
		return
	}

	for _, entry := range list {
		pub, _, _, _, perr := gossh.ParseAuthorizedKey([]byte(entry.Line))
		if perr != nil {
			continue
		}
		if gossh.FingerprintSHA256(pub) == req.Fingerprint {
			s.sendJSON(w, http.StatusOK, entry)
			return
		}
	}
	s.sendSSHError(w, &pkgauthorized.NotFoundError{Scope: req.Scope, Owner: req.Owner})
}

// ------------------------------------------------------------------ //
// Error helpers                                                       //
// ------------------------------------------------------------------ //

// sshErrEnvelope is the JSON shape emitted by all SSH error responses.
// Field names mirror the REST transport's sshErrorEnvelope so the REST
// SDK client (decodeErrorResponse) can decode QUIC responses unchanged.
type sshErrEnvelope struct {
	Error    string `json:"error"`
	Resource string `json:"resource,omitempty"`
	Host     string `json:"host,omitempty"`
	Expected string `json:"expected,omitempty"`
	Received string `json:"received,omitempty"`
}

// sendSSHError serialises err into the SSH error envelope and writes the
// appropriate HTTP status code. Known-host mismatch errors populate the
// Host/Expected/Received fields so the REST client can reconstruct a
// *MismatchError.
func (s *Server) sendSSHError(w http.ResponseWriter, err error) {
	status := sshHTTPStatus(err)
	env := sshErrEnvelope{
		Error:    err.Error(),
		Resource: sshResourceName(err),
	}
	var mm *pkgknownhosts.MismatchError
	if errors.As(err, &mm) {
		env.Host = mm.Host
		env.Expected = mm.Expected
		env.Received = mm.Received
	}
	s.sendJSON(w, status, env)
}

// sendSSHMismatch writes a 409 Conflict response for a host-key mismatch
// detected during the verify-known-host path.
func (s *Server) sendSSHMismatch(w http.ResponseWriter, host, expected, received string) {
	s.sendJSON(w, http.StatusConflict, sshErrEnvelope{
		Error:    "ssh/known_hosts: host key mismatch",
		Resource: "known_hosts",
		Host:     host,
		Expected: expected,
		Received: received,
	})
}

// sshHTTPStatus maps err to the correct HTTP status code. sshBadBodyError
// is handled here (400) because it is transport-specific; all other
// mappings are delegated to the shared SDK table.
func sshHTTPStatus(err error) int {
	var bb *sshBadBodyError
	if errors.As(err, &bb) {
		return http.StatusBadRequest
	}
	return sdkssh.HTTPStatusForError(err)
}

// sshResourceName returns the logical resource label for an error,
// mirroring the REST handler's sshErrorResource function so that
// clients can distinguish 404/409 responses across resource families.
func sshResourceName(err error) string {
	{
		var e *pkgkeys.KeyNotFoundError
		if errors.As(err, &e) {
			return "key"
		}
	}
	{
		var e *pkgknownhosts.NotFoundError
		if errors.As(err, &e) {
			return "known_hosts"
		}
	}
	{
		var e *pkgknownhosts.DuplicateError
		if errors.As(err, &e) {
			return "known_hosts"
		}
	}
	{
		var e *pkgknownhosts.MismatchError
		if errors.As(err, &e) {
			return "known_hosts"
		}
	}
	{
		var e *pkgauthorized.NotFoundError
		if errors.As(err, &e) {
			return "authorized_key"
		}
	}
	{
		var e *pkgauthorized.DuplicateError
		if errors.As(err, &e) {
			return "authorized_key"
		}
	}
	return ""
}

// ------------------------------------------------------------------ //
// Local types                                                         //
// ------------------------------------------------------------------ //

// sshBadBodyError is returned when the request body cannot be decoded.
type sshBadBodyError struct {
	err error
}

// Error implements the error interface.
func (e *sshBadBodyError) Error() string {
	if e.err == nil {
		return "quic/ssh: bad request body"
	}
	return "quic/ssh: bad request body: " + e.err.Error()
}

// Unwrap exposes the underlying decode failure.
func (e *sshBadBodyError) Unwrap() error { return e.err }

// sshImportDTO is the server-side wire shape for POST /keys/import.
// Passphrase uses secureio.PasswordField whose UnmarshalJSON lands the
// decoded bytes directly into a *secure.Buffer.
type sshImportDTO struct {
	Scope      string                 `json:"scope"`
	Owner      string                 `json:"owner"`
	Name       string                 `json:"name"`
	Comment    string                 `json:"comment,omitempty"`
	PEM        []byte                 `json:"pem"`
	Passphrase secureio.PasswordField `json:"passphrase_b64,omitempty"`
}

// sshBuffersProvider wraps a *secure.Buffer into the SDK
// PassphraseProvider contract. The handler owns the Buffer's lifetime;
// Passphrase returns a clone so the caller may destroy their copy
// independently.
type sshBuffersProvider struct {
	buf *secure.Buffer
}

// Passphrase implements secure.PassphraseProvider by cloning the
// underlying Buffer.
func (p *sshBuffersProvider) Passphrase(_ context.Context, _ string) (*secure.Buffer, error) {
	if p == nil || p.buf == nil || p.buf.Size() == 0 {
		return nil, &sdkssh.NilInputError{Field: "passphrase"}
	}
	cloned, err := secure.NewBuffer(p.buf.Size())
	if err != nil {
		return nil, err
	}
	copy(cloned.Bytes(), p.buf.Bytes())
	return cloned, nil
}

// sshSignReq is the JSON body of POST /keys/.../sign.
type sshSignReq struct {
	Digest []byte `json:"digest"`
}

// sshSignResp mirrors the REST transport's sign response shape.
type sshSignResp struct {
	Format string `json:"format"`
	Blob   []byte `json:"blob"`
	Rest   []byte `json:"rest,omitempty"`
}

// sshVerifyReq is the JSON body for both verify endpoints.
type sshVerifyReq struct {
	Scope       string `json:"scope"`
	Owner       string `json:"owner"`
	Fingerprint string `json:"fingerprint"`
	Algorithm   string `json:"algorithm,omitempty"`
}

// sshKeyListResp is the envelope returned by GET /keys.
type sshKeyListResp struct {
	Items []*sdkssh.Key `json:"items"`
}

// sshPinListResp is the envelope returned by GET /known-hosts.
type sshPinListResp struct {
	Items []*sdkssh.Pin `json:"items"`
}

// sshAuthorizedListResp is the envelope returned by GET /authorized-keys.
type sshAuthorizedListResp struct {
	Items []*sdkssh.AuthorizedEntry `json:"items"`
}

// sshEmitResp is the JSON body returned by POST /authorized-keys/emit.
type sshEmitResp struct {
	Line string `json:"line"`
}

// Compile-time interface checks.
var (
	_ secure.PassphraseProvider = (*sshBuffersProvider)(nil)
)
