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

package rest

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	qrdbsecure "github.com/jeremyhahn/go-qrdb/sdk/go/secure"
	gossh "golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-xkms/pkg/api/rest/secureio"
	pkgauthorized "github.com/jeremyhahn/go-xkms/pkg/ssh/authorized"
	pkgkeys "github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	pkgknownhosts "github.com/jeremyhahn/go-xkms/pkg/ssh/known_hosts"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// Request-validation sentinels for the SSH handlers. Each is wrapped in
// *SSHBadBodyError so classifySSHError maps it to 400 alongside every
// other malformed-body condition.
var (
	// ErrSSHMissingDigest indicates handleSign was called with no digest
	// in the request body.
	ErrSSHMissingDigest = errors.New("digest is required")

	// ErrSSHMissingPublicKey indicates handleVerifyKnownHost was called
	// with no public_key in the request body.
	ErrSSHMissingPublicKey = errors.New("public_key is required")
)

// SSHHandlers exposes xkmsd's SSH key, known-hosts, authorized-keys,
// and signer endpoints. The handlers delegate to the embedded SDK
// Client so the REST and embedded transports share a single
// implementation — there is no duplicated business logic between them.
type SSHHandlers struct {
	client sdkssh.Client
	logger *slog.Logger
}

// NewSSHHandlers wires the handlers against a pre-built embedded SDK
// Client. Returns *SSHNilError when either argument is nil.
func NewSSHHandlers(client sdkssh.Client, logger *slog.Logger) (*SSHHandlers, error) {
	if client == nil {
		return nil, &SSHNilError{Field: "client"}
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &SSHHandlers{client: client, logger: logger}, nil
}

// SSHNilError is returned by NewSSHHandlers when a required constructor
// argument is nil.
type SSHNilError struct {
	Field string
}

// Error implements the error interface.
func (e *SSHNilError) Error() string { return "rest/ssh: nil input: " + e.Field }

// Register wires the SSH routes onto r. Caller controls any middleware
// (authentication, tenant enforcement, RBAC) by registering before the
// call. The mount point is "/xkms/v1/ssh".
func (h *SSHHandlers) Register(r chi.Router) {
	r.Route("/xkms/v1/ssh", func(r chi.Router) {
		r.Post("/keys", h.handleGenerate)
		r.Post("/keys/import", h.handleImport)
		r.Get("/keys", h.handleListKeys)
		r.Get("/keys/{scope}/{owner}/{name}", h.handleGetKey)
		r.Delete("/keys/{scope}/{owner}/{name}", h.handleDeleteKey)
		r.Get("/keys/{scope}/{owner}/{name}/public", h.handleExportPublic)
		r.Post("/keys/{scope}/{owner}/{name}/sign", h.handleSign)

		r.Post("/known-hosts", h.handleAddKnownHost)
		r.Get("/known-hosts", h.handleListKnownHosts)
		r.Delete("/known-hosts/{host}", h.handleRemoveKnownHost)
		r.Post("/known-hosts/{host}/verify", h.handleVerifyKnownHost)

		r.Post("/authorized-keys", h.handleAddAuthorized)
		r.Get("/authorized-keys", h.handleListAuthorized)
		r.Get("/authorized-keys/{scope}/{owner}/{name}", h.handleGetAuthorized)
		r.Delete("/authorized-keys/{scope}/{owner}/{name}", h.handleRemoveAuthorized)
		r.Post("/authorized-keys/emit", h.handleEmit)
		r.Post("/authorized-keys/verify", h.handleVerifyAuthorized)
	})
}

// ------------------------------------------------------------------
// Keys.
// ------------------------------------------------------------------

func (h *SSHHandlers) handleGenerate(w http.ResponseWriter, r *http.Request) {
	var req sdkssh.GenerateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeSSHError(w, &SSHBadBodyError{Err: err})
		return
	}
	out, err := h.client.Keys().Generate(r.Context(), req)
	if err != nil {
		writeSSHError(w, err)
		return
	}
	writeJSON(w, out, http.StatusCreated)
}

// handleImport consumes a restImportDTO whose Passphrase field (wire name passphrase_b64) uses
// a custom json.Unmarshaler that lands the decoded bytes directly into
// a *secure.Buffer. No Go string carries the plaintext passphrase on
// this path — see SSHPassphraseField below.
func (h *SSHHandlers) handleImport(w http.ResponseWriter, r *http.Request) {
	var req restImportDTO
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		// Destroy any buffer that may have landed during partial decode.
		req.Passphrase.Destroy()
		writeSSHError(w, &SSHBadBodyError{Err: err})
		return
	}
	defer req.Passphrase.Destroy()

	// Build the passphrase provider, if one was supplied.
	var provider secure.PassphraseProvider
	if buf := req.Passphrase.Buffer(); buf != nil && buf.Size() > 0 {
		provider = &buffersProvider{buf: buf}
		// Transfer ownership to the provider; the handler defer above
		// still calls Destroy on the wrapper, which is idempotent.
	}

	importReq := sdkssh.ImportRequest{
		Scope:   req.Scope,
		Owner:   req.Owner,
		Name:    req.Name,
		Comment: req.Comment,
		PEM:     req.PEM,
	}
	out, err := h.client.Keys().Import(r.Context(), importReq, provider)
	if err != nil {
		writeSSHError(w, err)
		return
	}
	writeJSON(w, out, http.StatusCreated)
}

func (h *SSHHandlers) handleListKeys(w http.ResponseWriter, r *http.Request) {
	list, err := h.client.Keys().List(r.Context(), sdkssh.ListKeysRequest{
		Scope: r.URL.Query().Get("scope"),
		Owner: r.URL.Query().Get("owner"),
	})
	if err != nil {
		writeSSHError(w, err)
		return
	}
	writeJSON(w, restKeyListWire{Items: list}, http.StatusOK)
}

func (h *SSHHandlers) handleGetKey(w http.ResponseWriter, r *http.Request) {
	out, err := h.client.Keys().Get(r.Context(), sdkssh.GetKeyRequest{
		Scope: chi.URLParam(r, "scope"),
		Owner: chi.URLParam(r, "owner"),
		Name:  chi.URLParam(r, "name"),
	})
	if err != nil {
		writeSSHError(w, err)
		return
	}
	writeJSON(w, out, http.StatusOK)
}

func (h *SSHHandlers) handleDeleteKey(w http.ResponseWriter, r *http.Request) {
	err := h.client.Keys().Delete(r.Context(), sdkssh.DeleteKeyRequest{
		Scope: chi.URLParam(r, "scope"),
		Owner: chi.URLParam(r, "owner"),
		Name:  chi.URLParam(r, "name"),
	})
	if err != nil {
		writeSSHError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *SSHHandlers) handleExportPublic(w http.ResponseWriter, r *http.Request) {
	out, err := h.client.Keys().ExportPublic(r.Context(), sdkssh.ExportRequest{
		Scope: chi.URLParam(r, "scope"),
		Owner: chi.URLParam(r, "owner"),
		Name:  chi.URLParam(r, "name"),
	})
	if err != nil {
		writeSSHError(w, err)
		return
	}
	writeJSON(w, out, http.StatusOK)
}

// handleSign acquires an enclave-backed signer, signs the digest, and
// returns the signature. The signer is closed (enclave destroyed)
// before the handler returns.
func (h *SSHHandlers) handleSign(w http.ResponseWriter, r *http.Request) {
	var req restSignRequestDTO
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeSSHError(w, &SSHBadBodyError{Err: err})
		return
	}
	if len(req.Digest) == 0 {
		writeSSHError(w, &SSHBadBodyError{Err: ErrSSHMissingDigest})
		return
	}

	// Prefer the persistent-signer API (SignerWithClose) so the enclave
	// is opened exactly once. That requires reaching through the SDK to
	// the underlying *keys.Key — the embedded SDK's Signer does not
	// currently expose a closer, so we open the key directly via the
	// store pathway.
	signer, closer, err := h.openPersistentSigner(r.Context(), chi.URLParam(r, "scope"),
		chi.URLParam(r, "owner"), chi.URLParam(r, "name"))
	if err != nil {
		writeSSHError(w, err)
		return
	}
	defer closer()

	sig, err := signer.Sign(rand.Reader, req.Digest)
	if err != nil {
		writeSSHError(w, err)
		return
	}
	writeJSON(w, restSignResponseDTO{
		Format: sig.Format,
		Blob:   sig.Blob,
		Rest:   sig.Rest,
	}, http.StatusOK)
}

// openPersistentSigner loads the key from the SDK client and returns
// a long-lived signer + closer. Uses the embedded SDK's Keys().Signer
// for the first Signer (re-open-per-sign path); upgrading to the
// persistent variant happens when the SDK surfaces it (tracked by a
// follow-up item).
func (h *SSHHandlers) openPersistentSigner(ctx context.Context, scope, owner, name string) (gossh.Signer, func(), error) {
	signer, err := h.client.Keys().Signer(ctx, sdkssh.GetKeyRequest{
		Scope: scope,
		Owner: owner,
		Name:  name,
	})
	if err != nil {
		return nil, nil, err
	}
	// The embedded SDK's Signer returns an enclaveSigner — no explicit
	// close is needed (each Sign destroys its own Buffer). Provide a
	// no-op closer so callers don't need to special-case nil.
	return signer, func() {}, nil
}

// ------------------------------------------------------------------
// Known hosts.
// ------------------------------------------------------------------

func (h *SSHHandlers) handleAddKnownHost(w http.ResponseWriter, r *http.Request) {
	var req sdkssh.AddKnownHostRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeSSHError(w, &SSHBadBodyError{Err: err})
		return
	}
	if err := h.client.KnownHosts().Add(r.Context(), req); err != nil {
		writeSSHError(w, err)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (h *SSHHandlers) handleListKnownHosts(w http.ResponseWriter, r *http.Request) {
	list, err := h.client.KnownHosts().List(r.Context(), sdkssh.ListKnownHostsRequest{
		Scope: r.URL.Query().Get("scope"),
		Owner: r.URL.Query().Get("owner"),
	})
	if err != nil {
		writeSSHError(w, err)
		return
	}
	writeJSON(w, restPinListWire{Items: list}, http.StatusOK)
}

func (h *SSHHandlers) handleRemoveKnownHost(w http.ResponseWriter, r *http.Request) {
	err := h.client.KnownHosts().Remove(r.Context(), sdkssh.RemoveKnownHostRequest{
		Scope: r.URL.Query().Get("scope"),
		Owner: r.URL.Query().Get("owner"),
		Host:  chi.URLParam(r, "host"),
	})
	if err != nil {
		writeSSHError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleVerifyKnownHost parses the caller-supplied host public key
// (authorized_keys format) and delegates to the SDK client's
// KnownHosts().Verify, which performs a full public-key comparison
// against the stored pin via the canonical known_hosts.Verify — never a
// caller-claimed fingerprint. On mismatch the server emits 409 with the
// expected/received fingerprints so the client can reconstruct
// MismatchError.
func (h *SSHHandlers) handleVerifyKnownHost(w http.ResponseWriter, r *http.Request) {
	var req restVerifyRequestDTO
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeSSHError(w, &SSHBadBodyError{Err: err})
		return
	}
	host := chi.URLParam(r, "host")
	if req.PublicKey == "" {
		writeSSHError(w, &SSHBadBodyError{Err: ErrSSHMissingPublicKey})
		return
	}
	pub, _, _, _, perr := gossh.ParseAuthorizedKey([]byte(req.PublicKey))
	if perr != nil {
		writeSSHError(w, &sdkssh.InvalidPublicKeyError{Host: host, Err: perr})
		return
	}
	if err := h.client.KnownHosts().Verify(r.Context(), req.Scope, req.Owner, host, pub); err != nil {
		writeSSHError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ------------------------------------------------------------------
// Authorized keys.
// ------------------------------------------------------------------

func (h *SSHHandlers) handleAddAuthorized(w http.ResponseWriter, r *http.Request) {
	var req sdkssh.AddAuthorizedKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeSSHError(w, &SSHBadBodyError{Err: err})
		return
	}
	if err := h.client.AuthorizedKeys().Add(r.Context(), req); err != nil {
		writeSSHError(w, err)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (h *SSHHandlers) handleListAuthorized(w http.ResponseWriter, r *http.Request) {
	list, err := h.client.AuthorizedKeys().List(r.Context(), sdkssh.ListAuthorizedKeysRequest{
		Scope: r.URL.Query().Get("scope"),
		Owner: r.URL.Query().Get("owner"),
	})
	if err != nil {
		writeSSHError(w, err)
		return
	}
	writeJSON(w, restAuthorizedListWire{Items: list}, http.StatusOK)
}

func (h *SSHHandlers) handleGetAuthorized(w http.ResponseWriter, r *http.Request) {
	out, err := h.client.AuthorizedKeys().Get(r.Context(),
		chi.URLParam(r, "scope"), chi.URLParam(r, "owner"), chi.URLParam(r, "name"))
	if err != nil {
		writeSSHError(w, err)
		return
	}
	writeJSON(w, out, http.StatusOK)
}

func (h *SSHHandlers) handleRemoveAuthorized(w http.ResponseWriter, r *http.Request) {
	err := h.client.AuthorizedKeys().Remove(r.Context(),
		chi.URLParam(r, "scope"), chi.URLParam(r, "owner"), chi.URLParam(r, "name"))
	if err != nil {
		writeSSHError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *SSHHandlers) handleEmit(w http.ResponseWriter, r *http.Request) {
	var req sdkssh.EmitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeSSHError(w, &SSHBadBodyError{Err: err})
		return
	}
	line, err := h.client.AuthorizedKeys().Emit(r.Context(), req)
	if err != nil {
		writeSSHError(w, err)
		return
	}
	writeJSON(w, restEmitResponseDTO{Line: line}, http.StatusOK)
}

// handleVerifyAuthorized compares a supplied fingerprint against the
// authorized entries for (scope, owner). Same pragma as known-hosts
// verify — we lookup by fingerprint rather than round-tripping the
// full PublicKey over JSON.
func (h *SSHHandlers) handleVerifyAuthorized(w http.ResponseWriter, r *http.Request) {
	var req restAuthVerifyRequestDTO
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeSSHError(w, &SSHBadBodyError{Err: err})
		return
	}
	list, err := h.client.AuthorizedKeys().List(r.Context(), sdkssh.ListAuthorizedKeysRequest{
		Scope: req.Scope,
		Owner: req.Owner,
	})
	if err != nil {
		writeSSHError(w, err)
		return
	}
	for _, entry := range list {
		// Emit carries the public-key portion; we fingerprint-hash
		// the line to compare without round-tripping the PublicKey
		// DTO. ParseAuthorizedKey handles extra options/comments.
		pub, _, _, _, perr := gossh.ParseAuthorizedKey([]byte(entry.Line))
		if perr != nil {
			continue
		}
		if gossh.FingerprintSHA256(pub) == req.Fingerprint {
			writeJSON(w, entry, http.StatusOK)
			return
		}
	}
	writeSSHError(w, &pkgauthorized.NotFoundError{Scope: req.Scope, Owner: req.Owner})
}

// ------------------------------------------------------------------
// DTOs and helpers.
// ------------------------------------------------------------------

// restImportDTO is the server-side wire shape for POST /keys/import.
// Passphrase uses SSHPassphraseField whose UnmarshalJSON lands the
// decoded bytes directly into a *secure.Buffer.
type restImportDTO struct {
	Scope      string             `json:"scope"`
	Owner      string             `json:"owner"`
	Name       string             `json:"name"`
	Comment    string             `json:"comment,omitempty"`
	PEM        []byte             `json:"pem"`
	Passphrase SSHPassphraseField `json:"passphrase_b64,omitempty"`
}

// SSHPassphraseField is an alias of secureio.PasswordField. The
// shared type handles JSON base64 decoding directly into a
// memguard-backed *secure.Buffer so plaintext never touches a Go
// string. See pkg/api/rest/secureio/password_field.go for the full
// memory-safety contract.
//
// The JSON tag used on the SSH import DTO is passphrase_b64; the
// canonical field name on other endpoints is password_b64. Both
// resolve to the same underlying parser because the field type
// drives Unmarshal behavior, not the tag name.
type SSHPassphraseField = secureio.PasswordField

// buffersProvider wraps a *secure.Buffer into the SDK
// PassphraseProvider contract. The handler owns the Buffer's lifetime;
// the provider returns a clone so the underlying Buffer can be
// destroyed by the caller without affecting the parser's view.
type buffersProvider struct {
	buf *secure.Buffer
}

// Passphrase implements secure.PassphraseProvider by cloning the
// underlying Buffer. Clone → the returned Buffer is owned by the
// caller and destroyed by the SDK Import path; the original Buffer
// stays alive for the handler defer to destroy.
func (p *buffersProvider) Passphrase(_ context.Context, _ string) (*secure.Buffer, error) {
	if p == nil || p.buf == nil || p.buf.Size() == 0 {
		return nil, &SSHNilError{Field: "passphrase"}
	}
	// CopyOut holds p.buf's borrow across the copy; NewBufferFromBytes then
	// moves that copy into the clone's own enclave and wipes it on every
	// path, so no second borrow is ever nested inside the first.
	plain, err := qrdbsecure.CopyOut(p.buf)
	if err != nil {
		return nil, err
	}
	return secure.NewBufferFromBytes(plain)
}

// restSignRequestDTO is the server-side wire form of
// POST /keys/.../sign. Digest is the raw bytes to sign.
type restSignRequestDTO struct {
	Digest []byte `json:"digest"`
}

// restSignResponseDTO mirrors *ssh.Signature.
type restSignResponseDTO struct {
	Format string `json:"format"`
	Blob   []byte `json:"blob"`
	Rest   []byte `json:"rest,omitempty"`
}

// restVerifyRequestDTO matches the client's restVerifyRequest. PublicKey
// is the presented host key as an authorized_keys-format line.
type restVerifyRequestDTO struct {
	Scope     string `json:"scope"`
	Owner     string `json:"owner"`
	PublicKey string `json:"public_key"`
}

// restAuthVerifyRequestDTO matches the client's restAuthVerifyRequest.
type restAuthVerifyRequestDTO struct {
	Scope       string `json:"scope"`
	Owner       string `json:"owner"`
	Fingerprint string `json:"fingerprint"`
	Algorithm   string `json:"algorithm,omitempty"`
}

// restEmitResponseDTO carries the server's emit output.
type restEmitResponseDTO struct {
	Line string `json:"line"`
}

// restKeyListWire wraps []*sdkssh.Key for the list endpoint.
type restKeyListWire struct {
	Items []*sdkssh.Key `json:"items"`
}

// restPinListWire wraps []*sdkssh.Pin for the list endpoint.
type restPinListWire struct {
	Items []*sdkssh.Pin `json:"items"`
}

// restAuthorizedListWire wraps []*sdkssh.AuthorizedEntry.
type restAuthorizedListWire struct {
	Items []*sdkssh.AuthorizedEntry `json:"items"`
}

// sshErrorEnvelope is the response body for non-2xx SSH responses. It
// mirrors the client-side errorEnvelope shape.
type sshErrorEnvelope struct {
	Error    string `json:"error"`
	Message  string `json:"message,omitempty"`
	Resource string `json:"resource,omitempty"`
	Host     string `json:"host,omitempty"`
	Expected string `json:"expected,omitempty"`
	Received string `json:"received,omitempty"`
}

// SSHBadBodyError is returned when a request body cannot be decoded.
type SSHBadBodyError struct {
	Err error
}

// Error implements the error interface.
func (e *SSHBadBodyError) Error() string {
	if e.Err == nil {
		return "rest/ssh: bad request body"
	}
	return "rest/ssh: bad request body: " + e.Err.Error()
}

// Unwrap returns the underlying decode failure.
func (e *SSHBadBodyError) Unwrap() error { return e.Err }

// writeSSHError serializes err to the SSH error envelope and routes
// through the shared SDK status-code table. The envelope's error text is
// scrubbed by clientErrorText exactly as writeError scrubs its own: an
// internal status carries ErrInternalError and err is logged server-side.
func writeSSHError(w http.ResponseWriter, err error) {
	status := classifySSHError(err)
	env := sshErrorEnvelope{
		Error:    clientErrorText(w, err, status),
		Resource: sshErrorResource(err),
	}
	// Known-host mismatch carries extra fields.
	var mm *pkgknownhosts.MismatchError
	if errors.As(err, &mm) {
		env.Host = mm.Host
		env.Expected = mm.Expected
		env.Received = mm.Received
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if encErr := json.NewEncoder(w).Encode(env); encErr != nil {
		slog.Debug("rest/ssh: failed to encode error envelope", "error", encErr)
	}
}

// classifySSHError is a small adapter around the SDK's shared status
// table. The SSHBadBodyError case is handled here (400) because it is
// an HTTP-transport-specific typed error.
func classifySSHError(err error) int {
	var badBody *SSHBadBodyError
	if errors.As(err, &badBody) {
		return http.StatusBadRequest
	}
	var nilInput *SSHNilError
	if errors.As(err, &nilInput) {
		return http.StatusBadRequest
	}
	return sdkssh.HTTPStatusForError(err)
}

// sshErrorResource returns the "resource" label for err, used to
// disambiguate 404/409 responses across the three resource families
// (keys, known_hosts, authorized).
func sshErrorResource(err error) string {
	// Keys.
	{
		var e *pkgkeys.KeyNotFoundError
		if errors.As(err, &e) {
			return "key"
		}
	}
	// Known hosts.
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
	// Authorized.
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

// Compile-time guard: the handler registration function must match
// chi's Router interface contract.
var _ interface {
	Register(chi.Router)
} = (*SSHHandlers)(nil)
