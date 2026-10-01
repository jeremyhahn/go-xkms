// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package services

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/oidc"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// OIDC server credential service errors.
var (
	// ErrOIDCServerNotConnected indicates there is no connected xkmsd: server
	// credentials exist only on a server.
	ErrOIDCServerNotConnected = errors.New("oidc_server: no xkmsd server is connected")

	// ErrOIDCServerNameRequired indicates an empty credential name.
	ErrOIDCServerNameRequired = errors.New("oidc_server: credential name is required")

	// ErrOIDCServerScopeInvalid indicates a scope other than "tenant" or
	// "user".
	ErrOIDCServerScopeInvalid = errors.New("oidc_server: scope must be tenant or user")

	// ErrOIDCServerAccessTokenRequired indicates an import without an access
	// token.
	ErrOIDCServerAccessTokenRequired = errors.New("oidc_server: access token is required")

	// ErrOIDCServerExpiryInvalid indicates an imported expiry that is not an
	// RFC 3339 time.
	ErrOIDCServerExpiryInvalid = errors.New("oidc_server: expiry must be an RFC 3339 time")

	// ErrOIDCServerCodexAuthRequired indicates an empty codex auth.json.
	ErrOIDCServerCodexAuthRequired = errors.New("oidc_server: codex auth.json content is required")

	// ErrOIDCServerClipboardUnavailable indicates there is no clipboard to
	// copy an access token to.
	ErrOIDCServerClipboardUnavailable = errors.New("oidc_server: clipboard is not available")
)

// oidcServerCodexTemplate is the template a credential created from a codex
// auth.json uses: the codex CLI's ChatGPT login.
const oidcServerCodexTemplate = "openai"

// OIDCServerTokens are tokens obtained elsewhere, imported into a server
// credential.
type OIDCServerTokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`

	// ExpiresAt is the access token's expiry as an RFC 3339 time; empty lets
	// the server read it from a JWT access token or the template's token
	// lifetime.
	ExpiresAt string `json:"expires_at,omitempty"`
}

// OIDCServerDeviceLogin is a device login in progress: what the user needs
// to approve it on another device.
type OIDCServerDeviceLogin struct {
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	IntervalSeconds         int64  `json:"interval_seconds"`
	ExpiresAt               string `json:"expires_at"`
}

// OIDCServerCredentialInfo is a server credential's public view for the
// GUI: it never carries a token or the client secret.
type OIDCServerCredentialInfo struct {
	TenantID     string                 `json:"tenant_id,omitempty"`
	Scope        string                 `json:"scope"`
	Owner        string                 `json:"owner,omitempty"`
	Name         string                 `json:"name"`
	Template     string                 `json:"template,omitempty"`
	Issuer       string                 `json:"issuer,omitempty"`
	ClientID     string                 `json:"client_id,omitempty"`
	Scopes       []string               `json:"scopes,omitempty"`
	Status       string                 `json:"status"`
	StatusReason string                 `json:"status_reason,omitempty"`
	ExpiresAt    string                 `json:"expires_at,omitempty"`
	Refreshable  bool                   `json:"refreshable"`
	LastRefresh  string                 `json:"last_refresh,omitempty"`
	LastError    string                 `json:"last_error,omitempty"`
	DeviceLogin  *OIDCServerDeviceLogin `json:"device_login,omitempty"`
	CreatedAt    string                 `json:"created_at,omitempty"`
	UpdatedAt    string                 `json:"updated_at,omitempty"`
	CreatedBy    string                 `json:"created_by,omitempty"`

	// SupportsDevice reports whether a device login can be started: the
	// template offers one, or the configuration names a device endpoint.
	SupportsDevice bool `json:"supports_device"`
}

// OIDCServerTemplateInfo is a provider template a server credential can be
// created from.
type OIDCServerTemplateInfo struct {
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	Issuer         string   `json:"issuer,omitempty"`
	Scopes         []string `json:"scopes,omitempty"`
	RequiresIssuer bool     `json:"requires_issuer"`
	SupportsDevice bool     `json:"supports_device"`
	SupportsImport bool     `json:"supports_import"`
	NoRefresh      bool     `json:"no_refresh"`
}

// clipboardWriter copies sensitive text to the clipboard and clears it
// after the configured timeout (ClipboardService).
type clipboardWriter interface {
	CopyWithClear(text string) error
}

// OIDCServerService manages the server-side OIDC credentials of the
// connected xkmsd: named OAuth/OIDC logins the server holds on the tenant
// barrier and refreshes, tenant-shared (scope "tenant") or personal (scope
// "user"). It exists alongside OIDCService, xKey's own local providers,
// which it never touches. Without a connected server every operation fails
// with ErrOIDCServerNotConnected.
type OIDCServerService struct {
	ctx       context.Context
	log       *slog.Logger
	client    atomic.Pointer[transport.OIDCCredentialService]
	clipboard clipboardWriter
}

// NewOIDCServerService returns an OIDCServerService that copies access
// tokens through clipboard; a nil clipboard disables copying.
func NewOIDCServerService(clipboard *ClipboardService) *OIDCServerService {
	s := &OIDCServerService{log: slog.Default().With("component", "oidc_server_service")}
	if clipboard != nil {
		s.clipboard = clipboard
	}
	return s
}

// SetContext is called by the Wails startup lifecycle hook.
func (s *OIDCServerService) SetContext(ctx context.Context) {
	s.ctx = ctx
}

// SetClient sets the connected xkmsd -- any transport.Client serves the
// OIDC credential API; nil clears it on disconnect.
func (s *OIDCServerService) SetClient(c transport.OIDCCredentialService) {
	if c == nil {
		s.client.Store(nil)
		return
	}
	s.client.Store(&c)
}

// Connected reports whether a server is connected, so the GUI shows the
// server credentials section.
func (s *OIDCServerService) Connected() bool {
	return s.client.Load() != nil
}

// context returns the service context, or context.Background before
// startup.
func (s *OIDCServerService) context() context.Context {
	if s.ctx != nil {
		return s.ctx
	}
	return context.Background()
}

// server returns the connected client.
func (s *OIDCServerService) server() (transport.OIDCCredentialService, error) {
	c := s.client.Load()
	if c == nil {
		return nil, ErrOIDCServerNotConnected
	}
	return *c, nil
}

// recoverPanic converts a panic in a Wails-bound method into an error.
func (s *OIDCServerService) recoverPanic(method string, retErr *error) {
	if r := recover(); r != nil {
		s.log.Error("panic in "+method, "recover", r)
		*retErr = &MessageError{Msg: fmt.Sprintf("oidc_server_service: panic in %s: %v", method, r)}
	}
}

// ServerTemplates returns the provider templates a server credential can be
// created from, by name: every built-in template but the region-bound AWS
// ones, whose login only xKey's local backend performs.
func (s *OIDCServerService) ServerTemplates() []OIDCServerTemplateInfo {
	out := make([]OIDCServerTemplateInfo, 0, len(oidc.BuiltinTemplates))
	for _, t := range oidc.BuiltinTemplates {
		if t.RequiresRegion {
			continue
		}
		out = append(out, OIDCServerTemplateInfo{
			Name:           t.Name,
			Description:    t.Description,
			Issuer:         t.Issuer,
			Scopes:         t.Scopes,
			RequiresIssuer: t.Issuer == "",
			SupportsDevice: t.SupportsFlow(oidc.FlowDevice),
			SupportsImport: t.SupportsFlow(oidc.FlowImport),
			NoRefresh:      t.NoRefresh,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ListServerCredentials returns the credentials of tenantID (empty is the
// caller's own tenant) the caller can see: the shared ones, and in its own
// tenant its personal ones.
func (s *OIDCServerService) ListServerCredentials(tenantID string) (retVal []OIDCServerCredentialInfo, retErr error) {
	defer s.recoverPanic("ListServerCredentials", &retErr)
	c, err := s.server()
	if err != nil {
		return nil, err
	}
	resp, err := c.OIDCCredentialList(s.context(), &transport.OIDCCredentialListRequest{TenantID: strings.TrimSpace(tenantID)})
	if err != nil {
		return nil, err
	}
	out := make([]OIDCServerCredentialInfo, 0, len(resp.Credentials))
	for i := range resp.Credentials {
		out = append(out, *serverCredentialInfo(&resp.Credentials[i]))
	}
	return out, nil
}

// CreateServerCredential creates a credential from cfg (a template fills
// every field left empty). It is pending until a device login or an import
// gives it a login.
func (s *OIDCServerService) CreateServerCredential(ref transport.OIDCCredentialRef, cfg transport.OIDCCredentialConfig) (retVal *OIDCServerCredentialInfo, retErr error) {
	defer s.recoverPanic("CreateServerCredential", &retErr)
	r, err := normalizeServerRef(ref)
	if err != nil {
		return nil, err
	}
	c, err := s.server()
	if err != nil {
		return nil, err
	}
	cred, err := c.OIDCCredentialCreate(s.context(), &transport.OIDCCredentialCreateRequest{OIDCCredentialRef: *r, Config: cfg})
	if err != nil {
		return nil, err
	}
	return serverCredentialInfo(cred), nil
}

// ImportServerTokens imports tokens obtained elsewhere into a credential,
// making it active. With create the credential is created first from
// template; otherwise it must exist.
func (s *OIDCServerService) ImportServerTokens(ref transport.OIDCCredentialRef, tokens OIDCServerTokens, template string, create bool) (retVal *OIDCServerCredentialInfo, retErr error) {
	defer s.recoverPanic("ImportServerTokens", &retErr)
	t, err := importedTokens(tokens)
	if err != nil {
		return nil, err
	}
	return s.importTokens(ref, t, strings.TrimSpace(template), create)
}

// ImportCodexAuth imports the ChatGPT login of a codex auth.json (its
// content, pasted or read by the frontend) into a credential, creating it
// from the openai template with create. The content is never logged.
func (s *OIDCServerService) ImportCodexAuth(ref transport.OIDCCredentialRef, authJSON string, create bool) (retVal *OIDCServerCredentialInfo, retErr error) {
	defer s.recoverPanic("ImportCodexAuth", &retErr)
	if strings.TrimSpace(authJSON) == "" {
		return nil, ErrOIDCServerCodexAuthRequired
	}
	auth, err := xkms.ParseCodexAuth([]byte(authJSON))
	if err != nil {
		return nil, err
	}
	return s.importTokens(ref, xkms.CodexAuthTokens(auth), oidcServerCodexTemplate, create)
}

// importTokens creates the credential with tokens, or imports tokens into
// the existing one.
func (s *OIDCServerService) importTokens(ref transport.OIDCCredentialRef, tokens *transport.OIDCCredentialTokens, template string, create bool) (*OIDCServerCredentialInfo, error) {
	r, err := normalizeServerRef(ref)
	if err != nil {
		return nil, err
	}
	c, err := s.server()
	if err != nil {
		return nil, err
	}
	var cred *transport.OIDCCredential
	if create {
		cred, err = c.OIDCCredentialCreate(s.context(), &transport.OIDCCredentialCreateRequest{
			OIDCCredentialRef: *r,
			Config:            transport.OIDCCredentialConfig{Template: template},
			Tokens:            tokens,
		})
	} else {
		cred, err = c.OIDCCredentialImport(s.context(), &transport.OIDCCredentialImportRequest{OIDCCredentialRef: *r, Tokens: *tokens})
	}
	if err != nil {
		return nil, err
	}
	return serverCredentialInfo(cred), nil
}

// StartServerDeviceLogin starts a device login on the server; the returned
// credential's device_login carries the user code and verification URL.
// The server talks to the provider: no token reaches xKey.
func (s *OIDCServerService) StartServerDeviceLogin(ref transport.OIDCCredentialRef) (retVal *OIDCServerCredentialInfo, retErr error) {
	defer s.recoverPanic("StartServerDeviceLogin", &retErr)
	return s.credentialCall(ref, transport.OIDCCredentialService.OIDCCredentialDeviceStart)
}

// PollServerDeviceLogin polls the device login once. The credential stays
// pending, with its device_login, until the user approves; the frontend
// polls at device_login.interval_seconds until it is active.
func (s *OIDCServerService) PollServerDeviceLogin(ref transport.OIDCCredentialRef) (retVal *OIDCServerCredentialInfo, retErr error) {
	defer s.recoverPanic("PollServerDeviceLogin", &retErr)
	return s.credentialCall(ref, transport.OIDCCredentialService.OIDCCredentialDevicePoll)
}

// RefreshServerCredential refreshes a credential on the server now.
func (s *OIDCServerService) RefreshServerCredential(ref transport.OIDCCredentialRef) (retVal *OIDCServerCredentialInfo, retErr error) {
	defer s.recoverPanic("RefreshServerCredential", &retErr)
	return s.credentialCall(ref, transport.OIDCCredentialService.OIDCCredentialRefresh)
}

// credentialCall validates ref and runs a credential operation returning
// the credential.
func (s *OIDCServerService) credentialCall(ref transport.OIDCCredentialRef, call func(transport.OIDCCredentialService, context.Context, *transport.OIDCCredentialRef) (*transport.OIDCCredential, error)) (*OIDCServerCredentialInfo, error) {
	r, err := normalizeServerRef(ref)
	if err != nil {
		return nil, err
	}
	c, err := s.server()
	if err != nil {
		return nil, err
	}
	cred, err := call(c, s.context(), r)
	if err != nil {
		return nil, err
	}
	return serverCredentialInfo(cred), nil
}

// DeleteServerCredential deletes a credential from the server.
func (s *OIDCServerService) DeleteServerCredential(ref transport.OIDCCredentialRef) (retErr error) {
	defer s.recoverPanic("DeleteServerCredential", &retErr)
	r, err := normalizeServerRef(ref)
	if err != nil {
		return err
	}
	c, err := s.server()
	if err != nil {
		return err
	}
	return c.OIDCCredentialDelete(s.context(), r)
}

// CopyServerAccessToken asks the server for a current access token of a
// credential and copies it to the clipboard, which clears itself after the
// configured timeout. The token never crosses into the frontend.
func (s *OIDCServerService) CopyServerAccessToken(ref transport.OIDCCredentialRef) (retErr error) {
	defer s.recoverPanic("CopyServerAccessToken", &retErr)
	if s.clipboard == nil {
		return ErrOIDCServerClipboardUnavailable
	}
	r, err := normalizeServerRef(ref)
	if err != nil {
		return err
	}
	c, err := s.server()
	if err != nil {
		return err
	}
	tok, err := c.OIDCCredentialGetAccessToken(s.context(), r)
	if err != nil {
		return err
	}
	return s.clipboard.CopyWithClear(tok.AccessToken)
}

// normalizeServerRef validates a credential reference: a name is required,
// and the scope is "tenant" or "user" (empty is "user", like the CLI).
func normalizeServerRef(ref transport.OIDCCredentialRef) (*transport.OIDCCredentialRef, error) {
	r := transport.OIDCCredentialRef{
		TenantID: strings.TrimSpace(ref.TenantID),
		Scope:    strings.TrimSpace(ref.Scope),
		Owner:    strings.TrimSpace(ref.Owner),
		Name:     strings.TrimSpace(ref.Name),
	}
	if r.Name == "" {
		return nil, ErrOIDCServerNameRequired
	}
	switch r.Scope {
	case "":
		r.Scope = transport.OIDCCredentialScopeUser
	case transport.OIDCCredentialScopeUser, transport.OIDCCredentialScopeTenant:
	default:
		return nil, &DetailError{Err: ErrOIDCServerScopeInvalid, Detail: ": " + r.Scope}
	}
	return &r, nil
}

// importedTokens validates imported tokens and converts them to the wire
// type.
func importedTokens(t OIDCServerTokens) (*transport.OIDCCredentialTokens, error) {
	access := strings.TrimSpace(t.AccessToken)
	if access == "" {
		return nil, ErrOIDCServerAccessTokenRequired
	}
	out := &transport.OIDCCredentialTokens{
		AccessToken:  access,
		RefreshToken: strings.TrimSpace(t.RefreshToken),
		IDToken:      strings.TrimSpace(t.IDToken),
	}
	if exp := strings.TrimSpace(t.ExpiresAt); exp != "" {
		at, err := time.Parse(time.RFC3339, exp)
		if err != nil {
			return nil, &SentinelCauseError{Sentinel: ErrOIDCServerExpiryInvalid, Cause: err}
		}
		out.ExpiresAt = &at
	}
	return out, nil
}

// serverCredentialInfo converts a credential's wire view to the GUI's.
func serverCredentialInfo(c *transport.OIDCCredential) *OIDCServerCredentialInfo {
	info := &OIDCServerCredentialInfo{
		TenantID:     c.TenantID,
		Scope:        c.Scope,
		Owner:        c.Owner,
		Name:         c.Name,
		Template:     c.Config.Template,
		Issuer:       c.Config.Issuer,
		ClientID:     c.Config.ClientID,
		Scopes:       c.Config.Scopes,
		Status:       c.Status,
		StatusReason: c.StatusReason,
		ExpiresAt:    serverOptionalTime(c.ExpiresAt),
		Refreshable:  c.Refreshable,
		LastRefresh:  serverOptionalTime(c.LastRefresh),
		LastError:    c.LastError,
		CreatedAt:    serverTime(c.CreatedAt),
		UpdatedAt:    serverTime(c.UpdatedAt),
		CreatedBy:    c.CreatedBy,
	}
	info.SupportsDevice = c.Config.DeviceAuthorizationEndpoint != ""
	if t, err := oidc.GetTemplate(c.Config.Template); err == nil && t.SupportsFlow(oidc.FlowDevice) {
		info.SupportsDevice = true
	}
	if d := c.DeviceLogin; d != nil {
		info.DeviceLogin = &OIDCServerDeviceLogin{
			UserCode:                d.UserCode,
			VerificationURI:         d.VerificationURI,
			VerificationURIComplete: d.VerificationURIComplete,
			IntervalSeconds:         d.IntervalSeconds,
			ExpiresAt:               serverTime(d.ExpiresAt),
		}
	}
	return info
}

// serverTime renders t as RFC 3339, or "" for the zero time.
func serverTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// serverOptionalTime renders t as RFC 3339, or "" when it is nil.
func serverOptionalTime(t *time.Time) string {
	if t == nil {
		return ""
	}
	return serverTime(*t)
}
