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

package credential

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/audit"
	"github.com/jeremyhahn/go-xkms/pkg/oidc"
	"github.com/jeremyhahn/go-xkms/pkg/scope"
)

// refreshTimeout bounds one refresh: the token request and the write of
// its result. The refresh runs detached from the caller's context, because
// a refresh token that rotates is spent the moment the provider answers --
// a caller that gives up between that answer and the write must not cost
// the credential its login.
const refreshTimeout = 60 * time.Second

// Service is the OIDC credential service. Its methods take the calling
// Principal explicitly; the transports derive it from the request identity.
type Service struct {
	barriers   Barriers
	locks      *locker
	httpClient *http.Client
	logger     *slog.Logger
	audit      qrdbsdk.NodeAuditLogger
	now        func() time.Time
	leaseCtx   CallContext

	subMu  sync.RWMutex
	subs   map[uint64]func(Event)
	nextID uint64

	runMu   sync.Mutex
	cancel  context.CancelFunc
	done    chan struct{}
	closed  bool
	started bool
}

// Option configures a Service.
type Option func(*Service)

// WithLeases sets the qrdb lease primitive that serializes refreshes and
// elects the scheduler's leader across a cluster (qrdbsdk.Client
// .Coordination()). Without it the service assumes one process -- a
// standalone node -- and uses in-process exclusion only.
func WithLeases(leases Leases) Option {
	return func(s *Service) { s.locks = newLocker(leases, s.logger) }
}

// CallContext derives the context a call into go-qrdb runs on from the
// caller's. An embedded node's Node.ServiceContext is one: it binds the
// node's service principal.
type CallContext func(ctx context.Context) (context.Context, error)

// WithLeaseContext runs every lease call -- acquire, renew, release -- on the
// context bind derives from the caller's. The leases are the service's own
// coordination, not a caller's request, so over an embedded node the host
// passes Node.ServiceContext. Provider requests and barrier access keep the
// caller's context.
func WithLeaseContext(bind CallContext) Option {
	return func(s *Service) { s.leaseCtx = bind }
}

// WithHTTPClient sets the client used for provider requests.
func WithHTTPClient(c *http.Client) Option { return func(s *Service) { s.httpClient = c } }

// WithLogger sets the logger.
func WithLogger(l *slog.Logger) Option { return func(s *Service) { s.logger = l } }

// WithAudit records every credential event in the audit log.
func WithAudit(l qrdbsdk.NodeAuditLogger) Option { return func(s *Service) { s.audit = l } }

// WithClock sets the clock (tests).
func WithClock(now func() time.Time) Option { return func(s *Service) { s.now = now } }

// New returns a Service over barriers.
func New(barriers Barriers, opts ...Option) (*Service, error) {
	if barriers == nil {
		return nil, ErrNilBarriers
	}
	s := &Service{
		barriers:   barriers,
		httpClient: &http.Client{Timeout: oidc.DefaultHTTPTimeout},
		logger:     slog.Default(),
		now:        time.Now,
		subs:       make(map[uint64]func(Event)),
	}
	for _, opt := range opts {
		opt(s)
	}
	if s.locks == nil {
		s.locks = newLocker(nil, s.logger)
	}
	s.locks.logger = s.logger
	s.locks.bind = s.leaseCtx
	return s, nil
}

// Subscribe registers fn for every credential event and returns the
// function that removes it. fn runs on the goroutine that changed the
// credential and must not block.
func (s *Service) Subscribe(fn func(Event)) (unsubscribe func()) {
	s.subMu.Lock()
	defer s.subMu.Unlock()
	s.nextID++
	id := s.nextID
	s.subs[id] = fn
	return func() {
		s.subMu.Lock()
		defer s.subMu.Unlock()
		delete(s.subs, id)
	}
}

// emit delivers an event to the subscribers and the audit log.
func (s *Service) emit(ctx context.Context, typ EventType, ref Ref, reason string) {
	ev := Event{Type: typ, Ref: ref, Reason: reason, Time: s.now()}
	s.subMu.RLock()
	subs := make([]func(Event), 0, len(s.subs))
	for _, fn := range s.subs {
		subs = append(subs, fn)
	}
	s.subMu.RUnlock()
	for _, fn := range subs {
		fn(ev)
	}
	level := slog.LevelInfo
	if typ != EventRefreshed {
		level = slog.LevelWarn
	}
	s.logger.Log(ctx, level, "oidc credential event", "type", typ, "tenant", ref.TenantID,
		"scope", ref.Scope, "name", ref.Name, "reason", reason)
	if s.audit == nil {
		return
	}
	details := map[string]string{"tenant": ref.TenantID, "scope": string(ref.Scope)}
	if reason != "" {
		details["reason"] = reason
	}
	if err := audit.Emit(ctx, s.audit, &audit.Event{
		Timestamp:  ev.Time,
		Subject:    "xkms",
		Action:     string(typ),
		Resource:   "oidc_credential",
		ResourceID: ref.Name,
		Outcome:    audit.OutcomeAllow,
		Details:    details,
	}); err != nil {
		s.logger.Warn("oidc credential: audit log failed", "error", err)
	}
}

// resolve completes ref for p -- the caller's tenant, and the caller as the
// owner of a personal credential -- and authorizes p for it.
func resolve(p scope.Principal, ref Ref) (Ref, error) {
	if !ValidName(ref.Name) {
		return Ref{}, ErrInvalidName
	}
	switch ref.Scope {
	case scope.Tenant:
		ref.Owner = ""
	case scope.User:
		if ref.Owner == "" {
			ref.Owner = p.Subject
		}
	default:
		return Ref{}, ErrScopeUnsupported
	}
	if ref.TenantID == "" {
		ref.TenantID = p.TenantID
	}
	ref.TenantID = scope.TenantName(ref.TenantID)
	if err := p.Authorize(scope.Target{TenantID: ref.TenantID, Scope: ref.Scope, Owner: ref.Owner}); err != nil {
		return Ref{}, err
	}
	return ref, nil
}

// locate resolves ref for p and returns its barrier and record key.
func (s *Service) locate(p scope.Principal, ref Ref) (Ref, Backend, string, error) {
	ref, err := resolve(p, ref)
	if err != nil {
		return Ref{}, nil, "", err
	}
	back, err := s.barriers.Barrier(ref.TenantID)
	if err != nil {
		return Ref{}, nil, "", err
	}
	key, err := recordKey(ref)
	if err != nil {
		return Ref{}, nil, "", err
	}
	return ref, back, key, nil
}

// Create creates a credential from cfg, with tokens when they are already
// at hand (an import), or pending a device login or import otherwise.
func (s *Service) Create(ctx context.Context, p scope.Principal, ref Ref, cfg Config, tokens *Tokens) (*Credential, error) {
	ref, back, key, err := s.locate(p, ref)
	if err != nil {
		return nil, err
	}
	cfg, err = s.resolveConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	now := s.now()
	rec := &record{
		Ref:       ref,
		Config:    cfg,
		Status:    StatusPending,
		CreatedAt: now,
		UpdatedAt: now,
		CreatedBy: p.Subject,
	}
	if tokens != nil {
		if !cfg.flowSupported(oidc.FlowImport) {
			return nil, ErrFlowUnsupported
		}
		if err := s.applyTokens(rec, *tokens, now); err != nil {
			return nil, err
		}
	}
	if err := create(ctx, back, key, rec); err != nil {
		return nil, err
	}
	return rec.view(), nil
}

// ImportTokens replaces a credential's login with tokens obtained
// elsewhere -- an existing CLI login, or a browser login run by a client --
// and makes it active again.
func (s *Service) ImportTokens(ctx context.Context, p scope.Principal, ref Ref, tokens Tokens) (*Credential, error) {
	_, back, key, err := s.locate(p, ref)
	if err != nil {
		return nil, err
	}
	unlock, err := s.locks.lock(ctx, key)
	if err != nil {
		return nil, err
	}
	defer unlock()
	cur, err := load(ctx, back, key)
	if err != nil {
		return nil, err
	}
	if !cur.rec.Config.flowSupported(oidc.FlowImport) {
		return nil, ErrFlowUnsupported
	}
	now := s.now()
	next := cur.rec.clone()
	if err := s.applyTokens(next, tokens, now); err != nil {
		return nil, err
	}
	out, err := cur.replace(ctx, next, now)
	if err != nil {
		return nil, err
	}
	return out.rec.view(), nil
}

// applyTokens installs imported tokens on rec as an active login.
func (s *Service) applyTokens(rec *record, tokens Tokens, now time.Time) error {
	if tokens.AccessToken == "" {
		return ErrInvalidTokens
	}
	tr := &oidc.TokenResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		IDToken:      tokens.IDToken,
		TokenType:    tokens.TokenType,
		Scope:        tokens.Scope,
		Expiry:       tokens.ExpiresAt,
	}
	if tr.TokenType == "" {
		tr.TokenType = "Bearer"
	}
	tr.Expiry = tr.ExpiresAt()
	if tr.Expiry.IsZero() && rec.Config.NoRefresh && rec.Config.TokenLifetime > 0 {
		tr.Expiry = now.Add(rec.Config.TokenLifetime)
	}
	if rec.Config.NoRefresh {
		// A provider without refresh never gets a refresh token stored.
		tr.RefreshToken = ""
	}
	rec.Tokens = tr
	rec.Status = StatusActive
	rec.Reason = ""
	rec.LastError = ""
	rec.Device = nil
	rec.LastRefresh = now
	if rec.expired(now) {
		rec.Status = StatusExpired
		rec.Reason = "imported token already expired"
	}
	return nil
}

// Get returns a credential's public view.
func (s *Service) Get(ctx context.Context, p scope.Principal, ref Ref) (*Credential, error) {
	_, back, key, err := s.locate(p, ref)
	if err != nil {
		return nil, err
	}
	cur, err := load(ctx, back, key)
	if err != nil {
		return nil, err
	}
	return cur.rec.view(), nil
}

// List returns the credentials of tenantID ("" is the caller's) the caller
// can see: the tenant's shared credentials, and, in the caller's own tenant,
// the caller's personal ones. Nobody lists another user's personal
// credentials.
func (s *Service) List(ctx context.Context, p scope.Principal, tenantID string) ([]*Credential, error) {
	if tenantID == "" {
		tenantID = p.TenantID
	}
	tenantID = scope.TenantName(tenantID)
	if err := p.Authorize(scope.Target{TenantID: tenantID, Scope: scope.Tenant}); err != nil {
		return nil, err
	}
	back, err := s.barriers.Barrier(tenantID)
	if err != nil {
		return nil, err
	}
	prefixes := make([]string, 0, 2)
	shared, err := scope.SharedPrefix(tenantID, Feature)
	if err != nil {
		return nil, err
	}
	prefixes = append(prefixes, shared)
	if tenantID == p.TenantID && p.Subject != "" {
		personal, err := scope.PersonalPrefix(tenantID, Feature, p.Subject)
		if err != nil {
			return nil, err
		}
		prefixes = append(prefixes, personal)
	}

	out := make([]*Credential, 0)
	for _, prefix := range prefixes {
		keys, err := back.List(ctx, prefix)
		if err != nil {
			return nil, err
		}
		for _, key := range keys {
			// A listing is recursive; a shared prefix never holds personal
			// keys, but a record key must sit directly under its prefix.
			rest := strings.TrimPrefix(key, prefix)
			if !isRecordKey(key) || strings.Contains(rest, "/") {
				continue
			}
			cur, err := load(ctx, back, key)
			if errors.Is(err, ErrNotFound) {
				continue
			}
			if err != nil {
				return nil, err
			}
			out = append(out, cur.rec.view())
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Scope != out[j].Scope {
			return out[i].Scope < out[j].Scope
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

// Delete deletes a credential. Its tokens are not revoked at the provider:
// a credential imported from a CLI login may still be in use there.
func (s *Service) Delete(ctx context.Context, p scope.Principal, ref Ref) error {
	_, back, key, err := s.locate(p, ref)
	if err != nil {
		return err
	}
	unlock, err := s.locks.lock(ctx, key)
	if err != nil {
		return err
	}
	defer unlock()
	cur, err := load(ctx, back, key)
	if err != nil {
		return err
	}
	return cur.remove(ctx)
}

// Refresh refreshes a credential now, whether or not it is due.
func (s *Service) Refresh(ctx context.Context, p scope.Principal, ref Ref) (*Credential, error) {
	_, back, key, err := s.locate(p, ref)
	if err != nil {
		return nil, err
	}
	out, err := s.refresh(ctx, back, key, true)
	if err != nil {
		return nil, err
	}
	return out.rec.view(), nil
}

// GetAccessToken returns a current access token of the credential,
// refreshing it first when it is inside its refresh margin. A refresh that
// fails transiently still serves the current token while it is valid.
func (s *Service) GetAccessToken(ctx context.Context, p scope.Principal, ref Ref) (*AccessToken, error) {
	_, back, key, err := s.locate(p, ref)
	if err != nil {
		return nil, err
	}
	cur, err := load(ctx, back, key)
	if err != nil {
		return nil, err
	}
	now := s.now()
	if cur.rec.refreshDue(now) {
		refreshed, refreshErr := s.refresh(ctx, back, key, false)
		switch {
		case refreshErr == nil:
			cur = refreshed
		case errors.Is(refreshErr, ErrReloginRequired):
			return nil, refreshErr
		default:
			s.logger.Warn("oidc credential: refresh failed; serving the current token while it is valid",
				"name", cur.rec.Ref.Name, "error", refreshErr)
			if latest, loadErr := load(ctx, back, key); loadErr == nil {
				cur = latest
			}
		}
	}
	if cur.rec.Status == StatusActive && !cur.rec.refreshable() && cur.rec.expired(now) {
		if err := s.markExpired(ctx, cur, now); err != nil {
			return nil, err
		}
		return nil, ErrTokenExpired
	}
	return tokenOf(cur.rec, now)
}

// tokenOf returns the access token of rec, or the error its state means.
func tokenOf(rec *record, now time.Time) (*AccessToken, error) {
	switch rec.Status {
	case StatusPending:
		return nil, ErrNoLogin
	case StatusReloginRequired:
		return nil, &RefreshError{Name: rec.Ref.Name, Relogin: true, Reason: rec.Reason, Err: ErrReloginRequired}
	case StatusExpired:
		return nil, ErrTokenExpired
	}
	if rec.Tokens == nil || rec.Tokens.AccessToken == "" {
		return nil, ErrNoLogin
	}
	if rec.expired(now) {
		return nil, ErrTokenExpired
	}
	return &AccessToken{
		AccessToken: rec.Tokens.AccessToken,
		TokenType:   rec.Tokens.TokenType,
		ExpiresAt:   rec.expiresAt(),
		IDToken:     rec.Tokens.IDToken,
		Scope:       rec.Tokens.Scope,
	}, nil
}

// markExpired moves an active, non-refreshable credential to StatusExpired
// and emits EventExpired.
func (s *Service) markExpired(ctx context.Context, cur *stored, now time.Time) error {
	unlock, err := s.locks.lock(ctx, cur.key)
	if err != nil {
		return err
	}
	defer unlock()
	latest, err := load(ctx, cur.back, cur.key)
	if err != nil {
		return err
	}
	if latest.rec.Status != StatusActive || latest.rec.refreshable() || !latest.rec.expired(now) {
		return nil
	}
	next := latest.rec.clone()
	next.Status = StatusExpired
	next.Reason = "token expired"
	if _, err := latest.replace(ctx, next, now); err != nil {
		return err
	}
	s.emit(ctx, EventExpired, next.Ref, next.Reason)
	return nil
}

// refresh redeems the credential's refresh token under its lock. Without
// force it refreshes only when the credential is still due once the lock
// is held -- so of concurrent callers exactly one refreshes and the rest
// read its result.
func (s *Service) refresh(ctx context.Context, back Backend, key string, force bool) (*stored, error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), refreshTimeout)
	defer cancel()

	unlock, err := s.locks.lock(ctx, key)
	if err != nil {
		return nil, err
	}
	defer unlock()

	cur, err := load(ctx, back, key)
	if err != nil {
		return nil, err
	}
	rec := cur.rec
	now := s.now()
	switch {
	case rec.Status == StatusReloginRequired:
		return nil, &RefreshError{Name: rec.Ref.Name, Relogin: true, Reason: rec.Reason, Err: ErrReloginRequired}
	case rec.Status != StatusActive:
		return nil, ErrNoLogin
	case !rec.refreshable():
		return nil, ErrNotRefreshable
	case !force && !rec.refreshDue(now):
		return cur, nil
	}

	client, err := s.client(rec)
	if err != nil {
		return nil, err
	}
	tokens, refreshErr := client.Refresh(ctx, rec.Tokens.RefreshToken)
	if refreshErr != nil {
		return nil, s.recordRefreshFailure(ctx, cur, refreshErr, now)
	}

	tokens.InheritFrom(rec.Tokens)
	tokens.Expiry = tokens.ExpiresAt()
	next := rec.clone()
	next.Tokens = tokens
	next.LastRefresh = now
	next.LastError = ""
	next.Reason = ""
	out, err := cur.replace(ctx, next, now)
	if err != nil {
		// The provider has rotated the refresh token and the write of the
		// new one failed: the credential most likely needs a new login.
		s.logger.Error("oidc credential: refreshed tokens could not be stored", "name", rec.Ref.Name, "error", err)
		return nil, err
	}
	s.emit(ctx, EventRefreshed, next.Ref, "")
	return out, nil
}

// recordRefreshFailure stores a failed refresh on the credential: a
// rejected refresh token moves it to StatusReloginRequired and emits
// EventReloginRequired; any other failure is kept as LastError for the next
// attempt to clear.
func (s *Service) recordRefreshFailure(ctx context.Context, cur *stored, refreshErr error, now time.Time) error {
	reason, relogin := oidc.ReloginReason(refreshErr)
	next := cur.rec.clone()
	if relogin {
		next.Status = StatusReloginRequired
		next.Reason = reason
		next.LastError = ""
	} else {
		next.LastError = oidc.SanitizeProviderText(refreshErr.Error())
	}
	if _, err := cur.replace(ctx, next, now); err != nil {
		s.logger.Warn("oidc credential: refresh failure could not be recorded", "name", next.Ref.Name, "error", err)
	}
	if relogin {
		s.emit(ctx, EventReloginRequired, next.Ref, reason)
	}
	return &RefreshError{Name: next.Ref.Name, Relogin: relogin, Reason: reason, Err: refreshErr}
}

// StartDeviceLogin starts a device login for the credential. The returned
// view carries the user code and verification URI; PollDeviceLogin
// completes it.
func (s *Service) StartDeviceLogin(ctx context.Context, p scope.Principal, ref Ref) (*Credential, error) {
	_, back, key, err := s.locate(p, ref)
	if err != nil {
		return nil, err
	}
	unlock, err := s.locks.lock(ctx, key)
	if err != nil {
		return nil, err
	}
	defer unlock()
	cur, err := load(ctx, back, key)
	if err != nil {
		return nil, err
	}
	if !cur.rec.Config.flowSupported(oidc.FlowDevice) {
		return nil, ErrFlowUnsupported
	}
	client, err := s.client(cur.rec)
	if err != nil {
		return nil, err
	}
	da, err := client.StartDeviceAuthorization(ctx)
	if err != nil {
		return nil, err
	}
	next := cur.rec.clone()
	next.Device = da
	out, err := cur.replace(ctx, next, s.now())
	if err != nil {
		return nil, err
	}
	return out.rec.view(), nil
}

// PollDeviceLogin polls the provider once for the credential's device
// login. It returns the credential still pending while the user has not
// approved, active once they have, and ErrDeviceAccessDenied or
// ErrDeviceCodeExpired (from pkg/oidc) when the login ended without tokens.
// The caller polls no more often than the DeviceLogin interval.
func (s *Service) PollDeviceLogin(ctx context.Context, p scope.Principal, ref Ref) (*Credential, error) {
	_, back, key, err := s.locate(p, ref)
	if err != nil {
		return nil, err
	}
	unlock, err := s.locks.lock(ctx, key)
	if err != nil {
		return nil, err
	}
	defer unlock()
	cur, err := load(ctx, back, key)
	if err != nil {
		return nil, err
	}
	if cur.rec.Device == nil {
		return nil, ErrNoDeviceLogin
	}
	client, err := s.client(cur.rec)
	if err != nil {
		return nil, err
	}
	now := s.now()
	tokens, pollErr := client.PollDeviceToken(ctx, cur.rec.Device)
	next := cur.rec.clone()
	switch {
	case pollErr == nil:
		tokens.Expiry = tokens.ExpiresAt()
		next.Tokens = tokens
		next.Device = nil
		next.Status = StatusActive
		next.Reason = ""
		next.LastError = ""
		next.LastRefresh = now
	case errors.Is(pollErr, oidc.ErrAuthorizationPending):
		return cur.rec.view(), nil
	case errors.Is(pollErr, oidc.ErrSlowDown):
		next.Device.Interval += oidc.SlowDownStep
	case errors.Is(pollErr, oidc.ErrDeviceAccessDenied), errors.Is(pollErr, oidc.ErrDeviceCodeExpired):
		next.Device = nil
		if _, err := cur.replace(ctx, next, now); err != nil {
			return nil, err
		}
		return nil, pollErr
	default:
		return nil, pollErr
	}
	out, err := cur.replace(ctx, next, now)
	if err != nil {
		return nil, err
	}
	return out.rec.view(), nil
}

// RefreshDue refreshes every credential, in every unsealed tenant, whose
// access token is inside its refresh margin, and marks expired every
// non-refreshable one past its expiry. It returns how many it refreshed.
// The Scheduler calls it on the elected leader.
func (s *Service) RefreshDue(ctx context.Context) (int, error) {
	refreshed := 0
	var errs []error
	for _, tenant := range s.barriers.Tenants() {
		n, err := s.refreshTenant(ctx, tenant)
		refreshed += n
		if err != nil {
			errs = append(errs, err)
		}
	}
	return refreshed, errors.Join(errs...)
}

// refreshTenant is RefreshDue for one tenant. A sealed or unknown tenant is
// skipped: its credentials wait for the unseal.
func (s *Service) refreshTenant(ctx context.Context, tenant string) (int, error) {
	back, err := s.barriers.Barrier(tenant)
	if err != nil {
		s.logger.Debug("oidc credential: tenant skipped", "tenant", tenant, "error", err)
		return 0, nil
	}
	root, err := scope.Root(tenant, Feature)
	if err != nil {
		return 0, err
	}
	keys, err := back.List(ctx, root)
	if err != nil {
		s.logger.Debug("oidc credential: tenant skipped", "tenant", tenant, "error", err)
		return 0, nil
	}
	refreshed := 0
	var errs []error
	for _, key := range keys {
		if !isRecordKey(key) {
			continue
		}
		cur, err := load(ctx, back, key)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}
		now := s.now()
		switch {
		case cur.rec.refreshDue(now):
			if _, err := s.refresh(ctx, back, key, false); err != nil {
				errs = append(errs, err)
				continue
			}
			refreshed++
		case cur.rec.Status == StatusActive && !cur.rec.refreshable() && cur.rec.expired(now):
			if err := s.markExpired(ctx, cur, now); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return refreshed, errors.Join(errs...)
}

// client returns the OIDC client of rec's provider configuration.
func (s *Service) client(rec *record) (*oidc.Client, error) {
	cfg := rec.Config
	provider, err := oidc.NewEndpointProvider(cfg.Issuer, oidc.Endpoints{
		Authorization:       cfg.AuthorizationEndpoint,
		Token:               cfg.TokenEndpoint,
		DeviceAuthorization: cfg.DeviceAuthorizationEndpoint,
	}, s.httpClient)
	if err != nil {
		return nil, &ConfigError{Err: err}
	}
	client := oidc.NewClient(provider, &oidc.ProviderConfig{
		Issuer:        cfg.Issuer,
		ClientID:      cfg.ClientID,
		ClientSecret:  cfg.ClientSecret,
		Scopes:        cfg.Scopes,
		HTTPClient:    s.httpClient,
		TokenEncoding: cfg.TokenEncoding,
		DeviceStyle:   cfg.DeviceStyle,
	})
	if rec.Tokens != nil && rec.Tokens.DPoPKeyPEM != "" {
		key, err := rec.Tokens.GetDPoPKey()
		if err != nil {
			return nil, err
		}
		client.SetDPoPKey(key)
	}
	return client, nil
}

// Close stops the scheduler, if one runs, and waits for it.
func (s *Service) Close() error {
	s.runMu.Lock()
	s.closed = true
	cancel, done := s.cancel, s.done
	s.runMu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
	return nil
}
