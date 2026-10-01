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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/scope"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/hostdeps"
)

// fakeIdP is an OAuth 2.0 / OIDC provider for the tests: discovery, RFC 8628
// device authorization, and a token endpoint whose refresh tokens rotate on
// use -- a reused refresh token is refused the way OpenAI refuses it.
type fakeIdP struct {
	t   *testing.T
	srv *httptest.Server

	mu            sync.Mutex
	current       string // the one refresh token the provider accepts
	generation    int
	refreshes     int
	expiresIn     int
	failRefresh   int    // HTTP status every refresh answers with, when set
	rejectCode    string // OAuth error code a refresh is rejected with, when set
	deviceGranted bool
	deviceError   string // OAuth error code every device poll answers, when set
	devicePolls   int
	refreshGate   chan struct{} // when set, a refresh waits for it to close
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	idp := &fakeIdP{t: t, current: "rt-0", expiresIn: 3600}
	idp.srv = httptest.NewServer(http.HandlerFunc(idp.serve))
	t.Cleanup(idp.srv.Close)
	return idp
}

func (f *fakeIdP) URL() string { return f.srv.URL }

func (f *fakeIdP) set(fn func(f *fakeIdP)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

func (f *fakeIdP) refreshCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.refreshes
}

func (f *fakeIdP) currentToken() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.current
}

func (f *fakeIdP) reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	require.NoError(f.t, json.NewEncoder(w).Encode(v))
}

func (f *fakeIdP) serve(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		f.reply(w, http.StatusOK, map[string]string{
			"issuer":                        f.URL(),
			"authorization_endpoint":        f.URL() + "/authorize",
			"token_endpoint":                f.URL() + "/token",
			"jwks_uri":                      f.URL() + "/jwks",
			"device_authorization_endpoint": f.URL() + "/device",
		})
	case "/device":
		f.reply(w, http.StatusOK, map[string]any{
			"device_code": "dev-1", "user_code": "USER-CODE",
			"verification_uri": f.URL() + "/activate", "expires_in": 600, "interval": 1,
		})
	case "/token":
		f.token(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeIdP) token(w http.ResponseWriter, r *http.Request) {
	params := f.params(r)
	switch params.Get("grant_type") {
	case "refresh_token":
		f.mu.Lock()
		gate := f.refreshGate
		f.mu.Unlock()
		if gate != nil {
			<-gate
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		f.refreshes++
		switch {
		case f.failRefresh != 0:
			f.reply(w, f.failRefresh, map[string]string{"error": "temporarily_unavailable"})
		case f.rejectCode != "":
			f.reply(w, http.StatusBadRequest, map[string]string{"error": f.rejectCode})
		case params.Get("refresh_token") != f.current:
			// OpenAI's answer to a reused rotating refresh token.
			f.reply(w, http.StatusUnauthorized, map[string]any{
				"error": map[string]string{"code": "refresh_token_reused", "message": "already used"},
			})
		default:
			f.generation++
			f.current = fmt.Sprintf("rt-%d", f.generation)
			f.reply(w, http.StatusOK, map[string]any{
				"access_token":  fmt.Sprintf("at-%d", f.generation),
				"refresh_token": f.current,
				"token_type":    "Bearer",
				"expires_in":    f.expiresIn,
			})
		}
	case "urn:ietf:params:oauth:grant-type:device_code":
		f.mu.Lock()
		defer f.mu.Unlock()
		f.devicePolls++
		if f.deviceError != "" {
			f.reply(w, http.StatusBadRequest, map[string]string{"error": f.deviceError})
			return
		}
		if !f.deviceGranted {
			f.reply(w, http.StatusBadRequest, map[string]string{"error": "authorization_pending"})
			return
		}
		f.reply(w, http.StatusOK, map[string]any{
			"access_token": "at-device", "refresh_token": f.current, "id_token": "id-device", "expires_in": f.expiresIn,
		})
	default:
		f.reply(w, http.StatusBadRequest, map[string]string{"error": "unsupported_grant_type"})
	}
}

// params reads a token request in either encoding.
func (f *fakeIdP) params(r *http.Request) url.Values {
	body, err := io.ReadAll(r.Body)
	require.NoError(f.t, err)
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		var fields map[string]string
		require.NoError(f.t, json.Unmarshal(body, &fields))
		out := url.Values{}
		for k, v := range fields {
			out.Set(k, v)
		}
		return out
	}
	out, err := url.ParseQuery(string(body))
	require.NoError(f.t, err)
	return out
}

// env is a credential service over real tenant barriers.
type env struct {
	svc      *Service
	registry *seal.BarrierRegistry
	idp      *fakeIdP
	clock    *testClock
}

// testClock is a settable clock that otherwise follows real time, because
// pkg/oidc stamps token expiries with real time.
type testClock struct {
	mu     sync.Mutex
	offset time.Duration
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Now().Add(c.offset)
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.offset += d
}

const (
	tenantA = "acme"
	tenantB = "globex"
)

func newEnv(t *testing.T, opts ...Option) *env {
	t.Helper()
	registry := hostdeps.NewBarrierRegistry(t)
	hostdeps.RegisterTenant(t, registry, tenantA)
	hostdeps.RegisterTenant(t, registry, tenantB)
	idp := newFakeIdP(t)
	clock := &testClock{}
	all := append([]Option{WithHTTPClient(idp.srv.Client()), WithClock(clock.now)}, opts...)
	svc, err := New(RegistryBarriers(registry), all...)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, svc.Close()) })
	return &env{svc: svc, registry: registry, idp: idp, clock: clock}
}

// customConfig is a provider configured by issuer, discovered at creation.
func (e *env) customConfig() Config {
	return Config{Issuer: e.idp.URL(), ClientID: "client-1", Scopes: []string{"openid", "offline_access"}}
}

func user(tenant, subject string) scope.Principal {
	return scope.Principal{TenantID: tenant, Subject: subject}
}

func platform(subject string) scope.Principal {
	return scope.Principal{TenantID: scope.SystemTenant, Subject: subject, Platform: true}
}

func shared(name string) Ref { return Ref{Scope: scope.Tenant, Name: name} }

func personal(name string) Ref { return Ref{Scope: scope.User, Name: name} }

// importDue imports a login whose access token is already inside the
// refresh margin, holding the provider's current refresh token.
func (e *env) importDue(t *testing.T, p scope.Principal, ref Ref) {
	t.Helper()
	_, err := e.svc.Create(context.Background(), p, ref, e.customConfig(), &Tokens{
		AccessToken:  "at-0",
		RefreshToken: e.idp.currentToken(),
		ExpiresAt:    time.Now().Add(time.Minute),
	})
	require.NoError(t, err)
}

// fakeLeases is an in-memory exclusive TTL lease table with qrdb's
// AcquireLease semantics: a held key is refused with LeaseHeldError.
type fakeLeases struct {
	mu   sync.Mutex
	held map[string]*fakeLease
}

func newFakeLeases() *fakeLeases { return &fakeLeases{held: make(map[string]*fakeLease)} }

func (f *fakeLeases) AcquireLease(_ context.Context, key string, _ time.Duration) (qrdbsdk.Lease, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.held[key]; ok {
		return nil, &qrdbsdk.LeaseHeldError{Key: key}
	}
	l := &fakeLease{owner: f, key: key, done: make(chan struct{})}
	f.held[key] = l
	return l, nil
}

// revoke ends key's lease as an expiry would.
func (f *fakeLeases) revoke(key string) {
	f.mu.Lock()
	l, ok := f.held[key]
	delete(f.held, key)
	f.mu.Unlock()
	if ok {
		l.end()
	}
}

type fakeLease struct {
	owner *fakeLeases
	key   string
	once  sync.Once
	done  chan struct{}
}

func (l *fakeLease) Key() string { return l.key }

func (l *fakeLease) Renew(context.Context) error {
	select {
	case <-l.done:
		return &qrdbsdk.LeaseLostError{Key: l.key}
	default:
		return nil
	}
}

func (l *fakeLease) Release(context.Context) error {
	l.owner.mu.Lock()
	if l.owner.held[l.key] == l {
		delete(l.owner.held, l.key)
	}
	l.owner.mu.Unlock()
	l.end()
	return nil
}

func (l *fakeLease) Done() <-chan struct{} { return l.done }

func (l *fakeLease) end() { l.once.Do(func() { close(l.done) }) }
