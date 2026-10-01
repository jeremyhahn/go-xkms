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
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-xkms/sdk/go/vaulttoken"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/events"
)

// The browser bridge: the web console unlocks the vault with a key factor
// (PIV, certificate, TPM) through the xKey browser extension. The page asks
// the extension, the extension asks xKey over native messaging, and xKey --
// after the user approves the request in the app -- recovers the factor's
// secret with its own key backend and unlocks the vault ITSELF, over its own
// authenticated connection to the server. Nothing secret goes back to the
// page: not the vault's key, not even the factor secret. The page only
// learns whether the vault is now unlocked.
//
// A request is refused unless:
//   - its origin, which the extension takes from the browser (never from
//     the page), is the console's: https on the server's WebAuthn relying
//     party domain or a subdomain of it (http only for localhost);
//   - the key factors the page names are in the vault xKey itself reads from
//     the server, which proves the page and xKey are the same user;
//   - the user approves it in xKey within browserVaultApprovalTimeout.

// browserVaultApprovalTimeout bounds how long a request waits for the user.
const browserVaultApprovalTimeout = 2 * time.Minute

// Browser bridge errors.
var (
	// ErrBrowserVaultOriginRefused indicates a request from a page that is
	// not the console of the server xKey is connected to.
	ErrBrowserVaultOriginRefused = errors.New("staticpw_service: this page is not the console of the server xKey is connected to")

	// ErrBrowserVaultNoKeyFactor indicates a request naming no key factor.
	ErrBrowserVaultNoKeyFactor = errors.New("staticpw_service: the request names no PIV, certificate or TPM factor")

	// ErrBrowserVaultUserMismatch indicates the page's key factors are not
	// in the vault of the user xKey is signed in as.
	ErrBrowserVaultUserMismatch = errors.New("staticpw_service: the page's vault is not the vault of the user xKey is signed in as")

	// ErrBrowserVaultDenied indicates the user denied the request.
	ErrBrowserVaultDenied = errors.New("staticpw_service: the request was denied in xKey")

	// ErrBrowserVaultApprovalTimeout indicates nobody approved the request.
	ErrBrowserVaultApprovalTimeout = errors.New("staticpw_service: the request was not approved in xKey in time")

	// ErrBrowserVaultRequestNotFound indicates an approval or denial for a
	// request that is not pending.
	ErrBrowserVaultRequestNotFound = errors.New("staticpw_service: no such pending browser request")
)

// browserVaultBridge holds the browser requests awaiting approval.
type browserVaultBridge struct {
	emitter atomic.Pointer[func(events.Event)]
	pending sync.Map // request ID -> chan bool
	timeout time.Duration
}

// SetEventEmitter sets the callback that shows browser requests in the app.
func (s *StaticPasswordService) SetEventEmitter(fn func(events.Event)) {
	s.browser.emitter.Store(&fn)
}

func (s *StaticPasswordService) emit(evt events.Event) {
	if fn := s.browser.emitter.Load(); fn != nil && *fn != nil {
		(*fn)(evt)
	}
}

// BrowserUnlockWithKeyFactor unlocks the caller's vault, for the console
// page at origin, with the first of the key factors fingerprints whose key
// is in xKey's backends. See the bridge rules above.
func (s *StaticPasswordService) BrowserUnlockWithKeyFactor(ctx context.Context, origin string, fingerprints []string) error {
	err := s.browserUnlock(ctx, origin, fingerprints)
	details := map[string]any{"factor": "key", "origin": origin, "via": "browser_extension"}
	if auditErr := s.logPasswordEvent(audit.OpPasswordStoreUnlocked, "", err == nil, err, details); auditErr != nil {
		return auditErr
	}
	return err
}

func (s *StaticPasswordService) browserUnlock(ctx context.Context, origin string, fingerprints []string) error {
	if len(fingerprints) == 0 {
		return ErrBrowserVaultNoKeyFactor
	}
	client, err := s.getClient()
	if err != nil {
		return err
	}
	status, err := client.PasswordVaultStatus(ctx)
	if err != nil {
		return err
	}
	if !ConsoleOriginAllowed(origin, status.PasskeyRPID) {
		return ErrBrowserVaultOriginRefused
	}
	requested := make(map[string]bool, len(fingerprints))
	for _, fp := range fingerprints {
		requested[fp] = true
	}
	only := map[string]bool{}
	var labels []string
	for _, f := range status.Factors {
		if vaulttoken.IsKeyFactor(f.Factor) && requested[f.KeyFingerprint] {
			only[f.KeyFingerprint] = true
			labels = append(labels, keyFactorLabel(f.Factor, f.Label))
		}
	}
	if len(only) == 0 {
		return ErrBrowserVaultUserMismatch
	}
	if err := s.awaitApproval(ctx, origin, labels); err != nil {
		return err
	}
	return s.unlockWithKeyFactor(ctx, client, only)
}

// awaitApproval shows the request in the app and waits for the user.
func (s *StaticPasswordService) awaitApproval(ctx context.Context, origin string, labels []string) error {
	id, err := randomRequestID()
	if err != nil {
		return err
	}
	answer := make(chan bool, 1)
	s.browser.pending.Store(id, answer)
	defer s.browser.pending.Delete(id)

	s.emit(events.NewEvent(events.EventVaultBrowserUnlockRequest, events.VaultBrowserUnlockRequestPayload{
		ID: id, Origin: origin, Factors: labels,
	}))
	timeout := s.browser.timeout
	if timeout == 0 {
		timeout = browserVaultApprovalTimeout
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	approved := false
	var waitErr error
	select {
	case approved = <-answer:
		if !approved {
			waitErr = ErrBrowserVaultDenied
		}
	case <-timer.C:
		waitErr = ErrBrowserVaultApprovalTimeout
	case <-ctx.Done():
		waitErr = ctx.Err()
	}
	s.emit(events.NewEvent(events.EventVaultBrowserUnlockResolved, events.VaultBrowserUnlockResolvedPayload{ID: id, Approved: approved}))
	return waitErr
}

// ApproveBrowserVaultRequest approves the pending browser request id.
func (s *StaticPasswordService) ApproveBrowserVaultRequest(id string) error {
	return s.answerBrowserRequest(id, true)
}

// DenyBrowserVaultRequest denies the pending browser request id.
func (s *StaticPasswordService) DenyBrowserVaultRequest(id string) error {
	return s.answerBrowserRequest(id, false)
}

func (s *StaticPasswordService) answerBrowserRequest(id string, approve bool) error {
	v, ok := s.browser.pending.LoadAndDelete(id)
	if !ok {
		return ErrBrowserVaultRequestNotFound
	}
	v.(chan bool) <- approve
	return nil
}

// ConsoleOriginAllowed reports whether origin is the web console of a server
// whose WebAuthn relying party is rpID: https on rpID or a subdomain of it,
// or http on localhost. A server with no relying party has no console xKey
// can recognize, so nothing is allowed.
func ConsoleOriginAllowed(origin, rpID string) bool {
	if rpID == "" {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.User != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if host != rpID && !strings.HasSuffix(host, "."+rpID) {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		return host == "localhost" || net.ParseIP(host).IsLoopback()
	default:
		return false
	}
}

// keyFactorLabel names a key factor for the approval prompt.
func keyFactorLabel(factor, label string) string {
	names := map[string]string{
		vaulttoken.FactorPIV:         "PIV card",
		vaulttoken.FactorCertificate: "certificate",
		vaulttoken.FactorTPM:         "TPM key",
	}
	if label == "" {
		return names[factor]
	}
	return names[factor] + " (" + label + ")"
}

func randomRequestID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
