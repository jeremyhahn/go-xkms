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

package cdp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync/atomic"
)

// StoredCredential holds the credential data needed to register a FIDO2
// credential with a CDP virtual authenticator. Callers map their own
// credential storage types to this struct before calling SyncCredentials.
//
// The binary fields (CredentialID, PrivateKey, UserHandle) are carried in the
// Chrome DevTools Protocol wire encoding: standard base64 (RFC 4648 section 4)
// with padding — NOT base64url. They are passed verbatim to and from the CDP
// WebAuthn.Credential JSON, so callers must encode/decode with the standard
// alphabet, not the URL-safe one.
type StoredCredential struct {
	// CredentialID is the standard-base64-encoded credential identifier.
	CredentialID string

	// IsResidentCredential indicates whether this is a discoverable credential.
	IsResidentCredential bool

	// RpID is the relying party identifier (e.g., "example.com").
	RpID string

	// PrivateKey is the standard-base64-encoded PKCS#8 private key.
	PrivateKey string

	// UserHandle is the standard-base64-encoded user handle (may be empty).
	UserHandle string

	// SignCount is the current signature counter value.
	SignCount int
}

// CredentialSink persists a credential captured from the Chrome virtual
// authenticator into xkey's storage backend. It is invoked from the CDP read
// loop the instant Chrome reports a new credential (WebAuthn.credentialAdded),
// guaranteeing the private key is durable before the process can be killed.
// Implementations must be safe for concurrent invocation and must not block.
type CredentialSink func(cred StoredCredential) error

// Bridge syncs xkey FIDO2 credentials to a Chrome DevTools virtual authenticator
// and captures credentials created inside that authenticator back into xkey
// storage. It manages the lifecycle of a single virtual authenticator instance.
type Bridge struct {
	client          *Client
	authenticatorID string
	logger          *slog.Logger
	started         atomic.Bool
	sink            CredentialSink
}

// NewBridge creates a Bridge that will use the provided CDP client to manage
// a virtual authenticator. The client must already be connected. The optional
// sink, when non-nil, is called to persist credentials created inside the
// Chrome virtual authenticator during the session.
func NewBridge(client *Client, logger *slog.Logger) *Bridge {
	return &Bridge{
		client: client,
		logger: logger,
	}
}

// SetCredentialSink registers the persistence callback used to durably capture
// credentials created inside the Chrome virtual authenticator. It must be set
// before Start so the credentialAdded subscription is active for the whole
// session.
func (b *Bridge) SetCredentialSink(sink CredentialSink) {
	b.sink = sink
}

// credentialAddedEvent is the params payload of the WebAuthn.credentialAdded
// CDP event.
type credentialAddedEvent struct {
	AuthenticatorID string     `json:"authenticatorId"`
	Credential      Credential `json:"credential"`
}

// handleEvent dispatches CDP events relevant to credential capture.
func (b *Bridge) handleEvent(method string, params json.RawMessage) {
	if method != "WebAuthn.credentialAdded" {
		return
	}

	var ev credentialAddedEvent
	if err := json.Unmarshal(params, &ev); err != nil {
		b.logger.Warn("CDP credentialAdded parse failed",
			slog.String("error", err.Error()))
		return
	}

	b.persistCaptured(ev.Credential)
}

// persistCaptured maps a CDP credential to a StoredCredential and forwards it
// to the configured sink. Failures are logged; capture is best-effort but the
// private key has already been observed so the loss window is the sink itself.
func (b *Bridge) persistCaptured(cred Credential) {
	if b.sink == nil {
		return
	}

	if cred.CredentialID == "" || cred.PrivateKey == "" {
		b.logger.Warn("CDP captured credential missing id or key; skipping",
			slog.String("rpId", cred.RpID))
		return
	}

	// Mapped field by field rather than converted. This is the boundary
	// where a captured credential becomes a PERSISTED one, so what crosses
	// it should be an explicit decision: a struct conversion would silently
	// carry across any field later added to Credential.
	//nolint:staticcheck // S1016: deliberate, see above
	sc := StoredCredential{
		CredentialID:         cred.CredentialID,
		IsResidentCredential: cred.IsResidentCredential,
		RpID:                 cred.RpID,
		PrivateKey:           cred.PrivateKey,
		UserHandle:           cred.UserHandle,
		SignCount:            cred.SignCount,
	}

	if err := b.sink(sc); err != nil {
		b.logger.Warn("CDP credential capture persist failed",
			slog.String("credentialId", cred.CredentialID),
			slog.String("rpId", cred.RpID),
			slog.String("error", err.Error()))
		return
	}

	b.logger.Info("CDP credential captured and persisted",
		slog.String("credentialId", cred.CredentialID),
		slog.String("rpId", cred.RpID))
}

// Start enables the WebAuthn domain and creates a virtual authenticator
// configured for CTAP2/USB with resident keys, user verification, and
// automatic presence simulation.
func (b *Bridge) Start(ctx context.Context) error {
	if b.client == nil {
		return ErrBridgeNilClient
	}

	if b.started.Load() {
		return ErrBridgeAlreadyStarted
	}

	// Register the event handler before enabling WebAuthn so credentialAdded
	// events are captured for the entire session.
	if b.sink != nil {
		b.client.OnEvent(b.handleEvent)
	}

	if err := b.client.Enable(ctx); err != nil {
		return err
	}

	opts := &AuthenticatorOptions{
		Protocol:                    "ctap2",
		Transport:                   "usb",
		HasResidentKey:              true,
		HasUserVerification:         true,
		IsUserVerified:              true,
		AutomaticPresenceSimulation: true,
	}

	authID, err := b.client.AddVirtualAuthenticator(ctx, opts)
	if err != nil {
		// Best-effort disable on failure.
		_ = b.client.Disable(ctx)
		return err
	}

	b.authenticatorID = authID
	b.started.Store(true)

	b.logger.Info("CDP bridge started",
		slog.String("authenticatorId", authID))

	return nil
}

// SyncCredentials bulk-loads the given credentials into the virtual
// authenticator. Each credential is added independently; failures are
// collected and returned as a single wrapped error.
func (b *Bridge) SyncCredentials(ctx context.Context, credentials []StoredCredential) error {
	if !b.started.Load() {
		return ErrBridgeNotStarted
	}

	var firstErr error
	var failCount int

	for i := range credentials {
		cred := &Credential{
			CredentialID:         credentials[i].CredentialID,
			IsResidentCredential: credentials[i].IsResidentCredential,
			RpID:                 credentials[i].RpID,
			PrivateKey:           credentials[i].PrivateKey,
			UserHandle:           credentials[i].UserHandle,
			SignCount:            credentials[i].SignCount,
		}

		if err := b.client.AddCredential(ctx, b.authenticatorID, cred); err != nil {
			failCount++
			if firstErr == nil {
				firstErr = err
			}
			b.logger.Warn("failed to sync credential",
				slog.String("credentialId", credentials[i].CredentialID),
				slog.String("error", err.Error()))
		}
	}

	if firstErr != nil {
		return &SentinelCauseError{Sentinel: ErrCDPCredentialFailed,
			Cause: &WrappedError{Msg: fmt.Sprintf("%d of %d credentials failed", failCount, len(credentials)), Err: firstErr}}
	}

	b.logger.Info("credentials synced",
		slog.Int("count", len(credentials)),
		slog.String("authenticatorId", b.authenticatorID))

	return nil
}

// AuthenticatorID returns the CDP authenticator identifier, or an empty
// string if the bridge has not been started.
func (b *Bridge) AuthenticatorID() string {
	return b.authenticatorID
}

// CaptureAll performs a one-shot sweep of every credential currently held by
// the Chrome virtual authenticator and forwards each to the configured sink.
// It complements (but never replaces) event-driven capture: it guards against
// the unlikely loss of a credentialAdded event. Persistence on the event path
// is what protects against process kill — this sweep only runs at shutdown.
func (b *Bridge) CaptureAll(ctx context.Context) error {
	if !b.started.Load() {
		return ErrBridgeNotStarted
	}
	if b.sink == nil {
		return nil
	}

	creds, err := b.client.GetCredentials(ctx, b.authenticatorID)
	if err != nil {
		return err
	}

	for i := range creds {
		b.persistCaptured(creds[i])
	}

	b.logger.Info("CDP shutdown credential sweep complete",
		slog.Int("count", len(creds)),
		slog.String("authenticatorId", b.authenticatorID))

	return nil
}

// Close removes the virtual authenticator and disables the WebAuthn domain.
// It is safe to call Close on a bridge that was never started.
func (b *Bridge) Close() error {
	if !b.started.Load() {
		return nil
	}

	ctx := context.Background()

	var firstErr error

	// Complementary shutdown sweep: persist anything the event path may have
	// missed before the authenticator is torn down. The primary durability
	// guarantee is the credentialAdded event handler, not this sweep.
	if b.sink != nil {
		if err := b.CaptureAll(ctx); err != nil {
			b.logger.Warn("CDP shutdown credential sweep failed",
				slog.String("error", err.Error()))
		}
	}

	// Detach the event handler so a reused client stops delivering to us.
	b.client.OnEvent(nil)

	if err := b.client.RemoveVirtualAuthenticator(ctx, b.authenticatorID); err != nil {
		firstErr = err
		b.logger.Warn("failed to remove virtual authenticator",
			slog.String("authenticatorId", b.authenticatorID),
			slog.String("error", err.Error()))
	}

	if err := b.client.Disable(ctx); err != nil && firstErr == nil {
		firstErr = err
	}

	b.started.Store(false)
	b.authenticatorID = ""

	b.logger.Info("CDP bridge closed")

	return firstErr
}
