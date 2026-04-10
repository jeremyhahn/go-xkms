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
	"fmt"
	"log/slog"
	"sync/atomic"
)

// StoredCredential holds the credential data needed to register a FIDO2
// credential with a CDP virtual authenticator. Callers map their own
// credential storage types to this struct before calling SyncCredentials.
type StoredCredential struct {
	// CredentialID is the base64url-encoded credential identifier.
	CredentialID string

	// IsResidentCredential indicates whether this is a discoverable credential.
	IsResidentCredential bool

	// RpID is the relying party identifier (e.g., "example.com").
	RpID string

	// PrivateKey is the base64url-encoded PKCS#8 private key.
	PrivateKey string

	// UserHandle is the base64url-encoded user handle (may be empty).
	UserHandle string

	// SignCount is the current signature counter value.
	SignCount int
}

// Bridge syncs xkey FIDO2 credentials to a Chrome DevTools virtual authenticator.
// It manages the lifecycle of a single virtual authenticator instance.
type Bridge struct {
	client          *Client
	authenticatorID string
	logger          *slog.Logger
	started         atomic.Bool
}

// NewBridge creates a Bridge that will use the provided CDP client to manage
// a virtual authenticator. The client must already be connected.
func NewBridge(client *Client, logger *slog.Logger) *Bridge {
	return &Bridge{
		client: client,
		logger: logger,
	}
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
		return fmt.Errorf("%w: %d of %d credentials failed: %w",
			ErrCDPCredentialFailed, failCount, len(credentials), firstErr)
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

// Close removes the virtual authenticator and disables the WebAuthn domain.
// It is safe to call Close on a bridge that was never started.
func (b *Bridge) Close() error {
	if !b.started.Load() {
		return nil
	}

	ctx := context.Background()

	var firstErr error

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
