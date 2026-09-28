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

package client

import (
	"context"
	"net/url"
	"strings"
	"sync"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/fido2"
)

// Client is a headless WebAuthn client that performs registration and
// authentication ceremonies. It acts as the "browser" in the WebAuthn flow,
// bridging a RelyingParty (the server side) and an AuthenticatorAdapter (the
// authenticator side).
type Client struct {
	mu      sync.RWMutex
	config  *Config
	adapter AuthenticatorAdapter
	rp      RelyingParty
	origin  string
}

// NewClient creates a new headless WebAuthn client with the provided configuration.
func NewClient(config *Config) (*Client, error) {
	if config == nil {
		return nil, ErrNilConfig
	}

	config.SetDefaults()

	if err := config.Validate(); err != nil {
		return nil, err
	}

	rp := config.RelyingParty
	if rp == nil {
		httpRP, err := newDefaultHTTPRelyingParty(config)
		if err != nil {
			return nil, err
		}
		rp = httpRP
	}

	origin := config.Origin
	if origin == "" {
		origin = OriginFromURL(config.ServerURL)
	}
	if origin == "" {
		return nil, fido2.ErrOriginRequired
	}

	return &Client{
		config:  config,
		adapter: config.AuthenticatorAdapter,
		rp:      rp,
		origin:  origin,
	}, nil
}

// Register performs a full WebAuthn registration ceremony:
//  1. Ask the RelyingParty to begin registration, for the creation options.
//  2. Call the authenticator's MakeCredential with those options.
//  3. Ask the RelyingParty to finish registration with the attestation.
func (c *Client) Register(ctx context.Context, req *RegistrationRequest) (*RegistrationResult, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	if err := req.Validate(); err != nil {
		return nil, err
	}

	c.mu.RLock()
	adapter := c.adapter
	c.mu.RUnlock()

	if !adapter.Available() {
		return nil, ErrAuthenticatorNotFound
	}

	begin, err := c.rp.BeginRegistration(ctx, req)
	if err != nil {
		return nil, wrapError("begin registration", err)
	}

	attestation, err := adapter.MakeCredential(ctx, &CeremonyOptions{
		OptionsJSON: begin.OptionsJSON,
		Origin:      c.origin,
		PIN:         req.PIN,
	})
	if err != nil {
		return nil, wrapError("make credential", &errs.Joined{Lead: ErrCTAPOperationFailed, Cause: err})
	}

	result, err := c.rp.FinishRegistration(ctx, begin, req, attestation)
	if err != nil {
		return nil, wrapError("finish registration", err)
	}

	return result, nil
}

// Login performs a full WebAuthn authentication ceremony:
//  1. Ask the RelyingParty to begin authentication, for the request options.
//  2. Call the authenticator's GetAssertion with those options.
//  3. Ask the RelyingParty to finish authentication with the assertion.
func (c *Client) Login(ctx context.Context, req *AuthenticationRequest) (*AuthenticationResult, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	if err := req.Validate(); err != nil {
		return nil, err
	}

	c.mu.RLock()
	adapter := c.adapter
	c.mu.RUnlock()

	if !adapter.Available() {
		return nil, ErrAuthenticatorNotFound
	}

	begin, err := c.rp.BeginAuthentication(ctx, req)
	if err != nil {
		return nil, wrapError("begin login", err)
	}

	assertion, err := adapter.GetAssertion(ctx, &CeremonyOptions{
		OptionsJSON: begin.OptionsJSON,
		Origin:      c.origin,
		PIN:         req.PIN,
	})
	if err != nil {
		return nil, wrapError("get assertion", &errs.Joined{Lead: ErrCTAPOperationFailed, Cause: err})
	}

	result, err := c.rp.FinishAuthentication(ctx, begin, req, assertion)
	if err != nil {
		return nil, wrapError("finish login", err)
	}

	return result, nil
}

// Available checks if both the relying party and the authenticator are
// reachable. A RelyingParty that does not implement AvailabilityChecker is
// assumed reachable.
func (c *Client) Available(ctx context.Context) bool {
	c.mu.RLock()
	adapter := c.adapter
	rp := c.rp
	c.mu.RUnlock()

	if !adapter.Available() {
		return false
	}

	if checker, ok := rp.(AvailabilityChecker); ok {
		return checker.Available(ctx)
	}
	return true
}

// OriginFromURL derives the WebAuthn origin from a server URL: the scheme
// and authority with no path, which is what a browser would report. An
// unparsable or scheme-less URL yields an empty string, which every
// ceremony refuses (fido2.ErrOriginRequired); the origin is never derived
// from the server-supplied rpId.
func OriginFromURL(serverURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(serverURL))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	return parsed.Scheme + "://" + parsed.Host
}
