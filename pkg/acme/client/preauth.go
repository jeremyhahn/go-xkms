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
	"errors"
	"log/slog"
	"sync"

	"golang.org/x/crypto/acme"
)

// Pre-authorization error types
var (
	// ErrPreAuthNotSupported indicates the ACME server does not support
	// pre-authorization (newAuthz endpoint is not present in directory)
	ErrPreAuthNotSupported = errors.New("acme-client: server does not support pre-authorization")

	// ErrPreAuthFailed indicates the pre-authorization request failed
	ErrPreAuthFailed = errors.New("acme-client: pre-authorization request failed")

	// ErrPreAuthInvalidIdentifier indicates an invalid identifier was provided
	ErrPreAuthInvalidIdentifier = errors.New("acme-client: invalid identifier for pre-authorization")
)

// SupportsPreAuthorization checks if the ACME server supports pre-authorization.
// Per RFC 8555 Section 7.4.1, the newAuthz endpoint is optional and its presence
// in the directory indicates pre-authorization support.
//
// This method performs a Discover call to fetch the server directory and checks
// if the AuthzURL (newAuthz) field is present.
func (c *Client) SupportsPreAuthorization(ctx context.Context) bool {
	dir, err := c.client.Discover(ctx)
	if err != nil {
		c.logger.Warn("failed to discover directory for pre-auth support check",
			slog.String("error", err.Error()))
		return false
	}

	// Per RFC 8555, AuthzURL (newAuthz) is optional and indicates pre-auth support
	return dir.AuthzURL != ""
}

// PreAuthorize creates an authorization before creating an order.
// Per RFC 8555 Section 7.4.1, this allows clients to pre-authorize identifiers
// before creating an order, which can be useful for:
//   - Obtaining authorizations in advance of certificate issuance
//   - Reusing authorizations across multiple orders
//   - Spreading authorization work over time
//
// The identifier should specify the type ("dns" or "ip") and value (domain name
// or IP address) to authorize.
//
// Returns the authorization object containing challenges to complete, or an error
// if pre-authorization is not supported or the request fails.
func (c *Client) PreAuthorize(ctx context.Context, identifier Identifier) (*acme.Authorization, error) {
	if identifier.Type == "" || identifier.Value == "" {
		return nil, ErrPreAuthInvalidIdentifier
	}

	// Check if server supports pre-authorization
	dir, err := c.client.Discover(ctx)
	if err != nil {
		c.logger.Error("failed to discover directory",
			slog.String("error", err.Error()))
		return nil, err
	}

	if dir.AuthzURL == "" {
		c.logger.Warn("server does not support pre-authorization",
			slog.String("directoryURL", c.config.DirectoryURL))
		return nil, ErrPreAuthNotSupported
	}

	c.logger.Info("creating pre-authorization",
		slog.String("type", identifier.Type),
		slog.String("value", identifier.Value),
		slog.String("authzURL", dir.AuthzURL))

	// Convert our Identifier to acme.AuthzID
	authzID := acme.AuthzID{
		Type:  identifier.Type,
		Value: identifier.Value,
	}

	// Use the underlying ACME client's Authorize method which handles
	// the newAuthz endpoint when pre-authorization is supported
	authz, err := c.client.Authorize(ctx, authzID.Value)
	if err != nil {
		c.logger.Error("pre-authorization request failed",
			slog.String("type", identifier.Type),
			slog.String("value", identifier.Value),
			slog.String("error", err.Error()))
		return nil, errors.Join(ErrPreAuthFailed, err)
	}

	c.logger.Info("pre-authorization created successfully",
		slog.String("uri", authz.URI),
		slog.String("status", authz.Status),
		slog.Int("challenges", len(authz.Challenges)))

	return authz, nil
}

// PreAuthorizeMany pre-authorizes multiple identifiers.
// This is useful for preparing authorizations in bulk before creating orders.
//
// Per RFC 8555 Section 7.4.1, pre-authorization allows spreading the work of
// authorization across multiple requests rather than having all authorizations
// created automatically when an order is placed.
//
// The method processes identifiers concurrently for improved performance while
// ensuring all results are collected before returning.
//
// Returns a slice of authorizations in the same order as the input identifiers,
// or an error if any pre-authorization fails.
func (c *Client) PreAuthorizeMany(ctx context.Context, identifiers []Identifier) ([]*acme.Authorization, error) {
	if len(identifiers) == 0 {
		return []*acme.Authorization{}, nil
	}

	// Check server support once before processing
	if !c.SupportsPreAuthorization(ctx) {
		return nil, ErrPreAuthNotSupported
	}

	c.logger.Info("pre-authorizing multiple identifiers",
		slog.Int("count", len(identifiers)))

	// Use a result struct to maintain order and capture errors
	type result struct {
		index int
		authz *acme.Authorization
		err   error
	}

	results := make(chan result, len(identifiers))
	var wg sync.WaitGroup

	// Process identifiers concurrently
	for i, id := range identifiers {
		wg.Add(1)
		go func(index int, identifier Identifier) {
			defer wg.Done()

			authz, err := c.PreAuthorize(ctx, identifier)
			results <- result{
				index: index,
				authz: authz,
				err:   err,
			}
		}(i, id)
	}

	// Wait for all goroutines to complete and close the channel
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results maintaining order
	authorizations := make([]*acme.Authorization, len(identifiers))
	var firstErr error

	for r := range results {
		if r.err != nil {
			if firstErr == nil {
				firstErr = r.err
			}
			c.logger.Error("pre-authorization failed for identifier",
				slog.Int("index", r.index),
				slog.String("type", identifiers[r.index].Type),
				slog.String("value", identifiers[r.index].Value),
				slog.String("error", r.err.Error()))
			continue
		}
		authorizations[r.index] = r.authz
	}

	if firstErr != nil {
		return nil, firstErr
	}

	c.logger.Info("all pre-authorizations completed successfully",
		slog.Int("count", len(authorizations)))

	return authorizations, nil
}

// PreAuthorizeDomains is a convenience method to pre-authorize multiple DNS domains.
// It wraps PreAuthorizeMany with DNS identifier types.
func (c *Client) PreAuthorizeDomains(ctx context.Context, domains ...string) ([]*acme.Authorization, error) {
	identifiers := make([]Identifier, len(domains))
	for i, domain := range domains {
		identifiers[i] = Identifier{
			Type:  "dns",
			Value: domain,
		}
	}
	return c.PreAuthorizeMany(ctx, identifiers)
}

// PreAuthorizeIPs is a convenience method to pre-authorize multiple IP addresses.
// It wraps PreAuthorizeMany with IP identifier types.
func (c *Client) PreAuthorizeIPs(ctx context.Context, ips ...string) ([]*acme.Authorization, error) {
	identifiers := make([]Identifier, len(ips))
	for i, ip := range ips {
		identifiers[i] = Identifier{
			Type:  "ip",
			Value: ip,
		}
	}
	return c.PreAuthorizeMany(ctx, identifiers)
}
