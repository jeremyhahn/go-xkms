// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package client

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
)

// Chain selection error types
var (
	// ErrChainNotFound indicates the requested chain was not found
	ErrChainNotFound = errors.New("acme-client: requested chain not found")

	// ErrNoAlternateChains indicates no alternate chains are available
	ErrNoAlternateChains = errors.New("acme-client: no alternate chains available")

	// ErrChainFetchFailed indicates fetching the chain failed
	ErrChainFetchFailed = errors.New("acme-client: failed to fetch certificate chain")
)

// ChainOption represents options for chain selection
type ChainOption struct {
	// PreferredChain is the common name of the preferred root certificate
	// When set, the client will attempt to select a chain that ends with
	// a root certificate matching this name
	PreferredChain string

	// AllowFallback allows falling back to the default chain if the
	// preferred chain is not available. Default is true.
	AllowFallback bool
}

// DefaultChainOption returns the default chain selection options
func DefaultChainOption() *ChainOption {
	return &ChainOption{
		AllowFallback: true,
	}
}

// ChainInfo contains information about a certificate chain
type ChainInfo struct {
	// Chain is the certificate chain (leaf to root)
	Chain []*x509.Certificate

	// RootName is the common name of the root certificate
	RootName string

	// RootIssuer is the full issuer DN of the root certificate
	RootIssuer string

	// ChainLength is the number of certificates in the chain
	ChainLength int

	// URL is the URL from which this chain was fetched
	URL string
}

// FetchCertificateWithChain fetches a certificate with chain selection support.
// This method fetches the certificate from the given URL and allows selecting
// a specific chain when multiple chains are available.
//
// The options parameter allows specifying a preferred chain by root CA name.
// If the preferred chain is not available and AllowFallback is true, the
// default chain is returned.
//
// Example:
//
//	chains, err := client.FetchCertificateWithChain(ctx, certURL, &ChainOption{
//	    PreferredChain: "ISRG Root X1",
//	    AllowFallback:  true,
//	})
func (c *Client) FetchCertificateWithChain(ctx context.Context, certURL string, options *ChainOption) ([]*x509.Certificate, error) {
	if options == nil {
		options = DefaultChainOption()
	}

	c.logger.Info("fetching certificate with chain selection",
		slog.String("certURL", certURL),
		slog.String("preferredChain", options.PreferredChain))

	// Fetch the default chain first
	defaultChain, err := c.FetchCertificate(ctx, certURL, true)
	if err != nil {
		return nil, caerrors.ConnectionFailureError("failed to fetch certificate chain: %v", err)
	}

	// If no preferred chain specified, return the default
	if options.PreferredChain == "" {
		return defaultChain, nil
	}

	// Check if the default chain matches the preferred root
	if matchesPreferredChain(defaultChain, options.PreferredChain) {
		c.logger.Info("default chain matches preferred chain",
			slog.String("preferredChain", options.PreferredChain))
		return defaultChain, nil
	}

	// Try to find alternate chains via Link headers
	alternateChains, err := c.fetchAlternateChains(ctx, certURL)
	if err != nil {
		if options.AllowFallback {
			c.logger.Warn("failed to fetch alternate chains, using default",
				slog.String("error", err.Error()))
			return defaultChain, nil
		}
		return nil, err
	}

	// Search alternate chains for preferred root
	for _, chain := range alternateChains {
		if matchesPreferredChain(chain, options.PreferredChain) {
			c.logger.Info("found preferred chain in alternates",
				slog.String("preferredChain", options.PreferredChain))
			return chain, nil
		}
	}

	// Preferred chain not found
	if options.AllowFallback {
		c.logger.Warn("preferred chain not found, using default",
			slog.String("preferredChain", options.PreferredChain))
		return defaultChain, nil
	}

	return nil, caerrors.NotFoundError("no chain ending with root '%s' found", options.PreferredChain)
}

// GetAvailableChains fetches and returns all available certificate chains
// for a certificate. This is useful for inspecting which chains are available
// before making a selection.
func (c *Client) GetAvailableChains(ctx context.Context, certURL string) ([]*ChainInfo, error) {
	c.logger.Info("fetching all available chains",
		slog.String("certURL", certURL))

	var chains []*ChainInfo

	// Fetch the default chain
	defaultChain, err := c.FetchCertificate(ctx, certURL, true)
	if err != nil {
		return nil, caerrors.ConnectionFailureError("failed to fetch certificate chain: %v", err)
	}

	chains = append(chains, chainToInfo(defaultChain, certURL))

	// Fetch alternate chains
	alternateChains, err := c.fetchAlternateChains(ctx, certURL)
	if err == nil {
		for i, chain := range alternateChains {
			chains = append(chains, chainToInfo(chain, fmt.Sprintf("%s#alt%d", certURL, i+1)))
		}
	}

	c.logger.Info("found available chains",
		slog.Int("count", len(chains)))

	return chains, nil
}

// chainToInfo converts a certificate chain to ChainInfo
func chainToInfo(chain []*x509.Certificate, url string) *ChainInfo {
	if len(chain) == 0 {
		return nil
	}

	info := &ChainInfo{
		Chain:       chain,
		ChainLength: len(chain),
		URL:         url,
	}

	// Get root certificate info (last in chain)
	root := chain[len(chain)-1]
	info.RootName = root.Subject.CommonName
	info.RootIssuer = root.Issuer.String()

	return info
}

// matchesPreferredChain checks if a chain matches the preferred root name
func matchesPreferredChain(chain []*x509.Certificate, preferredName string) bool {
	if len(chain) == 0 || preferredName == "" {
		return false
	}

	// Check the root certificate (last in chain)
	root := chain[len(chain)-1]

	// Match against CommonName (case-insensitive)
	if strings.EqualFold(root.Subject.CommonName, preferredName) {
		return true
	}

	// Also check issuer CommonName for intermediate-only chains
	if strings.EqualFold(root.Issuer.CommonName, preferredName) {
		return true
	}

	return false
}

// fetchAlternateChains fetches alternate certificate chains via Link headers.
// Per RFC 8555 Section 7.4.2, ACME servers may provide alternate chains via
// Link headers with rel="alternate".
func (c *Client) fetchAlternateChains(ctx context.Context, certURL string) ([][]*x509.Certificate, error) {
	// Make a HEAD request to get Link headers
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, certURL, nil)
	if err != nil {
		return nil, caerrors.ConnectionFailureError("failed to create alternate chains request: %v", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, caerrors.ConnectionFailureError("alternate chains HEAD request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Parse Link headers
	alternateURLs := parseLinkHeaders(resp.Header.Values("Link"))
	if len(alternateURLs) == 0 {
		return nil, ErrNoAlternateChains
	}

	c.logger.Debug("found alternate chain URLs",
		slog.Int("count", len(alternateURLs)))

	// Fetch each alternate chain
	var chains [][]*x509.Certificate
	for _, url := range alternateURLs {
		chain, err := c.fetchChainFromURL(ctx, url)
		if err != nil {
			c.logger.Warn("failed to fetch alternate chain",
				slog.String("url", url),
				slog.String("error", err.Error()))
			continue
		}
		chains = append(chains, chain)
	}

	if len(chains) == 0 {
		return nil, ErrNoAlternateChains
	}

	return chains, nil
}

// parseLinkHeaders parses Link headers to find alternate chain URLs
func parseLinkHeaders(headers []string) []string {
	var alternates []string

	for _, header := range headers {
		// Parse Link header format: <URL>; rel="alternate"
		parts := strings.Split(header, ";")
		if len(parts) < 2 {
			continue
		}

		// Check for rel="alternate"
		isAlternate := false
		for _, part := range parts[1:] {
			part = strings.TrimSpace(part)
			if strings.EqualFold(part, `rel="alternate"`) ||
				strings.EqualFold(part, `rel=alternate`) {
				isAlternate = true
				break
			}
		}

		if !isAlternate {
			continue
		}

		// Extract URL from first part
		url := strings.TrimSpace(parts[0])
		url = strings.TrimPrefix(url, "<")
		url = strings.TrimSuffix(url, ">")

		if url != "" {
			alternates = append(alternates, url)
		}
	}

	return alternates
}

// fetchChainFromURL fetches a certificate chain from the given URL
func (c *Client) fetchChainFromURL(ctx context.Context, url string) ([]*x509.Certificate, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, caerrors.ConnectionFailureError("failed to create chain fetch request: %v", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, caerrors.ConnectionFailureError("chain fetch request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, caerrors.ConnectionFailureError("chain fetch server returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, caerrors.ConnectionFailureError("failed to read chain fetch response: %v", err)
	}

	return parseCertificateChain(body)
}

// parseCertificateChain parses a PEM-encoded certificate chain
func parseCertificateChain(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	for len(data) > 0 {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}

		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, caerrors.MalformedError("failed to parse certificate in chain: %v", err)
			}
			certs = append(certs, cert)
		}

		data = rest
	}

	if len(certs) == 0 {
		return nil, caerrors.MalformedError("no certificates found in data")
	}

	return certs, nil
}

// SelectChainByRootName selects a chain from available chains that matches
// the specified root name.
func SelectChainByRootName(chains []*ChainInfo, rootName string) *ChainInfo {
	if rootName == "" {
		return nil
	}

	for _, chain := range chains {
		if strings.EqualFold(chain.RootName, rootName) {
			return chain
		}
	}

	return nil
}

// SelectShortestChain selects the chain with the fewest certificates.
// Shorter chains are generally preferred for performance.
func SelectShortestChain(chains []*ChainInfo) *ChainInfo {
	if len(chains) == 0 {
		return nil
	}

	shortest := chains[0]
	for _, chain := range chains[1:] {
		if chain.ChainLength < shortest.ChainLength {
			shortest = chain
		}
	}

	return shortest
}

// SelectLongestChain selects the chain with the most certificates.
// Longer chains may be preferred for maximum compatibility.
func SelectLongestChain(chains []*ChainInfo) *ChainInfo {
	if len(chains) == 0 {
		return nil
	}

	longest := chains[0]
	for _, chain := range chains[1:] {
		if chain.ChainLength > longest.ChainLength {
			longest = chain
		}
	}

	return longest
}
