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

package main

import (
	"github.com/jeremyhahn/go-xkms/pkg/config"
	trustresolver "github.com/jeremyhahn/go-xkms/pkg/trust/resolver"
)

// trustConfigFromFile loads the trust: section from the xkmsd config file
// at path. Returns (nil, nil) when path is empty (no config file given).
// Returns (nil, err) when the file exists but cannot be loaded.
func trustConfigFromFile(path string) (*trustresolver.Config, error) {
	if path == "" {
		return nil, nil
	}
	cfg, err := config.Load(path)
	if err != nil {
		return nil, &ConfigLoadError{Path: path, Err: err}
	}
	return cfg.Trust, nil
}

// autoParamsFromResolverScope merges a ScopeConfig into an
// autoBootstrapParams, letting config-file values fill in wherever the
// corresponding CLI flag was not supplied (empty string / false). Flags
// always take precedence.
func autoParamsFromResolverScope(params *autoBootstrapParams, sc *trustresolver.ScopeConfig) {
	if sc == nil {
		return
	}
	if params.serverURL == "" && sc.ServerURL != "" {
		params.serverURL = sc.ServerURL
	}
	if sc.DANE != nil {
		if params.daneHostname == "" && sc.Hostname != "" {
			params.daneHostname = sc.Hostname
		}
		if params.daneDNSServer == "" && sc.DANE.DNSServer != "" {
			params.daneDNSServer = sc.DANE.DNSServer
		}
	}
	if sc.Noise != nil {
		if params.noiseKey == "" && sc.Noise.ServerStaticKey != "" {
			params.noiseKey = sc.Noise.ServerStaticKey
		}
		if params.noiseAddr == "" && sc.Noise.ServerAddr != "" {
			params.noiseAddr = sc.Noise.ServerAddr
		}
	}
	if sc.SPKI != nil && params.spkiPin == "" && sc.SPKI.Pin != "" {
		params.spkiPin = sc.SPKI.Pin
	}
}
