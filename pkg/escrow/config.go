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

package escrow

// Config holds the top-level escrow configuration.
type Config struct {
	// Enabled controls whether key escrow is active.
	Enabled bool `json:"enabled" yaml:"enabled"`

	// Agents configures the individual escrow agents.
	Agents []AgentConfig `json:"agents" yaml:"agents"`
}

// AgentConfig configures a single escrow agent.
type AgentConfig struct {
	// Type is the agent protocol type ("kmip" or "xkms").
	Type string `json:"type" yaml:"type"`

	// Endpoint is the agent's network address.
	// For KMIP: "kmip://host:5696"
	// For XKMS: "https://host:8443"
	Endpoint string `json:"endpoint" yaml:"endpoint"`

	// ClientCert is the path to the client TLS certificate PEM file.
	ClientCert string `json:"client_cert,omitempty" yaml:"client_cert,omitempty"`

	// ClientKey is the path to the client TLS private key PEM file.
	ClientKey string `json:"client_key,omitempty" yaml:"client_key,omitempty"`

	// CACert is the path to the CA certificate PEM file for server verification.
	CACert string `json:"ca_cert,omitempty" yaml:"ca_cert,omitempty"`

	// Authentication is the authentication method (e.g., "mtls").
	Authentication string `json:"authentication,omitempty" yaml:"authentication,omitempty"`

	// Name is a human-readable name for this agent instance.
	Name string `json:"name,omitempty" yaml:"name,omitempty"`
}

// Validate checks the agent configuration for required fields.
func (c *AgentConfig) Validate() error {
	if c.Type == "" {
		return ErrAgentNotConfigured
	}
	if c.Endpoint == "" {
		return ErrEmptyEndpoint
	}
	return nil
}
