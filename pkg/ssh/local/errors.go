// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package local

// NilInputError is returned when a required argument is nil or empty.
// Field names the offending argument so callers can surface precise
// diagnostics.
type NilInputError struct {
	Field string
}

// Error implements the error interface.
func (e *NilInputError) Error() string {
	return "ssh/local: nil input: " + e.Field
}

// ConfigParseError wraps a failure to read or decode an ssh_config(5)
// file. A missing file is never an error (see LoadConfig) — this type is
// reserved for files that exist but cannot be opened or parsed.
type ConfigParseError struct {
	Path string
	Err  error
}

// Error implements the error interface.
func (e *ConfigParseError) Error() string {
	return "ssh/local: parse " + e.Path + ": " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *ConfigParseError) Unwrap() error { return e.Err }

// AgentUnavailableError is returned by DialAgent (and, transitively,
// SignerForPublicKey) when the ssh-agent socket cannot be reached — an
// empty path, a missing socket, or any other dial failure.
type AgentUnavailableError struct {
	Path string
	Err  error
}

// Error implements the error interface.
func (e *AgentUnavailableError) Error() string {
	return "ssh/local: agent unavailable at " + e.Path + ": " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *AgentUnavailableError) Unwrap() error { return e.Err }

// AgentKeyNotFoundError is returned by SignerForPublicKey when the agent
// is reachable but does not hold a signer for the requested public key.
type AgentKeyNotFoundError struct {
	Fingerprint string
}

// Error implements the error interface.
func (e *AgentKeyNotFoundError) Error() string {
	return "ssh/local: agent has no signer for key " + e.Fingerprint
}

// IdentityReadError wraps a failure to stat or read an identity file (the
// private key itself, not its paired .pub — a missing or unparsable .pub
// is not an error; see DiscoverIdentities).
type IdentityReadError struct {
	Path string
	Err  error
}

// Error implements the error interface.
func (e *IdentityReadError) Error() string {
	return "ssh/local: read identity " + e.Path + ": " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *IdentityReadError) Unwrap() error { return e.Err }

// HostNotConfiguredError is returned by LookupStrict when alias does not
// match any literal Host pattern known to the loaded configuration. Plain
// Lookup never returns this — it always falls back to a synthesized
// HostConfig — this error exists for callers (e.g. a host picker in the
// xkey GUI) that need to distinguish "the operator has this host
// configured" from "nothing matched, defaults were substituted".
type HostNotConfiguredError struct {
	Alias string
}

// Error implements the error interface.
func (e *HostNotConfiguredError) Error() string {
	return "ssh/local: host not configured: " + e.Alias
}
