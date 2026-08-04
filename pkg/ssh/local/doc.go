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

// Package local provides a read-only view of the operator's local OpenSSH
// configuration: the ssh_config(5) file chain ($HOME/.ssh/config and
// /etc/ssh/ssh_config), the conventional default identity files under
// $HOME/.ssh, and the system ssh-agent (SSH_AUTH_SOCK). It exists so xkey
// can act as a GUI layer over an unmodified — or locally customized — SSH
// setup: discovering the hosts an operator has already configured, the
// identities available for each, and a signer for the chosen identity,
// without requiring the operator to migrate their configuration into xkey.
//
// This package never writes to $HOME/.ssh or /etc/ssh; every exported
// entry point only reads state that already exists on disk or is exposed by
// a running ssh-agent. Callers that need to originate new SSH key material
// or manage xkey-owned keys should use pkg/ssh/keys and pkg/ssh/agent
// instead — this package is strictly about discovering and using what the
// operator already has.
package local
