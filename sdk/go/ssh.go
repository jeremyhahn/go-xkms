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

package xkms

import (
	sshkeys "github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	sshknownhosts "github.com/jeremyhahn/go-xkms/pkg/ssh/known_hosts"
	sshscope "github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
	sshsession "github.com/jeremyhahn/go-xkms/pkg/ssh/session"
)

// SSH primitive re-exports (from pkg/ssh/{keys,known_hosts,scope,session}).
// The full SSH client surface lives in sdk/go/client/ssh; these aliases
// cover composers that wire the low-level primitives directly.

// SSHKey is a managed SSH key (backend-resident private key material).
type SSHKey = sshkeys.Key

// SSHParsePEM parses a PEM-encoded private key into an SSHKey, prompting
// for a passphrase through the provider when the key is encrypted.
var SSHParsePEM = sshkeys.ParsePEM

// SSHKnownHostsStore is the known-hosts store interface.
type SSHKnownHostsStore = sshknownhosts.Store

// NewSSHKnownHostsBackendStore constructs a storage.Backend-backed
// known-hosts store.
var NewSSHKnownHostsBackendStore = sshknownhosts.NewBackendStore

// SSHScope identifies the ownership scope of an SSH asset.
type SSHScope = sshscope.Scope

// Re-exported SSH ownership scope constants.
const (
	SSHScopeTenant  = sshscope.Tenant
	SSHScopeUser    = sshscope.User
	SSHScopeService = sshscope.Service
)

// SSHSession is an established outbound SSH session.
type SSHSession = sshsession.Session

// SSHSessionDialRequest describes an outbound SSH session to establish.
type SSHSessionDialRequest = sshsession.DialRequest

// SSHSessionDial establishes an outbound SSH session.
var SSHSessionDial = sshsession.Dial
