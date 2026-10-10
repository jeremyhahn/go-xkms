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

// NewSSHKnownHostsStore constructs the known-hosts store over the go-qrdb
// DAOs a DAO factory builds.
var NewSSHKnownHostsStore = sshknownhosts.NewDAOStore

// SSHKnownHostsPin is a single pinned host-key envelope persisted by an
// SSHKnownHostsStore.
type SSHKnownHostsPin = sshknownhosts.Pin

// SSHPinFromPublicKey builds an SSHKnownHostsPin from a host public key,
// filling the OpenSSH SHA256 fingerprint, algorithm, and wire-format key.
// The caller persists it via SSHKnownHostsStore.Add.
var SSHPinFromPublicKey = sshknownhosts.PinFromPublicKey

// SSHImportKnownHostsFile imports an OpenSSH known_hosts file into an
// SSHKnownHostsStore under the given scope/owner, returning the count added.
var SSHImportKnownHostsFile = sshknownhosts.ImportKnownHostsFile

// SSHValidateFingerprint returns nil if the argument is a well-formed
// OpenSSH SHA256 host-key fingerprint, as `ssh-keygen -lf` prints it:
// a "SHA256:" prefix followed by the unpadded standard-base64 encoding
// of a 32-byte digest. It returns *SSHInvalidFingerprintError otherwise.
// Composers validate an operator-supplied fingerprint through this before
// building or looking up an SSHKnownHostsPin.
var SSHValidateFingerprint = sshknownhosts.ValidateFingerprint

// SSHInvalidFingerprintError reports a fingerprint string that does not
// match the OpenSSH "SHA256:<base64>" form.
type SSHInvalidFingerprintError = sshknownhosts.InvalidFingerprintError

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
