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

package ssh

import (
	"context"

	gossh "golang.org/x/crypto/ssh"

	pkgconnect "github.com/jeremyhahn/go-xkms/pkg/ssh/connect"
	pkgknownhosts "github.com/jeremyhahn/go-xkms/pkg/ssh/known_hosts"
	pkgscope "github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// HostKeyStore is the host-key pin store used by the connection launcher.
type HostKeyStore = pkgknownhosts.Store

// ConnectSession is a launched connection handle. Spawn the system ssh client
// with Args/Env, then call SyncAndStop when it exits.
type ConnectSession = pkgconnect.Session

// NewHostKeyStore builds a folder-namespaced host-key pin store over a storage
// backend (barrier-routed in the GUI). It is the same store the SSH client's
// KnownHosts() sub-client persists pins into.
func NewHostKeyStore(backend storage.Backend) (HostKeyStore, error) {
	return pkgknownhosts.NewBackendStore(backend)
}

// ConnectOptions configures StartConnect. Scope is the string form
// ("tenant"/"user"/"service"); Signer comes from Client.Keys().Signer.
type ConnectOptions struct {
	Host                  string
	Port                  int
	User                  string
	Signer                gossh.Signer
	HostKeys              HostKeyStore
	Scope                 string
	Owner                 string
	ExtraOptions          []string
	StrictHostKeyChecking string

	// ExtraKnownHosts are additional known_hosts files merged into the seed and
	// mirrored on sync (e.g. ~/.ssh/known_hosts for the "system"/"both"
	// policies). SkipStore disables barrier seeding/sync (the "system" policy).
	ExtraKnownHosts []string
	SkipStore       bool
}

// StartConnect serves the signer over an in-process SSH agent, seeds a
// known_hosts file from the store, and returns the ssh argv/env. The caller
// spawns the system ssh client (in a terminal window or inline) and calls
// (*ConnectSession).SyncAndStop afterward to pin first-contact hosts and stop
// the agent. That call takes a context bounding the shutdown, and returns a
// report naming any signing operation still running when it elapsed — a signer
// wedged inside Sign cannot be interrupted, so the bound is what keeps teardown
// from hanging on it.
func StartConnect(ctx context.Context, opts ConnectOptions) (*ConnectSession, error) {
	scopeVal := opts.Scope
	if scopeVal == "" {
		scopeVal = string(pkgscope.User)
	}
	sc, err := pkgscope.Parse(scopeVal)
	if err != nil {
		return nil, &InvalidScopeError{Value: opts.Scope}
	}
	return pkgconnect.Start(ctx, pkgconnect.Request{
		Host:                  opts.Host,
		Port:                  opts.Port,
		User:                  opts.User,
		Signer:                opts.Signer,
		KnownHostsStore:       opts.HostKeys,
		Scope:                 sc,
		Owner:                 opts.Owner,
		ExtraOptions:          opts.ExtraOptions,
		StrictHostKeyChecking: opts.StrictHostKeyChecking,
		ExtraKnownHosts:       opts.ExtraKnownHosts,
		SkipStore:             opts.SkipStore,
	})
}
