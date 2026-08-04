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

// Package sshlocal enumerates the operator's local ssh_config(5) hosts and
// ssh-agent/~/.ssh identities for read-only display in xkey. It is the
// single place this presentation logic lives, shared by the GUI's
// SSHLocalService (xkey/pkg/gui/services) and the `xkey ssh local` CLI
// commands (xkey/cmd/xkey/cmd) so the two front ends never diverge. All SSH
// protocol/config parsing is delegated to the SDK
// (sdk/go/client/ssh) — this package never imports go-xkms/pkg directly.
package sshlocal

import (
	sshclient "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// ConfigHostEntry is one Host alias resolved from the operator's ssh_config
// files.
type ConfigHostEntry struct {
	Alias         string
	Hostname      string
	User          string
	Port          int
	IdentityFiles []string
}

// ListConfigHosts returns every literal Host alias known to the operator's
// ssh_config(5) files (~/.ssh/config, /etc/ssh/ssh_config), fully resolved.
// Neither file existing is not an error — it yields an empty list.
func ListConfigHosts() ([]ConfigHostEntry, error) {
	cfg, err := sshclient.LoadLocalSSHConfig(sshclient.DefaultLocalSSHConfigPaths()...)
	if err != nil {
		return nil, &ConfigLoadError{Err: err}
	}

	aliases := cfg.Aliases()
	out := make([]ConfigHostEntry, 0, len(aliases))
	for _, alias := range aliases {
		hc := cfg.Lookup(alias)
		out = append(out, ConfigHostEntry{
			Alias:         hc.Alias,
			Hostname:      hc.HostName,
			User:          hc.User,
			Port:          hc.Port,
			IdentityFiles: hc.IdentityFiles,
		})
	}
	return out, nil
}
