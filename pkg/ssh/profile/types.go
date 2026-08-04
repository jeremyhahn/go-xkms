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

// Package profile provides SSH host connection profiles organized in a folder
// hierarchy, mirroring the static-password manager (pkg/staticpw). A Profile
// references an xkey-managed SSH key by (scope, owner, name) — it never stores
// key material. Profiles persist in a pluggable storage.Backend (barrier-routed
// in the GUI) under the "ssh/profiles/" namespace.
package profile

import (
	"fmt"
	"strings"
	"time"

	"github.com/cespare/xxhash/v2"
)

// defaultPort is the SSH port assumed when a profile leaves Port unset.
const defaultPort = 22

// Profile is a saved SSH connection target.
type Profile struct {
	// ID is a deterministic identifier derived from Name and FolderPath.
	ID string `json:"id"`

	// Name is the human-readable label, unique within its folder.
	Name string `json:"name"`

	// FolderPath is the hierarchical folder location (e.g. "work/prod").
	FolderPath string `json:"folder_path,omitempty"`

	// Host is the target hostname or IP. Required.
	Host string `json:"host"`

	// Port is the target SSH port. Defaults to 22 when zero.
	Port int `json:"port,omitempty"`

	// User is the remote login user. May be empty (resolved at connect time).
	User string `json:"user,omitempty"`

	// KeyScope / KeyOwner / KeyName reference the xkey-managed SSH key used to
	// authenticate. They may be empty, in which case the key is chosen at
	// connect time.
	KeyScope string `json:"key_scope,omitempty"`
	KeyOwner string `json:"key_owner,omitempty"`
	KeyName  string `json:"key_name,omitempty"`

	// KeySource selects where the authentication key comes from: "" (the
	// default) uses the xkey-managed key named by KeyScope/KeyOwner/KeyName;
	// "local" uses the operator's local ssh-agent / ~/.ssh identity files
	// instead, resolved via SSHConfigAlias (or Host, when SSHConfigAlias is
	// empty) — no xkey-managed key or in-process agent is involved.
	KeySource string `json:"key_source,omitempty"`

	// SSHConfigAlias names the Host alias in the operator's ssh_config(5)
	// files to connect through when KeySource is "local". Empty means the
	// connection uses Host/Port/User directly instead of a configured alias.
	SSHConfigAlias string `json:"ssh_config_alias,omitempty"`

	// LocalIdentity pins the connection to one specific local key when
	// KeySource is "local": either the absolute path of an identity file
	// (e.g. "/home/op/.ssh/id_ed25519") or "agent:<SHA256-fingerprint>"
	// for a key held only by the system ssh-agent. Empty means every
	// discovered local identity is offered, OpenSSH-style.
	LocalIdentity string `json:"local_identity,omitempty"`

	// PersistSession, when true, records embedded-console sessions opened
	// from this profile in the persistent session store so their tabs are
	// restored (disconnected, reconnect-on-demand) after a reload or
	// restart. False (the default) keeps sessions memory-only.
	PersistSession bool `json:"persist_session,omitempty"`

	// Options carries extra OpenSSH client options (passed as -o KEY=VALUE).
	Options []string `json:"options,omitempty"`

	// ConsoleMode selects how connections to this host open: "system" (the OS
	// terminal) or "embedded" (the in-app xterm.js console). Empty means defer
	// to the user's global default.
	ConsoleMode string `json:"console_mode,omitempty"`

	// Notes is optional free-form text.
	Notes string `json:"notes,omitempty"`

	// CreatedAt / UpdatedAt are lifecycle timestamps.
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Validate checks that the profile carries the required fields.
func (p *Profile) Validate() error {
	if strings.TrimSpace(p.Name) == "" {
		return ErrInvalidName
	}
	if strings.TrimSpace(p.Host) == "" {
		return ErrInvalidHost
	}
	return nil
}

// EffectivePort returns Port, or the default (22) when Port is unset.
func (p *Profile) EffectivePort() int {
	if p.Port <= 0 {
		return defaultPort
	}
	return p.Port
}

// GenerateID creates a deterministic 16-char hex identifier from the profile
// name and optional folder path by hashing the lowercased "folderPath/name".
func GenerateID(name string, folderPath string) string {
	var path string
	if folderPath != "" {
		path = strings.ToLower(folderPath + "/" + name)
	} else {
		path = strings.ToLower(name)
	}
	return fmt.Sprintf("%016x", xxhash.Sum64String(path))
}

// generateID is an unexported convenience wrapper.
func generateID(name string, folderPath string) string {
	return GenerateID(name, folderPath)
}
