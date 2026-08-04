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

package services

import (
	"log/slog"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/sshlocal"
)

// SSHConfigHostEntry is the frontend-facing view of one Host alias resolved
// from the operator's ssh_config(5) files.
type SSHConfigHostEntry struct {
	Alias         string   `json:"alias"`
	Hostname      string   `json:"hostname"`
	User          string   `json:"user"`
	Port          int      `json:"port"`
	IdentityFiles []string `json:"identity_files"`
}

// SSHLocalKeyInfo is the frontend-facing view of one key discovered from the
// local ssh-agent or ~/.ssh directory (read-only — xkey never manages this
// key material).
type SSHLocalKeyInfo struct {
	Source      string `json:"source"`
	Path        string `json:"path"`
	KeyType     string `json:"key_type"`
	Fingerprint string `json:"fingerprint"`
	Comment     string `json:"comment"`
}

// SSHLocalService exposes read-only discovery of the operator's local SSH
// tooling to the frontend: ssh_config(5) hosts and ssh-agent/~/.ssh
// identities. It never manages or persists this data — it is a live view
// used to drive "connect with my local key" flows (see SSHConnectService's
// KeySource == "local" and SSHConsoleService.OpenConfigHostConsole).
type SSHLocalService struct {
	logger *slog.Logger
}

// NewSSHLocalService constructs the service.
func NewSSHLocalService() *SSHLocalService {
	return &SSHLocalService{}
}

// SetLogger wires the structured logger.
func (s *SSHLocalService) SetLogger(l *slog.Logger) { s.logger = l }

// ListConfigHosts returns every literal Host alias known to the operator's
// ssh_config(5) files, fully resolved (HostName/User/Port/IdentityFiles). An
// absent configuration is not an error — it yields an empty list.
func (s *SSHLocalService) ListConfigHosts() ([]SSHConfigHostEntry, error) {
	hosts, err := sshlocal.ListConfigHosts()
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("ssh local: list config hosts failed", "error", err)
		}
		return nil, err
	}
	out := make([]SSHConfigHostEntry, 0, len(hosts))
	for _, h := range hosts {
		out = append(out, SSHConfigHostEntry{
			Alias:         h.Alias,
			Hostname:      h.Hostname,
			User:          h.User,
			Port:          h.Port,
			IdentityFiles: h.IdentityFiles,
		})
	}
	return out, nil
}

// ListLocalKeys returns every key visible to the operator's local SSH
// tooling (ssh-agent plus ~/.ssh identity files, deduplicated by
// fingerprint). A missing agent or ~/.ssh directory is not an error — it
// yields an empty list.
func (s *SSHLocalService) ListLocalKeys() ([]SSHLocalKeyInfo, error) {
	keys, err := sshlocal.ListLocalKeys()
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("ssh local: list local keys failed", "error", err)
		}
		return nil, err
	}
	out := make([]SSHLocalKeyInfo, 0, len(keys))
	for _, k := range keys {
		out = append(out, SSHLocalKeyInfo{
			Source:      k.Source,
			Path:        k.Path,
			KeyType:     k.KeyType,
			Fingerprint: k.Fingerprint,
			Comment:     k.Comment,
		})
	}
	return out, nil
}
