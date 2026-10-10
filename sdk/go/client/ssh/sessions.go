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
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	pkgsessions "github.com/jeremyhahn/go-xkms/pkg/ssh/sessions"
)

// ConsoleSessionRecord is one persisted embedded-console session: a display
// title plus its reconnect origin (one-time params, a profile ID, or an
// ssh_config alias) — never key material or live connection state. Only
// sessions explicitly started with persistence enabled are recorded;
// everything else stays memory-only.
type ConsoleSessionRecord = pkgsessions.Session

// ConsoleSessionStore is the persisted-session store interface.
type ConsoleSessionStore = pkgsessions.Store

// NewConsoleSessionStore constructs a session store over the DAOs daos
// builds.
func NewConsoleSessionStore(daos *qrdbsdk.DAOFactory) (ConsoleSessionStore, error) {
	return pkgsessions.NewStore(daos)
}

// Re-exported session error sentinels for errors.Is checks.
var (
	ErrConsoleSessionNotFound      = pkgsessions.ErrNotFound
	ErrConsoleSessionInvalidTitle  = pkgsessions.ErrInvalidTitle
	ErrConsoleSessionInvalidOrigin = pkgsessions.ErrInvalidOrigin
	ErrConsoleSessionNilDAOFactory = pkgsessions.ErrNilDAOFactory
)
