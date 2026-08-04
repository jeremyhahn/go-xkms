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

// Package sessions persists embedded-console session records for sessions
// explicitly started with persistence enabled. A record carries a session's
// display title and its reconnect origin — never any key material or live
// connection state (an SSH connection cannot survive a restart; the record
// lets the UI restore the session tab and reconnect on demand). Sessions
// started without persistence are memory-only and never touch this store.
package sessions

import "time"

// Session is one persisted embedded-console session.
type Session struct {
	// ID is a random unique identifier assigned by the store on Save.
	ID string `json:"id"`

	// Title is the display label, typically "user@host".
	Title string `json:"title"`

	// Exactly one origin group below is set; it is the reconnect recipe.

	// Host/Port/User plus the key reference describe a one-time connection
	// origin (mirrors the connect params the session was opened with).
	Host          string `json:"host,omitempty"`
	Port          int    `json:"port,omitempty"`
	User          string `json:"user,omitempty"`
	KeyScope      string `json:"key_scope,omitempty"`
	KeyOwner      string `json:"key_owner,omitempty"`
	KeyName       string `json:"key_name,omitempty"`
	KeySource     string `json:"key_source,omitempty"`
	LocalIdentity string `json:"local_identity,omitempty"`

	// ProfileID names a saved profile origin.
	ProfileID string `json:"profile_id,omitempty"`

	// Alias names an ssh_config(5) Host origin.
	Alias string `json:"alias,omitempty"`

	// CreatedAt / LastConnectedAt are lifecycle timestamps.
	CreatedAt       time.Time `json:"created_at"`
	LastConnectedAt time.Time `json:"last_connected_at"`
}

// Validate checks that the record carries a title and exactly one origin.
func (s *Session) Validate() error {
	if s.Title == "" {
		return ErrInvalidTitle
	}
	origins := 0
	if s.Host != "" {
		origins++
	}
	if s.ProfileID != "" {
		origins++
	}
	if s.Alias != "" {
		origins++
	}
	if origins != 1 {
		return ErrInvalidOrigin
	}
	return nil
}
