// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package challenge

// ExtractURL returns the challenge URL for REST transport routing.
func (r *GetRequest) ExtractURL() string {
	return r.ChallengeURL
}

// ExtractURL returns the challenge URL for REST transport routing.
func (r *RespondRequest) ExtractURL() string {
	return r.ChallengeURL
}
