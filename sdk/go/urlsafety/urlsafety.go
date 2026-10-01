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

// Package urlsafety re-exports go-xkms pkg/urlsafety: the check every URL
// passes before it is handed to a browser or an OS opener.
package urlsafety

import pkg "github.com/jeremyhahn/go-xkms/pkg/urlsafety"

// ValidateLaunchURL parses raw and refuses any URL that is not safe to hand
// to a browser or an OS opener: one that could parse as a flag, carries
// control characters, uses a scheme other than http or https, or has no
// host. Pass the returned URL's String() to the launcher, not raw.
var ValidateLaunchURL = pkg.ValidateLaunchURL
