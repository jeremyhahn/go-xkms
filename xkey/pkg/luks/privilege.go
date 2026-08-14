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

package luks

import "os"

// geteuid returns the effective user ID of the calling process. It is a
// variable so tests can drive both the privileged and unprivileged branches
// of the ownership helpers regardless of the uid the test binary runs under.
var geteuid = os.Geteuid
