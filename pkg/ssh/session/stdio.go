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

package session

import (
	"io"
	"os"
)

// osStdin / osStdout / osStderr isolate the single os.File usage in
// this package so session.go stays easy to audit. The session struct
// reads through the package-level stdin / stdout / stderr variables
// (see init in session.go).
var (
	osStdin  io.Reader = os.Stdin
	osStdout io.Writer = os.Stdout
	osStderr io.Writer = os.Stderr
)
