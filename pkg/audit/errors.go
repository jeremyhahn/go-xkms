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

package audit

import "errors"

var (
	// ErrLoggerClosed is returned when a write is attempted on a closed logger.
	ErrLoggerClosed = errors.New("audit logger closed")

	// ErrNilEvent is returned when a nil event is passed to Log.
	ErrNilEvent = errors.New("nil audit event")
)
