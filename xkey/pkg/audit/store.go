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

import "time"

// Store is an audit Logger whose entries can be read back. xkey's Store is
// QRDBStore, over go-qrdb's audit store.
type Store interface {
	Logger
	// Query returns the entries matching filter, oldest first. A read that
	// cannot return every match fails instead of returning a partial result.
	Query(filter QueryFilter) ([]Entry, error)
	// Count returns the number of entries, or the error of a failed read.
	Count() (int, error)
}

// QueryFilter selects audit entries. Zero fields match everything; Until is
// inclusive; Offset and Limit page the matches.
type QueryFilter struct {
	Operation OperationType
	Backend   string
	KeyID     string
	DeviceID  string
	Success   *bool
	Since     time.Time
	Until     time.Time
	Limit     int
	Offset    int
}
