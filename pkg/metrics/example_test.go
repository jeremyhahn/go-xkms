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

package metrics

import (
	"fmt"
	"time"
)

// Example_recordOperation demonstrates recording a service-boundary
// operation's outcome and duration. pkg/xkms's servicer methods call this
// (via a small per-package helper) so every transport (REST, gRPC, MCP,
// QUIC, embedded) is counted exactly once, at the XKMSService boundary.
func Example_recordOperation() {
	start := time.Now()
	// ... perform the operation ...
	RecordOperation(OpSign, "pkcs11", StatusSuccess, time.Since(start).Seconds())

	fmt.Println("Operation recorded")
	// Output: Operation recorded
}

// Example_recordError demonstrates recording an operation failure. The
// error_type label must stay bounded cardinality -- a Go error type name
// (e.g. "*xkms.ErrKeyIDParse"), never a key ID, common name, or tenant ID.
func Example_recordError() {
	RecordError(OpGet, "pkcs11", "*xkms.ErrKeyNotFound")

	fmt.Println("Error recorded")
	// Output: Error recorded
}

// Example_connectionTracker demonstrates tracking a protocol listener's
// active connections for a transport with no per-request middleware, such
// as the Unix domain socket listener.
func Example_connectionTracker() {
	tracker := NewConnectionTracker(ProtocolUnix)
	defer tracker.Close()

	fmt.Println("Connection tracked")
	// Output: Connection tracked
}

// Example_backendHealth demonstrates publishing a backend's health state,
// keys total, and certs total -- the gauges an operator's dashboard reads
// to see real backend state instead of a hard-coded value.
func Example_backendHealth() {
	SetBackendHealth("pkcs11", true)
	SetKeysTotal("pkcs11", 42)
	SetCertsTotal("pkcs11", 7)

	fmt.Println("Backend gauges published")
	// Output: Backend gauges published
}
