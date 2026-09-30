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

package embeddednode

// NodeSealError is returned when the node barrier is configured to encrypt
// the data plane but the required auto-unseal material cannot be resolved.
type NodeSealError struct {
	// Reason describes the failure.
	Reason string
	// Err is the underlying error, when one exists. Nil for a NodeSealError
	// raised without an underlying cause.
	Err error
}

// Error implements the error interface.
func (e *NodeSealError) Error() string {
	return "embeddednode: node barrier seal: " + e.Reason
}

// Unwrap exposes Err so errors.Is/errors.As can reach it.
func (e *NodeSealError) Unwrap() error {
	return e.Err
}

// ErrDatastorePathRequired is returned when a standalone datastore needs
// Datastore.Path but the deployment left it empty -- e.g. an embedded caller
// that never ran config.Config.Validate. This covers two callers: every
// standalone node (go-qrdb roots its on-disk state, the vector-storage
// subsystem in particular, under this directory regardless of the primary
// KV engine -- there is no engine, "memory" included, that lets a
// standalone node run with no directory at all), and specifically resolving
// the TPM2 node-barrier seal strategy's key directory. It is never derived
// from the process's working directory.
type ErrDatastorePathRequired struct {
	// Reason names what needed the path, e.g. "standalone datastore" or
	// "TPM2 seal key directory". Empty is accepted and reports the general
	// case.
	Reason string
}

// Error implements the error interface.
func (e *ErrDatastorePathRequired) Error() string {
	reason := e.Reason
	if reason == "" {
		reason = "the standalone datastore"
	}
	return "embeddednode: datastore.path is required for " + reason +
		" and is never derived from the process's working directory"
}
