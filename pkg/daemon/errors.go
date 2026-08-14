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

package daemon

import (
	"errors"
	"strconv"
)

// Sentinel errors for structurally invalid options.
var (
	// ErrNilOptions is returned when NewNode is called with nil options.
	ErrNilOptions = errors.New("daemon: options are required")

	// ErrNilQRDBConfig is returned when Options.QRDB is unset.
	ErrNilQRDBConfig = errors.New("daemon: options.QRDB is required")

	// ErrNilLogger is returned when Options.Logger is unset.
	ErrNilLogger = errors.New("daemon: options.Logger is required")

	// ErrClusterRequiresRaftBuild is returned when a clustered configuration
	// is supplied to a binary built without the `raft` build tag. Clustering
	// pulls in the Raft transport and is compiled in only with `-tags raft`.
	// This fails loudly rather than silently running unclustered.
	ErrClusterRequiresRaftBuild = errors.New(
		"daemon: clustering requires building with -tags raft")
)

// MemberFormatError reports a peer entry that is not in nodeID=address form.
type MemberFormatError struct {
	Entry string
}

// Error returns the error message.
func (e *MemberFormatError) Error() string {
	return "daemon: peer " + strconv.Quote(e.Entry) + " is not in nodeID=address form"
}

// MemberNodeIDError reports a peer entry whose node ID is unparseable or zero.
type MemberNodeIDError struct {
	Entry string
}

// Error returns the error message.
func (e *MemberNodeIDError) Error() string {
	return "daemon: peer " + strconv.Quote(e.Entry) + " has an invalid node ID"
}

// MemberAddressError reports a peer entry with an empty address.
type MemberAddressError struct {
	Entry string
}

// Error returns the error message.
func (e *MemberAddressError) Error() string {
	return "daemon: peer " + strconv.Quote(e.Entry) + " has an empty address"
}
