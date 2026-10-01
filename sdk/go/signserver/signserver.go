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

// Package signserver re-exports go-xkms pkg/signserver: the embeddable,
// node-local, sign-only xkms server a remote-mode PKCS#11 module
// (libxkms_pkcs11.so) signs through, and the key provisioning that creates
// its keys with the CKA_LABEL and CKA_ID the module exposes.
//
// It builds with CGO_ENABLED=0, so a pure-Go daemon runs the server in
// process and creates the keys a separate, cgo-loading consumer (an IKE
// daemon loading the module) later signs with.
package signserver

import (
	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
	pkgsignserver "github.com/jeremyhahn/go-xkms/pkg/signserver"
)

// Server types.
type (
	// Server is the node-local sign-only server.
	Server = pkgsignserver.Server

	// Config configures a Server.
	Config = pkgsignserver.Config

	// Slot is a sign-only view of one PKCS#11 token.
	Slot = pkgsignserver.Slot

	// KeyRequest describes a key to create in a slot.
	KeyRequest = pkgsignserver.KeyRequest

	// Key is a provisioned key.
	Key = pkgsignserver.Key

	// Error reports the server operation that failed.
	Error = pkgsignserver.Error

	// SlotError adds the slot a failure concerns.
	SlotError = pkgsignserver.SlotError
)

// Key provisioning against any key service and token store, for an embedder
// that provisions a remote-mode module's keys without running a Server (for
// example against xkmsd over its unix socket).
type (
	// ProvisionConfig names the key service and token store.
	ProvisionConfig = module.ProvisionConfig

	// KeyPairRequest describes the EC key pair to create.
	KeyPairRequest = module.KeyPairRequest

	// ProvisionedKeyPair describes the key pair on the token.
	ProvisionedKeyPair = module.ProvisionedKeyPair

	// ProvisionError reports the Cryptoki step that failed.
	ProvisionError = module.ProvisionError

	// PKCS11Transport is the key-service client provisioning drives.
	PKCS11Transport = module.PKCS11Transport

	// PKCS11StateClient is the token-record client a remote token store uses.
	PKCS11StateClient = module.PKCS11StateClient
)

var (
	// New builds a Server.
	New = pkgsignserver.New

	// ProvisionECKeyPair creates an EC key pair with the requested CKA_LABEL
	// and CKA_ID on a token, idempotently.
	ProvisionECKeyPair = module.ProvisionECKeyPair

	// NewRemoteStorage returns the token store a remote-mode module reads,
	// over a PKCS11StateClient.
	NewRemoteStorage = module.NewRemoteStorage
)

// DefaultSocketMode is the socket file mode when Config.SocketMode is zero.
const DefaultSocketMode = pkgsignserver.DefaultSocketMode

// Sentinel errors, matched with errors.Is.
var (
	ErrSocketPathRequired   = pkgsignserver.ErrSocketPathRequired
	ErrNoAllowedPeers       = pkgsignserver.ErrNoAllowedPeers
	ErrBackendsRequired     = pkgsignserver.ErrBackendsRequired
	ErrStateStorageRequired = pkgsignserver.ErrStateStorageRequired
	ErrSlotsRequired        = pkgsignserver.ErrSlotsRequired
	ErrSlotTokenRequired    = pkgsignserver.ErrSlotTokenRequired
	ErrSlotDuplicate        = pkgsignserver.ErrSlotDuplicate
	ErrSlotKeysRequired     = pkgsignserver.ErrSlotKeysRequired
	ErrUnknownSlot          = pkgsignserver.ErrUnknownSlot
	ErrKeyNotNamed          = pkgsignserver.ErrKeyNotNamed
	ErrKeyNotAdmitted       = pkgsignserver.ErrKeyNotAdmitted
	ErrTokenWriteDenied     = pkgsignserver.ErrTokenWriteDenied
	ErrRequestShape         = pkgsignserver.ErrRequestShape

	ErrProvisionClientRequired   = module.ErrProvisionClientRequired
	ErrProvisionStorageRequired  = module.ErrProvisionStorageRequired
	ErrProvisionLabelRequired    = module.ErrProvisionLabelRequired
	ErrProvisionIDRequired       = module.ErrProvisionIDRequired
	ErrProvisionCurveUnsupported = module.ErrProvisionCurveUnsupported
	ErrProvisionUserPINRequired  = module.ErrProvisionUserPINRequired
	ErrProvisionSOPINRequired    = module.ErrProvisionSOPINRequired
	ErrProvisionECPoint          = module.ErrProvisionECPoint
	ErrProvisionKeyConflict      = module.ErrProvisionKeyConflict
)
