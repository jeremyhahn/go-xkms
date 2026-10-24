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

// Package checkpoint re-exports go-xkms's transparency log checkpoints
// (c2sp.org/tlog-checkpoint) in signed notes (c2sp.org/signed-note), with the
// registrable note signature algorithms, for SDK consumers. The
// implementation is pkg/ca/checkpoint.
package checkpoint

import pkgcheckpoint "github.com/jeremyhahn/go-xkms/pkg/ca/checkpoint"

// Types.
type (
	// Checkpoint is the note text of a transparency log checkpoint.
	Checkpoint = pkgcheckpoint.Checkpoint
	// Signer signs note text under one key name with a crypto.Signer.
	Signer = pkgcheckpoint.Signer
	// SignerOption configures NewSigner.
	SignerOption = pkgcheckpoint.SignerOption
	// Verifier verifies note signatures under one key.
	Verifier = pkgcheckpoint.Verifier
	// Note is a signed note opened by Open.
	Note = pkgcheckpoint.Note
	// Signature is one signature line of a note.
	Signature = pkgcheckpoint.Signature
	// Algorithm is one note signature algorithm.
	Algorithm = pkgcheckpoint.Algorithm
)

// Constants.
const (
	TypeExtended        = pkgcheckpoint.TypeExtended
	MaxIdentifierLength = pkgcheckpoint.MaxIdentifierLength
	MaxSignatures       = pkgcheckpoint.MaxSignatures
	HashSize            = pkgcheckpoint.HashSize

	AlgorithmEd25519         = pkgcheckpoint.AlgorithmEd25519
	AlgorithmECDSA           = pkgcheckpoint.AlgorithmECDSA
	AlgorithmECDSAP224SHA256 = pkgcheckpoint.AlgorithmECDSAP224SHA256
	AlgorithmECDSAP384SHA384 = pkgcheckpoint.AlgorithmECDSAP384SHA384
	AlgorithmECDSAP521SHA512 = pkgcheckpoint.AlgorithmECDSAP521SHA512
	AlgorithmRSAPKCS1SHA256  = pkgcheckpoint.AlgorithmRSAPKCS1SHA256
	AlgorithmRSAPKCS1SHA384  = pkgcheckpoint.AlgorithmRSAPKCS1SHA384
	AlgorithmRSAPKCS1SHA512  = pkgcheckpoint.AlgorithmRSAPKCS1SHA512
	AlgorithmRSAPSSSHA256    = pkgcheckpoint.AlgorithmRSAPSSSHA256
	AlgorithmRSAPSSSHA384    = pkgcheckpoint.AlgorithmRSAPSSSHA384
	AlgorithmRSAPSSSHA512    = pkgcheckpoint.AlgorithmRSAPSSSHA512
	AlgorithmMLDSA44         = pkgcheckpoint.AlgorithmMLDSA44
	AlgorithmMLDSA65         = pkgcheckpoint.AlgorithmMLDSA65
	AlgorithmMLDSA87         = pkgcheckpoint.AlgorithmMLDSA87
)

// Functions.
var (
	// NewSigner returns a Signer for a key name and crypto.Signer.
	NewSigner = pkgcheckpoint.NewSigner
	// WithAlgorithm names the algorithm a Signer uses.
	WithAlgorithm = pkgcheckpoint.WithAlgorithm
	// NewVerifier parses a signed-note verifier key.
	NewVerifier = pkgcheckpoint.NewVerifier
	// Register adds a note signature algorithm.
	Register = pkgcheckpoint.Register
	// Sign signs note text.
	Sign = pkgcheckpoint.Sign
	// Open parses and verifies a signed note.
	Open = pkgcheckpoint.Open
	// ParseCheckpoint strictly parses checkpoint note text.
	ParseCheckpoint = pkgcheckpoint.ParseCheckpoint
	// SignCheckpoint marshals and signs a checkpoint.
	SignCheckpoint = pkgcheckpoint.SignCheckpoint
	// OpenCheckpoint opens a signed checkpoint and parses its text.
	OpenCheckpoint = pkgcheckpoint.OpenCheckpoint
)

// Errors.
var (
	ErrMalformedCheckpoint  = pkgcheckpoint.ErrMalformedCheckpoint
	ErrInvalidTreeSize      = pkgcheckpoint.ErrInvalidTreeSize
	ErrInvalidRootHash      = pkgcheckpoint.ErrInvalidRootHash
	ErrMalformedNote        = pkgcheckpoint.ErrMalformedNote
	ErrInvalidText          = pkgcheckpoint.ErrInvalidText
	ErrInvalidKeyName       = pkgcheckpoint.ErrInvalidKeyName
	ErrTooManySignatures    = pkgcheckpoint.ErrTooManySignatures
	ErrDuplicateSignature   = pkgcheckpoint.ErrDuplicateSignature
	ErrSignatureInvalid     = pkgcheckpoint.ErrSignatureInvalid
	ErrNoValidSignature     = pkgcheckpoint.ErrNoValidSignature
	ErrNoSigner             = pkgcheckpoint.ErrNoSigner
	ErrNoVerifier           = pkgcheckpoint.ErrNoVerifier
	ErrDuplicateVerifier    = pkgcheckpoint.ErrDuplicateVerifier
	ErrSigningFailed        = pkgcheckpoint.ErrSigningFailed
	ErrMalformedVerifierKey = pkgcheckpoint.ErrMalformedVerifierKey
	ErrKeyIDMismatch        = pkgcheckpoint.ErrKeyIDMismatch
	ErrUnknownAlgorithm     = pkgcheckpoint.ErrUnknownAlgorithm
	ErrUnsupportedKey       = pkgcheckpoint.ErrUnsupportedKey
	ErrAmbiguousAlgorithm   = pkgcheckpoint.ErrAmbiguousAlgorithm
	ErrInvalidAlgorithm     = pkgcheckpoint.ErrInvalidAlgorithm
	ErrReservedType         = pkgcheckpoint.ErrReservedType
	ErrDuplicateAlgorithm   = pkgcheckpoint.ErrDuplicateAlgorithm
)
