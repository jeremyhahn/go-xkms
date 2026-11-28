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

// Package authenticator is the SDK re-export of the FIDO2 CTAP2 authenticator
// (pkg/fido2/authenticator). Client binaries import this package instead of
// pkg/* so they depend only on the SDK.
package authenticator

import (
	"github.com/jeremyhahn/go-xkms/pkg/fido2/authenticator"
)

const (
	AttestationFormatNone      = authenticator.AttestationFormatNone
	ClientDataHashSize         = authenticator.ClientDataHashSize
	COSEAlgES256               = authenticator.COSEAlgES256
	COSEAlgES384               = authenticator.COSEAlgES384
	DefaultUserPresenceTimeout = authenticator.DefaultUserPresenceTimeout
	HIDPacketSize              = authenticator.HIDPacketSize
)

// CTAP commands, status codes and vendor authenticatorConfig subcommands.
const (
	AuthConfigCmdVendorPrototype = authenticator.AuthConfigCmdVendorPrototype
	CmdConfig                    = authenticator.CmdConfig
	CmdGetAssertion              = authenticator.CmdGetAssertion
	CmdMakeCredential            = authenticator.CmdMakeCredential
	StatusOK                     = authenticator.StatusOK
	VendorCmdReplaceAttestKey    = authenticator.VendorCmdReplaceAttestKey
	VendorCmdSetAttestCert       = authenticator.VendorCmdSetAttestCert
	VendorCmdSetSOPIN            = authenticator.VendorCmdSetSOPIN
	VendorCmdUnlockWithSOPIN     = authenticator.VendorCmdUnlockWithSOPIN
)

type (
	AuditLogger               = authenticator.AuditLogger
	Authenticator             = authenticator.Authenticator
	AuthenticatorState        = authenticator.AuthenticatorState
	AutoGrantHandler          = authenticator.AutoGrantHandler
	CTAPHIDHandler            = authenticator.CTAPHIDHandler
	Config                    = authenticator.Config
	CredentialDescriptor      = authenticator.CredentialDescriptor
	GetAssertionOptions       = authenticator.GetAssertionOptions
	InteractiveHandler        = authenticator.InteractiveHandler
	ListableStorage           = authenticator.ListableStorage
	MakeCredentialOptions     = authenticator.MakeCredentialOptions
	MemoryStorage             = authenticator.MemoryStorage
	PublicKeyCredentialParam  = authenticator.PublicKeyCredentialParam
	RPPolicy                  = authenticator.RPPolicy
	RPPolicyStore             = authenticator.RPPolicyStore
	RPPolicyUpdate            = authenticator.RPPolicyUpdate
	RelyingParty              = authenticator.RelyingParty
	StatefulCredentialStorage = authenticator.StatefulCredentialStorage
	StoredCredential          = authenticator.StoredCredential
	User                      = authenticator.User

	UserPresenceHandler     = authenticator.UserPresenceHandler
	UserPresenceRequest     = authenticator.UserPresenceRequest
	UserPresenceResult      = authenticator.UserPresenceResult
	UserVerificationRequest = authenticator.UserVerificationRequest
	UserVerificationResult  = authenticator.UserVerificationResult
)

var (
	DecodeCOSEPublicKey         = authenticator.DecodeCOSEPublicKey
	DefaultAAGUID               = authenticator.DefaultAAGUID
	DefaultConfig               = authenticator.DefaultConfig
	NewAuthenticator            = authenticator.NewAuthenticator
	NewAuthenticatorState       = authenticator.NewAuthenticatorState
	NewAutoGrantHandler         = authenticator.NewAutoGrantHandler
	NewBackendRPPolicyStore     = authenticator.NewBackendRPPolicyStore
	NewBackendStorage           = authenticator.NewBackendStorage
	NewCTAPHIDHandler           = authenticator.NewCTAPHIDHandler
	NewInteractiveHandler       = authenticator.NewInteractiveHandler
	NewInteractiveHandlerWithIO = authenticator.NewInteractiveHandlerWithIO
	NewMemoryRPPolicyStore      = authenticator.NewMemoryRPPolicyStore
	NewMemoryStorage            = authenticator.NewMemoryStorage
	ParseAuthData               = authenticator.ParseAuthData

	ErrAttestationCertNotIssuedForKey = authenticator.ErrAttestationCertNotIssuedForKey
	ErrConfigInvalidVendorCmd         = authenticator.ErrConfigInvalidVendorCmd
	ErrCredentialExists               = authenticator.ErrCredentialExists
	ErrInvalidParameter               = authenticator.ErrInvalidParameter
	ErrKeyManagerAlreadyInitialized   = authenticator.ErrKeyManagerAlreadyInitialized
	ErrKeyManagerLocked               = authenticator.ErrKeyManagerLocked
	ErrKeyManagerNoAttestKey          = authenticator.ErrKeyManagerNoAttestKey
	ErrKeyManagerNoSOPIN              = authenticator.ErrKeyManagerNoSOPIN
	ErrNilStorage                     = authenticator.ErrNilStorage
	ErrPINAlreadySet                  = authenticator.ErrPINAlreadySet
	ErrPINPolicyViolation             = authenticator.ErrPINPolicyViolation
	ErrRPPolicyInvalidRPID            = authenticator.ErrRPPolicyInvalidRPID
	ErrRPPolicyNotFound               = authenticator.ErrRPPolicyNotFound
	ErrSOPINInvalid                   = authenticator.ErrSOPINInvalid
	ErrSOPINNotSet                    = authenticator.ErrSOPINNotSet
	ErrSOPINPolicyViolation           = authenticator.ErrSOPINPolicyViolation
	ErrStateNotFound                  = authenticator.ErrStateNotFound
	ErrTerminalUnavailable            = authenticator.ErrTerminalUnavailable
	ErrTokenUninitialized             = authenticator.ErrTokenUninitialized
	ErrUserPresenceDenied             = authenticator.ErrUserPresenceDenied
	ErrUserPresenceTimeout            = authenticator.ErrUserPresenceTimeout
	ErrUserVerificationDenied         = authenticator.ErrUserVerificationDenied
)
