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
	COSEAlgES256               = authenticator.COSEAlgES256
	DefaultUserPresenceTimeout = authenticator.DefaultUserPresenceTimeout
	HIDPacketSize              = authenticator.HIDPacketSize
)

// CTAP commands, status codes and vendor authenticatorConfig subcommands.
const (
	AuthConfigCmdVendorPrototype = authenticator.AuthConfigCmdVendorPrototype
	CmdConfig                    = authenticator.CmdConfig
	StatusOK                     = authenticator.StatusOK
	VendorCmdReplaceAttestKey    = authenticator.VendorCmdReplaceAttestKey
	VendorCmdSetAttestCert       = authenticator.VendorCmdSetAttestCert
	VendorCmdUnlockWithSOPIN     = authenticator.VendorCmdUnlockWithSOPIN
)

type (
	Authenticator             = authenticator.Authenticator
	CTAPHIDHandler            = authenticator.CTAPHIDHandler
	Config                    = authenticator.Config
	CredentialDescriptor      = authenticator.CredentialDescriptor
	GetAssertionOptions       = authenticator.GetAssertionOptions
	ListableStorage           = authenticator.ListableStorage
	MakeCredentialOptions     = authenticator.MakeCredentialOptions
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
	NewAuthenticator            = authenticator.NewAuthenticator
	NewAutoGrantHandler         = authenticator.NewAutoGrantHandler
	NewBackendRPPolicyStore     = authenticator.NewBackendRPPolicyStore
	NewBackendStorage           = authenticator.NewBackendStorage
	NewCTAPHIDHandler           = authenticator.NewCTAPHIDHandler
	NewInteractiveHandler       = authenticator.NewInteractiveHandler
	NewInteractiveHandlerWithIO = authenticator.NewInteractiveHandlerWithIO
	NewMemoryRPPolicyStore      = authenticator.NewMemoryRPPolicyStore
	NewMemoryStorage            = authenticator.NewMemoryStorage
	ParseAuthData               = authenticator.ParseAuthData

	ErrCredentialExists             = authenticator.ErrCredentialExists
	ErrKeyManagerAlreadyInitialized = authenticator.ErrKeyManagerAlreadyInitialized
	ErrKeyManagerNoSOPIN            = authenticator.ErrKeyManagerNoSOPIN
	ErrPINAlreadySet                = authenticator.ErrPINAlreadySet
	ErrSOPINNotSet                  = authenticator.ErrSOPINNotSet
	ErrStateNotFound                = authenticator.ErrStateNotFound
	ErrTerminalUnavailable          = authenticator.ErrTerminalUnavailable
	ErrTokenUninitialized           = authenticator.ErrTokenUninitialized
	ErrUserPresenceDenied           = authenticator.ErrUserPresenceDenied
	ErrUserPresenceTimeout          = authenticator.ErrUserPresenceTimeout
)
