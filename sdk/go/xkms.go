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

// Package xkms provides a unified client SDK for communicating with
// the xkms daemon (xkmsd). The client supports multiple protocols
// including Unix domain socket (default), REST, gRPC, QUIC, and embedded.
package xkms

import (
	"crypto/tls"
	"errors"
	"net/url"
	"strings"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport/embedded"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport/grpc"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport/mcp"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport/quic"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport/rest"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport/unix"
)

// Protocol represents the communication protocol to use.
type Protocol string

const (
	// ProtocolUnix uses gRPC over Unix domain socket (default)
	ProtocolUnix Protocol = "unix"
	// ProtocolUnixGRPC is an alias for ProtocolUnix
	ProtocolUnixGRPC Protocol = "unix-grpc"
	// ProtocolREST uses HTTP/HTTPS REST API
	ProtocolREST Protocol = "rest"
	// ProtocolGRPC uses gRPC over TCP
	ProtocolGRPC Protocol = "grpc"
	// ProtocolQUIC uses HTTP/3 over QUIC
	ProtocolQUIC Protocol = "quic"
	// ProtocolMCP uses JSON-RPC 2.0 over TCP (Model Context Protocol)
	ProtocolMCP Protocol = "mcp"
	// ProtocolEmbedded uses direct in-process calls (no network)
	ProtocolEmbedded Protocol = "embedded"
)

// Key rotation result states: a key a scope rotation rotated, skipped on
// purpose (KeyRotationResult.Reason says why) or failed to rotate.
const (
	KeyRotationRotated = transport.KeyRotationRotated
	KeyRotationSkipped = transport.KeyRotationSkipped
	KeyRotationFailed  = transport.KeyRotationFailed
)

// DefaultUnixSocketPath is the default Unix socket path (relative to current working directory)
const DefaultUnixSocketPath = "xkms-data/xkms.sock"

var (
	// ErrUnsupportedProtocol is returned when an unsupported protocol is specified.
	ErrUnsupportedProtocol = errors.New("unsupported protocol")
	// ErrConnectionFailed is returned when a connection attempt fails.
	ErrConnectionFailed = errors.New("connection failed")
	// ErrNotConnected is returned when an operation is attempted on a disconnected client.
	ErrNotConnected = errors.New("client not connected")
	// ErrNotSupported is returned when an operation is not supported by the protocol.
	ErrNotSupported = errors.New("operation not supported by this protocol")
	// ErrNilService is returned when a nil service is provided for embedded protocol.
	ErrNilService = errors.New("xkms service is required")
	// ErrKeyNotFound is returned when a key is not found.
	ErrKeyNotFound = errors.New("key not found")
	// ErrCertificateNotFound is returned when a certificate is not found.
	ErrCertificateNotFound = errors.New("certificate not found")
	// ErrBackendNotFound is returned when a backend is not found.
	ErrBackendNotFound = errors.New("backend not found")
	// ErrInvalidRequest is returned when a request is malformed or invalid.
	ErrInvalidRequest = errors.New("invalid request")
	// ErrIncompleteTLSMaterial is returned when TLS client-certificate
	// material is only half configured (certificate without key, or key
	// without certificate). The client fails closed instead of connecting
	// without the credential the caller asked for.
	ErrIncompleteTLSMaterial = errors.New("incomplete TLS client certificate material")
)

// Client is a type alias for transport.Client.
type Client = transport.Client

// XKMSServicer is a type alias for embedded.XKMSServicer.
type XKMSServicer = embedded.XKMSServicer

// ListOption configures pagination parameters for list operations.
type ListOption = transport.ListOption

// WithPage sets the 1-based page number to retrieve.
var WithPage = transport.WithPage

// WithPageSize sets the maximum number of items to return per page.
var WithPageSize = transport.WithPageSize

// WithSortField sets the field name to sort results by.
var WithSortField = transport.WithSortField

// WithSortDesc sets the sort order to descending.
var WithSortDesc = transport.WithSortDesc

// WithSortAsc sets the sort order to ascending.
var WithSortAsc = transport.WithSortAsc

// BackendConfig holds the configuration for creating a new xkms client.
type BackendConfig struct {
	// Protocol specifies the communication protocol to use.
	Protocol Protocol
	// Address specifies the server address.
	Address string
	// TLSEnabled indicates whether TLS is enabled.
	TLSEnabled bool
	// TLSCertFile is the path to the client TLS certificate file.
	TLSCertFile string
	// TLSKeyFile is the path to the client TLS private key file.
	TLSKeyFile string
	// TLSCAFile is the path to the CA certificate file.
	TLSCAFile string
	// TLSConfig is a custom TLS configuration.
	TLSConfig *tls.Config
	// SPKIPin is the SPKI pin for certificate pinning.
	SPKIPin string
	// JWTToken is the JWT token for authentication.
	JWTToken string
	// Headers are additional HTTP headers to send with requests.
	Headers map[string]string
	// Service is the embedded service implementation (only for ProtocolEmbedded).
	Service XKMSServicer
}

// New creates a new xkms client with the given configuration.
// If cfg is nil, defaults are used (Unix gRPC protocol).
func New(cfg *BackendConfig) (Client, error) {
	if cfg == nil {
		cfg = &BackendConfig{}
	}

	protocol := cfg.Protocol
	if protocol == "" {
		protocol = ProtocolUnixGRPC
	}

	address := cfg.Address
	if address == "" {
		address = defaultAddressForProtocol(protocol)
	}

	opts, err := optsFromConfig(cfg, address)
	if err != nil {
		return nil, err
	}

	switch protocol {
	case ProtocolUnix, ProtocolUnixGRPC:
		return unix.New(opts...)

	case ProtocolREST:
		return rest.New(opts...)

	case ProtocolGRPC:
		return grpc.New(opts...)

	case ProtocolQUIC:
		return quic.New(opts...)

	case ProtocolMCP:
		return mcp.New(opts...)

	case ProtocolEmbedded:
		if cfg.Service == nil {
			return nil, ErrNilService
		}
		return embedded.New(cfg.Service, opts...)

	default:
		return nil, &UnsupportedProtocolError{Detail: string(protocol)}
	}
}

// optsFromConfig converts a BackendConfig to a slice of transport options.
// It returns an error when TLS is requested but the supplied material cannot
// produce a usable TLS client; the caller must not fall back to plaintext.
func optsFromConfig(cfg *BackendConfig, address string) ([]transport.Option, error) {
	var opts []transport.Option

	if address != "" {
		opts = append(opts, transport.WithAddress(address))
	}
	tlsOpt, err := tlsOptionFromConfig(cfg)
	if err != nil {
		return nil, err
	}
	if tlsOpt != nil {
		opts = append(opts, tlsOpt)
	}
	if cfg.SPKIPin != "" {
		opts = append(opts, transport.WithSPKIPin(cfg.SPKIPin))
	}
	if cfg.JWTToken != "" {
		opts = append(opts, transport.WithJWTToken(cfg.JWTToken))
	}
	if len(cfg.Headers) > 0 {
		opts = append(opts, transport.WithHeaders(cfg.Headers))
	}

	return opts, nil
}

// tlsOptionFromConfig selects the single transport TLS option implied by cfg.
// Exactly one option is emitted, in descending order of specificity:
//
//  1. TLSConfig — a caller-built *tls.Config (hardware-backed mTLS, pinning).
//  2. TLSCertFile + TLSKeyFile — mTLS, optionally with TLSCAFile.
//  3. TLSCAFile — server verification against a private CA bundle.
//  4. TLSEnabled — server verification against the system root pool.
//
// Each of the first three enables TLS on its own, so the more specific
// options always win over the bare TLSEnabled flag. A nil option means the
// caller asked for plaintext.
func tlsOptionFromConfig(cfg *BackendConfig) (transport.Option, error) {
	switch {
	case cfg.TLSConfig != nil:
		return transport.WithTLSConfig(cfg.TLSConfig), nil
	case cfg.TLSCertFile != "" && cfg.TLSKeyFile != "":
		return transport.WithMTLS(cfg.TLSCertFile, cfg.TLSKeyFile, cfg.TLSCAFile), nil
	case cfg.TLSCertFile != "":
		return nil, &IncompleteTLSMaterialError{Missing: "TLSKeyFile"}
	case cfg.TLSKeyFile != "":
		return nil, &IncompleteTLSMaterialError{Missing: "TLSCertFile"}
	case cfg.TLSCAFile != "":
		return transport.WithTLS(cfg.TLSCAFile), nil
	case cfg.TLSEnabled:
		return transport.WithTLSEnabled(true), nil
	default:
		return nil, nil
	}
}

// NewEmbedded creates a new embedded xkms client using the given service implementation.
func NewEmbedded(service XKMSServicer) (Client, error) {
	if service == nil {
		return nil, ErrNilService
	}
	return embedded.New(service)
}

// NewFromURL creates a new xkms client from a URL string.
// Supported schemes: unix, http, https, grpc, grpcs, quic, mcp, mcps.
// If rawURL is empty, defaults to Unix gRPC protocol.
func NewFromURL(rawURL string) (Client, error) {
	if rawURL == "" {
		return New(nil)
	}

	cfg, err := configFromURL(rawURL)
	if err != nil {
		return nil, err
	}

	return New(cfg)
}

// configFromURL maps a client URL onto a BackendConfig. The TLS-implying
// schemes (https, grpcs, mcps, quic) set TLSEnabled so the transport dials
// with TLS even when the caller supplies no CA bundle; the plaintext schemes
// (http, grpc, mcp, unix) leave it unset.
func configFromURL(rawURL string) (*BackendConfig, error) {
	// Handle host:port without scheme
	if !strings.Contains(rawURL, "://") {
		rawURL = "http://" + rawURL
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, &InvalidURLError{Err: err}
	}

	cfg := &BackendConfig{
		Address: u.Host,
	}

	switch strings.ToLower(u.Scheme) {
	case "unix":
		cfg.Protocol = ProtocolUnix
		if u.Path != "" {
			cfg.Address = u.Path
		}
	case "http":
		cfg.Protocol = ProtocolREST
		cfg.Address = rawURL
	case "https":
		cfg.Protocol = ProtocolREST
		cfg.TLSEnabled = true
		cfg.Address = rawURL
	case "grpc":
		cfg.Protocol = ProtocolGRPC
	case "grpcs":
		cfg.Protocol = ProtocolGRPC
		cfg.TLSEnabled = true
	case "quic":
		cfg.Protocol = ProtocolQUIC
		// QUIC mandates TLS 1.3; record it so the config never claims the
		// connection is plaintext.
		cfg.TLSEnabled = true
	case "mcp":
		cfg.Protocol = ProtocolMCP
	case "mcps":
		cfg.Protocol = ProtocolMCP
		cfg.TLSEnabled = true
	default:
		return nil, &UnsupportedProtocolError{Detail: "scheme " + u.Scheme}
	}

	return cfg, nil
}

// Type aliases for transport types to provide a clean public API.
type (
	// Core types
	HealthResponse         = transport.HealthResponse
	ListBackendsResponse   = transport.ListBackendsResponse
	BackendInfo            = transport.BackendInfo
	GenerateKeyRequest     = transport.GenerateKeyRequest
	GenerateKeyResponse    = transport.GenerateKeyResponse
	ListKeysResponse       = transport.ListKeysResponse
	KeyInfo                = transport.KeyInfo
	GetKeyResponse         = transport.GetKeyResponse
	DeleteKeyResponse      = transport.DeleteKeyResponse
	ImportKeyRequest       = transport.ImportKeyRequest
	ImportKeyResponse      = transport.ImportKeyResponse
	ExportKeyRequest       = transport.ExportKeyRequest
	ExportKeyResponse      = transport.ExportKeyResponse
	RotateKeyRequest       = transport.RotateKeyRequest
	RotateKeyResponse      = transport.RotateKeyResponse
	SignRequest            = transport.SignRequest
	SignResponse           = transport.SignResponse
	VerifyRequest          = transport.VerifyRequest
	VerifyResponse         = transport.VerifyResponse
	EncryptRequest         = transport.EncryptRequest
	EncryptResponse        = transport.EncryptResponse
	DecryptRequest         = transport.DecryptRequest
	DecryptResponse        = transport.DecryptResponse
	EncryptAsymRequest     = transport.EncryptAsymRequest
	EncryptAsymResponse    = transport.EncryptAsymResponse
	GetCertificateResponse = transport.GetCertificateResponse
	SaveCertificateRequest = transport.SaveCertificateRequest
	SealRequest            = transport.SealRequest
	SealResponse           = transport.SealResponse
	UnsealRequest          = transport.UnsealRequest
	UnsealResponse         = transport.UnsealResponse
	CanSealResponse        = transport.CanSealResponse

	GetImportParametersRequest   = transport.GetImportParametersRequest
	GetImportParametersResponse  = transport.GetImportParametersResponse
	WrapKeyRequest               = transport.WrapKeyRequest
	WrapKeyResponse              = transport.WrapKeyResponse
	UnwrapKeyRequest             = transport.UnwrapKeyRequest
	UnwrapKeyResponse            = transport.UnwrapKeyResponse
	CopyKeyRequest               = transport.CopyKeyRequest
	CopyKeyResponse              = transport.CopyKeyResponse
	CertificateInfo              = transport.CertificateInfo
	ListCertificatesResponse     = transport.ListCertificatesResponse
	SaveCertificateChainRequest  = transport.SaveCertificateChainRequest
	GetCertificateChainResponse  = transport.GetCertificateChainResponse
	GetTLSCertificateResponse    = transport.GetTLSCertificateResponse
	BeginRegistrationRequest     = transport.BeginRegistrationRequest
	BeginRegistrationResponse    = transport.BeginRegistrationResponse
	FinishRegistrationRequest    = transport.FinishRegistrationRequest
	FinishRegistrationResponse   = transport.FinishRegistrationResponse
	BeginAuthenticationRequest   = transport.BeginAuthenticationRequest
	BeginAuthenticationResponse  = transport.BeginAuthenticationResponse
	FinishAuthenticationRequest  = transport.FinishAuthenticationRequest
	FinishAuthenticationResponse = transport.FinishAuthenticationResponse
	DeriveKeyRequest             = transport.DeriveKeyRequest
	DeriveKeyResponse            = transport.DeriveKeyResponse
	DeriveKeyECDHRequest         = transport.DeriveKeyECDHRequest
	DeriveKeyECDHResponse        = transport.DeriveKeyECDHResponse
	WrapKeyByIDRequest           = transport.WrapKeyByIDRequest
	WrapKeyByIDResponse          = transport.WrapKeyByIDResponse
	UnwrapKeyByIDRequest         = transport.UnwrapKeyByIDRequest
	UnwrapKeyByIDResponse        = transport.UnwrapKeyByIDResponse
	ExportKeyMaterialRequest     = transport.ExportKeyMaterialRequest
	ExportKeyMaterialResponse    = transport.ExportKeyMaterialResponse
	AttestKeyRequest             = transport.AttestKeyRequest
	AttestKeyResponse            = transport.AttestKeyResponse

	// CA Operations
	GetCABundleRequest        = transport.GetCABundleRequest
	GetCABundleResponse       = transport.GetCABundleResponse
	GetCACertificateRequest   = transport.GetCACertificateRequest
	GetCACertificateResponse  = transport.GetCACertificateResponse
	SignCSRRequest            = transport.SignCSRRequest
	SignCSRResponse           = transport.SignCSRResponse
	IssueCertificateRequest   = transport.IssueCertificateRequest
	IssueCertificateResponse  = transport.IssueCertificateResponse
	RevokeCertificateRequest  = transport.RevokeCertificateRequest
	RevokeCertificateResponse = transport.RevokeCertificateResponse
	GenerateCRLRequest        = transport.GenerateCRLRequest
	GenerateCRLResponse       = transport.GenerateCRLResponse
	IsRevokedRequest          = transport.IsRevokedRequest
	IsRevokedResponse         = transport.IsRevokedResponse

	// TCG CA Operations
	IssueEKCertificateRequest  = transport.IssueEKCertificateRequest
	IssueEKCertificateResponse = transport.IssueEKCertificateResponse
	IssueAKCertificateRequest  = transport.IssueAKCertificateRequest
	IssueAKCertificateResponse = transport.IssueAKCertificateResponse
	SignTCGCSRRequest          = transport.SignTCGCSRRequest
	SignTCGCSRResponse         = transport.SignTCGCSRResponse
	EnrollDeviceRequest        = transport.EnrollDeviceRequest
	EnrollDeviceResponse       = transport.EnrollDeviceResponse

	// PIV Operations
	ListPIVSlotsRequest         = transport.ListPIVSlotsRequest
	ListPIVSlotsResponse        = transport.ListPIVSlotsResponse
	PIVSlotStatus               = transport.PIVSlotStatus
	GetPIVCertificateRequest    = transport.GetPIVCertificateRequest
	GetPIVCertificateResponse   = transport.GetPIVCertificateResponse
	StorePIVCertificateRequest  = transport.StorePIVCertificateRequest
	DeletePIVCertificateRequest = transport.DeletePIVCertificateRequest
	GeneratePIVKeyRequest       = transport.GeneratePIVKeyRequest
	GeneratePIVKeyResponse      = transport.GeneratePIVKeyResponse
	GeneratePIVCSRRequest       = transport.GeneratePIVCSRRequest
	GeneratePIVCSRResponse      = transport.GeneratePIVCSRResponse

	// Barrier Operations
	BarrierInitializeRequest           = transport.BarrierInitializeRequest
	BarrierUnsealRequest               = transport.BarrierUnsealRequest
	BarrierStatusResponse              = transport.BarrierStatusResponse
	BarrierInitializeShamirRequest     = transport.BarrierInitializeShamirRequest
	BarrierInitializeShamirResponse    = transport.BarrierInitializeShamirResponse
	BarrierUnsealShareRequest          = transport.BarrierUnsealShareRequest
	BarrierUnsealShareResponse         = transport.BarrierUnsealShareResponse
	BarrierUnsealSharesRequest         = transport.BarrierUnsealSharesRequest
	BarrierRekeyRequest                = transport.BarrierRekeyRequest
	BarrierRekeyResponse               = transport.BarrierRekeyResponse
	BarrierGenerateRecoveryKeysRequest = transport.BarrierGenerateRecoveryKeysRequest
	BarrierRecoveryKeysResponse        = transport.BarrierRecoveryKeysResponse
	BarrierRecoverWithKeysRequest      = transport.BarrierRecoverWithKeysRequest
	BarrierHasRecoveryKeysResponse     = transport.BarrierHasRecoveryKeysResponse
	BarrierGenerateRootTokenRequest    = transport.BarrierGenerateRootTokenRequest
	BarrierRootTokenResponse           = transport.BarrierRootTokenResponse
	BarrierEnableEncryptionRequest     = transport.BarrierEnableEncryptionRequest
	BarrierEnableEncryptionResponse    = transport.BarrierEnableEncryptionResponse

	// Trust Bootstrap Listener
	BootstrapListenerKeysResponse = transport.BootstrapListenerKeysResponse

	// PIN Operations
	SetSOPINRequest       = transport.SetSOPINRequest
	SetUserPINRequest     = transport.SetUserPINRequest
	ChangeSOPINRequest    = transport.ChangeSOPINRequest
	ChangeUserPINRequest  = transport.ChangeUserPINRequest
	VerifySOPINRequest    = transport.VerifySOPINRequest
	VerifyUserPINRequest  = transport.VerifyUserPINRequest
	LockoutStatusResponse = transport.LockoutStatusResponse
	ResetLockoutRequest   = transport.ResetLockoutRequest

	// User Operations
	UserInfo                    = transport.UserInfo
	CredentialInfo              = transport.CredentialInfo
	CreateUserRequest           = transport.CreateUserRequest
	ListUsersResponse           = transport.ListUsersResponse
	GetUserResponse             = transport.GetUserResponse
	ListUserCredentialsResponse = transport.ListUserCredentialsResponse
	// InviteInfo is the one-time account-activation invitation CreateUser
	// mints for an account with an email login key (go-xkms#1294 part B).
	InviteInfo = transport.InviteInfo

	// Invite redemption Operations. Public, unauthenticated capabilities
	// available on every transport (go-xkms#1294 part B).
	GetInviteRequest                 = transport.GetInviteRequest
	GetInviteResponse                = transport.GetInviteResponse
	BeginInviteRegistrationRequest   = transport.BeginInviteRegistrationRequest
	BeginInviteRegistrationResponse  = transport.BeginInviteRegistrationResponse
	FinishInviteRegistrationRequest  = transport.FinishInviteRegistrationRequest
	FinishInviteRegistrationResponse = transport.FinishInviteRegistrationResponse
	ActivateInvitePIVRequest         = transport.ActivateInvitePIVRequest
	ActivateInvitePIVResponse        = transport.ActivateInvitePIVResponse

	// Password Store Operations
	PasswordAddRequest                = transport.PasswordAddRequest
	PasswordAddResponse               = transport.PasswordAddResponse
	PasswordGetRequest                = transport.PasswordGetRequest
	PasswordGetResponse               = transport.PasswordGetResponse
	PasswordListRequest               = transport.PasswordListRequest
	PasswordListResponse              = transport.PasswordListResponse
	PasswordUpdateRequest             = transport.PasswordUpdateRequest
	PasswordDeleteRequest             = transport.PasswordDeleteRequest
	PasswordStoreUnlockRequest        = transport.PasswordStoreUnlockRequest
	PasswordStoreStatusResponse       = transport.PasswordStoreStatusResponse
	PasswordStoreSetAccessModeRequest = transport.PasswordStoreSetAccessModeRequest
	PasswordGenerateRequest           = transport.PasswordGenerateRequest
	PasswordGenerateResponse          = transport.PasswordGenerateResponse

	// Platform Store Operations
	SealStorePutRequest     = transport.SealStorePutRequest
	SealStoreGetRequest     = transport.SealStoreGetRequest
	SealStoreGetResponse    = transport.SealStoreGetResponse
	SealStoreDeleteRequest  = transport.SealStoreDeleteRequest
	SealStoreListResponse   = transport.SealStoreListResponse
	SealStoreResealRequest  = transport.SealStoreResealRequest
	SealStoreStatusResponse = transport.SealStoreStatusResponse

	// Escrow Operations
	EscrowRequest   = transport.EscrowRequest
	EscrowReceipt   = transport.EscrowReceipt
	RecoverRequest  = transport.RecoverRequest
	RecoverResponse = transport.RecoverResponse
	EscrowRecord    = transport.EscrowRecord

	// Key Version Operations
	KeyVersionInfo          = transport.KeyVersionInfo
	ListKeyVersionsRequest  = transport.ListKeyVersionsRequest
	ListKeyVersionsResponse = transport.ListKeyVersionsResponse
	KeyVersionRequest       = transport.KeyVersionRequest
	KeyVersionStateResponse = transport.KeyVersionStateResponse
	AllKeyVersionsRequest   = transport.AllKeyVersionsRequest
	AllKeyVersionsResponse  = transport.AllKeyVersionsResponse
	RotateScopeKeysRequest  = transport.RotateScopeKeysRequest
	RotateScopeKeysResponse = transport.RotateScopeKeysResponse
	KeyRotationResult       = transport.KeyRotationResult

	// TPM Policy Operations
	TPMPolicy                   = transport.TPMPolicy
	TPMPolicyBranch             = transport.TPMPolicyBranch
	TPMPolicyCondition          = transport.TPMPolicyCondition
	TPMPolicyCreateRequest      = transport.TPMPolicyCreateRequest
	TPMPolicyDescriptionRequest = transport.TPMPolicyDescriptionRequest
	TPMPolicyBranchVerification = transport.TPMPolicyBranchVerification
	TPMPolicyBranchSpecError    = transport.TPMPolicyBranchSpecError
	TPMPolicyRequest            = transport.TPMPolicyRequest
	TPMPolicyListRequest        = transport.TPMPolicyListRequest
	TPMPolicyListResponse       = transport.TPMPolicyListResponse
	TPMPolicyDeleteRequest      = transport.TPMPolicyDeleteRequest
	TPMPolicyVerifyResponse     = transport.TPMPolicyVerifyResponse
	TPMPolicyObjectsResponse    = transport.TPMPolicyObjectsResponse
	TPMPolicyAutoUnsealRequest  = transport.TPMPolicyAutoUnsealRequest
	TPMObjectPolicyRequest      = transport.TPMObjectPolicyRequest
	TPMObjectPolicyResponse     = transport.TPMObjectPolicyResponse
	TPMAuthorityRotateRequest   = transport.TPMAuthorityRotateRequest
	TPMAuthorityRotateResponse  = transport.TPMAuthorityRotateResponse
	TenantTPMModeResponse       = transport.TenantTPMModeResponse
	SetTenantTPMModeRequest     = transport.SetTenantTPMModeRequest
	TenantVTPMStatusResponse    = transport.TenantVTPMStatusResponse

	// Audit Operations
	AuditEvent  = transport.AuditEvent
	AuditFilter = transport.AuditFilter
	AuditPage   = transport.AuditPage

	// Backup Operations
	CompressionType     = transport.CompressionType
	EncryptionType      = transport.EncryptionType
	BackupStatus        = transport.BackupStatus
	BackupRequest       = transport.BackupRequest
	BackupInfo          = transport.BackupInfo
	RestoreRequest      = transport.RestoreRequest
	RestoreResult       = transport.RestoreResult
	ShardError          = transport.ShardError
	VerifyResult        = transport.VerifyResult
	ListBackupsResponse = transport.ListBackupsResponse

	// Custodian Group Operations
	CustodianGroupInfo           = transport.CustodianGroupInfo
	CustodianMemberInfo          = transport.CustodianMemberInfo
	CreateCustodianGroupRequest  = transport.CreateCustodianGroupRequest
	CreateCustodianGroupResponse = transport.CreateCustodianGroupResponse
	GetCustodianGroupResponse    = transport.GetCustodianGroupResponse
	ListCustodianGroupsResponse  = transport.ListCustodianGroupsResponse
	AddCustodianMemberRequest    = transport.AddCustodianMemberRequest
	AddCustodianMemberResponse   = transport.AddCustodianMemberResponse
	RemoveCustodianMemberRequest = transport.RemoveCustodianMemberRequest
	DistributeSharesRequest      = transport.DistributeSharesRequest
	DistributeSharesResponse     = transport.DistributeSharesResponse

	// Share Operations
	SubmitShareRequest    = transport.SubmitShareRequest
	SubmitShareResponse   = transport.SubmitShareResponse
	ShareInfo             = transport.ShareInfo
	ListSharesResponse    = transport.ListSharesResponse
	ShareCollectionStatus = transport.ShareCollectionStatus

	// Tenant Operations
	TenantInfo                       = transport.TenantInfo
	CreateTenantRequest              = transport.CreateTenantRequest
	CreateTenantResponse             = transport.CreateTenantResponse
	GetTenantResponse                = transport.GetTenantResponse
	ListTenantsResponse              = transport.ListTenantsResponse
	TenantBarrierInitRequest         = transport.TenantBarrierInitRequest
	TenantBarrierUnsealRequest       = transport.TenantBarrierUnsealRequest
	TenantBarrierStatusResponse      = transport.TenantBarrierStatusResponse
	UpdateTenantEntitlementsRequest  = transport.UpdateTenantEntitlementsRequest
	UpdateTenantEntitlementsResponse = transport.UpdateTenantEntitlementsResponse
	UpdateTenantQuotasRequest        = transport.UpdateTenantQuotasRequest
	UpdateTenantQuotasResponse       = transport.UpdateTenantQuotasResponse

	// Init Ceremony Operations
	InitStatusResponse         = transport.InitStatusResponse
	ClaimCertBeginRequest      = transport.ClaimCertBeginRequest
	ClaimCertBeginResponse     = transport.ClaimCertBeginResponse
	ClaimCertCompleteRequest   = transport.ClaimCertCompleteRequest
	ClaimCertCompleteResponse  = transport.ClaimCertCompleteResponse
	ClaimShareBeginRequest     = transport.ClaimShareBeginRequest
	ClaimShareBeginResponse    = transport.ClaimShareBeginResponse
	ClaimShareCompleteRequest  = transport.ClaimShareCompleteRequest
	ClaimShareCompleteResponse = transport.ClaimShareCompleteResponse
	SignCSRInitRequest         = transport.SignCSRInitRequest
	SignCSRInitResponse        = transport.SignCSRInitResponse
	CredentialSubmitRequest    = transport.CredentialSubmitRequest
	CredentialSubmitResponse   = transport.CredentialSubmitResponse
	CredentialStrategyResponse = transport.CredentialStrategyResponse
)
