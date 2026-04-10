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

package services

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/md5"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/go-tpm/tpm2"
	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/jeremyhahn/go-xkms/pkg/certstore"
	tpm2pkg "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/truststore"
)

// TPM service errors.
var (
	ErrTPMNotAvailable     = errors.New("tpm_service: TPM not available")
	ErrTPMNotOpen          = errors.New("tpm_service: TPM not open")
	ErrTPMInitFailed       = errors.New("tpm_service: TPM device found but initialization failed")
	ErrTPMInvalidBank      = errors.New("tpm_service: invalid PCR bank")
	ErrTPMInvalidNonce     = errors.New("tpm_service: invalid nonce")
	ErrTPMInvalidPCRs      = errors.New("tpm_service: invalid PCR selection")
	ErrTPMInvalidLength    = errors.New("tpm_service: invalid byte length")
	ErrTPMInvalidCert      = errors.New("tpm_service: invalid certificate PEM")
	ErrTPMCertNotFound     = errors.New("tpm_service: certificate not found")
	ErrTPMEventLogNotFound = errors.New("tpm_service: event log not found")
	ErrTPMProvisionFailed  = errors.New("tpm_service: provisioning failed")
	ErrTPMNonceGenFailed   = errors.New("tpm_service: failed to generate nonce")
	ErrTPMBankNotSupported = errors.New("tpm_service: PCR bank not supported by this TPM")
)

// isTPMAuthError returns true if the error indicates a TPM authorization failure.
func isTPMAuthError(err error) bool {
	if err == nil {
		return false
	}
	var rc tpm2.TPMRC
	if errors.As(err, &rc) {
		rcVal := uint32(rc)
		// Format-1 errors: bit 7 set, bits 0-5 encode the error code.
		// 0x0E = TPM_RC_AUTH_FAIL (authorization HMAC check failed).
		if rcVal&0x80 != 0 && rcVal&0x3F == 0x0E {
			return true
		}
		// Format-0: TPM_RC_BAD_AUTH = 0x0022.
		if rcVal == 0x0022 {
			return true
		}
	}
	// Fallback: string matching for wrapped errors.
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "auth_fail") || strings.Contains(msg, "bad_auth")
}

// validPCRBanks maps user-facing bank names to internal validation.
var validPCRBanks = map[string]struct{}{
	"sha1":   {},
	"sha256": {},
	"sha384": {},
	"sha512": {},
}

// wellKnownHandles maps standard TPM persistent handle addresses to
// human-readable descriptions per TCG TPM 2.0 Provisioning Guidance.
var wellKnownHandles = map[string]string{
	"0x81000001": "TCG Shared SRK (RSA)",
	"0x81000002": "TCG Shared SRK (ECC)",
	"0x81010001": "Endorsement Key (EK-RSA)",
	"0x81010002": "Endorsement Key (EK-ECC)",
	"0x81020000": "Initial Device Identifier (IDevID)",
	"0x81020001": "Initial Attestation Key (IAK)",
	"0x81800001": "Platform EK",
}

// TPM provisioning status levels (ordered by completeness).
const (
	TPMStatusLevelNone           = "none"            // No EK found
	TPMStatusLevelManufacturer   = "manufacturer"    // EK exists but no SRK
	TPMStatusLevelOwner          = "owner"           // SRK exists but no IDevID key+cert
	TPMStatusLevelDeviceIdentity = "device_identity" // IDevID key AND certificate present

	// Deprecated: kept for backward compatibility in JSON responses.
	TPMStatusLevelDefault     = "default"
	TPMStatusLevelProvisioned = "provisioned"
	TPMStatusLevelVerified    = "verified"
)

// Provision modes.
const (
	ProvisionModeInstall   = "install"
	ProvisionModeProvision = "provision"
)

// handleDescriptionsFile is the JSON file name for persisted handle descriptions.
const handleDescriptionsFile = "handle_descriptions.json"

// pcrPoliciesFile is the JSON file name for persisted PCR policies.
const pcrPoliciesFile = "pcr_policies.json"

// policyAssignmentsFile is the JSON file name for persisted policy-to-key assignments.
const policyAssignmentsFile = "policy_assignments.json"

// compositePoliciesFile is the JSON file name for persisted composite policies.
const compositePoliciesFile = "composite_policies.json"

// policyPasswordFolder is the folder path used when saving policy passwords
// to the static password store.
const policyPasswordFolder = "TPM Policies"

// defaultTPMDevice is the standard Linux kernel resource manager device path.
const defaultTPMDevice = "/dev/tpmrm0"

// bankNameMap normalizes user-facing bank names to the algorithm strings
// used by tpm2pkg.ReadPCRs results.
var bankNameMap = map[string]string{
	"sha1":   "SHA1",
	"sha256": "SHA256",
	"sha384": "SHA384",
	"sha512": "SHA512",
}

// TPMStatus describes the availability and state of the TPM.
type TPMStatus struct {
	Available    bool   `json:"available"`
	DeviceExists bool   `json:"device_exists"`
	Provisioned  bool   `json:"provisioned"`
	StatusLevel  string `json:"status_level"`
	Manufacturer string `json:"manufacturer"`
	FirmwareVer  string `json:"firmware_version"`
	DevicePath   string `json:"device_path"`
	InitError    string `json:"init_error,omitempty"`
}

// TPMInfo holds extended information about the TPM hardware.
type TPMInfo struct {
	Manufacturer       string                `json:"manufacturer"`
	VendorID           string                `json:"vendor_id"`
	ManufacturerID     string                `json:"manufacturer_id,omitempty"`
	FirmwareVersion    string                `json:"firmware_version"`
	Family             string                `json:"family"`
	Level              int                   `json:"level"`
	Revision           string                `json:"revision"`
	Version            string                `json:"version,omitempty"`
	MaxRSAKeySize      int                   `json:"max_rsa_key_size"`
	MaxECCKeySize      int                   `json:"max_ecc_key_size"`
	PCRBanks           []string              `json:"pcr_banks"`
	Algorithms         []string              `json:"algorithms"`
	FIPSMode           bool                  `json:"fips_mode"`
	Capabilities       []string              `json:"capabilities"`
	MaxNVBufferSize    int                   `json:"max_nv_buffer_size"`
	LockoutCounter     int                   `json:"lockout_counter"`
	MaxAuthFail        int                   `json:"max_auth_fail"`
	Model              string                `json:"model"`
	ActiveSessionsMax  int                   `json:"active_sessions_max"`
	AuthSessionsLoaded int                   `json:"auth_sessions_loaded"`
	AuthSessionsActive int                   `json:"auth_sessions_active"`
	PersistentLoaded   int                   `json:"persistent_loaded"`
	PersistentAvail    int                   `json:"persistent_avail"`
	TransientAvail     int                   `json:"transient_avail"`
	NVIndexesDefined   int                   `json:"nv_indexes_defined"`
	NVIndexesMax       int                   `json:"nv_indexes_max"`
	Commands           []tpm2pkg.CommandInfo `json:"commands"`
	ECCCurves          []string              `json:"ecc_curves"`
	InputBufferMax     int                   `json:"input_buffer_max"`
	MaxDigestSize      int                   `json:"max_digest_size"`
	MaxObjectContext   int                   `json:"max_object_context"`
	LockoutInterval    int                   `json:"lockout_interval"`
	LockoutRecovery    int                   `json:"lockout_recovery"`
	FixedProperties    []tpm2pkg.TPMProperty `json:"fixed_properties,omitempty"`
	VariableProperties []tpm2pkg.TPMProperty `json:"variable_properties,omitempty"`
}

// TPMKey describes a key managed by the TPM.
type TPMKey struct {
	ID         string    `json:"id"`
	Algorithm  string    `json:"algorithm"`
	KeySize    int       `json:"key_size"`
	Persistent bool      `json:"persistent"`
	Purpose    string    `json:"purpose"`
	CreatedAt  time.Time `json:"created_at"`
}

// PCRValue holds the digest for a single PCR register.
type PCRValue struct {
	Index  int    `json:"index"`
	Bank   string `json:"bank"`
	Digest string `json:"digest"`
}

// EKInfo describes the RSA Endorsement Key.
type EKInfo struct {
	Present     bool   `json:"present"`
	Algorithm   string `json:"algorithm"`
	KeySize     int    `json:"key_size"`
	Certificate string `json:"certificate,omitempty"`
	Verified    bool   `json:"verified"`
}

// EKECCInfo describes the ECC Endorsement Key.
type EKECCInfo struct {
	Present     bool   `json:"present"`
	Algorithm   string `json:"algorithm"`
	KeySize     int    `json:"key_size"`
	Certificate string `json:"certificate,omitempty"`
	Verified    bool   `json:"verified"`
}

// IAKInfo describes the Initial Attestation Key.
type IAKInfo struct {
	Present     bool   `json:"present"`
	Algorithm   string `json:"algorithm"`
	KeySize     int    `json:"key_size"`
	Handle      string `json:"handle"`
	Certificate string `json:"certificate,omitempty"`
}

// IDevIDInfo describes the Initial Device Identifier.
type IDevIDInfo struct {
	Present     bool   `json:"present"`
	Algorithm   string `json:"algorithm"`
	KeySize     int    `json:"key_size"`
	Certificate string `json:"certificate,omitempty"`
	Verified    bool   `json:"verified"`
}

// SharedSRKInfo describes the TCG-standard Shared Storage Root Key.
// The shared SRK has no authorization policy by definition.
type SharedSRKInfo struct {
	Present   bool   `json:"present"`
	Algorithm string `json:"algorithm"`
	Handle    string `json:"handle"`
}

// PlatformSRKInfo describes the Platform Key Store SRK which may have
// an authorization policy (e.g. TPM platform policy) applied to it.
type PlatformSRKInfo struct {
	Present       bool   `json:"present"`
	Algorithm     string `json:"algorithm"`
	Handle        string `json:"handle"`
	PolicyEnabled bool   `json:"policy_enabled"`
	PolicyName    string `json:"policy_name,omitempty"`
	Initialized   bool   `json:"initialized"`
}

// ProvisionOptions holds the parameters for TPM provisioning.
type ProvisionOptions struct {
	Mode            string `json:"mode"` // "install" or "provision"
	OwnerAuth       string `json:"owner_auth"`
	EndorsementAuth string `json:"endorsement_auth"`
	LockoutAuth     string `json:"lockout_auth"`
	CreateEK        bool   `json:"create_ek"`
	CreateIAK       bool   `json:"create_iak"`
	CreateIDevID    bool   `json:"create_idevid"`
}

// Quote holds the result of a TPM2 quote operation.
type Quote struct {
	QuoteData string    `json:"quote_data"`
	Signature string    `json:"signature"`
	PCRDigest string    `json:"pcr_digest"`
	Nonce     string    `json:"nonce"`
	CreatedAt time.Time `json:"created_at"`
}

// EventLogEntry represents a single parsed TPM event log entry.
type EventLogEntry struct {
	PCRIndex  int    `json:"pcr_index"`
	EventType string `json:"event_type"`
	DigestHex string `json:"digest_hex"`
	EventData string `json:"event_data"`
}

// CertifyKeyResult holds the result of a TPM2_Certify operation.
type CertifyKeyResult struct {
	Attested  string `json:"attested"`
	Signature string `json:"signature"`
	Nonce     string `json:"nonce"`
}

// HandleInfo describes a TPM handle with optional user description.
type HandleInfo struct {
	Handle      string `json:"handle"`
	Algorithm   string `json:"algorithm,omitempty"`
	Type        string `json:"type"` // "persistent", "transient"
	Description string `json:"description,omitempty"`
}

// LockoutInfo holds dictionary attack lockout status.
type LockoutInfo struct {
	Counter  int  `json:"counter"`
	MaxFail  int  `json:"max_fail"`
	Interval int  `json:"interval"`
	Recovery int  `json:"recovery"`
	IsLocked bool `json:"is_locked"`
}

// NVIndexEntry describes an NV index for the frontend.
type NVIndexEntry struct {
	Handle    string `json:"handle"`
	Type      string `json:"type"` // "ordinary", "counter", "extend"
	Size      int    `json:"size"`
	AuthRead  bool   `json:"auth_read"`
	AuthWrite bool   `json:"auth_write"`
}

// NVSummary provides an overview of NV storage usage.
type NVSummary struct {
	IndexesDefined int            `json:"indexes_defined"`
	IndexesMax     int            `json:"indexes_max"`
	Indexes        []NVIndexEntry `json:"indexes"`
}

// VerificationStatus holds manufacturer CA verification results.
type VerificationStatus struct {
	Verified     bool   `json:"verified"`
	Issuer       string `json:"issuer,omitempty"`
	ErrorMessage string `json:"error_message,omitempty"`
}

// KeyViewData holds detailed key information for the frontend dialog.
type KeyViewData struct {
	Name         string `json:"name"`
	Algorithm    string `json:"algorithm"`
	KeySize      int    `json:"key_size"`
	Handle       string `json:"handle,omitempty"`
	PublicKeyPEM string `json:"public_key_pem,omitempty"`
	Certificate  string `json:"certificate,omitempty"`
}

// ExtensionInfo describes a single certificate extension.
type ExtensionInfo struct {
	OID      string `json:"oid"`
	Name     string `json:"name"`
	Critical bool   `json:"critical"`
	Value    string `json:"value"`
}

// CertificateDetails holds parsed X.509 certificate data for frontend display.
type CertificateDetails struct {
	// Identity
	Version      int    `json:"version"`
	SerialNumber string `json:"serial_number"`

	// Subject
	SubjectCN           string `json:"subject_cn"`
	SubjectOrg          string `json:"subject_org"`
	SubjectOrgUnit      string `json:"subject_org_unit"`
	SubjectCountry      string `json:"subject_country"`
	SubjectProvince     string `json:"subject_province"`
	SubjectLocality     string `json:"subject_locality"`
	SubjectSerialNumber string `json:"subject_serial_number"`

	// Issuer
	IssuerCN      string `json:"issuer_cn"`
	IssuerOrg     string `json:"issuer_org"`
	IssuerOrgUnit string `json:"issuer_org_unit"`
	IssuerCountry string `json:"issuer_country"`

	// Validity
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`

	// Signature
	SignatureAlgorithm string `json:"signature_algorithm"`
	SignatureHex       string `json:"signature_hex"`

	// Fingerprints (colon-separated uppercase hex)
	FingerprintSHA256 string `json:"fingerprint_sha256"`
	FingerprintSHA1   string `json:"fingerprint_sha1"`
	FingerprintMD5    string `json:"fingerprint_md5"`

	// Public Key
	PublicKeyAlgorithm string `json:"public_key_algorithm"`
	PublicKeySize      int    `json:"public_key_size"`
	PublicKeyHex       string `json:"public_key_hex"`
	SubjectKeyID       string `json:"subject_key_id"`

	// Basic constraints
	IsCA           bool `json:"is_ca"`
	MaxPathLen     int  `json:"max_path_len"`
	MaxPathLenZero bool `json:"max_path_len_zero"`

	// Key usage
	KeyUsage    string   `json:"key_usage"`
	ExtKeyUsage []string `json:"ext_key_usage"`

	// SAN
	SubjectAltNames string `json:"subject_alt_names"`

	// Extensions
	Extensions []ExtensionInfo `json:"extensions"`
}

// PCRSelection describes a single PCR index and bank for policy definitions.
type PCRSelection struct {
	Index int    `json:"index"`
	Bank  string `json:"bank"`
}

// PCRPolicy defines a named set of PCR selections for quoting and sealing.
type PCRPolicy struct {
	Name             string            `json:"name"`
	Description      string            `json:"description"`
	PCRSelections    []PCRSelection    `json:"pcr_selections"`
	CreatedAt        string            `json:"created_at"`
	UpdatedAt        string            `json:"updated_at,omitempty"`
	PCRDigests       map[string]string `json:"pcr_digests,omitempty"`
	IsPlatformPolicy bool              `json:"is_platform_policy,omitempty"`
	Valid            *bool             `json:"valid,omitempty"`
}

// PolicyAssignment records which policy is assigned to a persistent key handle.
type PolicyAssignment struct {
	PolicyName string `json:"policy_name"`
	KeyHandle  string `json:"key_handle"`
	AssignedAt string `json:"assigned_at"`
}

// PolicyElement describes a single element in a composite policy.
type PolicyElement struct {
	Type          string         `json:"type"`
	PCRSelections []PCRSelection `json:"pcr_selections,omitempty"`
	PCRBank       string         `json:"pcr_bank,omitempty"`
	PasswordHash  string         `json:"password_hash,omitempty"`
}

// CompositePolicy describes a compound AND/OR policy combining multiple elements.
type CompositePolicy struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Operator    string            `json:"operator"`
	Elements    []PolicyElement   `json:"elements"`
	CreatedAt   string            `json:"created_at"`
	UpdatedAt   string            `json:"updated_at,omitempty"`
	PCRDigests  map[string]string `json:"pcr_digests,omitempty"`
	Valid       *bool             `json:"valid,omitempty"`
}

// PolicyDeletionImpact describes the cascade effects of deleting a policy.
type PolicyDeletionImpact struct {
	PolicyName         string   `json:"policy_name"`
	PolicyType         string   `json:"policy_type"`
	AssignedKeyHandles []string `json:"assigned_key_handles"`
	HasPasswordEntry   bool     `json:"has_password_entry"`
	PasswordEntryID    string   `json:"password_entry_id,omitempty"`
}

// PCRReplayEntry describes a single PCR comparison from event log replay.
type PCRReplayEntry struct {
	PCRIndex int    `json:"pcr_index"`
	Bank     string `json:"bank"`
	Expected string `json:"expected"`
	Actual   string `json:"actual"`
	Match    bool   `json:"match"`
}

// EventLogReplayResult describes the outcome of replaying the event log
// and comparing computed PCR values against the live TPM state.
type EventLogReplayResult struct {
	Success       bool             `json:"success"`
	TotalPCRs     int              `json:"total_pcrs"`
	MatchCount    int              `json:"match_count"`
	MismatchCount int              `json:"mismatch_count"`
	Entries       []PCRReplayEntry `json:"entries"`
	Banks         []string         `json:"banks"`
	EventCount    int              `json:"event_count"`
	Error         string           `json:"error,omitempty"`
}

// PCRComparisonEntry describes a single PCR comparison between saved and current values.
type PCRComparisonEntry struct {
	Key     string `json:"key"`
	Bank    string `json:"bank"`
	Index   int    `json:"index"`
	Saved   string `json:"saved"`
	Current string `json:"current"`
	Match   bool   `json:"match"`
}

// PolicyComparisonResult describes the outcome of comparing a policy's
// saved PCR digests against current live TPM values.
type PolicyComparisonResult struct {
	PolicyName    string               `json:"policy_name"`
	AllMatch      bool                 `json:"all_match"`
	TotalPCRs     int                  `json:"total_pcrs"`
	MatchCount    int                  `json:"match_count"`
	MismatchCount int                  `json:"mismatch_count"`
	Entries       []PCRComparisonEntry `json:"entries"`
	ComparedAt    string               `json:"compared_at"`
	Error         string               `json:"error,omitempty"`
}

// ElevatorFunc is a callback for operations requiring privilege elevation.
type ElevatorFunc func(args ...string) error

// TPMService exposes TPM2 operations to the frontend.
type TPMService struct {
	ctx                   context.Context
	log                   *slog.Logger
	auditLog              atomic.Pointer[audit.Logger]
	tpmAccessor           *TPMAccessor
	devicePath            string
	dataDir               string
	elevator              Elevator
	elevatorFunc          ElevatorFunc
	mfgCACerts            []*x509.Certificate
	trustStore            truststore.TrustStore
	staticPWService       *StaticPasswordService
	platformPolicyService *PlatformPolicyService
}

// NewTPMService creates a new TPMService.
func NewTPMService() *TPMService {
	return &TPMService{
		log:        slog.Default().With("component", "tpm_service"),
		devicePath: defaultTPMDevice,
	}
}

// SetDevicePath sets the TPM device path. When empty the default
// /dev/tpmrm0 is used.
func (s *TPMService) SetDevicePath(path string) {
	if path != "" {
		s.devicePath = path
	}
}

// DevicePath returns the configured TPM device path.
func (s *TPMService) DevicePath() string {
	return s.devicePath
}

// SetContext is called by the Wails startup lifecycle hook.
func (s *TPMService) SetContext(ctx context.Context) {
	s.ctx = ctx
}

// SetAuditLogger sets the audit logger for security event logging.
func (s *TPMService) SetAuditLogger(logger audit.Logger) {
	s.auditLog.Store(&logger)
}

// logTPMOperation logs a TPM operation to the audit log.
func (s *TPMService) logTPMOperation(op audit.OperationType, success bool, err error, details map[string]any) {
	ptr := s.auditLog.Load()
	if ptr == nil {
		return
	}
	(*ptr).LogTPMOperation(op, success, err, details)
}

// SetTPMAccessor sets the shared TPMAccessor used for serialized TPM access.
func (s *TPMService) SetTPMAccessor(a *TPMAccessor) {
	s.tpmAccessor = a
}

// SetDataDir sets the persistent data directory for handle descriptions
// and other metadata files.
func (s *TPMService) SetDataDir(dir string) {
	s.dataDir = dir
}

// SetElevator sets the Elevator used for privileged operations.
func (s *TPMService) SetElevator(e Elevator) {
	s.elevator = e
}

// SetElevatorFunc sets a callback used by ForceResetLockout for privilege elevation.
func (s *TPMService) SetElevatorFunc(fn ElevatorFunc) {
	s.elevatorFunc = fn
}

// SetTrustStore sets the trust store used for EK and IDevID certificate verification.
func (s *TPMService) SetTrustStore(ts truststore.TrustStore) {
	s.trustStore = ts
}

// SetStaticPasswordService sets the static password service used for
// persisting policy passwords to the password store.
func (s *TPMService) SetStaticPasswordService(svc *StaticPasswordService) {
	s.staticPWService = svc
}

// SetPlatformPolicyService sets the PlatformPolicyService used for unified
// policy menu support. This allows AssignPolicyToKey and AssignPolicyToKeys
// to recognise the "Platform Policy" name without a TPM-side PCR policy.
func (s *TPMService) SetPlatformPolicyService(svc *PlatformPolicyService) {
	s.platformPolicyService = svc
}

// isPlatformPolicyName returns true when the given name matches the
// well-known platform policy name and a platform policy is currently loaded.
func (s *TPMService) isPlatformPolicyName(name string) bool {
	if name != "Platform Policy" {
		return false
	}
	if s.platformPolicyService == nil {
		return false
	}
	return s.platformPolicyService.policy.Load() != nil
}

// ConflictingAssignment reports a key handle that already has a policy assigned.
type ConflictingAssignment struct {
	KeyHandle     string `json:"key_handle"`
	CurrentPolicy string `json:"current_policy"`
	AssignedAt    string `json:"assigned_at"`
}

// GetConflictingAssignments returns existing policy assignments for the given
// key handles so the frontend can prompt for overwrite confirmation.
func (s *TPMService) GetConflictingAssignments(keyHandles []string) (retVal []ConflictingAssignment, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in GetConflictingAssignments", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in GetConflictingAssignments: %v", r)
		}
	}()

	assignments := s.loadAssignments()

	// Build lookup set for requested handles.
	requested := make(map[string]struct{}, len(keyHandles))
	for _, h := range keyHandles {
		h = strings.TrimSpace(h)
		if h != "" {
			requested[h] = struct{}{}
		}
	}

	var conflicts []ConflictingAssignment
	for _, a := range assignments {
		if _, ok := requested[a.KeyHandle]; ok {
			conflicts = append(conflicts, ConflictingAssignment{
				KeyHandle:     a.KeyHandle,
				CurrentPolicy: a.PolicyName,
				AssignedAt:    a.AssignedAt,
			})
		}
	}

	return conflicts, nil
}

// getTPM acquires the shared TPM accessor and returns the current TPM instance.
// Callers MUST defer s.tpmAccessor.Release() after a successful call to
// serialise all operations against the single /dev/tpmrm0 file descriptor.
func (s *TPMService) getTPM() (tpm2pkg.TrustedPlatformModule, error) {
	if s.tpmAccessor == nil {
		return nil, ErrTPMNotAvailable
	}
	return s.tpmAccessor.Acquire()
}

// deviceExists checks whether the TPM device node exists on the filesystem.
func deviceExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// GetStatus returns the TPM availability and state using the refined
// four-level provisioning model: none -> manufacturer -> owner -> device_identity.
//
// When TPM initialization fails, GetStatus returns Available=false regardless
// of whether the device node exists. A device file without a working TPM
// is not an available TPM.
func (s *TPMService) GetStatus() (status *TPMStatus, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in GetStatus", "recover", r)
			status = &TPMStatus{Available: false, Provisioned: false, StatusLevel: TPMStatusLevelNone}
			retErr = nil
		}
	}()

	devExists := deviceExists(s.devicePath)

	tpm, err := s.getTPM()
	if err != nil {
		if devExists {
			s.log.Warn("TPM device node exists but initialization failed",
				"device", s.devicePath, "error", err)
		}
		return &TPMStatus{
			Available:    false,
			DeviceExists: devExists,
			Provisioned:  false,
			StatusLevel:  TPMStatusLevelNone,
			DevicePath:   s.devicePath,
			InitError:    err.Error(),
		}, nil
	}
	defer s.tpmAccessor.Release()

	status = &TPMStatus{
		Available:    true,
		DeviceExists: true,
		DevicePath:   tpm.Device(),
		StatusLevel:  TPMStatusLevelNone,
	}

	props, err := tpm.FixedProperties()
	if err != nil {
		s.log.Warn("failed to read TPM fixed properties", "error", err)
		return status, nil
	}
	status.Manufacturer = props.Manufacturer
	status.FirmwareVer = fmt.Sprintf("%d.%d", props.FwMajor, props.FwMinor)

	// Level 1: Check for EK presence.
	_, ekErr := tpm.EKAttributes()
	if ekErr != nil {
		// No EK at all.
		status.StatusLevel = TPMStatusLevelNone
		return status, nil
	}

	// EK exists -> at least manufacturer level.
	status.StatusLevel = TPMStatusLevelManufacturer

	// Level 2: Check for SRK presence using SSRKAttributes which returns
	// an error instead of panicking when the SRK handle does not exist.
	_, srkErr := tpm.SSRKAttributes()
	if srkErr != nil {
		return status, nil
	}

	// SRK exists -> owner level.
	status.StatusLevel = TPMStatusLevelOwner

	// Level 3: Check for IDevID key + cert.
	_, idevidAttrErr := tpm.IDevIDAttributes()
	_, idevidCertErr := tpm.IDevIDCertificate()
	if idevidAttrErr == nil && idevidCertErr == nil {
		status.StatusLevel = TPMStatusLevelDeviceIdentity
		status.Provisioned = true
	}

	return status, nil
}

// GetInfo returns extended information about the TPM.
// Returns a safe empty TPMInfo when the TPM is unavailable rather than an error,
// so the frontend can render gracefully.
func (s *TPMService) GetInfo() (info *TPMInfo, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in GetInfo", "recover", r)
			info = &TPMInfo{}
			retErr = nil
		}
	}()

	tpm, err := s.getTPM()
	if err != nil {
		return &TPMInfo{}, nil
	}
	defer s.tpmAccessor.Release()

	props, err := tpm.FixedProperties()
	if err != nil {
		s.log.Warn("failed to read TPM fixed properties", "error", err)
		return &TPMInfo{}, nil
	}

	fips, fipsErr := tpm.IsFIPS140_2()
	if fipsErr != nil {
		s.log.Warn("failed to read FIPS mode", "error", fipsErr)
	}

	cfg := tpm.Config()

	info = &TPMInfo{
		Manufacturer:    props.Manufacturer,
		VendorID:        props.VendorID,
		FirmwareVersion: fmt.Sprintf("%d.%d", props.FwMajor, props.FwMinor),
		Family:          props.Family,
		Level:           int(props.Level),
		Revision:        props.Revision,
		FIPSMode:        fips,
		MaxNVBufferSize: int(props.NVBufferMax),
		LockoutCounter:  int(props.LockoutCounter),
		MaxAuthFail:     int(props.MaxAuthFail),
		Model:           props.Model,

		// Session and resource info from FixedProperties.
		ActiveSessionsMax:  int(props.ActiveSessionsMax),
		AuthSessionsLoaded: int(props.AuthSessionsLoaded),
		AuthSessionsActive: int(props.AuthSessionsActive),
		PersistentLoaded:   int(props.PersistentLoaded),
		PersistentAvail:    int(props.PersistentAvail),
		TransientAvail:     int(props.TransientAvail),
		NVIndexesDefined:   int(props.NVIndexesDefined),
		NVIndexesMax:       int(props.NVIndexesMax),
	}

	// MaxRSAKeySize and MaxECCKeySize: prefer FixedProperties values,
	// fall back to standard TPM 2.0 defaults.
	info.MaxRSAKeySize = 2048
	info.MaxECCKeySize = 521
	if props.MaxRSAKeyBits > 0 {
		info.MaxRSAKeySize = int(props.MaxRSAKeyBits)
	}
	if props.MaxECCKeyBits > 0 {
		info.MaxECCKeySize = int(props.MaxECCKeyBits)
	}

	// Algorithms: try SupportedAlgorithms() (being added to the interface),
	// then fall back to config hash, then a reasonable default list.
	algos, algErr := tpm.SupportedAlgorithms()
	if algErr == nil && len(algos) > 0 {
		info.Algorithms = algos
	} else if cfg != nil && cfg.Hash != "" {
		info.Algorithms = []string{cfg.Hash}
	}

	// Commands: try detailed SupportedCommandsInfo via type assertion,
	// fall back to SupportedCommands and wrap each string in CommandInfo.
	if concrete, ok := tpm.(*tpm2pkg.TPM2); ok {
		if cmdInfos, cmdErr := concrete.SupportedCommandsInfo(); cmdErr == nil && len(cmdInfos) > 0 {
			info.Commands = cmdInfos
		}
	} else {
		if cmds, cmdErr := tpm.SupportedCommands(); cmdErr == nil && len(cmds) > 0 {
			infos := make([]tpm2pkg.CommandInfo, len(cmds))
			for i, name := range cmds {
				infos[i] = tpm2pkg.CommandInfo{Name: name, Description: "TPM 2.0 command"}
			}
			info.Commands = infos
		}
	}

	// New overview properties from FixedProperties.
	info.InputBufferMax = int(props.InputBufferMax)
	info.MaxDigestSize = int(props.MaxDigestSize)
	info.MaxObjectContext = int(props.MaxObjectContext)
	info.LockoutInterval = int(props.LockoutInterval)
	info.LockoutRecovery = int(props.LockoutRecovery)

	// All TPM properties for detailed view.
	if concrete, ok := tpm.(*tpm2pkg.TPM2); ok {
		if fixedProps, fpErr := concrete.AllFixedProperties(); fpErr == nil {
			info.FixedProperties = fixedProps
		}
		if varProps, vpErr := concrete.AllVariableProperties(); vpErr == nil {
			info.VariableProperties = varProps
		}
	}

	// ECC Curves: query supported elliptic curves.
	curves, curveErr := tpm.SupportedECCCurves()
	if curveErr == nil && len(curves) > 0 {
		info.ECCCurves = curves
	}

	// Detect actual PCR banks by reading PCR 0 from each known bank.
	actualBanks := detectPCRBanks(tpm)
	if len(actualBanks) > 0 {
		info.PCRBanks = actualBanks
	} else {
		info.PCRBanks = []string{"sha256"}
	}

	// Parse TCG OID attributes from EK certificate (best-effort).
	// EK cert values override TPM property values when the cert provides
	// richer data (e.g., a real model string vs a numeric vendor type ID).
	if ekCert, ekErr := tpm.EKCertificate(); ekErr == nil && ekCert != nil {
		tcg := certstore.ParseTCGAttributes(ekCert)
		if tcg.Manufacturer != "" {
			info.ManufacturerID = tcg.Manufacturer
			info.VendorID = tcg.Manufacturer
		}
		if tcg.ManufacturerName != "" {
			info.Manufacturer = tcg.ManufacturerName
		}
		if tcg.Model != "" {
			info.Model = tcg.Model
		}
		if tcg.Version != "" {
			info.Version = tcg.Version
		}
		if tcg.SpecFamily != "" {
			info.Family = tcg.SpecFamily
		}
		if tcg.SpecLevel > 0 {
			info.Level = tcg.SpecLevel
		}
		if tcg.SpecRevision > 0 {
			info.Revision = fmt.Sprintf("%d", tcg.SpecRevision)
		}
	}

	// Capabilities derived from the populated info fields.
	info.Capabilities = buildCapabilities(info)

	return info, nil
}

// detectPCRBanks queries the TPM for PCR bank 0 and returns normalized
// lowercase bank names for each bank that is present. Results are sorted
// in the standard order: sha1, sha256, sha384, sha512.
func detectPCRBanks(tpm tpm2pkg.TrustedPlatformModule) []string {
	testPCRs, bankErr := tpm.ReadPCRs([]uint{0})
	if bankErr != nil {
		return nil
	}
	var banks []string
	for _, bank := range testPCRs {
		switch strings.ToUpper(bank.Algorithm) {
		case "SHA1":
			banks = append(banks, "sha1")
		case "SHA256":
			banks = append(banks, "sha256")
		case "SHA384", "SHA386":
			banks = append(banks, "sha384")
		case "SHA512":
			banks = append(banks, "sha512")
		}
	}
	// Sort in standard order: sha1, sha256, sha384, sha512.
	bankOrder := map[string]int{"sha1": 0, "sha256": 1, "sha384": 2, "sha512": 3}
	sort.Slice(banks, func(i, j int) bool {
		return bankOrder[banks[i]] < bankOrder[banks[j]]
	})
	return banks
}

// buildCapabilities produces a human-readable list of TPM capabilities
// derived from the populated TPMInfo fields.
func buildCapabilities(info *TPMInfo) []string {
	var caps []string
	if info.MaxRSAKeySize > 0 {
		caps = append(caps, fmt.Sprintf("RSA (up to %d-bit)", info.MaxRSAKeySize))
	}
	if info.MaxECCKeySize > 0 {
		caps = append(caps, fmt.Sprintf("ECC (up to %d-bit)", info.MaxECCKeySize))
	}
	caps = append(caps, "PCR Read/Extend", "Quoting", "Sealing", "Random Number Generation")
	if info.NVIndexesMax > 0 {
		caps = append(caps, fmt.Sprintf("NV Storage (%d/%d indexes)", info.NVIndexesDefined, info.NVIndexesMax))
	}
	if info.PersistentAvail > 0 || info.PersistentLoaded > 0 {
		caps = append(caps, fmt.Sprintf("Persistent Keys (%d loaded, %d avail)", info.PersistentLoaded, info.PersistentAvail))
	}
	if info.ActiveSessionsMax > 0 {
		caps = append(caps, fmt.Sprintf("Sessions (max %d)", info.ActiveSessionsMax))
	}
	if info.FIPSMode {
		caps = append(caps, "FIPS 140-2")
	}
	return caps
}

// GetEKInfo returns RSA Endorsement Key information.
func (s *TPMService) GetEKInfo() (info *EKInfo, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in GetEKInfo", "recover", r)
			info = &EKInfo{Present: false}
			retErr = nil
		}
	}()

	tpm, err := s.getTPM()
	if err != nil {
		return &EKInfo{Present: false}, nil
	}
	defer s.tpmAccessor.Release()

	ekAttrs, err := tpm.EKAttributes()
	if err != nil {
		return &EKInfo{Present: false}, nil
	}

	info = &EKInfo{
		Present:   true,
		Algorithm: algoDisplayName(ekAttrs),
		KeySize:   keySize(ekAttrs),
	}

	cert, certErr := tpm.EKCertificate()
	if certErr == nil && cert != nil {
		info.Certificate = certToPEM(cert)
		info.Verified = s.verifyCertAgainstTrustStore(cert, truststore.PurposeTPMManufacturer)
	}

	return info, nil
}

// GetEKECCInfo returns ECC Endorsement Key information.
// It reads the ECC EK certificate directly rather than calling EKECC(),
// which can panic when the underlying EK is RSA-based.
func (s *TPMService) GetEKECCInfo() (info *EKECCInfo, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in GetEKECCInfo", "recover", r)
			info = &EKECCInfo{Present: false}
			retErr = nil
		}
	}()

	tpm, err := s.getTPM()
	if err != nil {
		return &EKECCInfo{Present: false}, nil
	}
	defer s.tpmAccessor.Release()

	// Try reading the ECC EK certificate first (safer than EKECC() which
	// panics on RSA-based EKs).
	cert, certErr := tpm.EKCertificateEC()
	if certErr != nil || cert == nil {
		return &EKECCInfo{Present: false}, nil
	}

	info = &EKECCInfo{
		Present:     true,
		Algorithm:   certAlgorithmName(cert),
		KeySize:     certKeySize(cert),
		Certificate: certToPEM(cert),
		Verified:    s.verifyCertAgainstTrustStore(cert, truststore.PurposeTPMManufacturer),
	}

	return info, nil
}

// GetIAKInfo returns Initial Attestation Key information.
// It uses IAKAttributes existence as the presence indicator rather than
// IAK() which can panic when key parsing fails.
func (s *TPMService) GetIAKInfo() (info *IAKInfo, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in GetIAKInfo", "recover", r)
			info = &IAKInfo{Present: false}
			retErr = nil
		}
	}()

	tpm, err := s.getTPM()
	if err != nil {
		return &IAKInfo{Present: false}, nil
	}
	defer s.tpmAccessor.Release()

	iakAttrs, err := tpm.IAKAttributes()
	if err != nil {
		s.log.Debug("IAKAttributes failed", "error", err)
		return &IAKInfo{Present: false}, nil
	}
	if iakAttrs == nil {
		return &IAKInfo{Present: false}, nil
	}

	info = &IAKInfo{
		Present:   true,
		Algorithm: algoDisplayName(iakAttrs),
		KeySize:   keySize(iakAttrs),
	}

	if iakAttrs.TPMAttributes != nil {
		info.Handle = fmt.Sprintf("0x%08X", iakAttrs.TPMAttributes.Handle)
	}

	cert, certErr := tpm.IAKCertificate()
	if certErr == nil && cert != nil {
		info.Certificate = certToPEM(cert)
	}

	return info, nil
}

// GetIDevIDInfo returns Initial Device Identifier information.
// It uses IDevIDAttributes existence as the presence indicator rather than
// IDevID() which can panic when key parsing fails.
func (s *TPMService) GetIDevIDInfo() (info *IDevIDInfo, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in GetIDevIDInfo", "recover", r)
			info = &IDevIDInfo{Present: false}
			retErr = nil
		}
	}()

	tpm, err := s.getTPM()
	if err != nil {
		return &IDevIDInfo{Present: false}, nil
	}
	defer s.tpmAccessor.Release()

	idevidAttrs, err := tpm.IDevIDAttributes()
	if err != nil {
		s.log.Debug("IDevIDAttributes failed", "error", err)
		return &IDevIDInfo{Present: false}, nil
	}
	if idevidAttrs == nil {
		return &IDevIDInfo{Present: false}, nil
	}

	info = &IDevIDInfo{
		Present:   true,
		Algorithm: algoDisplayName(idevidAttrs),
		KeySize:   keySize(idevidAttrs),
	}

	cert, certErr := tpm.IDevIDCertificate()
	if certErr == nil && cert != nil {
		info.Certificate = certToPEM(cert)
		info.Verified = s.verifyCertAgainstTrustStore(cert, truststore.PurposeIDevIDIssuer)
	}

	return info, nil
}

// GetSharedSRKInfo returns TCG Shared Storage Root Key information.
// The shared SRK never has an authorization policy applied.
// Returns a safe empty SharedSRKInfo when the TPM is unavailable.
func (s *TPMService) GetSharedSRKInfo() (info *SharedSRKInfo, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in GetSharedSRKInfo", "recover", r)
			info = &SharedSRKInfo{Present: false, Algorithm: "N/A"}
			retErr = nil
		}
	}()

	tpm, err := s.getTPM()
	if err != nil {
		return &SharedSRKInfo{Present: false, Algorithm: "N/A"}, nil
	}
	defer s.tpmAccessor.Release()

	ssrkAttrs, ssrkErr := tpm.SSRKAttributes()
	present := ssrkErr == nil && ssrkAttrs != nil

	algo := "unknown"
	if present {
		algo = algoDisplayName(ssrkAttrs)
	}

	result := &SharedSRKInfo{
		Present:   present,
		Algorithm: algo,
	}

	if ssrkCfg := tpm.SSRK(); ssrkCfg != nil {
		result.Handle = fmt.Sprintf("0x%08X", ssrkCfg.Handle)
	}

	return result, nil
}

// GetPlatformSRKInfo returns Platform Key Store SRK information.
// The platform SRK may have a TPM platform policy applied.
// Returns a safe empty PlatformSRKInfo when the TPM is unavailable.
func (s *TPMService) GetPlatformSRKInfo() (info *PlatformSRKInfo, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in GetPlatformSRKInfo", "recover", r)
			info = &PlatformSRKInfo{Present: false, Algorithm: "N/A"}
			retErr = nil
		}
	}()

	tpm, err := s.getTPM()
	if err != nil {
		return &PlatformSRKInfo{Present: false, Algorithm: "N/A"}, nil
	}
	defer s.tpmAccessor.Release()

	result := &PlatformSRKInfo{
		Present:   false,
		Algorithm: "N/A",
	}

	pks := tpm.PlatformKeyStore()
	if pks == nil {
		return result, nil
	}

	// Get SRK attributes from the platform key store.
	if srkAttrs := pks.SRKAttributes(); srkAttrs != nil {
		result.Algorithm = algoDisplayName(srkAttrs)
		if srkAttrs.TPMAttributes != nil {
			result.Handle = fmt.Sprintf("0x%08X", srkAttrs.TPMAttributes.Handle)
			// Verify the handle actually exists in the TPM.
			_, _, readErr := tpm.ReadHandle(srkAttrs.TPMAttributes.Handle)
			if readErr == nil {
				result.Present = true
			}
		}
	}

	// Fall back to PlatformSRK config for handle if attributes are missing.
	if result.Handle == "" {
		cfg := tpm.Config()
		if cfg != nil && cfg.PlatformSRK != nil {
			result.Handle = fmt.Sprintf("0x%08X", cfg.PlatformSRK.SRKHandle)
		}
	}

	// Only show policy/initialized when key is present or store is initialized.
	if result.Present || pks.IsInitialized() {
		result.Initialized = pks.IsInitialized()
		result.PolicyEnabled = pks.PlatformPolicyEnabled()
		if result.PolicyEnabled {
			result.PolicyName = "Platform Policy"
		}
	}

	return result, nil
}

// GetPCRs returns the PCR values for the specified bank.
func (s *TPMService) GetPCRs(bank string) (retVal []PCRValue, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in GetPCRs", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in GetPCRs: %v", r)
		}
	}()

	if _, ok := validPCRBanks[bank]; !ok {
		return nil, ErrTPMInvalidBank
	}

	tpm, err := s.getTPM()
	if err != nil {
		return nil, ErrTPMNotAvailable
	}
	defer s.tpmAccessor.Release()

	allPCRs := make([]uint, 24)
	for i := range allPCRs {
		allPCRs[i] = uint(i)
	}

	banks, err := tpm.ReadPCRs(allPCRs)
	if err != nil {
		return nil, fmt.Errorf("tpm_service: read PCRs: %w", err)
	}

	// Find the matching bank by algorithm name (case-insensitive),
	// also handling the SHA384/SHA386 typo from ReadPCRs.
	targetAlgo := bankNameMap[bank]
	for _, b := range banks {
		if !strings.EqualFold(b.Algorithm, targetAlgo) {
			// Handle the SHA384/SHA386 mismatch from ReadPCRs.
			if !(strings.EqualFold(targetAlgo, "SHA384") && strings.EqualFold(b.Algorithm, "SHA386")) {
				continue
			}
		}
		values := make([]PCRValue, len(b.PCRs))
		for i, pcr := range b.PCRs {
			values[i] = PCRValue{
				Index:  int(pcr.ID),
				Bank:   bank,
				Digest: hex.EncodeToString(pcr.Value),
			}
		}
		return values, nil
	}

	// Bank not found — the TPM does not support this hash algorithm.
	return nil, ErrTPMBankNotSupported
}

// ReadPCRs is an alias for GetPCRs, matching the method name expected
// by the frontend PlatformPolicyDialog component.
func (s *TPMService) ReadPCRs(bank string) ([]PCRValue, error) {
	return s.GetPCRs(bank)
}

// ListKeys returns TPM-managed keys. Currently returns empty as there
// is no key enumeration API on the TrustedPlatformModule interface.
func (s *TPMService) ListKeys() (retVal []TPMKey, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in ListKeys", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in ListKeys: %v", r)
		}
	}()

	return []TPMKey{}, nil
}

// Provision performs TPM provisioning with the given options.
// Supports two modes: "install" (safe, reuses existing keys) and
// "provision" (full provisioning).
func (s *TPMService) Provision(opts *ProvisionOptions) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in Provision", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in Provision: %v", r)
		}
	}()

	if opts == nil {
		return ErrTPMProvisionFailed
	}

	tpm, err := s.getTPM()
	if err != nil {
		return ErrTPMNotAvailable
	}
	defer s.tpmAccessor.Release()

	var opErr error
	switch opts.Mode {
	case ProvisionModeInstall:
		opErr = tpm.Install(types.NewPassword([]byte(opts.OwnerAuth)), nil)
	case ProvisionModeProvision, "":
		opErr = tpm.Provision(types.NewPassword([]byte(opts.OwnerAuth)))
	default:
		return ErrTPMInvalidProvisionMode
	}
	if opErr != nil {
		if isTPMAuthError(opErr) {
			s.logTPMOperation(audit.OpTPMAuthFailed, false, opErr, map[string]any{
				"operation": "provision",
				"mode":      opts.Mode,
			})
			return ErrTPMAuthRequired
		}
		s.logTPMOperation(audit.OpTPMProvisioned, false, opErr, map[string]any{
			"mode": opts.Mode,
		})
		return opErr
	}

	s.logTPMOperation(audit.OpTPMProvisioned, true, nil, map[string]any{
		"mode": opts.Mode,
	})
	return nil
}

// Install performs a safe TPM installation using pre-existing keys when available.
func (s *TPMService) Install(ownerAuth string) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in Install", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in Install: %v", r)
		}
	}()

	tpm, err := s.getTPM()
	if err != nil {
		return ErrTPMNotAvailable
	}
	defer s.tpmAccessor.Release()

	// Pass nil when no owner auth is provided so Install skips
	// SetHierarchyAuth and just provisions keys.
	var auth types.Password
	if ownerAuth != "" {
		auth = types.NewPassword([]byte(ownerAuth))
	}
	if err := tpm.Install(auth, nil); err != nil {
		if isTPMAuthError(err) {
			s.logTPMOperation(audit.OpTPMAuthFailed, false, err, map[string]any{
				"operation": "install",
			})
			return ErrTPMAuthRequired
		}
		s.logTPMOperation(audit.OpTPMProvisioned, false, err, map[string]any{
			"mode": "install",
		})
		return err
	}

	s.logTPMOperation(audit.OpTPMProvisioned, true, nil, map[string]any{
		"mode": "install",
	})
	return nil
}

// InitializePlatformKeyStore initializes the Platform Key Store by setting up
// PINs and creating the Platform SRK.
func (s *TPMService) InitializePlatformKeyStore(soPIN, userPIN string) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in InitializePlatformKeyStore", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in InitializePlatformKeyStore: %v", r)
		}
	}()

	tpm, err := s.getTPM()
	if err != nil {
		return ErrTPMNotAvailable
	}
	defer s.tpmAccessor.Release()

	pks := tpm.PlatformKeyStore()
	if pks == nil {
		return fmt.Errorf("tpm_service: platform key store not configured")
	}
	return pks.Initialize(soPIN, userPIN)
}

// InitializePlatformKeyStoreWithDefaults initializes the Platform Key Store
// by creating the Platform SRK with empty (default) TPM hierarchy auth. This
// skips PINManager setup and is used when the user chose not to set hierarchy
// authorization passwords.
func (s *TPMService) InitializePlatformKeyStoreWithDefaults() (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in InitializePlatformKeyStoreWithDefaults", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in InitializePlatformKeyStoreWithDefaults: %v", r)
		}
	}()

	tpm, err := s.getTPM()
	if err != nil {
		return ErrTPMNotAvailable
	}
	defer s.tpmAccessor.Release()

	pks := tpm.PlatformKeyStore()
	if pks == nil {
		return fmt.Errorf("tpm_service: platform key store not configured")
	}
	return pks.InitializeWithDefaults()
}

// FactoryReset returns the TPM to manufacturer state by evicting all provisioned
// keys and NV indexes except the manufacturer EK.
func (s *TPMService) FactoryReset(ownerAuth string) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in FactoryReset", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in FactoryReset: %v", r)
		}
	}()

	tpm, err := s.getTPM()
	if err != nil {
		return ErrTPMNotAvailable
	}
	defer s.tpmAccessor.Release()

	if err := tpm.FactoryReset([]byte(ownerAuth)); err != nil {
		if isTPMAuthError(err) {
			return ErrTPMAuthRequired
		}
		s.log.Error("factory reset failed", "error", err)
		return ErrTPMFactoryResetFailed
	}
	return nil
}

// ProvisionIAK creates an Initial Attestation Key on the TPM.
func (s *TPMService) ProvisionIAK(ownerAuth string) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in ProvisionIAK", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in ProvisionIAK: %v", r)
		}
	}()

	tpm, err := s.getTPM()
	if err != nil {
		return ErrTPMNotAvailable
	}
	defer s.tpmAccessor.Release()

	ekAttrs, err := tpm.EKAttributes()
	if err != nil {
		s.log.Error("failed to get EK attributes for IAK provisioning", "error", err)
		return ErrTPMProvisionIAKFailed
	}

	ekAttrs.TPMAttributes.HierarchyAuth = types.NewPassword([]byte(ownerAuth))

	if _, err := tpm.CreateIAK(ekAttrs, nil); err != nil {
		if isTPMAuthError(err) {
			return ErrTPMAuthRequired
		}
		s.log.Error("IAK provisioning failed", "error", err)
		return ErrTPMProvisionIAKFailed
	}
	return nil
}

// ProvisionIDevID creates an Initial Device Identity key on the TPM.
func (s *TPMService) ProvisionIDevID(ownerAuth string) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in ProvisionIDevID", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in ProvisionIDevID: %v", r)
		}
	}()

	tpm, err := s.getTPM()
	if err != nil {
		return ErrTPMNotAvailable
	}
	defer s.tpmAccessor.Release()

	iakAttrs, err := tpm.IAKAttributes()
	if err != nil {
		s.log.Error("failed to get IAK attributes for IDevID provisioning", "error", err)
		return ErrTPMProvisionIDevIDFailed
	}

	iakAttrs.TPMAttributes.HierarchyAuth = types.NewPassword([]byte(ownerAuth))

	// Get EK certificate for IDevID CSR (optional, may not exist)
	ekCert, _ := tpm.EKCertificate()

	if _, _, err := tpm.CreateIDevID(iakAttrs, ekCert, nil); err != nil {
		if isTPMAuthError(err) {
			return ErrTPMAuthRequired
		}
		s.log.Error("IDevID provisioning failed", "error", err)
		return ErrTPMProvisionIDevIDFailed
	}
	return nil
}

// GenerateQuote creates a TPM2 quote over the specified PCRs.
// When nonce is empty, a random 32-byte nonce is generated automatically.
func (s *TPMService) GenerateQuote(nonce string, pcrs []int, bank string) (retVal *Quote, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in GenerateQuote", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in GenerateQuote: %v", r)
		}
	}()

	if len(pcrs) == 0 {
		return nil, ErrTPMInvalidPCRs
	}

	if _, ok := validPCRBanks[bank]; !ok {
		return nil, ErrTPMInvalidBank
	}

	tpm, tpmErr := s.getTPM()
	if tpmErr != nil {
		return nil, ErrTPMNotAvailable
	}
	defer s.tpmAccessor.Release()

	var nonceBytes []byte
	if nonce == "" {
		// Auto-generate a random 32-byte nonce.
		randomNonce, err := tpm.RandomBytes(32)
		if err != nil {
			return nil, ErrTPMNonceGenFailed
		}
		nonceBytes = randomNonce
	} else {
		var err error
		nonceBytes, err = hex.DecodeString(nonce)
		if err != nil {
			return nil, ErrTPMInvalidNonce
		}
	}

	pcrUints := make([]uint, len(pcrs))
	for i, p := range pcrs {
		if p < 0 || p > 23 {
			return nil, ErrTPMInvalidPCRs
		}
		pcrUints[i] = uint(p)
	}

	q, err := tpm.Quote(pcrUints, nonceBytes)
	if err != nil {
		return nil, fmt.Errorf("tpm_service: quote: %w", err)
	}

	return &Quote{
		QuoteData: hex.EncodeToString(q.Quoted),
		Signature: hex.EncodeToString(q.Signature),
		PCRDigest: hex.EncodeToString(q.PCRs),
		Nonce:     hex.EncodeToString(q.Nonce),
		CreatedAt: time.Now(),
	}, nil
}

// GetEventLog returns the parsed TPM event log.
func (s *TPMService) GetEventLog() (retVal []EventLogEntry, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in GetEventLog", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in GetEventLog: %v", r)
		}
	}()

	tpm, err := s.getTPM()
	if err != nil {
		return nil, ErrTPMNotAvailable
	}
	defer s.tpmAccessor.Release()

	events, err := tpm.ParsedEventLog()
	if err != nil {
		return nil, ErrTPMEventLogNotFound
	}

	entries := make([]EventLogEntry, len(events))
	for i, evt := range events {
		digestHex := ""
		if len(evt.Digests) > 0 {
			digestHex = evt.Digests[0].Digest
		}
		entries[i] = EventLogEntry{
			PCRIndex:  evt.PCRIndex,
			EventType: evt.EventType,
			DigestHex: digestHex,
			EventData: evt.EventString,
		}
	}

	return entries, nil
}

// GetRandomBytes returns cryptographically random bytes from the TPM.
func (s *TPMService) GetRandomBytes(length int) (retVal string, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in GetRandomBytes", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in GetRandomBytes: %v", r)
		}
	}()

	if length < 1 || length > 1024 {
		return "", ErrTPMInvalidLength
	}

	tpm, err := s.getTPM()
	if err != nil {
		return "", ErrTPMNotAvailable
	}
	defer s.tpmAccessor.Release()

	randomBytes, err := tpm.RandomBytes(length)
	if err != nil {
		return "", fmt.Errorf("tpm_service: random bytes: %w", err)
	}

	return hex.EncodeToString(randomBytes), nil
}

// GetPlatformPolicy returns the platform policy digest hash.
func (s *TPMService) GetPlatformPolicy() (retVal string, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in GetPlatformPolicy", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in GetPlatformPolicy: %v", r)
		}
	}()

	tpm, err := s.getTPM()
	if err != nil {
		return "", ErrTPMNotAvailable
	}
	defer s.tpmAccessor.Release()

	digest, err := tpm.PlatformPolicyDigestHash()
	if err != nil {
		return "", fmt.Errorf("tpm_service: platform policy: %w", err)
	}

	return hex.EncodeToString(digest), nil
}

// ExportEKCert returns the Endorsement Key certificate in PEM format.
func (s *TPMService) ExportEKCert(format string) (retVal string, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in ExportEKCert", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in ExportEKCert: %v", r)
		}
	}()

	tpm, err := s.getTPM()
	if err != nil {
		return "", ErrTPMNotAvailable
	}
	defer s.tpmAccessor.Release()

	cert, err := tpm.EKCertificate()
	if err != nil {
		return "", ErrTPMCertNotFound
	}

	return certToPEM(cert), nil
}

// ImportEKCert imports an Endorsement Key certificate from PEM format.
func (s *TPMService) ImportEKCert(certPEM string) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in ImportEKCert", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in ImportEKCert: %v", r)
		}
	}()

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return ErrTPMInvalidCert
	}

	// Validate the certificate parses correctly.
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return ErrTPMInvalidCert
	}

	tpm, err := s.getTPM()
	if err != nil {
		return ErrTPMNotAvailable
	}
	defer s.tpmAccessor.Release()

	return tpm.WriteEKCert(block.Bytes)
}

// ExportEKECCCert returns the ECC Endorsement Key certificate in PEM format.
func (s *TPMService) ExportEKECCCert(format string) (retVal string, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in ExportEKECCCert", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in ExportEKECCCert: %v", r)
		}
	}()

	tpm, err := s.getTPM()
	if err != nil {
		return "", ErrTPMNotAvailable
	}
	defer s.tpmAccessor.Release()

	cert, err := tpm.EKCertificateEC()
	if err != nil {
		return "", ErrTPMCertNotFound
	}

	return certToPEM(cert), nil
}

// ImportEKECCCert imports an ECC Endorsement Key certificate from PEM format.
func (s *TPMService) ImportEKECCCert(certPEM string) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in ImportEKECCCert", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in ImportEKECCCert: %v", r)
		}
	}()

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return ErrTPMInvalidCert
	}

	// Validate the certificate parses correctly.
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return ErrTPMInvalidCert
	}

	tpm, err := s.getTPM()
	if err != nil {
		return ErrTPMNotAvailable
	}
	defer s.tpmAccessor.Release()

	return tpm.WriteEKCert(block.Bytes)
}

// ExportIAKCert returns the IAK certificate in PEM format.
func (s *TPMService) ExportIAKCert(format string) (retVal string, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in ExportIAKCert", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in ExportIAKCert: %v", r)
		}
	}()

	tpm, err := s.getTPM()
	if err != nil {
		return "", ErrTPMNotAvailable
	}
	defer s.tpmAccessor.Release()

	cert, err := tpm.IAKCertificate()
	if err != nil {
		return "", ErrTPMCertNotFound
	}

	return certToPEM(cert), nil
}

// ImportIAKCert imports an IAK certificate from PEM format.
func (s *TPMService) ImportIAKCert(certPEM string) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in ImportIAKCert", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in ImportIAKCert: %v", r)
		}
	}()

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return ErrTPMInvalidCert
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ErrTPMInvalidCert
	}

	tpm, tpmErr := s.getTPM()
	if tpmErr != nil {
		return ErrTPMNotAvailable
	}
	defer s.tpmAccessor.Release()

	return tpm.ProvisionIAKCert(cert)
}

// ExportIDevIDCert returns the IDevID certificate in PEM format.
func (s *TPMService) ExportIDevIDCert(format string) (retVal string, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in ExportIDevIDCert", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in ExportIDevIDCert: %v", r)
		}
	}()

	tpm, err := s.getTPM()
	if err != nil {
		return "", ErrTPMNotAvailable
	}
	defer s.tpmAccessor.Release()

	cert, err := tpm.IDevIDCertificate()
	if err != nil {
		return "", ErrTPMCertNotFound
	}

	return certToPEM(cert), nil
}

// ImportIDevIDCert imports an IDevID certificate from PEM format.
func (s *TPMService) ImportIDevIDCert(certPEM string) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in ImportIDevIDCert", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in ImportIDevIDCert: %v", r)
		}
	}()

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return ErrTPMInvalidCert
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ErrTPMInvalidCert
	}

	tpm, tpmErr := s.getTPM()
	if tpmErr != nil {
		return ErrTPMNotAvailable
	}
	defer s.tpmAccessor.Release()

	return tpm.ProvisionIDevIDCert(cert)
}

// --- Phase 2A: Handle Enumeration ---

// ListPersistentHandles returns all persistent handles with optional descriptions.
func (s *TPMService) ListPersistentHandles() (retVal []HandleInfo, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in ListPersistentHandles", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in ListPersistentHandles: %v", r)
		}
	}()

	tpm, err := s.getTPM()
	if err != nil {
		return nil, ErrTPMNotAvailable
	}
	defer s.tpmAccessor.Release()

	props, err := tpm.FixedProperties()
	if err != nil {
		return nil, fmt.Errorf("tpm_service: list persistent handles: %w", err)
	}
	handles := props.PersistentHandles

	// Resolve the configured Platform SRK handle for dynamic labeling.
	var platformSRKHandle string
	if cfg := tpm.Config(); cfg != nil && cfg.PlatformSRK != nil && cfg.PlatformSRK.SRKHandle != 0 {
		platformSRKHandle = fmt.Sprintf("0x%08X", cfg.PlatformSRK.SRKHandle)
	}

	descriptions := s.loadHandleDescriptions()
	result := make([]HandleInfo, len(handles))
	for i, h := range handles {
		hexHandle := fmt.Sprintf("0x%08X", h)
		desc := descriptions[hexHandle]
		if desc == "" {
			if platformSRKHandle != "" && hexHandle == platformSRKHandle {
				desc = "Platform SRK"
			} else {
				desc = wellKnownHandles[hexHandle]
			}
		}

		// Read key attributes for algorithm display.
		algo := ""
		attrs, readErr := tpm.KeyAttributes(tpm2.TPMHandle(h))
		if readErr == nil && attrs != nil {
			algo = algoDisplayName(attrs)
		}

		result[i] = HandleInfo{
			Handle:      hexHandle,
			Algorithm:   algo,
			Type:        "persistent",
			Description: desc,
		}
	}

	return result, nil
}

// ListTransientHandles returns all currently loaded transient handles.
func (s *TPMService) ListTransientHandles() (retVal []HandleInfo, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in ListTransientHandles", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in ListTransientHandles: %v", r)
		}
	}()

	tpm, err := s.getTPM()
	if err != nil {
		return nil, ErrTPMNotAvailable
	}
	defer s.tpmAccessor.Release()

	props, err := tpm.FixedProperties()
	if err != nil {
		return nil, fmt.Errorf("tpm_service: list transient handles: %w", err)
	}
	handles := props.TransientHandles

	result := make([]HandleInfo, len(handles))
	for i, h := range handles {
		result[i] = HandleInfo{
			Handle: fmt.Sprintf("0x%08X", h),
			Type:   "transient",
		}
	}

	return result, nil
}

// SetHandleDescription sets or removes a user description for a persistent handle.
// Pass an empty description to remove the entry.
func (s *TPMService) SetHandleDescription(handle string, description string) error {
	if s.dataDir == "" {
		return ErrTPMDataDirNotSet
	}

	descriptions := s.loadHandleDescriptions()
	if description == "" {
		delete(descriptions, handle)
	} else {
		descriptions[handle] = description
	}

	return s.saveHandleDescriptions(descriptions)
}

// loadHandleDescriptions reads the persisted handle descriptions from disk.
func (s *TPMService) loadHandleDescriptions() map[string]string {
	descriptions := make(map[string]string)
	if s.dataDir == "" {
		return descriptions
	}

	filePath := filepath.Join(s.dataDir, handleDescriptionsFile)
	data, err := os.ReadFile(filePath)
	if err != nil {
		return descriptions
	}

	if jsonErr := json.Unmarshal(data, &descriptions); jsonErr != nil {
		s.log.Warn("failed to parse handle descriptions", "error", jsonErr)
	}

	return descriptions
}

// saveHandleDescriptions writes the handle descriptions to disk.
func (s *TPMService) saveHandleDescriptions(descriptions map[string]string) error {
	if s.dataDir == "" {
		return ErrTPMDataDirNotSet
	}

	filePath := filepath.Join(s.dataDir, handleDescriptionsFile)
	data, err := json.MarshalIndent(descriptions, "", "  ")
	if err != nil {
		return ErrTPMHandleDescriptionFailed
	}

	if writeErr := os.WriteFile(filePath, data, 0600); writeErr != nil {
		return ErrTPMHandleDescriptionFailed
	}

	return nil
}

// --- Phase 2B: Lockout Management ---

// GetLockoutInfo returns the current dictionary attack lockout status.
func (s *TPMService) GetLockoutInfo() (retVal *LockoutInfo, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in GetLockoutInfo", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in GetLockoutInfo: %v", r)
		}
	}()

	tpm, err := s.getTPM()
	if err != nil {
		return nil, ErrTPMNotAvailable
	}
	defer s.tpmAccessor.Release()

	props, err := tpm.FixedProperties()
	if err != nil {
		return nil, fmt.Errorf("tpm_service: lockout info: %w", err)
	}

	return &LockoutInfo{
		Counter:  int(props.LockoutCounter),
		MaxFail:  int(props.MaxAuthFail),
		Interval: int(props.LockoutInterval),
		Recovery: int(props.LockoutRecovery),
		IsLocked: props.LockoutCounter >= props.MaxAuthFail,
	}, nil
}

// ResetLockout resets the dictionary attack lockout counter.
func (s *TPMService) ResetLockout(lockoutAuth string) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in ResetLockout", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in ResetLockout: %v", r)
		}
	}()

	tpm, err := s.getTPM()
	if err != nil {
		return ErrTPMNotAvailable
	}
	defer s.tpmAccessor.Release()

	if resetErr := tpm.DictionaryAttackLockoutReset([]byte(lockoutAuth)); resetErr != nil {
		s.log.Error("lockout reset failed", "error", resetErr)
		return ErrTPMLockoutResetFailed
	}

	return nil
}

// ForceResetLockout resets the dictionary attack lockout counter using
// the lockout hierarchy authorization. This does NOT clear the TPM -
// it only resets the DA lockout counter so authentication can resume.
func (s *TPMService) ForceResetLockout(lockoutAuth string) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in ForceResetLockout", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in ForceResetLockout: %v", r)
		}
	}()

	tpm, err := s.getTPM()
	if err != nil {
		return ErrTPMNotAvailable
	}
	defer s.tpmAccessor.Release()

	if resetErr := tpm.DictionaryAttackLockoutReset([]byte(lockoutAuth)); resetErr != nil {
		s.log.Error("force lockout reset failed", "error", resetErr)
		return ErrTPMLockoutResetFailed
	}

	return nil
}

// --- Phase 2B+: Attestation ---

// CertifyKey performs a TPM2_Certify operation on the specified key handle
// using the IAK as the attesting (signing) key. Returns the certification
// result with hex-encoded attested data, signature, and nonce.
func (s *TPMService) CertifyKey(keyHandleHex string) (retVal *CertifyKeyResult, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in CertifyKey", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in CertifyKey: %v", r)
		}
	}()

	tpm, err := s.getTPM()
	if err != nil {
		return nil, ErrTPMNotAvailable
	}
	defer s.tpmAccessor.Release()

	// Parse the target key handle.
	var handle uint32
	if _, parseErr := fmt.Sscanf(keyHandleHex, "0x%x", &handle); parseErr != nil {
		if _, parseErr2 := fmt.Sscanf(keyHandleHex, "%x", &handle); parseErr2 != nil {
			return nil, fmt.Errorf("tpm_service: invalid key handle: %s", keyHandleHex)
		}
	}

	// Generate random nonce.
	nonceBytes, nonceErr := tpm.RandomBytes(32)
	if nonceErr != nil {
		return nil, ErrTPMNonceGenFailed
	}

	// Build key attributes for the target key.
	keyAttrs := &types.KeyAttributes{
		TPMAttributes: &types.TPMAttributes{
			Handle: tpm2.TPMHandle(handle),
		},
	}

	result, certErr := tpm.CertifyKey(keyAttrs, nonceBytes, nil)
	if certErr != nil {
		return nil, fmt.Errorf("tpm_service: certify key: %w", certErr)
	}

	return &CertifyKeyResult{
		Attested:  hex.EncodeToString(result.CertifyInfo),
		Signature: hex.EncodeToString(result.Signature),
		Nonce:     hex.EncodeToString(nonceBytes),
	}, nil
}

// ViewKey returns detailed key information for the specified identity key.
// The keyName parameter should be one of: "EK-RSA", "EK-ECC", "IAK", "IDevID", "SRK".
func (s *TPMService) ViewKey(keyName string) (retVal *KeyViewData, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in ViewKey", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in ViewKey: %v", r)
		}
	}()

	tpm, err := s.getTPM()
	if err != nil {
		return nil, ErrTPMNotAvailable
	}
	defer s.tpmAccessor.Release()

	data := &KeyViewData{Name: keyName}

	switch {
	case strings.Contains(keyName, "EK-ECC"):
		// ECC EK: extract info from the ECC EK certificate since there
		// is no EKECCAttributes method on the TrustedPlatformModule interface.
		cert, cErr := tpm.EKCertificateEC()
		if cErr != nil || cert == nil {
			return nil, fmt.Errorf("tpm_service: EK-ECC not available: %w", cErr)
		}
		data.Algorithm = certAlgorithmName(cert)
		data.KeySize = certKeySize(cert)
		data.Certificate = certToPEM(cert)

	case strings.Contains(keyName, "EK"):
		attrs, aErr := tpm.EKAttributes()
		if aErr != nil {
			return nil, fmt.Errorf("tpm_service: EK not available: %w", aErr)
		}
		data.Algorithm = algoDisplayName(attrs)
		data.KeySize = keySize(attrs)
		if attrs.TPMAttributes != nil {
			data.Handle = fmt.Sprintf("0x%08X", attrs.TPMAttributes.Handle)
			if len(attrs.TPMAttributes.PublicKeyBytes) > 0 {
				data.PublicKeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: attrs.TPMAttributes.PublicKeyBytes}))
			}
		}
		cert, cErr := tpm.EKCertificate()
		if cErr == nil && cert != nil {
			data.Certificate = certToPEM(cert)
		}

	case strings.Contains(keyName, "IAK"):
		attrs, aErr := tpm.IAKAttributes()
		if aErr != nil {
			return nil, fmt.Errorf("tpm_service: IAK not available: %w", aErr)
		}
		data.Algorithm = algoDisplayName(attrs)
		data.KeySize = keySize(attrs)
		if attrs.TPMAttributes != nil {
			data.Handle = fmt.Sprintf("0x%08X", attrs.TPMAttributes.Handle)
			if len(attrs.TPMAttributes.PublicKeyBytes) > 0 {
				data.PublicKeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: attrs.TPMAttributes.PublicKeyBytes}))
			}
		}
		cert, cErr := tpm.IAKCertificate()
		if cErr == nil && cert != nil {
			data.Certificate = certToPEM(cert)
		}

	case strings.Contains(keyName, "IDevID"):
		attrs, aErr := tpm.IDevIDAttributes()
		if aErr != nil {
			return nil, fmt.Errorf("tpm_service: IDevID not available: %w", aErr)
		}
		data.Algorithm = algoDisplayName(attrs)
		data.KeySize = keySize(attrs)
		if attrs.TPMAttributes != nil {
			data.Handle = fmt.Sprintf("0x%08X", attrs.TPMAttributes.Handle)
			if len(attrs.TPMAttributes.PublicKeyBytes) > 0 {
				data.PublicKeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: attrs.TPMAttributes.PublicKeyBytes}))
			}
		}
		cert, cErr := tpm.IDevIDCertificate()
		if cErr == nil && cert != nil {
			data.Certificate = certToPEM(cert)
		}

	case strings.Contains(keyName, "SRK"):
		attrs, aErr := tpm.SSRKAttributes()
		if aErr != nil {
			return nil, fmt.Errorf("tpm_service: SRK not available: %w", aErr)
		}
		data.Algorithm = algoDisplayName(attrs)
		data.KeySize = keySize(attrs)
		if attrs.TPMAttributes != nil {
			data.Handle = fmt.Sprintf("0x%08X", attrs.TPMAttributes.Handle)
		}

	default:
		return nil, fmt.Errorf("tpm_service: unknown key name: %s", keyName)
	}

	return data, nil
}

// GenerateIDevIDCSR generates a TCG-CSR-IDEVID certificate signing request
// for the IDevID key. The CSR can be submitted to a Certificate Authority
// for signing. Returns the CSR as hex-encoded binary data.
func (s *TPMService) GenerateIDevIDCSR() (retVal string, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in GenerateIDevIDCSR", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in GenerateIDevIDCSR: %v", r)
		}
	}()

	tpm, err := s.getTPM()
	if err != nil {
		return "", ErrTPMNotAvailable
	}
	defer s.tpmAccessor.Release()

	ekCert, ekErr := tpm.EKCertificate()
	if ekErr != nil {
		return "", fmt.Errorf("tpm_service: EK certificate required for CSR: %w", ekErr)
	}

	iakAttrs, iakErr := tpm.IAKAttributes()
	if iakErr != nil {
		// Fallback: try reading standard IAK handles directly from the TPM.
		s.log.Debug("IAKAttributes failed in CSR, trying standard handles", "error", iakErr)
		for _, handle := range []uint32{0x81020001, 0x81020000} {
			attrs, readErr := tpm.KeyAttributes(tpm2.TPMHandle(handle))
			if readErr == nil && attrs != nil {
				iakAttrs = attrs
				iakErr = nil
				break
			}
		}
		if iakErr != nil {
			return "", fmt.Errorf("tpm_service: IAK required for CSR: %w", iakErr)
		}
	}

	idevidAttrs, idevidErr := tpm.IDevIDAttributes()
	if idevidErr != nil {
		// Fallback: try reading the standard IDevID handle directly.
		s.log.Debug("IDevIDAttributes failed in CSR, trying standard handle", "error", idevidErr)
		attrs, readErr := tpm.KeyAttributes(tpm2.TPMHandle(0x81020000))
		if readErr == nil && attrs != nil {
			idevidAttrs = attrs
			idevidErr = nil
		}
		if idevidErr != nil {
			return "", fmt.Errorf("tpm_service: IDevID required for CSR: %w", idevidErr)
		}
	}

	csr, csrErr := tpm.CreateTCG_CSR_IDEVID(ekCert, iakAttrs, idevidAttrs)
	if csrErr != nil {
		return "", fmt.Errorf("tpm_service: CSR generation failed: %w", csrErr)
	}

	// Marshal the CSR to binary.
	csrBytes, marshalErr := csr.Marshal()
	if marshalErr != nil {
		return "", fmt.Errorf("tpm_service: CSR marshaling failed: %w", marshalErr)
	}

	return hex.EncodeToString(csrBytes), nil
}

// --- Phase 2C: Authorization Hierarchy Changes ---

// ChangeOwnerAuth changes the Owner hierarchy authorization password.
func (s *TPMService) ChangeOwnerAuth(oldAuth, newAuth string) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in ChangeOwnerAuth", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in ChangeOwnerAuth: %v", r)
		}
	}()

	return s.changeHierarchyAuth(oldAuth, newAuth, tpm2.TPMRHOwner)
}

// ChangeEndorsementAuth changes the Endorsement hierarchy authorization password.
func (s *TPMService) ChangeEndorsementAuth(oldAuth, newAuth string) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in ChangeEndorsementAuth", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in ChangeEndorsementAuth: %v", r)
		}
	}()

	return s.changeHierarchyAuth(oldAuth, newAuth, tpm2.TPMRHEndorsement)
}

// ChangeLockoutAuth changes the Lockout hierarchy authorization password.
func (s *TPMService) ChangeLockoutAuth(oldAuth, newAuth string) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in ChangeLockoutAuth", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in ChangeLockoutAuth: %v", r)
		}
	}()

	return s.changeHierarchyAuth(oldAuth, newAuth, tpm2.TPMRHLockout)
}

// changeHierarchyAuth is the shared implementation for hierarchy auth changes.
func (s *TPMService) changeHierarchyAuth(oldAuth, newAuth string, hierarchy tpm2.TPMHandle) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in changeHierarchyAuth", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in changeHierarchyAuth: %v", r)
		}
	}()

	tpm, err := s.getTPM()
	if err != nil {
		return ErrTPMNotAvailable
	}
	defer s.tpmAccessor.Release()

	var oldPwd, newPwd types.Password
	if oldAuth != "" {
		oldPwd = types.NewPassword([]byte(oldAuth))
	}
	if newAuth != "" {
		newPwd = types.NewPassword([]byte(newAuth))
	}

	h := hierarchy
	hierarchyName := s.hierarchyHandleToName(hierarchy)
	if err := tpm.SetHierarchyAuth(oldPwd, newPwd, &h); err != nil {
		if isTPMAuthError(err) {
			s.logTPMOperation(audit.OpTPMAuthFailed, false, err, map[string]any{
				"operation": "change_hierarchy_auth",
				"hierarchy": hierarchyName,
			})
		} else {
			s.logTPMOperation(audit.OpTPMHierarchyChanged, false, err, map[string]any{
				"hierarchy": hierarchyName,
			})
		}
		return err
	}

	s.logTPMOperation(audit.OpTPMHierarchyChanged, true, nil, map[string]any{
		"hierarchy": hierarchyName,
	})
	return nil
}

// hierarchyHandleToName converts a TPM handle to a human-readable hierarchy name.
func (s *TPMService) hierarchyHandleToName(h tpm2.TPMHandle) string {
	switch h {
	case tpm2.TPMRHOwner:
		return "owner"
	case tpm2.TPMRHEndorsement:
		return "endorsement"
	case tpm2.TPMRHPlatform:
		return "platform"
	case tpm2.TPMRHLockout:
		return "lockout"
	default:
		return fmt.Sprintf("0x%x", uint32(h))
	}
}

// --- Phase 2D: NV Index Management ---

// GetNVSummary returns an overview of NV storage including all defined indexes.
func (s *TPMService) GetNVSummary() (retVal *NVSummary, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in GetNVSummary", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in GetNVSummary: %v", r)
		}
	}()

	tpm, err := s.getTPM()
	if err != nil {
		return nil, ErrTPMNotAvailable
	}
	defer s.tpmAccessor.Release()

	props, err := tpm.FixedProperties()
	if err != nil {
		return nil, fmt.Errorf("tpm_service: nv summary: %w", err)
	}

	entries := make([]NVIndexEntry, len(props.NVIndexes))
	for i, idx := range props.NVIndexes {
		entries[i] = NVIndexEntry{
			Handle:    fmt.Sprintf("0x%08X", idx.Handle),
			Type:      idx.Type,
			Size:      int(idx.Size),
			AuthRead:  idx.AuthRead,
			AuthWrite: idx.AuthWrite,
		}
	}

	return &NVSummary{
		IndexesDefined: int(props.NVIndexesDefined),
		IndexesMax:     int(props.NVIndexesMax),
		Indexes:        entries,
	}, nil
}

// DefineNVOrdinary defines a new ordinary NV index.
func (s *TPMService) DefineNVOrdinary(handle uint32, size int, ownerAuth string) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in DefineNVOrdinary", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in DefineNVOrdinary: %v", r)
		}
	}()

	if size < 1 || size > 2048 {
		return ErrTPMInvalidNVSize
	}

	tpm, err := s.getTPM()
	if err != nil {
		return ErrTPMNotAvailable
	}
	defer s.tpmAccessor.Release()

	keyAttrs := s.buildNVKeyAttributes(handle, ownerAuth, tpm2.TPMAlgSHA256)
	keyAttrs.SealData = types.NewPassword(make([]byte, size))

	return tpm.NVWrite(keyAttrs)
}

// DefineNVCounter defines a new counter NV index.
func (s *TPMService) DefineNVCounter(handle uint32, ownerAuth string) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in DefineNVCounter", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in DefineNVCounter: %v", r)
		}
	}()

	tpm, err := s.getTPM()
	if err != nil {
		return ErrTPMNotAvailable
	}
	defer s.tpmAccessor.Release()

	keyAttrs := s.buildNVKeyAttributes(handle, ownerAuth, tpm2.TPMAlgSHA256)
	return tpm.NVDefineCounter(keyAttrs)
}

// DefineNVExtend defines a new extend NV index.
func (s *TPMService) DefineNVExtend(handle uint32, ownerAuth string) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in DefineNVExtend", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in DefineNVExtend: %v", r)
		}
	}()

	tpm, err := s.getTPM()
	if err != nil {
		return ErrTPMNotAvailable
	}
	defer s.tpmAccessor.Release()

	keyAttrs := s.buildNVKeyAttributes(handle, ownerAuth, tpm2.TPMAlgSHA256)
	return tpm.NVDefineExtend(keyAttrs)
}

// ReadNVData reads data from an ordinary NV index. When size is 0 or
// negative, the size is auto-detected from the NV index public metadata.
func (s *TPMService) ReadNVData(handle uint32, size int, ownerAuth string) (retVal string, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in ReadNVData", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in ReadNVData: %v", r)
		}
	}()

	tpm, err := s.getTPM()
	if err != nil {
		return "", ErrTPMNotAvailable
	}
	defer s.tpmAccessor.Release()

	// Auto-detect size from NV public metadata when not specified.
	if size < 1 {
		props, propsErr := tpm.FixedProperties()
		if propsErr == nil {
			for _, idx := range props.NVIndexes {
				if uint32(idx.Handle) == handle {
					size = int(idx.Size)
					break
				}
			}
		}
		if size < 1 {
			return "", ErrTPMInvalidNVSize
		}
	}

	keyAttrs := s.buildNVKeyAttributes(handle, ownerAuth, tpm2.TPMAlgSHA256)
	data, readErr := tpm.NVRead(keyAttrs, uint16(size))
	if readErr != nil {
		return "", fmt.Errorf("tpm_service: read NV data: %w", readErr)
	}

	return hex.EncodeToString(data), nil
}

// WriteNVData writes hex-encoded data to an ordinary NV index.
func (s *TPMService) WriteNVData(handle uint32, hexData string, ownerAuth string) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in WriteNVData", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in WriteNVData: %v", r)
		}
	}()

	data, err := hex.DecodeString(hexData)
	if err != nil {
		return ErrTPMInvalidNVData
	}
	if len(data) == 0 {
		return ErrTPMInvalidNVData
	}

	tpm, tpmErr := s.getTPM()
	if tpmErr != nil {
		return ErrTPMNotAvailable
	}
	defer s.tpmAccessor.Release()

	keyAttrs := s.buildNVKeyAttributes(handle, ownerAuth, tpm2.TPMAlgSHA256)
	keyAttrs.SealData = types.NewPassword(data)

	return tpm.NVWrite(keyAttrs)
}

// IncrementNVCounter increments a counter NV index and returns the new value.
func (s *TPMService) IncrementNVCounter(handle uint32, ownerAuth string) (retVal uint64, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in IncrementNVCounter", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in IncrementNVCounter: %v", r)
		}
	}()

	tpm, err := s.getTPM()
	if err != nil {
		return 0, ErrTPMNotAvailable
	}
	defer s.tpmAccessor.Release()

	keyAttrs := s.buildNVKeyAttributes(handle, ownerAuth, tpm2.TPMAlgSHA256)
	return tpm.NVIncrement(keyAttrs)
}

// ReadNVCounter reads the current value of a counter NV index.
func (s *TPMService) ReadNVCounter(handle uint32, ownerAuth string) (retVal uint64, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in ReadNVCounter", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in ReadNVCounter: %v", r)
		}
	}()

	tpm, err := s.getTPM()
	if err != nil {
		return 0, ErrTPMNotAvailable
	}
	defer s.tpmAccessor.Release()

	keyAttrs := s.buildNVKeyAttributes(handle, ownerAuth, tpm2.TPMAlgSHA256)
	return tpm.NVReadCounter(keyAttrs)
}

// ExtendNV extends hex-encoded data into an extend NV index.
func (s *TPMService) ExtendNV(handle uint32, hexData string, ownerAuth string) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in ExtendNV", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in ExtendNV: %v", r)
		}
	}()

	data, err := hex.DecodeString(hexData)
	if err != nil {
		return ErrTPMInvalidNVData
	}
	if len(data) == 0 {
		return ErrTPMInvalidNVData
	}

	tpm, tpmErr := s.getTPM()
	if tpmErr != nil {
		return ErrTPMNotAvailable
	}
	defer s.tpmAccessor.Release()

	keyAttrs := s.buildNVKeyAttributes(handle, ownerAuth, tpm2.TPMAlgSHA256)
	return tpm.NVExtend(keyAttrs, data)
}

// ReadNVExtend reads the digest from an extend NV index.
func (s *TPMService) ReadNVExtend(handle uint32, ownerAuth string) (retVal string, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in ReadNVExtend", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in ReadNVExtend: %v", r)
		}
	}()

	tpm, err := s.getTPM()
	if err != nil {
		return "", ErrTPMNotAvailable
	}
	defer s.tpmAccessor.Release()

	keyAttrs := s.buildNVKeyAttributes(handle, ownerAuth, tpm2.TPMAlgSHA256)
	data, readErr := tpm.NVReadExtend(keyAttrs)
	if readErr != nil {
		return "", fmt.Errorf("tpm_service: read NV extend: %w", readErr)
	}

	return hex.EncodeToString(data), nil
}

// DeleteNVIndex removes an NV index definition.
func (s *TPMService) DeleteNVIndex(handle uint32, ownerAuth string) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in DeleteNVIndex", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in DeleteNVIndex: %v", r)
		}
	}()

	tpm, err := s.getTPM()
	if err != nil {
		return ErrTPMNotAvailable
	}
	defer s.tpmAccessor.Release()

	keyAttrs := s.buildNVKeyAttributes(handle, ownerAuth, tpm2.TPMAlgSHA256)
	return tpm.NVUndefine(keyAttrs)
}

// buildNVKeyAttributes constructs KeyAttributes for NV index operations.
func (s *TPMService) buildNVKeyAttributes(handle uint32, ownerAuth string, hashAlg tpm2.TPMIAlgHash) *types.KeyAttributes {
	var hierarchyAuth types.Password
	if ownerAuth != "" {
		hierarchyAuth = types.NewPassword([]byte(ownerAuth))
	}

	return &types.KeyAttributes{
		TPMAttributes: &types.TPMAttributes{
			Handle:    tpm2.TPMHandle(handle),
			Hierarchy: tpm2.TPMRHOwner,
			HashAlg:   hashAlg,
		},
		Parent: &types.KeyAttributes{
			TPMAttributes: &types.TPMAttributes{
				Hierarchy:     tpm2.TPMRHOwner,
				HierarchyAuth: hierarchyAuth,
			},
		},
	}
}

// --- Phase 2E: Manufacturer CA Verification ---

// ImportManufacturerCA imports a PEM-encoded manufacturer CA certificate
// for use in TPM EK verification.
func (s *TPMService) ImportManufacturerCA(certPEM string) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in ImportManufacturerCA", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in ImportManufacturerCA: %v", r)
		}
	}()

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return ErrTPMInvalidCACert
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ErrTPMInvalidCACert
	}

	s.mfgCACerts = append(s.mfgCACerts, cert)

	// Persist to trust store for long-term storage and visibility in trust store UI.
	if s.trustStore != nil {
		opts := &truststore.AddCertificateOptions{
			Purpose: truststore.PurposeTPMManufacturer,
			Source:  "user-import",
		}
		if err := s.trustStore.AddCertificateWithOptions(cert, opts); err != nil {
			if !errors.Is(err, truststore.ErrCertificateExists) {
				s.log.Warn("failed to persist manufacturer CA to trust store", "error", err)
			}
		}
	}
	return nil
}

// VerifyTPM verifies the TPM EK certificate against the loaded manufacturer
// CA certificates. Returns the verification status.
func (s *TPMService) VerifyTPM() (retVal *VerificationStatus, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in VerifyTPM", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in VerifyTPM: %v", r)
		}
	}()

	tpm, err := s.getTPM()
	if err != nil {
		return &VerificationStatus{Verified: false, ErrorMessage: "TPM not available"}, nil
	}
	defer s.tpmAccessor.Release()

	ekCert, err := tpm.EKCertificate()
	if err != nil {
		return &VerificationStatus{Verified: false, ErrorMessage: "EK certificate not found"}, nil
	}

	roots := x509.NewCertPool()
	certsLoaded := 0
	for _, ca := range s.mfgCACerts {
		roots.AddCert(ca)
		certsLoaded++
	}
	if s.trustStore != nil {
		if purposeCerts, tsErr := s.trustStore.CertificatesByPurpose(truststore.PurposeTPMManufacturer); tsErr == nil {
			for _, ca := range purposeCerts {
				roots.AddCert(ca)
				certsLoaded++
			}
		}
	}
	if certsLoaded == 0 {
		return &VerificationStatus{Verified: false, ErrorMessage: "no manufacturer CA certificates loaded"}, nil
	}

	verifyOpts := x509.VerifyOptions{
		Roots: roots,
	}

	if _, verifyErr := ekCert.Verify(verifyOpts); verifyErr != nil {
		return &VerificationStatus{
			Verified:     false,
			ErrorMessage: verifyErr.Error(),
		}, nil
	}

	return &VerificationStatus{
		Verified: true,
		Issuer:   ekCert.Issuer.CommonName,
	}, nil
}

// GetVerificationStatus returns the current manufacturer CA verification status
// without re-verifying. If no CA certs are loaded, returns unverified.
func (s *TPMService) GetVerificationStatus() (retVal *VerificationStatus, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in GetVerificationStatus", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in GetVerificationStatus: %v", r)
		}
	}()

	return s.VerifyTPM()
}

// --- Helpers ---

// verifyCertAgainstTrustStore verifies a certificate against the trust store
// CAs for the given purpose. Returns true if verification succeeds.
func (s *TPMService) verifyCertAgainstTrustStore(cert *x509.Certificate, purpose truststore.CertPurpose) bool {
	if s.trustStore == nil || cert == nil {
		return false
	}

	purposeCerts, err := s.trustStore.CertificatesByPurpose(purpose)
	if err != nil || len(purposeCerts) == 0 {
		return false
	}

	pool := x509.NewCertPool()
	for _, ca := range purposeCerts {
		pool.AddCert(ca)
	}

	_, err = cert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	return err == nil
}

// certToPEM encodes an x509 certificate to PEM format.
func certToPEM(cert *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}))
}

// algoDisplayName returns a human-readable algorithm name that distinguishes
// RSA-SSA from RSA-PSS, which is critical for FIPS 140-2 compliance display.
func algoDisplayName(attrs *types.KeyAttributes) string {
	if attrs == nil {
		return "Unknown"
	}
	switch attrs.KeyAlgorithm {
	case x509.RSA:
		if types.IsRSAPSS(attrs.SignatureAlgorithm) {
			return "RSA-PSS"
		}
		return "RSA-SSA"
	case x509.ECDSA:
		return "ECDSA"
	case x509.Ed25519:
		return "Ed25519"
	default:
		return attrs.KeyAlgorithm.String()
	}
}

// keySize extracts the key size from KeyAttributes, handling RSA and ECC.
// Falls back to standard sizes when sub-attributes are not populated.
func keySize(attrs *types.KeyAttributes) int {
	if attrs == nil {
		return 0
	}
	if attrs.RSAAttributes != nil && attrs.RSAAttributes.KeySize > 0 {
		return attrs.RSAAttributes.KeySize
	}
	if attrs.ECCAttributes != nil && attrs.ECCAttributes.Curve != nil {
		return attrs.ECCAttributes.Curve.Params().BitSize
	}
	// Fallback to standard sizes when sub-attributes are not populated.
	switch attrs.KeyAlgorithm {
	case x509.RSA:
		return 2048
	case x509.ECDSA:
		return 256
	}
	return 0
}

// formatFingerprint formats a hash digest as colon-separated uppercase hex.
func formatFingerprint(hash []byte) string {
	parts := make([]string, len(hash))
	for i, b := range hash {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

// publicKeyBitSize returns the key size in bits for the given public key.
func publicKeyBitSize(pub interface{}) int {
	switch key := pub.(type) {
	case *rsa.PublicKey:
		return key.N.BitLen()
	case *ecdsa.PublicKey:
		return key.Curve.Params().BitSize
	case ed25519.PublicKey:
		return 256
	default:
		return 0
	}
}

// buildSubjectAltNames constructs a comma-separated SAN string from
// the certificate's DNS names, IP addresses, URIs, and email addresses.
func buildSubjectAltNames(cert *x509.Certificate) string {
	var parts []string
	for _, dns := range cert.DNSNames {
		parts = append(parts, "DNS:"+dns)
	}
	for _, ip := range cert.IPAddresses {
		parts = append(parts, "IP:"+ip.String())
	}
	for _, uri := range cert.URIs {
		parts = append(parts, "URI:"+uri.String())
	}
	for _, email := range cert.EmailAddresses {
		parts = append(parts, "email:"+email)
	}
	return strings.Join(parts, ", ")
}

// --- Certificate Parsing ---

// ParseCertificate parses a PEM-encoded X.509 certificate and returns
// detailed information suitable for frontend display.
func (s *TPMService) ParseCertificate(certPEM string) (retVal *CertificateDetails, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in ParseCertificate", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in ParseCertificate: %v", r)
		}
	}()

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, ErrTPMInvalidCert
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, ErrTPMInvalidCert
	}

	// Compute fingerprints from the raw DER bytes.
	sha256Hash := sha256.Sum256(cert.Raw)
	sha1Hash := sha1.Sum(cert.Raw)
	md5Hash := md5.Sum(cert.Raw)

	// Build extended key usage strings.
	extKeyUsageStrs := make([]string, len(cert.ExtKeyUsage))
	for i, eku := range cert.ExtKeyUsage {
		extKeyUsageStrs[i] = certstore.ExtKeyUsageToString(eku)
	}

	// Build extensions list.
	extensions := make([]ExtensionInfo, len(cert.Extensions))
	for i, ext := range cert.Extensions {
		extensions[i] = ExtensionInfo{
			OID:      ext.Id.String(),
			Name:     certstore.OIDToName(ext.Id),
			Critical: ext.Critical,
			Value:    certstore.ParseExtensionValue(ext),
		}
	}

	details := &CertificateDetails{
		// Identity
		Version:      cert.Version,
		SerialNumber: cert.SerialNumber.Text(16),

		// Subject
		SubjectCN:           cert.Subject.CommonName,
		SubjectOrg:          strings.Join(cert.Subject.Organization, ", "),
		SubjectOrgUnit:      strings.Join(cert.Subject.OrganizationalUnit, ", "),
		SubjectCountry:      strings.Join(cert.Subject.Country, ", "),
		SubjectProvince:     strings.Join(cert.Subject.Province, ", "),
		SubjectLocality:     strings.Join(cert.Subject.Locality, ", "),
		SubjectSerialNumber: cert.Subject.SerialNumber,

		// Issuer
		IssuerCN:      cert.Issuer.CommonName,
		IssuerOrg:     strings.Join(cert.Issuer.Organization, ", "),
		IssuerOrgUnit: strings.Join(cert.Issuer.OrganizationalUnit, ", "),
		IssuerCountry: strings.Join(cert.Issuer.Country, ", "),

		// Validity
		NotBefore: cert.NotBefore.Format(time.RFC3339),
		NotAfter:  cert.NotAfter.Format(time.RFC3339),

		// Signature
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		SignatureHex:       hex.EncodeToString(cert.Signature),

		// Fingerprints
		FingerprintSHA256: formatFingerprint(sha256Hash[:]),
		FingerprintSHA1:   formatFingerprint(sha1Hash[:]),
		FingerprintMD5:    formatFingerprint(md5Hash[:]),

		// Public Key
		PublicKeyAlgorithm: certstore.PublicKeyTypeString(cert.PublicKey),
		PublicKeySize:      publicKeyBitSize(cert.PublicKey),
		PublicKeyHex:       hex.EncodeToString(cert.RawSubjectPublicKeyInfo),
		SubjectKeyID:       hex.EncodeToString(cert.SubjectKeyId),

		// Basic constraints
		IsCA:           cert.IsCA,
		MaxPathLen:     cert.MaxPathLen,
		MaxPathLenZero: cert.MaxPathLenZero,

		// Key usage
		KeyUsage:    certstore.KeyUsageToString(cert.KeyUsage),
		ExtKeyUsage: extKeyUsageStrs,

		// SAN
		SubjectAltNames: buildSubjectAltNames(cert),

		// Extensions
		Extensions: extensions,
	}

	return details, nil
}

// --- PCR Policy CRUD ---

// ListPolicies returns all saved PCR policies. Returns an empty slice
// if no policies file exists yet.
func (s *TPMService) ListPolicies() (retVal []PCRPolicy, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in ListPolicies", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in ListPolicies: %v", r)
		}
	}()

	return s.loadPolicies(), nil
}

// CreatePolicy creates a new named PCR policy. The policy name must be
// non-empty and unique among existing policies.
func (s *TPMService) CreatePolicy(policy *PCRPolicy) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in CreatePolicy", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in CreatePolicy: %v", r)
		}
	}()

	if policy == nil || strings.TrimSpace(policy.Name) == "" {
		return ErrTPMInvalidPolicyName
	}

	policies := s.loadPolicies()
	for _, p := range policies {
		if p.Name == policy.Name {
			return ErrTPMPolicyExists
		}
	}

	policy.CreatedAt = time.Now().Format(time.RFC3339)

	// Attempt to capture initial PCR digests from the TPM so the policy
	// is immediately useful for viewing without a separate refresh step.
	if len(policy.PCRSelections) > 0 {
		tpm, tpmErr := s.getTPM()
		if tpmErr == nil {
			defer s.tpmAccessor.Release()
			digests := s.readPCRDigests(tpm, policy.PCRSelections)
			if len(digests) > 0 {
				policy.PCRDigests = digests
			}
		}
	}

	policies = append(policies, *policy)

	return s.savePolicies(policies)
}

// GetPolicyDeletionImpact returns the cascade effects of deleting a policy.
// It checks both PCR policies and composite policies, lists assigned key
// handles, and checks for a password store entry.
func (s *TPMService) GetPolicyDeletionImpact(name string) (retVal *PolicyDeletionImpact, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in GetPolicyDeletionImpact", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in GetPolicyDeletionImpact: %v", r)
		}
	}()

	impact := &PolicyDeletionImpact{
		PolicyName:         name,
		AssignedKeyHandles: make([]string, 0),
	}

	// Determine policy type.
	pcrPolicies := s.loadPolicies()
	for _, p := range pcrPolicies {
		if p.Name == name {
			impact.PolicyType = "pcr"
			break
		}
	}
	if impact.PolicyType == "" {
		compositePolicies := s.loadCompositePolicies()
		for _, p := range compositePolicies {
			if p.Name == name {
				impact.PolicyType = "composite"
				break
			}
		}
	}
	if impact.PolicyType == "" {
		return nil, ErrTPMPolicyNotFound
	}

	// Collect assigned key handles.
	assignments := s.loadAssignments()
	for _, a := range assignments {
		if a.PolicyName == name {
			impact.AssignedKeyHandles = append(impact.AssignedKeyHandles, a.KeyHandle)
		}
	}

	// Check for password store entry.
	if pwID, found := s.findPolicyPasswordEntry(name); found {
		impact.HasPasswordEntry = true
		impact.PasswordEntryID = pwID
	}

	return impact, nil
}

// DeletePolicy removes a PCR policy by name, cascading to remove all
// associated key assignments and any password store entry. Returns
// ErrTPMPolicyNotFound if no policy with the given name exists.
func (s *TPMService) DeletePolicy(name string) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in DeletePolicy", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in DeletePolicy: %v", r)
		}
	}()

	policies := s.loadPolicies()
	found := false
	filtered := make([]PCRPolicy, 0, len(policies))
	for _, p := range policies {
		if p.Name == name {
			found = true
			continue
		}
		filtered = append(filtered, p)
	}

	if !found {
		return ErrTPMPolicyNotFound
	}

	// Cascade: remove policy assignments.
	s.removeAssignmentsForPolicy(name)

	// Cascade: remove password store entry (best-effort).
	s.deletePolicyPassword(name)

	return s.savePolicies(filtered)
}

// GetPolicy returns a single PCR policy by name. Returns ErrTPMPolicyNotFound
// if no policy with the given name exists.
func (s *TPMService) GetPolicy(name string) (retVal *PCRPolicy, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in GetPolicy", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in GetPolicy: %v", r)
		}
	}()

	policies := s.loadPolicies()
	for _, p := range policies {
		if p.Name == name {
			return &p, nil
		}
	}

	return nil, ErrTPMPolicyNotFound
}

// loadPolicies reads the persisted PCR policies from disk.
func (s *TPMService) loadPolicies() []PCRPolicy {
	if s.dataDir == "" {
		return []PCRPolicy{}
	}

	filePath := filepath.Join(s.dataDir, pcrPoliciesFile)
	data, err := os.ReadFile(filePath)
	if err != nil {
		return []PCRPolicy{}
	}

	var policies []PCRPolicy
	if jsonErr := json.Unmarshal(data, &policies); jsonErr != nil {
		s.log.Warn("failed to parse PCR policies", "error", jsonErr)
		return []PCRPolicy{}
	}

	return policies
}

// savePolicies writes the PCR policies to disk.
func (s *TPMService) savePolicies(policies []PCRPolicy) error {
	if s.dataDir == "" {
		return ErrTPMDataDirNotSet
	}

	filePath := filepath.Join(s.dataDir, pcrPoliciesFile)
	data, err := json.MarshalIndent(policies, "", "  ")
	if err != nil {
		return fmt.Errorf("tpm_service: marshal policies: %w", err)
	}

	if writeErr := os.WriteFile(filePath, data, 0600); writeErr != nil {
		return fmt.Errorf("tpm_service: write policies: %w", writeErr)
	}

	return nil
}

// readPCRDigests reads current PCR values from the given TPM for the
// specified selections and returns a map of "bank:index" -> hex digest.
// Read errors for individual banks are silently skipped so that partial
// results are still returned.
func (s *TPMService) readPCRDigests(tpm tpm2pkg.TrustedPlatformModule, selections []PCRSelection) map[string]string {
	digests := make(map[string]string)

	// Group PCR selections by bank.
	bankPCRs := make(map[string][]uint)
	for _, sel := range selections {
		bankPCRs[sel.Bank] = append(bankPCRs[sel.Bank], uint(sel.Index))
	}

	for bank, pcrIndices := range bankPCRs {
		banks, readErr := tpm.ReadPCRs(pcrIndices)
		if readErr != nil {
			continue
		}
		for _, b := range banks {
			if strings.EqualFold(b.Algorithm, bank) {
				for _, pcr := range b.PCRs {
					key := fmt.Sprintf("%s:%d", bank, pcr.ID)
					digests[key] = fmt.Sprintf("%x", pcr.Value)
				}
			}
		}
	}

	return digests
}

// UpdatePolicy updates an existing PCR policy's selections, refreshes the
// PCR digests from the TPM, and persists the changes. The policy is located
// by its original name. Only the PCRSelections and Description fields are
// updated; the name and creation date are preserved.
func (s *TPMService) UpdatePolicy(name string, updated *PCRPolicy) (retVal *PCRPolicy, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in UpdatePolicy", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in UpdatePolicy: %v", r)
		}
	}()

	if strings.TrimSpace(name) == "" {
		return nil, ErrTPMInvalidPolicyName
	}
	if updated == nil {
		return nil, ErrTPMInvalidPolicyName
	}

	policies := s.loadPolicies()
	idx := -1
	for i, p := range policies {
		if p.Name == name {
			idx = i
			break
		}
	}
	if idx == -1 {
		return nil, ErrTPMPolicyNotFound
	}

	// Update mutable fields.
	policies[idx].Description = updated.Description
	policies[idx].PCRSelections = updated.PCRSelections
	policies[idx].UpdatedAt = time.Now().Format(time.RFC3339)

	// Re-capture PCR digests.
	if len(updated.PCRSelections) > 0 {
		tpm, tpmErr := s.getTPM()
		if tpmErr == nil {
			defer s.tpmAccessor.Release()
			digests := s.readPCRDigests(tpm, updated.PCRSelections)
			if len(digests) > 0 {
				policies[idx].PCRDigests = digests
			}
		}
	}

	if saveErr := s.savePolicies(policies); saveErr != nil {
		return nil, saveErr
	}

	result := policies[idx]
	return &result, nil
}

// RefreshPolicyPCRs reads current PCR values for the policy's selections and
// stores them as PCRDigests. Requires an open TPM connection.
func (s *TPMService) RefreshPolicyPCRs(name string) (retVal *PCRPolicy, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in RefreshPolicyPCRs", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in RefreshPolicyPCRs: %v", r)
		}
	}()

	policies := s.loadPolicies()
	idx := -1
	for i, p := range policies {
		if p.Name == name {
			idx = i
			break
		}
	}
	if idx == -1 {
		return nil, ErrTPMPolicyNotFound
	}

	tpm, err := s.getTPM()
	if err != nil {
		return nil, ErrTPMNotAvailable
	}
	defer s.tpmAccessor.Release()

	policy := &policies[idx]
	policy.PCRDigests = s.readPCRDigests(tpm, policy.PCRSelections)
	policy.UpdatedAt = time.Now().Format(time.RFC3339)

	if saveErr := s.savePolicies(policies); saveErr != nil {
		return nil, saveErr
	}

	return policy, nil
}

// ExportPolicy returns the policy as a tpm2-tools compatible JSON string.
func (s *TPMService) ExportPolicy(name string) (retVal string, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in ExportPolicy", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in ExportPolicy: %v", r)
		}
	}()

	policy, err := s.GetPolicy(name)
	if err != nil {
		return "", err
	}

	// Build tpm2-tools compatible export format
	export := map[string]interface{}{
		"name":       policy.Name,
		"created_at": policy.CreatedAt,
	}

	if policy.UpdatedAt != "" {
		export["updated_at"] = policy.UpdatedAt
	}

	// Extract unique bank and PCR indices
	if len(policy.PCRSelections) > 0 {
		export["pcr_bank"] = policy.PCRSelections[0].Bank
		indices := make([]int, 0, len(policy.PCRSelections))
		for _, sel := range policy.PCRSelections {
			indices = append(indices, sel.Index)
		}
		export["pcr_selections"] = indices
	}

	if len(policy.PCRDigests) > 0 {
		export["pcr_digests"] = policy.PCRDigests
	}

	data, err := json.MarshalIndent(export, "", "  ")
	if err != nil {
		return "", ErrTPMPolicyExportFailed
	}

	return string(data), nil
}

// ExportCompositePolicy returns a composite policy as a JSON string.
func (s *TPMService) ExportCompositePolicy(name string) (retVal string, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in ExportCompositePolicy", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in ExportCompositePolicy: %v", r)
		}
	}()

	cp, err := s.GetCompositePolicy(name)
	if err != nil {
		return "", err
	}

	export := map[string]interface{}{
		"name":       cp.Name,
		"operator":   cp.Operator,
		"elements":   cp.Elements,
		"created_at": cp.CreatedAt,
	}

	if cp.UpdatedAt != "" {
		export["updated_at"] = cp.UpdatedAt
	}
	if cp.Description != "" {
		export["description"] = cp.Description
	}
	if len(cp.PCRDigests) > 0 {
		export["pcr_digests"] = cp.PCRDigests
	}

	// Include pcr_bank and pcr_selections for tpm2-tools compatibility.
	for _, elem := range cp.Elements {
		if elem.Type == "pcr" && len(elem.PCRSelections) > 0 {
			bank := elem.PCRBank
			if bank == "" && len(elem.PCRSelections) > 0 {
				bank = elem.PCRSelections[0].Bank
			}
			if bank != "" {
				export["pcr_bank"] = bank
			}
			indices := make([]int, 0, len(elem.PCRSelections))
			for _, sel := range elem.PCRSelections {
				indices = append(indices, sel.Index)
			}
			export["pcr_selections"] = indices
			break
		}
	}

	data, err := json.MarshalIndent(export, "", "  ")
	if err != nil {
		return "", ErrTPMPolicyExportFailed
	}

	return string(data), nil
}

// SavePolicyToFile opens a native save dialog and writes the policy JSON
// to the selected file. The format is compatible with tpm2-tools.
func (s *TPMService) SavePolicyToFile(policyJSON string) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in SavePolicyToFile", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in SavePolicyToFile: %v", r)
		}
	}()

	filePath, err := wailsruntime.SaveFileDialog(s.ctx, wailsruntime.SaveDialogOptions{
		Title:           "Save Policy",
		DefaultFilename: "tpm-policy.json",
		Filters: []wailsruntime.FileFilter{
			{DisplayName: "JSON Files", Pattern: "*.json"},
			{DisplayName: "Binary Policy Digest", Pattern: "*.bin;*.dat"},
			{DisplayName: "All Files", Pattern: "*"},
		},
	})
	if err != nil {
		return err
	}
	if filePath == "" {
		return nil // User cancelled.
	}

	// If the user selected a .bin or .dat extension, export the raw policy
	// digest bytes (tpm2_createpolicy compatible binary format).
	ext := strings.ToLower(filepath.Ext(filePath))
	if ext == ".bin" || ext == ".dat" {
		return s.savePolicyDigestBinary(filePath, policyJSON)
	}

	return os.WriteFile(filePath, []byte(policyJSON), 0600)
}

// savePolicyDigestBinary computes a TPM2 policy digest from the JSON policy
// and writes the raw binary digest to disk. This is the same binary format
// produced by tpm2_createpolicy / tpm2_policypcr -L policy.bin.
// Delegates to pkg/tpm2.ComputePolicyPCRDigest for the actual computation.
func (s *TPMService) savePolicyDigestBinary(filePath, policyJSON string) error {
	var exported map[string]interface{}
	if err := json.Unmarshal([]byte(policyJSON), &exported); err != nil {
		return ErrTPMPolicyExportFailed
	}

	pcrBank := "sha256"
	if b, ok := exported["pcr_bank"].(string); ok {
		pcrBank = b
	}

	digestMap := make(map[string]string)
	if d, ok := exported["pcr_digests"].(map[string]interface{}); ok {
		for k, v := range d {
			if vs, ok := v.(string); ok {
				digestMap[k] = vs
			}
		}
	}

	var pcrIndices []int
	if sels, ok := exported["pcr_selections"].([]interface{}); ok {
		for _, v := range sels {
			if n, ok := v.(float64); ok {
				pcrIndices = append(pcrIndices, int(n))
			}
		}
	}

	policyDigest, err := tpm2pkg.ComputePolicyPCRDigest(pcrBank, pcrIndices, digestMap)
	if err != nil {
		return ErrTPMPolicyExportFailed
	}

	return os.WriteFile(filePath, policyDigest, 0600)
}

// ImportPolicyFile opens a native file dialog for the user to select a policy
// file (JSON or binary digest), reads it, and imports it as a new policy.
// Returns the name of the imported policy, or empty string if cancelled.
func (s *TPMService) ImportPolicyFile() (retVal string, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in ImportPolicyFile", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in ImportPolicyFile: %v", r)
		}
	}()

	filePath, err := wailsruntime.OpenFileDialog(s.ctx, wailsruntime.OpenDialogOptions{
		Title: "Import Policy",
		Filters: []wailsruntime.FileFilter{
			{DisplayName: "JSON Policy Files", Pattern: "*.json"},
			{DisplayName: "Binary Policy Digest", Pattern: "*.bin;*.dat"},
			{DisplayName: "All Files", Pattern: "*"},
		},
	})
	if err != nil {
		return "", err
	}
	if filePath == "" {
		return "", nil // User cancelled.
	}

	data, err := os.ReadFile(filePath) // #nosec G304 -- user-selected file via native dialog
	if err != nil {
		return "", err
	}

	// Detect format: JSON starts with '{', binary is raw bytes.
	trimmed := strings.TrimSpace(string(data))
	if len(trimmed) > 0 && trimmed[0] == '{' {
		return s.importJSONPolicy(data)
	}

	return s.importBinaryPolicyDigest(filePath, data)
}

// importJSONPolicy imports a JSON-format policy file (our export format or
// a compatible tpm2-tools JSON representation).
func (s *TPMService) importJSONPolicy(data []byte) (string, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return "", ErrTPMPolicyImportFailed
	}

	name, _ := raw["name"].(string)
	if name == "" {
		return "", ErrTPMInvalidPolicyName
	}

	// Detect if this is a composite policy (has "operator" and "elements" fields).
	if op, ok := raw["operator"].(string); ok && op != "" {
		return s.importCompositePolicy(raw)
	}

	// Import as a PCR policy.
	description, _ := raw["description"].(string)
	pcrBank, _ := raw["pcr_bank"].(string)
	if pcrBank == "" {
		pcrBank = "sha256"
	}

	var selections []PCRSelection
	if sels, ok := raw["pcr_selections"].([]interface{}); ok {
		for _, v := range sels {
			switch n := v.(type) {
			case float64:
				selections = append(selections, PCRSelection{Index: int(n), Bank: pcrBank})
			}
		}
	}

	digests := make(map[string]string)
	if d, ok := raw["pcr_digests"].(map[string]interface{}); ok {
		for k, v := range d {
			if vs, ok := v.(string); ok {
				digests[k] = vs
			}
		}
	}

	policy := PCRPolicy{
		Name:          name,
		Description:   description,
		PCRSelections: selections,
		PCRDigests:    digests,
	}

	if err := s.CreatePolicy(&policy); err != nil {
		return "", err
	}

	return name, nil
}

// importCompositePolicy imports a composite policy from a JSON map.
func (s *TPMService) importCompositePolicy(raw map[string]interface{}) (string, error) {
	data, err := json.Marshal(raw)
	if err != nil {
		return "", ErrTPMPolicyImportFailed
	}

	var cp CompositePolicy
	if err := json.Unmarshal(data, &cp); err != nil {
		return "", ErrTPMPolicyImportFailed
	}

	if cp.Name == "" {
		return "", ErrTPMInvalidPolicyName
	}

	cp.CreatedAt = time.Now().UTC().Format(time.RFC3339)

	policies := s.loadCompositePolicies()
	for _, existing := range policies {
		if existing.Name == cp.Name {
			return "", ErrTPMPolicyExists
		}
	}

	policies = append(policies, cp)
	if err := s.saveCompositePolicies(policies); err != nil {
		return "", err
	}

	return cp.Name, nil
}

// importBinaryPolicyDigest imports a raw binary policy digest file
// (as produced by tpm2_createpolicy). Since the binary format only contains
// the digest and no metadata, we generate a name from the filename and store
// it with the digest as a marker.
func (s *TPMService) importBinaryPolicyDigest(filePath string, data []byte) (string, error) {
	if len(data) == 0 {
		return "", ErrTPMPolicyImportFailed
	}

	// Generate a policy name from the filename (without extension).
	base := filepath.Base(filePath)
	ext := filepath.Ext(base)
	name := strings.TrimSuffix(base, ext)
	if name == "" {
		name = "imported-policy"
	}

	// Store the binary digest as a hex string in the policy metadata.
	digestHex := hex.EncodeToString(data)

	policy := PCRPolicy{
		Name:        name,
		Description: fmt.Sprintf("Imported binary policy digest from %s", base),
		PCRDigests:  map[string]string{"policy_digest": digestHex},
	}

	if err := s.CreatePolicy(&policy); err != nil {
		// If name conflict, append a timestamp.
		if errors.Is(err, ErrTPMPolicyExists) {
			policy.Name = fmt.Sprintf("%s-%d", name, time.Now().Unix())
			if err := s.CreatePolicy(&policy); err != nil {
				return "", err
			}
			return policy.Name, nil
		}
		return "", err
	}

	return name, nil
}

// --- Policy Assignments ---

// AssignPolicyToKey creates an assignment between a policy and a persistent key handle.
func (s *TPMService) AssignPolicyToKey(policyName, keyHandle string) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in AssignPolicyToKey", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in AssignPolicyToKey: %v", r)
		}
	}()

	if strings.TrimSpace(policyName) == "" {
		return ErrTPMInvalidPolicyName
	}
	if strings.TrimSpace(keyHandle) == "" {
		return ErrTPMInvalidHandle
	}

	// Verify policy exists — fall back to platform policy check.
	if _, err := s.GetPolicy(policyName); err != nil {
		if !s.isPlatformPolicyName(policyName) {
			return err
		}
	}

	assignments := s.loadAssignments()

	// Check for existing assignment to this handle
	for i, a := range assignments {
		if a.KeyHandle == keyHandle {
			assignments[i].PolicyName = policyName
			assignments[i].AssignedAt = time.Now().Format(time.RFC3339)
			return s.saveAssignments(assignments)
		}
	}

	assignments = append(assignments, PolicyAssignment{
		PolicyName: policyName,
		KeyHandle:  keyHandle,
		AssignedAt: time.Now().Format(time.RFC3339),
	})

	return s.saveAssignments(assignments)
}

// ListPolicyAssignments returns all policy-to-key assignments.
func (s *TPMService) ListPolicyAssignments() (retVal []PolicyAssignment, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in ListPolicyAssignments", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in ListPolicyAssignments: %v", r)
		}
	}()

	return s.loadAssignments(), nil
}

// UnassignPolicyFromKey removes a policy assignment from a key handle.
func (s *TPMService) UnassignPolicyFromKey(keyHandle string) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in UnassignPolicyFromKey", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in UnassignPolicyFromKey: %v", r)
		}
	}()

	assignments := s.loadAssignments()
	found := false
	filtered := make([]PolicyAssignment, 0, len(assignments))
	for _, a := range assignments {
		if a.KeyHandle == keyHandle {
			found = true
			continue
		}
		filtered = append(filtered, a)
	}

	if !found {
		return ErrTPMPolicyNotFound
	}

	return s.saveAssignments(filtered)
}

// loadAssignments reads policy assignments from disk.
func (s *TPMService) loadAssignments() []PolicyAssignment {
	if s.dataDir == "" {
		return []PolicyAssignment{}
	}

	filePath := filepath.Join(s.dataDir, policyAssignmentsFile)
	data, err := os.ReadFile(filePath)
	if err != nil {
		return []PolicyAssignment{}
	}

	var assignments []PolicyAssignment
	if jsonErr := json.Unmarshal(data, &assignments); jsonErr != nil {
		s.log.Warn("failed to parse policy assignments", "error", jsonErr)
		return []PolicyAssignment{}
	}

	return assignments
}

// saveAssignments writes policy assignments to disk.
func (s *TPMService) saveAssignments(assignments []PolicyAssignment) error {
	if s.dataDir == "" {
		return ErrTPMDataDirNotSet
	}

	filePath := filepath.Join(s.dataDir, policyAssignmentsFile)
	data, err := json.MarshalIndent(assignments, "", "  ")
	if err != nil {
		return fmt.Errorf("tpm_service: marshal assignments: %w", err)
	}

	return os.WriteFile(filePath, data, 0600)
}

// removeAssignmentsForPolicy removes all policy assignments referencing
// the given policy name. Errors are logged but not returned.
func (s *TPMService) removeAssignmentsForPolicy(policyName string) {
	assignments := s.loadAssignments()
	filtered := make([]PolicyAssignment, 0, len(assignments))
	removed := 0
	for _, a := range assignments {
		if a.PolicyName == policyName {
			removed++
			continue
		}
		filtered = append(filtered, a)
	}
	if removed > 0 {
		if err := s.saveAssignments(filtered); err != nil {
			s.log.Warn("failed to remove policy assignments",
				"policy", policyName, "error", err)
		}
	}
}

// --- Composite Policies ---

// compositePolicyPCRSelections extracts all PCR selections from a composite policy's elements.
func compositePolicyPCRSelections(policy *CompositePolicy) []PCRSelection {
	var selections []PCRSelection
	for _, elem := range policy.Elements {
		if elem.Type == "pcr" {
			for _, sel := range elem.PCRSelections {
				if sel.Bank == "" && elem.PCRBank != "" {
					sel.Bank = elem.PCRBank
				}
				selections = append(selections, sel)
			}
		}
	}
	return selections
}

// CreateCompositePolicy creates a new composite policy with AND/OR operator.
func (s *TPMService) CreateCompositePolicy(policy *CompositePolicy) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in CreateCompositePolicy", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in CreateCompositePolicy: %v", r)
		}
	}()

	if policy == nil || strings.TrimSpace(policy.Name) == "" {
		return ErrTPMInvalidPolicyName
	}

	if policy.Operator != "AND" && policy.Operator != "OR" && policy.Operator != "SINGLE" {
		return ErrTPMInvalidPolicyOperator
	}

	policies := s.loadCompositePolicies()
	for _, p := range policies {
		if p.Name == policy.Name {
			return ErrTPMPolicyExists
		}
	}

	policy.CreatedAt = time.Now().Format(time.RFC3339)

	// Capture PCR digests for PCR elements at creation time.
	pcrSelections := compositePolicyPCRSelections(policy)
	if len(pcrSelections) > 0 {
		tpm, tpmErr := s.getTPM()
		if tpmErr == nil {
			defer s.tpmAccessor.Release()
			digests := s.readPCRDigests(tpm, pcrSelections)
			if len(digests) > 0 {
				policy.PCRDigests = digests
			}
		}
	}

	policies = append(policies, *policy)

	return s.saveCompositePolicies(policies)
}

// CreateDefaultPlatformPolicy creates the standard platform integrity policy
// with PCRs 0 (firmware), 7 (secure boot), and 9 (kernel cmdline) using
// SHA-256. It uses the existing composite policy infrastructure so the policy
// appears in the TPM > Policies UI and is managed like any other policy.
// If the policy already exists this method returns nil (create-if-not-exists
// semantics).
func (s *TPMService) CreateDefaultPlatformPolicy() error {
	policy := &CompositePolicy{
		Name:        "Platform Policy",
		Description: "Default platform integrity policy (PCRs 0, 7, 9)",
		Operator:    "SINGLE",
		Elements: []PolicyElement{
			{
				Type:    "pcr",
				PCRBank: "sha256",
				PCRSelections: []PCRSelection{
					{Index: 0, Bank: "sha256"},
					{Index: 7, Bank: "sha256"},
					{Index: 9, Bank: "sha256"},
				},
			},
		},
	}
	err := s.CreateCompositePolicy(policy)
	if err != nil && errors.Is(err, ErrTPMPolicyExists) {
		return nil // Already exists, idempotent
	}
	return err
}

// ListCompositePolicies returns all composite policies.
func (s *TPMService) ListCompositePolicies() (retVal []CompositePolicy, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in ListCompositePolicies", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in ListCompositePolicies: %v", r)
		}
	}()

	return s.loadCompositePolicies(), nil
}

// ListCompositePoliciesWithDigests returns all composite policies with their
// Valid field populated by comparing saved PCR digests against current TPM values.
func (s *TPMService) ListCompositePoliciesWithDigests() (retVal []CompositePolicy, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in ListCompositePoliciesWithDigests", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in ListCompositePoliciesWithDigests: %v", r)
		}
	}()

	policies := s.loadCompositePolicies()
	if len(policies) == 0 {
		return policies, nil
	}

	// Collect unique PCR selections across all composite policies.
	bankPCRs := make(map[string]map[uint]struct{})
	for _, policy := range policies {
		for _, sel := range compositePolicyPCRSelections(&policy) {
			if _, ok := bankPCRs[sel.Bank]; !ok {
				bankPCRs[sel.Bank] = make(map[uint]struct{})
			}
			bankPCRs[sel.Bank][uint(sel.Index)] = struct{}{}
		}
	}

	if len(bankPCRs) == 0 {
		return policies, nil
	}

	tpm, err := s.getTPM()
	if err != nil {
		s.log.Debug("TPM unavailable for composite digest comparison, returning policies as-is")
		return policies, nil
	}
	defer s.tpmAccessor.Release()

	// Batch-read PCRs per bank.
	bankDigests := make(map[string]map[int]string)
	for bank, indexSet := range bankPCRs {
		indices := make([]uint, 0, len(indexSet))
		for idx := range indexSet {
			indices = append(indices, idx)
		}
		banks, readErr := tpm.ReadPCRs(indices)
		if readErr != nil {
			continue
		}
		normalizedBank, ok := bankNameMap[bank]
		if !ok {
			normalizedBank = strings.ToUpper(bank)
		}
		for _, b := range banks {
			if strings.EqualFold(b.Algorithm, normalizedBank) || strings.EqualFold(b.Algorithm, bank) {
				if bankDigests[bank] == nil {
					bankDigests[bank] = make(map[int]string)
				}
				for _, pcr := range b.PCRs {
					bankDigests[bank][int(pcr.ID)] = fmt.Sprintf("%x", pcr.Value)
				}
			}
		}
	}

	// Compare saved digests against current TPM values.
	for i := range policies {
		if len(policies[i].PCRDigests) == 0 {
			continue
		}
		allMatch := true
		for _, sel := range compositePolicyPCRSelections(&policies[i]) {
			key := fmt.Sprintf("%s:%d", sel.Bank, sel.Index)
			savedHex, hasSaved := policies[i].PCRDigests[key]
			if !hasSaved {
				allMatch = false
				break
			}
			currentHex := ""
			if bankMap, ok := bankDigests[sel.Bank]; ok {
				if d, ok := bankMap[sel.Index]; ok {
					currentHex = d
				}
			}
			if currentHex == "" {
				allMatch = false
				break
			}
			savedBytes, err1 := hex.DecodeString(savedHex)
			currentBytes, err2 := hex.DecodeString(currentHex)
			if err1 != nil || err2 != nil || subtle.ConstantTimeCompare(savedBytes, currentBytes) != 1 {
				allMatch = false
				break
			}
		}
		policies[i].Valid = &allMatch
	}

	return policies, nil
}

// GetCompositePolicy returns a single composite policy by name.
func (s *TPMService) GetCompositePolicy(name string) (retVal *CompositePolicy, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in GetCompositePolicy", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in GetCompositePolicy: %v", r)
		}
	}()

	policies := s.loadCompositePolicies()
	for _, p := range policies {
		if p.Name == name {
			return &p, nil
		}
	}

	return nil, ErrTPMPolicyNotFound
}

// DeleteCompositePolicy removes a composite policy by name, cascading to
// remove all associated key assignments and any password store entry.
func (s *TPMService) DeleteCompositePolicy(name string) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in DeleteCompositePolicy", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in DeleteCompositePolicy: %v", r)
		}
	}()

	policies := s.loadCompositePolicies()
	found := false
	filtered := make([]CompositePolicy, 0, len(policies))
	for _, p := range policies {
		if p.Name == name {
			found = true
			continue
		}
		filtered = append(filtered, p)
	}

	if !found {
		return ErrTPMPolicyNotFound
	}

	// Cascade: remove policy assignments.
	s.removeAssignmentsForPolicy(name)

	// Cascade: remove password store entry (best-effort).
	s.deletePolicyPassword(name)

	return s.saveCompositePolicies(filtered)
}

// RefreshCompositePolicyPCRs re-reads PCR values from the TPM for the
// named composite policy and persists the updated digests.
func (s *TPMService) RefreshCompositePolicyPCRs(name string) (retVal *CompositePolicy, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in RefreshCompositePolicyPCRs", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in RefreshCompositePolicyPCRs: %v", r)
		}
	}()

	policies := s.loadCompositePolicies()
	idx := -1
	for i, p := range policies {
		if p.Name == name {
			idx = i
			break
		}
	}
	if idx == -1 {
		return nil, ErrTPMPolicyNotFound
	}

	pcrSelections := compositePolicyPCRSelections(&policies[idx])
	if len(pcrSelections) == 0 {
		return &policies[idx], nil
	}

	tpm, err := s.getTPM()
	if err != nil {
		return nil, ErrTPMNotAvailable
	}
	defer s.tpmAccessor.Release()

	policies[idx].PCRDigests = s.readPCRDigests(tpm, pcrSelections)
	policies[idx].UpdatedAt = time.Now().Format(time.RFC3339)

	if saveErr := s.saveCompositePolicies(policies); saveErr != nil {
		return nil, saveErr
	}

	result := policies[idx]
	return &result, nil
}

// loadCompositePolicies reads composite policies from disk.
func (s *TPMService) loadCompositePolicies() []CompositePolicy {
	if s.dataDir == "" {
		return []CompositePolicy{}
	}

	filePath := filepath.Join(s.dataDir, compositePoliciesFile)
	data, err := os.ReadFile(filePath)
	if err != nil {
		return []CompositePolicy{}
	}

	var policies []CompositePolicy
	if jsonErr := json.Unmarshal(data, &policies); jsonErr != nil {
		s.log.Warn("failed to parse composite policies", "error", jsonErr)
		return []CompositePolicy{}
	}

	return policies
}

// saveCompositePolicies writes composite policies to disk.
func (s *TPMService) saveCompositePolicies(policies []CompositePolicy) error {
	if s.dataDir == "" {
		return ErrTPMDataDirNotSet
	}

	filePath := filepath.Join(s.dataDir, compositePoliciesFile)
	data, err := json.MarshalIndent(policies, "", "  ")
	if err != nil {
		return fmt.Errorf("tpm_service: marshal composite policies: %w", err)
	}

	return os.WriteFile(filePath, data, 0600)
}

// --- Phase 2: Auto-load PCR Digests ---

// ListPoliciesWithDigests returns all PCR policies with their current PCR
// digest values populated. It batch-reads PCRs from the TPM for all unique
// bank+index pairs across all policies. If the TPM is unavailable, policies
// are returned without digests (graceful degradation).
func (s *TPMService) ListPoliciesWithDigests() (retVal []PCRPolicy, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in ListPoliciesWithDigests", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in ListPoliciesWithDigests: %v", r)
		}
	}()

	policies := s.loadPolicies()
	if len(policies) == 0 {
		return policies, nil
	}

	tpm, err := s.getTPM()
	if err != nil {
		// Graceful degradation: return policies without digests.
		s.log.Debug("TPM unavailable for digest population, returning policies as-is")
		return policies, nil
	}
	defer s.tpmAccessor.Release()

	// Collect all unique bank+PCR index pairs across all policies.
	bankPCRs := make(map[string]map[uint]struct{})
	for _, policy := range policies {
		for _, sel := range policy.PCRSelections {
			if _, ok := bankPCRs[sel.Bank]; !ok {
				bankPCRs[sel.Bank] = make(map[uint]struct{})
			}
			bankPCRs[sel.Bank][uint(sel.Index)] = struct{}{}
		}
	}

	// Batch-read PCRs per bank.
	bankDigests := make(map[string]map[int]string) // bank -> (index -> hex digest)
	for bank, indexSet := range bankPCRs {
		indices := make([]uint, 0, len(indexSet))
		for idx := range indexSet {
			indices = append(indices, idx)
		}

		banks, readErr := tpm.ReadPCRs(indices)
		if readErr != nil {
			s.log.Debug("failed to read PCRs for bank", "bank", bank, "error", readErr)
			continue
		}

		// Find the matching bank in results.
		normalizedBank, ok := bankNameMap[bank]
		if !ok {
			normalizedBank = strings.ToUpper(bank)
		}

		for _, b := range banks {
			if strings.EqualFold(b.Algorithm, normalizedBank) || strings.EqualFold(b.Algorithm, bank) {
				if bankDigests[bank] == nil {
					bankDigests[bank] = make(map[int]string)
				}
				for _, pcr := range b.PCRs {
					bankDigests[bank][int(pcr.ID)] = fmt.Sprintf("%x", pcr.Value)
				}
			}
		}
	}

	// Compare saved digests against current TPM values and set Valid flag.
	for i := range policies {
		if len(policies[i].PCRDigests) == 0 {
			// No saved digests yet - validity unknown.
			continue
		}
		allMatch := true
		for _, sel := range policies[i].PCRSelections {
			key := fmt.Sprintf("%s:%d", sel.Bank, sel.Index)
			savedHex, hasSaved := policies[i].PCRDigests[key]
			if !hasSaved {
				allMatch = false
				break
			}
			currentHex := ""
			if bankMap, ok := bankDigests[sel.Bank]; ok {
				if d, ok := bankMap[sel.Index]; ok {
					currentHex = d
				}
			}
			if currentHex == "" {
				allMatch = false
				break
			}
			savedBytes, err1 := hex.DecodeString(savedHex)
			currentBytes, err2 := hex.DecodeString(currentHex)
			if err1 != nil || err2 != nil || subtle.ConstantTimeCompare(savedBytes, currentBytes) != 1 {
				allMatch = false
				break
			}
		}
		policies[i].Valid = &allMatch
	}

	return policies, nil
}

// --- Phase 2: Multi-Key Policy Assignment ---

// AssignPolicyToKeys creates assignments between a policy and multiple
// persistent key handles. Existing assignments for the same handles are updated.
func (s *TPMService) AssignPolicyToKeys(policyName string, keyHandles []string) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in AssignPolicyToKeys", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in AssignPolicyToKeys: %v", r)
		}
	}()

	if strings.TrimSpace(policyName) == "" {
		return ErrTPMInvalidPolicyName
	}
	if len(keyHandles) == 0 {
		return ErrTPMInvalidHandle
	}

	// Verify policy exists — fall back to platform policy check.
	if _, err := s.GetPolicy(policyName); err != nil {
		if !s.isPlatformPolicyName(policyName) {
			return err
		}
	}

	assignments := s.loadAssignments()
	now := time.Now().Format(time.RFC3339)

	// Build index of existing assignments by handle.
	handleIndex := make(map[string]int, len(assignments))
	for i, a := range assignments {
		handleIndex[a.KeyHandle] = i
	}

	for _, handle := range keyHandles {
		handle = strings.TrimSpace(handle)
		if handle == "" {
			continue
		}
		if idx, exists := handleIndex[handle]; exists {
			assignments[idx].PolicyName = policyName
			assignments[idx].AssignedAt = now
		} else {
			assignments = append(assignments, PolicyAssignment{
				PolicyName: policyName,
				KeyHandle:  handle,
				AssignedAt: now,
			})
		}
	}

	return s.saveAssignments(assignments)
}

// --- Phase 2: Password Policies + Compound Policies ---

// CreatePasswordPolicy creates a composite policy that uses password-only
// authorization. The password is stored as an argon2id hash. If
// saveToPasswordStore is true and a StaticPasswordService is configured,
// the raw password is also saved as a read-only entry in the password store
// under the "TPM Policies" folder.
func (s *TPMService) CreatePasswordPolicy(name, description, password string, saveToPasswordStore bool) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in CreatePasswordPolicy", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in CreatePasswordPolicy: %v", r)
		}
	}()

	if strings.TrimSpace(name) == "" {
		return ErrTPMInvalidPolicyName
	}
	if strings.TrimSpace(password) == "" {
		return ErrTPMInvalidAuth
	}

	passwordHash, err := hashPassword(password)
	if err != nil {
		return fmt.Errorf("tpm_service: hash password: %w", err)
	}

	policy := &CompositePolicy{
		Name:        name,
		Description: description,
		Operator:    "SINGLE",
		Elements: []PolicyElement{
			{
				Type:         "password",
				PasswordHash: passwordHash,
			},
		},
	}

	if err := s.CreateCompositePolicy(policy); err != nil {
		return err
	}

	if saveToPasswordStore {
		s.savePolicyPassword(name, "SINGLE", password)
	}

	return nil
}

// CreatePCROrPasswordPolicy creates a composite OR policy with two branches:
// a PCR-based branch and a password-based fallback branch. If
// saveToPasswordStore is true, the raw password is also saved as a read-only
// entry in the password store.
func (s *TPMService) CreatePCROrPasswordPolicy(name, description string, pcrSelections []PCRSelection, pcrBank, password string, saveToPasswordStore bool) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in CreatePCROrPasswordPolicy", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in CreatePCROrPasswordPolicy: %v", r)
		}
	}()

	if strings.TrimSpace(name) == "" {
		return ErrTPMInvalidPolicyName
	}
	if len(pcrSelections) == 0 {
		return ErrTPMInvalidPCRs
	}
	if strings.TrimSpace(password) == "" {
		return ErrTPMInvalidAuth
	}

	passwordHash, err := hashPassword(password)
	if err != nil {
		return fmt.Errorf("tpm_service: hash password: %w", err)
	}

	policy := &CompositePolicy{
		Name:        name,
		Description: description,
		Operator:    "OR",
		Elements: []PolicyElement{
			{
				Type:          "pcr",
				PCRSelections: pcrSelections,
				PCRBank:       pcrBank,
			},
			{
				Type:         "password",
				PasswordHash: passwordHash,
			},
		},
	}

	if err := s.CreateCompositePolicy(policy); err != nil {
		return err
	}

	if saveToPasswordStore {
		s.savePolicyPassword(name, "OR", password)
	}

	return nil
}

// CreatePCRAndPasswordPolicy creates a composite AND policy that requires BOTH
// PCR values to match AND the correct password to be provided. If
// saveToPasswordStore is true, the raw password is also saved as a read-only
// entry in the password store.
func (s *TPMService) CreatePCRAndPasswordPolicy(name, description string, pcrSelections []PCRSelection, pcrBank, password string, saveToPasswordStore bool) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in CreatePCRAndPasswordPolicy", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in CreatePCRAndPasswordPolicy: %v", r)
		}
	}()

	if strings.TrimSpace(name) == "" {
		return ErrTPMInvalidPolicyName
	}
	if len(pcrSelections) == 0 {
		return ErrTPMInvalidPCRs
	}
	if strings.TrimSpace(password) == "" {
		return ErrTPMInvalidAuth
	}

	passwordHash, err := hashPassword(password)
	if err != nil {
		return fmt.Errorf("tpm_service: hash password: %w", err)
	}

	policy := &CompositePolicy{
		Name:        name,
		Description: description,
		Operator:    "AND",
		Elements: []PolicyElement{
			{
				Type:          "pcr",
				PCRSelections: pcrSelections,
				PCRBank:       pcrBank,
			},
			{
				Type:         "password",
				PasswordHash: passwordHash,
			},
		},
	}

	if err := s.CreateCompositePolicy(policy); err != nil {
		return err
	}

	if saveToPasswordStore {
		s.savePolicyPassword(name, "AND", password)
	}

	return nil
}

// savePolicyPassword stores a policy's raw password as a read-only entry in
// the static password store. Failures are logged but not returned because the
// policy itself was already persisted successfully.
func (s *TPMService) savePolicyPassword(policyName, operator, rawPassword string) {
	if s.staticPWService == nil {
		s.log.Debug("static password service not configured, skipping policy password save")
		return
	}

	_, err := s.staticPWService.AddPasswordV2(AddPasswordParams{
		Name:       fmt.Sprintf("Policy: %s", policyName),
		Password:   rawPassword,
		FolderPath: policyPasswordFolder,
		Notes:      fmt.Sprintf("Composite policy '%s' (%s)", policyName, operator),
		ReadOnly:   true,
	})
	if err != nil {
		s.log.Warn("failed to save policy password to password store",
			"policy", policyName, "error", err)
	}
}

// deletePolicyPassword removes a policy's stored password from the password
// store (best-effort). It looks for a read-only entry named "Policy: <name>"
// in the TPM Policies folder.
func (s *TPMService) deletePolicyPassword(policyName string) {
	if s.staticPWService == nil {
		return
	}

	entries, err := s.staticPWService.ListPasswordsByFolder(policyPasswordFolder)
	if err != nil {
		s.log.Debug("failed to list policy passwords", "error", err)
		return
	}

	expectedName := fmt.Sprintf("Policy: %s", policyName)
	for _, entry := range entries {
		if entry.Name == expectedName {
			if delErr := s.staticPWService.DeletePasswordForce(entry.ID); delErr != nil {
				s.log.Warn("failed to delete policy password entry",
					"policy", policyName, "id", entry.ID, "error", delErr)
			}
			return
		}
	}
}

// findPolicyPasswordEntry returns the password entry ID for a given policy
// name, if one exists in the TPM Policies folder.
func (s *TPMService) findPolicyPasswordEntry(policyName string) (id string, found bool) {
	if s.staticPWService == nil {
		return "", false
	}

	entries, err := s.staticPWService.ListPasswordsByFolder(policyPasswordFolder)
	if err != nil {
		return "", false
	}

	expectedName := fmt.Sprintf("Policy: %s", policyName)
	for _, entry := range entries {
		if entry.Name == expectedName {
			return entry.ID, true
		}
	}
	return "", false
}

// VerifyPolicyPassword checks whether the given password matches the stored
// argon2id hash in a composite policy's password element.
func (s *TPMService) VerifyPolicyPassword(policyName, password string) (retVal bool, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in VerifyPolicyPassword", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in VerifyPolicyPassword: %v", r)
		}
	}()

	policy, err := s.GetCompositePolicy(policyName)
	if err != nil {
		return false, err
	}

	for _, elem := range policy.Elements {
		if elem.Type == "password" && elem.PasswordHash != "" {
			return verifyPassword(password, elem.PasswordHash), nil
		}
	}

	return false, ErrTPMInvalidPolicyType
}

// ComparePolicyPCRs compares a policy's saved PCR digests against the
// current live TPM values and returns a per-PCR comparison result.
func (s *TPMService) ComparePolicyPCRs(name string) (retVal *PolicyComparisonResult, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in ComparePolicyPCRs", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in ComparePolicyPCRs: %v", r)
		}
	}()

	if strings.TrimSpace(name) == "" {
		return nil, ErrTPMInvalidPolicyName
	}

	policy, err := s.GetPolicy(name)
	if err != nil {
		return nil, err
	}

	if len(policy.PCRDigests) == 0 {
		return nil, ErrTPMPolicyNoDigests
	}

	tpm, tpmErr := s.getTPM()
	if tpmErr != nil {
		return nil, ErrTPMNotAvailable
	}
	defer s.tpmAccessor.Release()

	currentDigests := s.readPCRDigests(tpm, policy.PCRSelections)

	result := &PolicyComparisonResult{
		PolicyName: name,
		AllMatch:   true,
		ComparedAt: time.Now().Format(time.RFC3339),
	}

	// Sort keys for deterministic output.
	keys := make([]string, 0, len(policy.PCRDigests))
	for k := range policy.PCRDigests {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		savedHex := policy.PCRDigests[key]
		currentHex := currentDigests[key]

		// Parse "bank:index" key.
		parts := strings.SplitN(key, ":", 2)
		bank := ""
		index := 0
		if len(parts) == 2 {
			bank = parts[0]
			fmt.Sscanf(parts[1], "%d", &index)
		}

		// Decode hex to bytes for constant-time comparison.
		savedBytes, decErr := hex.DecodeString(savedHex)
		if decErr != nil {
			savedBytes = []byte(savedHex)
		}
		currentBytes, decErr := hex.DecodeString(currentHex)
		if decErr != nil {
			currentBytes = []byte(currentHex)
		}

		match := subtle.ConstantTimeCompare(savedBytes, currentBytes) == 1

		entry := PCRComparisonEntry{
			Key:     key,
			Bank:    bank,
			Index:   index,
			Saved:   savedHex,
			Current: currentHex,
			Match:   match,
		}
		result.Entries = append(result.Entries, entry)
		result.TotalPCRs++

		if match {
			result.MatchCount++
		} else {
			result.MismatchCount++
			result.AllMatch = false
		}
	}

	return result, nil
}

// ReplayEventLog replays the TPM event log to compute expected PCR values,
// then compares them against the live TPM PCR state.
func (s *TPMService) ReplayEventLog() (retVal *EventLogReplayResult, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in ReplayEventLog", "recover", r)
			retErr = fmt.Errorf("tpm_service: panic in ReplayEventLog: %v", r)
		}
	}()

	tpm, err := s.getTPM()
	if err != nil {
		return nil, ErrTPMNotAvailable
	}
	defer s.tpmAccessor.Release()

	events, parseErr := tpm.ParsedEventLog()
	if parseErr != nil {
		return nil, ErrTPMEventLogNotFound
	}

	result := &EventLogReplayResult{
		Success:    true,
		EventCount: len(events),
	}

	if len(events) == 0 {
		return result, nil
	}

	// Compute expected PCR values from event log replay.
	computed := tpm2pkg.CalculatePCRs(events)

	// Collect all PCR indices across all banks.
	allIndices := make(map[uint]struct{})
	for _, bankPCRs := range computed {
		for idx := range bankPCRs {
			allIndices[uint(idx)] = struct{}{}
		}
	}

	indexList := make([]uint, 0, len(allIndices))
	for idx := range allIndices {
		indexList = append(indexList, idx)
	}

	// Read actual PCR values from TPM.
	actualBanks, readErr := tpm.ReadPCRs(indexList)
	if readErr != nil {
		return nil, ErrTPMEventLogReplayFailed
	}

	// Index actual PCR values by lowercase bank name and PCR index.
	actual := make(map[string]map[int][]byte)
	for _, bank := range actualBanks {
		normalizedBank := strings.ToLower(bank.Algorithm)
		if actual[normalizedBank] == nil {
			actual[normalizedBank] = make(map[int][]byte)
		}
		for _, pcr := range bank.PCRs {
			actual[normalizedBank][int(pcr.ID)] = pcr.Value
		}
	}

	// Track banks seen for the result.
	bankSet := make(map[string]struct{})

	// Compare computed vs actual for each bank and PCR index.
	// Sort banks and indices for deterministic output.
	bankNames := make([]string, 0, len(computed))
	for bankName := range computed {
		bankNames = append(bankNames, bankName)
	}
	sort.Strings(bankNames)

	for _, bankName := range bankNames {
		bankPCRs := computed[bankName]
		bankSet[bankName] = struct{}{}

		indices := make([]int, 0, len(bankPCRs))
		for idx := range bankPCRs {
			indices = append(indices, idx)
		}
		sort.Ints(indices)

		for _, idx := range indices {
			expectedBytes := bankPCRs[idx]
			expectedHex := fmt.Sprintf("%x", expectedBytes)

			var actualBytes []byte
			actualHex := ""
			if actualBank, ok := actual[bankName]; ok {
				if val, ok := actualBank[idx]; ok {
					actualBytes = val
					actualHex = fmt.Sprintf("%x", val)
				}
			}

			match := len(actualBytes) > 0 &&
				subtle.ConstantTimeCompare(expectedBytes, actualBytes) == 1

			entry := PCRReplayEntry{
				PCRIndex: idx,
				Bank:     bankName,
				Expected: expectedHex,
				Actual:   actualHex,
				Match:    match,
			}
			result.Entries = append(result.Entries, entry)
			result.TotalPCRs++

			if match {
				result.MatchCount++
			} else {
				result.MismatchCount++
				result.Success = false
			}
		}
	}

	banks := make([]string, 0, len(bankSet))
	for b := range bankSet {
		banks = append(banks, b)
	}
	sort.Strings(banks)
	result.Banks = banks

	return result, nil
}

// TPMClearRequest contains parameters for clearing the TPM.
type TPMClearRequest struct {
	// LockoutAuth is the lockout hierarchy authorization password.
	// Required for standard clear, ignored for force clear.
	LockoutAuth string `json:"lockout_auth"`

	// Force uses UEFI Physical Presence Interface for clear.
	// Requires privilege elevation and triggers a system reboot.
	Force bool `json:"force"`

	// SudoPassword is the user's sudo password for privilege elevation.
	// Required only when Force is true.
	SudoPassword string `json:"sudo_password"`
}

// TPMClearResult contains the result of a TPM clear operation.
type TPMClearResult struct {
	// Success indicates whether the clear operation succeeded.
	Success bool `json:"success"`

	// Message provides additional information about the result.
	Message string `json:"message"`

	// RebootRequired indicates that a system reboot is required to complete
	// the operation (for force clear via PPI).
	RebootRequired bool `json:"reboot_required"`
}

// ClearTPM clears the TPM state using standard TPM2_Clear command.
// This requires lockout hierarchy authorization. Use ForceClearTPM if
// the hierarchy authorization is unknown or locked out.
func (s *TPMService) ClearTPM(req *TPMClearRequest) (*TPMClearResult, error) {
	if req == nil {
		return nil, errors.New("tpm_service: nil clear request")
	}

	if req.Force {
		return s.ForceClearTPM(req)
	}

	s.log.Info("clearing TPM via standard TPM2_Clear")

	tpm, err := s.getTPM()
	if err != nil {
		s.log.Error("failed to open TPM for clear", "error", err)
		return nil, fmt.Errorf("%w: %v", ErrTPMClearFailed, err)
	}
	defer s.tpmAccessor.Release()

	lockoutAuth := []byte(req.LockoutAuth)
	if err := tpm.Clear(lockoutAuth); err != nil {
		s.log.Error("TPM clear failed", "error", err)

		// Provide helpful error message
		if isTPMAuthError(err) {
			return &TPMClearResult{
				Success: false,
				Message: "TPM clear failed: incorrect lockout authorization. " +
					"If you don't know the lockout password, use force clear " +
					"which will clear the TPM via UEFI firmware on next reboot.",
			}, ErrTPMClearFailed
		}

		return &TPMClearResult{
			Success: false,
			Message: fmt.Sprintf("TPM clear failed: %v", err),
		}, ErrTPMClearFailed
	}

	s.log.Info("TPM cleared successfully")
	return &TPMClearResult{
		Success: true,
		Message: "TPM cleared successfully. You may need to re-provision the TPM.",
	}, nil
}

// ForceClearTPM clears the TPM using UEFI Physical Presence Interface (PPI).
// This schedules a TPM clear at the next system reboot and does not require
// knowing the hierarchy authorization passwords. Requires privilege elevation.
func (s *TPMService) ForceClearTPM(req *TPMClearRequest) (*TPMClearResult, error) {
	if req == nil {
		return nil, errors.New("tpm_service: nil clear request")
	}

	s.log.Info("scheduling TPM force clear via UEFI PPI")

	// Use sudo elevator with the user's password
	elevator := NewSudoElevator(req.SudoPassword)
	if !elevator.IsAvailable() {
		return &TPMClearResult{
			Success: false,
			Message: "Privilege elevation not available. sudo is required for force clear.",
		}, ErrSudoUnavailable
	}

	// Run: xkey tpm clear --force --yes
	args := []string{"tpm", "clear", "--force", "--yes"}

	s.log.Debug("executing elevated TPM force clear", "args", args)
	_, err := elevator.Run(args, nil)
	if err != nil {
		s.log.Error("TPM force clear failed", "error", err)

		// Check for specific error types
		if errors.Is(err, ErrElevationDenied) {
			return &TPMClearResult{
				Success: false,
				Message: "Privilege elevation denied. Please provide the correct sudo password.",
			}, ErrTPMForceClearFailed
		}

		return &TPMClearResult{
			Success: false,
			Message: fmt.Sprintf("TPM force clear failed: %v", err),
		}, ErrTPMForceClearFailed
	}

	s.log.Info("TPM force clear scheduled, reboot required")
	return &TPMClearResult{
		Success:        true,
		Message:        "TPM clear scheduled via UEFI firmware. Please reboot to complete the operation.",
		RebootRequired: true,
	}, nil
}
