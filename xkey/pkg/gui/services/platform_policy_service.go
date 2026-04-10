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
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	tpm2pkg "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// Platform policy errors.
var (
	ErrPolicyNotConfigured   = errors.New("platform_policy: not configured")
	ErrPolicyTPMNotAvailable = errors.New("platform_policy: TPM not available")
	ErrPolicyInvalidPCRs     = errors.New("platform_policy: invalid PCR selection")
	ErrPolicyInvalidBank     = errors.New("platform_policy: invalid PCR bank")
	ErrPolicySaveFailed      = errors.New("platform_policy: failed to save policy")
	ErrPolicyLoadFailed      = errors.New("platform_policy: failed to load policy")
	ErrPolicyVerifyFailed    = errors.New("platform_policy: verification failed")
	ErrPolicyExportFailed    = errors.New("platform_policy: export failed")
	ErrPolicyNoClient        = errors.New("platform_policy: no connected client")
	ErrPolicyInvalidName     = errors.New("platform_policy: policy name is required")
)

// PolicyType represents the type of seal policy applied to a blob.
type PolicyType string

const (
	PolicyTypeNone           PolicyType = "none"
	PolicyTypePassword       PolicyType = "password"
	PolicyTypePlatformPolicy PolicyType = "platform_policy"
	PolicyTypeCustomPCR      PolicyType = "custom_pcr"
)

// policyTypeMap provides O(1) validation of policy type strings.
var policyTypeMap = map[string]PolicyType{
	"none":            PolicyTypeNone,
	"password":        PolicyTypePassword,
	"platform_policy": PolicyTypePlatformPolicy,
	"custom_pcr":      PolicyTypeCustomPCR,
}

// maxPCRIndex is the maximum valid PCR index (0-23).
const maxPCRIndex = 23

// PlatformPolicyDefinition is the on-disk representation of a platform policy.
type PlatformPolicyDefinition struct {
	PCRs      []int          `json:"pcrs"`
	Bank      string         `json:"bank"`
	Digests   map[int]string `json:"digests"` // PCR index -> hex digest at capture time
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

// PlatformPolicyStatus is the frontend-facing representation of a platform policy.
type PlatformPolicyStatus struct {
	Configured bool   `json:"configured"`
	PCRs       []int  `json:"pcrs"`
	Bank       string `json:"bank"`
	Valid      bool   `json:"valid"` // current PCRs match stored digests
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at"`
}

// PolicyVerifyResult is the frontend-facing result of a server-side
// policy verification via the transport client.
type PolicyVerifyResult struct {
	Name    string `json:"name"`
	Valid   bool   `json:"valid"`
	Message string `json:"message,omitempty"`
}

// PlatformPolicyService manages platform PCR-based policies for data sealing.
type PlatformPolicyService struct {
	ctx         context.Context
	log         *slog.Logger
	policyPath  string
	policy      atomic.Pointer[PlatformPolicyDefinition]
	tpmAccessor *TPMAccessor
	client      atomic.Pointer[transport.Client]
}

// NewPlatformPolicyService creates a new PlatformPolicyService that stores
// the policy definition at the given file path.
func NewPlatformPolicyService(policyPath string) *PlatformPolicyService {
	return &PlatformPolicyService{
		log:        slog.Default().With("component", "platform_policy_service"),
		policyPath: policyPath,
	}
}

// SetContext is called by the Wails startup lifecycle hook.
func (s *PlatformPolicyService) SetContext(ctx context.Context) {
	s.ctx = ctx
}

// SetTPMAccessor sets the shared TPMAccessor used for serialized TPM access.
func (s *PlatformPolicyService) SetTPMAccessor(a *TPMAccessor) {
	s.tpmAccessor = a
}

// SetClient sets the transport client used for server-side policy operations
// (verify, export via the xkms server).
func (s *PlatformPolicyService) SetClient(c transport.Client) {
	s.client.Store(&c)
}

// getPolicyClient returns the current transport client or ErrPolicyNoClient.
func (s *PlatformPolicyService) getPolicyClient() (transport.Client, error) {
	ptr := s.client.Load()
	if ptr == nil {
		return nil, ErrPolicyNoClient
	}
	return *ptr, nil
}

// getPolicyContext returns the service context, falling back to
// context.Background if no context has been set.
func (s *PlatformPolicyService) getPolicyContext() context.Context {
	if s.ctx != nil {
		return s.ctx
	}
	return context.Background()
}

// Initialize loads the policy from disk if a policy file exists.
func (s *PlatformPolicyService) Initialize() error {
	data, err := os.ReadFile(s.policyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return ErrPolicyLoadFailed
	}

	var def PlatformPolicyDefinition
	if err := json.Unmarshal(data, &def); err != nil {
		return ErrPolicyLoadFailed
	}

	s.policy.Store(&def)
	return nil
}

// GetStatus returns the current platform policy status, including whether
// the live PCR values match the stored digests.
func (s *PlatformPolicyService) GetStatus() (retStatus *PlatformPolicyStatus, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in GetStatus", "recover", r)
			retStatus = nil
			retErr = fmt.Errorf("platform_policy_service: panic in GetStatus: %v", r)
		}
	}()

	def := s.policy.Load()
	if def == nil {
		return &PlatformPolicyStatus{Configured: false}, nil
	}

	valid, _ := s.verifyDigests(def)

	return &PlatformPolicyStatus{
		Configured: true,
		PCRs:       def.PCRs,
		Bank:       def.Bank,
		Valid:      valid,
		CreatedAt:  def.CreatedAt.Format(time.RFC3339),
		UpdatedAt:  def.UpdatedAt.Format(time.RFC3339),
	}, nil
}

// CreatePolicy captures the current PCR values from the TPM and stores
// them as the platform policy definition.
func (s *PlatformPolicyService) CreatePolicy(pcrs []int, bank string) (retStatus *PlatformPolicyStatus, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in CreatePolicy", "recover", r)
			retStatus = nil
			retErr = fmt.Errorf("platform_policy_service: panic in CreatePolicy: %v", r)
		}
	}()

	if err := validatePCRSelection(pcrs); err != nil {
		return nil, err
	}
	if err := validatePCRBank(bank); err != nil {
		return nil, err
	}

	digests, err := s.readPCRDigests(pcrs, bank)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	def := &PlatformPolicyDefinition{
		PCRs:      pcrs,
		Bank:      bank,
		Digests:   digests,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := s.savePolicy(def); err != nil {
		return nil, err
	}

	s.policy.Store(def)

	return &PlatformPolicyStatus{
		Configured: true,
		PCRs:       def.PCRs,
		Bank:       def.Bank,
		Valid:      true,
		CreatedAt:  def.CreatedAt.Format(time.RFC3339),
		UpdatedAt:  def.UpdatedAt.Format(time.RFC3339),
	}, nil
}

// UpdatePolicy re-captures the PCR values from the TPM for the given
// PCR selection and bank.
func (s *PlatformPolicyService) UpdatePolicy(pcrs []int, bank string) (retStatus *PlatformPolicyStatus, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in UpdatePolicy", "recover", r)
			retStatus = nil
			retErr = fmt.Errorf("platform_policy_service: panic in UpdatePolicy: %v", r)
		}
	}()

	existing := s.policy.Load()
	if existing == nil {
		return nil, ErrPolicyNotConfigured
	}

	if err := validatePCRSelection(pcrs); err != nil {
		return nil, err
	}
	if err := validatePCRBank(bank); err != nil {
		return nil, err
	}

	digests, err := s.readPCRDigests(pcrs, bank)
	if err != nil {
		return nil, err
	}

	def := &PlatformPolicyDefinition{
		PCRs:      pcrs,
		Bank:      bank,
		Digests:   digests,
		CreatedAt: existing.CreatedAt,
		UpdatedAt: time.Now(),
	}

	if err := s.savePolicy(def); err != nil {
		return nil, err
	}

	s.policy.Store(def)

	return &PlatformPolicyStatus{
		Configured: true,
		PCRs:       def.PCRs,
		Bank:       def.Bank,
		Valid:      true,
		CreatedAt:  def.CreatedAt.Format(time.RFC3339),
		UpdatedAt:  def.UpdatedAt.Format(time.RFC3339),
	}, nil
}

// DeletePolicy removes the platform policy from memory and disk.
func (s *PlatformPolicyService) DeletePolicy() error {
	existing := s.policy.Load()
	if existing == nil {
		return ErrPolicyNotConfigured
	}

	s.policy.Store(nil)

	if err := os.Remove(s.policyPath); err != nil && !os.IsNotExist(err) {
		return ErrPolicySaveFailed
	}

	return nil
}

// VerifyPolicy compares stored PCR digests to the live TPM PCR values
// using constant-time comparison.
func (s *PlatformPolicyService) VerifyPolicy() (retValid bool, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in VerifyPolicy", "recover", r)
			retValid = false
			retErr = fmt.Errorf("platform_policy_service: panic in VerifyPolicy: %v", r)
		}
	}()

	def := s.policy.Load()
	if def == nil {
		return false, ErrPolicyNotConfigured
	}

	return s.verifyDigests(def)
}

// GetPolicyPCRs returns the PCR indices and bank configured in the
// current platform policy. This is used by SealService when sealing
// with PolicyTypePlatformPolicy.
func (s *PlatformPolicyService) GetPolicyPCRs() ([]int, string, error) {
	def := s.policy.Load()
	if def == nil {
		return nil, "", ErrPolicyNotConfigured
	}
	return def.PCRs, def.Bank, nil
}

// ExportPolicy produces a tpm2-tools compatible JSON export of the
// platform policy definition, matching the format from TPMService.ExportPolicy.
func (s *PlatformPolicyService) ExportPolicy() (retVal string, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in ExportPolicy", "recover", r)
			retErr = fmt.Errorf("platform_policy_service: panic in ExportPolicy: %v", r)
		}
	}()

	def := s.policy.Load()
	if def == nil {
		return "", ErrPolicyNotConfigured
	}

	// Build tpm2-tools compatible export format.
	export := map[string]interface{}{
		"name":       "Platform Policy",
		"created_at": def.CreatedAt.Format(time.RFC3339),
		"updated_at": def.UpdatedAt.Format(time.RFC3339),
		"pcr_bank":   def.Bank,
	}

	if len(def.PCRs) > 0 {
		export["pcr_selections"] = def.PCRs
	}

	if len(def.Digests) > 0 {
		digests := make(map[string]string, len(def.Digests))
		for idx, hexVal := range def.Digests {
			key := fmt.Sprintf("%s:%d", def.Bank, idx)
			digests[key] = hexVal
		}
		export["pcr_digests"] = digests
	}

	data, err := json.MarshalIndent(export, "", "  ")
	if err != nil {
		return "", ErrPolicyExportFailed
	}

	return string(data), nil
}

// GetPlatformPolicyAsPCRPolicy returns the platform policy in PCRPolicy format
// so it can be displayed alongside other PCR policies in the UI. Returns nil
// if no platform policy is configured.
func (s *PlatformPolicyService) GetPlatformPolicyAsPCRPolicy() (retPolicy *PCRPolicy, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in GetPlatformPolicyAsPCRPolicy", "recover", r)
			retPolicy = nil
			retErr = fmt.Errorf("platform_policy_service: panic in GetPlatformPolicyAsPCRPolicy: %v", r)
		}
	}()

	def := s.policy.Load()
	if def == nil {
		return nil, nil
	}

	policy := s.definitionToPCRPolicy(def)

	// Validate saved digests against current TPM values.
	valid := s.validatePlatformPolicyDigests(def)
	policy.Valid = valid

	return policy, nil
}

// RefreshPlatformPolicyPCRs re-reads the PCR values for the platform policy
// from the TPM and returns the updated policy in PCRPolicy format.
func (s *PlatformPolicyService) RefreshPlatformPolicyPCRs() (retPolicy *PCRPolicy, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in RefreshPlatformPolicyPCRs", "recover", r)
			retPolicy = nil
			retErr = fmt.Errorf("platform_policy_service: panic in RefreshPlatformPolicyPCRs: %v", r)
		}
	}()

	def := s.policy.Load()
	if def == nil {
		return nil, ErrPolicyNotConfigured
	}

	digests, err := s.readPCRDigests(def.PCRs, def.Bank)
	if err != nil {
		return nil, err
	}

	def.Digests = digests
	def.UpdatedAt = time.Now()

	if err := s.savePolicy(def); err != nil {
		return nil, err
	}

	s.policy.Store(def)

	policy := s.definitionToPCRPolicy(def)
	valid := true
	policy.Valid = &valid

	return policy, nil
}

// ---------------------------------------------------------------------------
// Server-side policy operations (via transport client)
// ---------------------------------------------------------------------------

// VerifyPolicyRemote verifies a named policy against the current PCR values
// via the xkms server's PolicyVerify endpoint. This is used for server-managed
// policies (as opposed to local platform policies verified directly via TPM).
func (s *PlatformPolicyService) VerifyPolicyRemote(name string) (*PolicyVerifyResult, error) {
	if name == "" {
		return nil, ErrPolicyInvalidName
	}

	client, err := s.getPolicyClient()
	if err != nil {
		return nil, err
	}

	resp, err := client.PolicyVerify(s.getPolicyContext(), &transport.PolicyVerifyRequest{
		Name: name,
	})
	if err != nil {
		return nil, err
	}

	return &PolicyVerifyResult{
		Name:    resp.Name,
		Valid:   resp.Valid,
		Message: resp.Message,
	}, nil
}

// ExportPolicyRemote exports a named policy from the xkms server via the
// PolicyExport endpoint. Returns the exported policy data as a string.
func (s *PlatformPolicyService) ExportPolicyRemote(name string) (string, error) {
	if name == "" {
		return "", ErrPolicyInvalidName
	}

	client, err := s.getPolicyClient()
	if err != nil {
		return "", err
	}

	resp, err := client.PolicyExport(s.getPolicyContext(), &transport.PolicyExportRequest{
		Name: name,
	})
	if err != nil {
		return "", err
	}

	return resp.Data, nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// definitionToPCRPolicy converts a PlatformPolicyDefinition to a PCRPolicy.
func (s *PlatformPolicyService) definitionToPCRPolicy(def *PlatformPolicyDefinition) *PCRPolicy {
	selections := make([]PCRSelection, len(def.PCRs))
	for i, idx := range def.PCRs {
		selections[i] = PCRSelection{Index: idx, Bank: def.Bank}
	}

	digests := make(map[string]string, len(def.Digests))
	for idx, hexVal := range def.Digests {
		key := fmt.Sprintf("%s:%d", def.Bank, idx)
		digests[key] = hexVal
	}

	return &PCRPolicy{
		Name:             "Platform Policy",
		Description:      "Platform PCR-based seal/unseal policy",
		PCRSelections:    selections,
		PCRDigests:       digests,
		CreatedAt:        def.CreatedAt.Format(time.RFC3339),
		UpdatedAt:        def.UpdatedAt.Format(time.RFC3339),
		IsPlatformPolicy: true,
	}
}

// validatePlatformPolicyDigests compares the saved digests in a platform policy
// definition against the current TPM PCR values. Returns a *bool pointer:
// nil if the TPM is unavailable (unknown state), true if all digests match,
// false if any mismatch is detected.
func (s *PlatformPolicyService) validatePlatformPolicyDigests(def *PlatformPolicyDefinition) *bool {
	if len(def.Digests) == 0 {
		return nil
	}

	valid, err := s.verifyDigests(def)
	if err != nil {
		// TPM unavailable or verification error - validity unknown.
		return nil
	}

	return &valid
}

// getTPM acquires the shared TPM accessor and returns the current TPM instance.
// Callers MUST call s.tpmAccessor.Release() after a successful call.
func (s *PlatformPolicyService) getTPM() (tpm2pkg.TrustedPlatformModule, error) {
	if s.tpmAccessor == nil {
		return nil, ErrPolicyTPMNotAvailable
	}
	tpm, err := s.tpmAccessor.Acquire()
	if err != nil {
		return nil, ErrPolicyTPMNotAvailable
	}
	return tpm, nil
}

// readPCRDigests reads the specified PCRs from the TPM and returns a
// map of PCR index to hex-encoded digest.
func (s *PlatformPolicyService) readPCRDigests(pcrs []int, bank string) (retDigests map[int]string, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in readPCRDigests", "recover", r)
			retDigests = nil
			retErr = fmt.Errorf("platform_policy_service: panic in readPCRDigests: %v", r)
		}
	}()

	tpm, err := s.getTPM()
	if err != nil {
		return nil, err
	}
	defer s.tpmAccessor.Release()

	pcrUints := make([]uint, len(pcrs))
	for i, p := range pcrs {
		pcrUints[i] = uint(p)
	}

	banks, err := tpm.ReadPCRs(pcrUints)
	if err != nil {
		return nil, ErrPolicyVerifyFailed
	}

	normalizedBank := strings.ToLower(bank)
	digests := make(map[int]string, len(pcrs))

	for _, b := range banks {
		bankAlg := strings.ToLower(b.Algorithm)
		// Handle common TPM algorithm naming (e.g., "SHA256" -> "sha256").
		bankAlg = normalizeBankAlg(bankAlg)

		if bankAlg != normalizedBank {
			continue
		}

		for _, pcr := range b.PCRs {
			for _, requestedPCR := range pcrs {
				if int(pcr.ID) == requestedPCR {
					digests[requestedPCR] = hex.EncodeToString(pcr.Value)
				}
			}
		}
	}

	return digests, nil
}

// verifyDigests compares stored digests against live TPM PCR values.
func (s *PlatformPolicyService) verifyDigests(def *PlatformPolicyDefinition) (retValid bool, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in verifyDigests", "recover", r)
			retValid = false
			retErr = fmt.Errorf("platform_policy_service: panic in verifyDigests: %v", r)
		}
	}()

	liveDigests, err := s.readPCRDigests(def.PCRs, def.Bank)
	if err != nil {
		return false, err
	}

	for pcrIndex, storedHex := range def.Digests {
		liveHex, ok := liveDigests[pcrIndex]
		if !ok {
			return false, nil
		}

		storedBytes, err := hex.DecodeString(storedHex)
		if err != nil {
			return false, ErrPolicyVerifyFailed
		}
		liveBytes, err := hex.DecodeString(liveHex)
		if err != nil {
			return false, ErrPolicyVerifyFailed
		}

		if subtle.ConstantTimeCompare(storedBytes, liveBytes) != 1 {
			return false, nil
		}
	}

	return true, nil
}

// savePolicy atomically writes the policy definition to disk using
// write-to-tmp then rename.
func (s *PlatformPolicyService) savePolicy(def *PlatformPolicyDefinition) error {
	dir := filepath.Dir(s.policyPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return ErrPolicySaveFailed
	}

	data, err := json.MarshalIndent(def, "", "  ")
	if err != nil {
		return ErrPolicySaveFailed
	}

	tmpPath := s.policyPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return ErrPolicySaveFailed
	}

	if err := os.Rename(tmpPath, s.policyPath); err != nil {
		return ErrPolicySaveFailed
	}

	return nil
}

// validatePCRSelection validates that PCR indices are non-empty and within
// the valid range of 0-23.
func validatePCRSelection(pcrs []int) error {
	if len(pcrs) == 0 {
		return ErrPolicyInvalidPCRs
	}
	for _, p := range pcrs {
		if p < 0 || p > maxPCRIndex {
			return ErrPolicyInvalidPCRs
		}
	}
	return nil
}

// validatePCRBank validates that the bank name is one of the supported
// PCR hash algorithms. Uses the validPCRBanks map defined in tpm_service.go.
func validatePCRBank(bank string) error {
	if _, ok := validPCRBanks[bank]; !ok {
		return ErrPolicyInvalidBank
	}
	return nil
}

// normalizeBankAlg normalizes TPM PCR bank algorithm names to lowercase
// simple names (e.g., "SHA256" -> "sha256", "SHA386" -> "sha384").
func normalizeBankAlg(alg string) string {
	lower := strings.ToLower(alg)
	// Handle the SHA386 variant that some TPMs report.
	if lower == "sha386" {
		return "sha384"
	}
	return lower
}
