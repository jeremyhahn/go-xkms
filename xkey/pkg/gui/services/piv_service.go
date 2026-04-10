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
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/backendregistry"
)

// PIV service errors.
var (
	ErrPIVInvalidSlot      = errors.New("piv_service: invalid slot identifier")
	ErrPIVInvalidAlgorithm = errors.New("piv_service: invalid algorithm")
	ErrPIVNoCertificate    = errors.New("piv_service: no certificate in slot")
	ErrPIVInvalidPEM       = errors.New("piv_service: invalid PEM data")
	ErrPIVInvalidSubject   = errors.New("piv_service: invalid CSR subject")
	ErrPIVClientNotSet     = errors.New("piv_service: server connection required for PIV operations")
	ErrPIVLocalUnavailable = errors.New("piv_service: local PIV storage not initialized")
)

// PIVSlot describes a PIV slot and any certificate it holds.
type PIVSlot struct {
	Slot               string `json:"slot"`
	Name               string `json:"name"`
	Description        string `json:"description"`
	HasCert            bool   `json:"has_cert"`
	Subject            string `json:"subject,omitempty"`
	Issuer             string `json:"issuer,omitempty"`
	Algorithm          string `json:"algorithm,omitempty"`
	KeySize            int    `json:"key_size,omitempty"`
	NotBefore          string `json:"not_before,omitempty"`
	NotAfter           string `json:"not_after,omitempty"`
	Fingerprint        string `json:"fingerprint,omitempty"`
	Backend            string `json:"backend,omitempty"`
	BackendDisplayName string `json:"backend_display_name,omitempty"`
}

// PIVCertificate holds the details of a certificate in a PIV slot.
type PIVCertificate struct {
	Slot         string `json:"slot"`
	Subject      string `json:"subject"`
	Issuer       string `json:"issuer"`
	SerialNumber string `json:"serial_number"`
	Algorithm    string `json:"algorithm"`
	KeySize      int    `json:"key_size"`
	NotBefore    string `json:"not_before"`
	NotAfter     string `json:"not_after"`
	Fingerprint  string `json:"fingerprint"`
	PEM          string `json:"pem"`
}

// PIVGenerateKeyResult holds the result of a PIV key generation operation.
type PIVGenerateKeyResult struct {
	Slot      string `json:"slot"`
	Algorithm string `json:"algorithm"`
	KeySize   int    `json:"key_size"`
	Subject   string `json:"subject"`
	Message   string `json:"message"`
}

// CSRSubject holds X.509 distinguished name fields for CSR generation.
type CSRSubject struct {
	CommonName         string `json:"common_name"`
	Organization       string `json:"organization"`
	OrganizationalUnit string `json:"organizational_unit"`
	Country            string `json:"country"`
	State              string `json:"state"`
	Locality           string `json:"locality"`
}

// pivSlotMeta is a static table for the primary PIV slots.
var pivSlotMeta = []struct {
	Slot        string
	Name        string
	Description string
}{
	{"9a", "PIV Authentication", "Card and cardholder authentication"},
	{"9c", "Digital Signature", "Document signing and non-repudiation"},
	{"9d", "Key Management", "Key establishment and transport"},
	{"9e", "Card Authentication", "Card authentication without interaction"},
	{"f9", "Attestation", "Device attestation certificate"},
}

// pivSlotNameMap provides O(1) lookup of slot names from the pivSlotMeta table.
var pivSlotNameMap = func() map[string]string {
	m := make(map[string]string, len(pivSlotMeta))
	for _, meta := range pivSlotMeta {
		m[meta.Slot] = meta.Name
	}
	return m
}()

// validAlgorithms provides O(1) validation of PIV key generation algorithms.
var validAlgorithms = map[string]struct{}{
	"RSA2048": {},
	"RSA4096": {},
	"ECCP256": {},
	"ECCP384": {},
	"Ed25519": {},
}

// algorithmToLocalName maps GUI algorithm names to the lowercase names
// expected by the xkms PIV manager's key generators.
var algorithmToLocalName = map[string]string{
	"RSA2048": "rsa2048",
	"RSA4096": "rsa4096",
	"ECCP256": "ecdsap256",
	"ECCP384": "ecdsap384",
	"Ed25519": "ed25519",
}

// CCIDBackendNotifier is called when the active PIV backend changes,
// allowing the CCID bridge to update its default backend in lockstep.
type CCIDBackendNotifier func(backend string)

// PIVService exposes PIV certificate and key operations to the frontend.
// When a remote transport client is set, operations delegate to the remote
// server. Otherwise, operations fall back to the local PIV manager backed
// by file-based certificate storage.
type PIVService struct {
	ctx           context.Context
	client        transport.Client
	backend       string
	localBackend  string
	localEnabled  bool
	ccidNotifier  CCIDBackendNotifier
	registry      backendregistry.Registry
	backendTypeFn func(id string) string // resolves backend ID to xkms type (e.g., "softhsm" → "pkcs11")
}

// NewPIVService creates a new PIVService. The client parameter may be nil,
// in which case the service falls back to local PIV operations if the local
// PIV manager has been initialized. The backend parameter identifies the
// server-side backend to use for remote PIV operations.
func NewPIVService(client transport.Client, backend string) *PIVService {
	return &PIVService{
		client:       client,
		backend:      backend,
		localBackend: "software",
	}
}

// SetContext is called by the Wails startup lifecycle hook.
func (s *PIVService) SetContext(ctx context.Context) {
	s.ctx = ctx
}

// SetClient sets the transport client for remote PIV operations.
func (s *PIVService) SetClient(client transport.Client) {
	s.client = client
}

// SetLocalEnabled enables or disables local PIV operations.
func (s *PIVService) SetLocalEnabled(enabled bool) {
	s.localEnabled = enabled
}

// SetLocalBackend configures the local backend name used when delegating
// to the xkms PIV manager.
func (s *PIVService) SetLocalBackend(backend string) {
	s.localBackend = backend
}

// SetCCIDNotifier registers a callback that is invoked whenever the active
// PIV backend changes, keeping the CCID bridge in sync with the GUI selection.
func (s *PIVService) SetCCIDNotifier(fn CCIDBackendNotifier) {
	s.ccidNotifier = fn
}

// SetRegistry sets the backend registry for resolving backend display names.
func (s *PIVService) SetRegistry(registry backendregistry.Registry) {
	s.registry = registry
}

// SetBackendTypeFn sets a function that resolves a backend ID to its xkms
// backend type. This is used as a fallback when the registry doesn't contain
// the backend (e.g., auto-detected PKCS#11 modules from AdminService).
func (s *PIVService) SetBackendTypeFn(fn func(id string) string) {
	s.backendTypeFn = fn
}

// SetBackend switches the backend used for PIV operations at runtime.
// This updates both the remote and local backend names, allowing the
// frontend to change the active backend before performing operations.
// If a CCID notifier is registered, it is called to keep the CCID bridge
// in sync with the selected backend.
func (s *PIVService) SetBackend(backend string) {
	s.backend = backend
	s.localBackend = backend
	if s.ccidNotifier != nil {
		s.ccidNotifier(backend)
	}
}

// GetBackend returns the name of the remote backend currently in use for
// PIV operations.
func (s *PIVService) GetBackend() string {
	return s.backend
}

// IsConnected reports whether the PIV service can perform operations,
// either through a remote transport client or via local storage.
func (s *PIVService) IsConnected() bool {
	return s.client != nil || s.localEnabled
}

// GetSlots returns all primary PIV slots with their current certificate status.
func (s *PIVService) GetSlots() ([]PIVSlot, error) {
	if s.client != nil {
		return s.getRemoteSlots()
	}
	if s.localEnabled {
		return s.getLocalSlots()
	}
	return s.emptySlots(), nil
}

// GetCertificate returns the certificate details for a given slot.
func (s *PIVService) GetCertificate(slot string) (*PIVCertificate, error) {
	if slot == "" {
		return nil, ErrPIVInvalidSlot
	}
	slot = strings.ToLower(slot)

	if s.client != nil {
		return s.getRemoteCertificate(slot)
	}
	if s.localEnabled {
		return s.getLocalCertificate(slot)
	}
	return nil, ErrPIVClientNotSet
}

// GenerateKey generates a new key pair in the specified PIV slot. A
// self-signed certificate is created and stored alongside the private key.
func (s *PIVService) GenerateKey(slot string, algorithm string) (*PIVGenerateKeyResult, error) {
	if slot == "" {
		return nil, ErrPIVInvalidSlot
	}
	slot = strings.ToLower(slot)

	if _, ok := validAlgorithms[algorithm]; !ok {
		return nil, ErrPIVInvalidAlgorithm
	}

	if s.client != nil {
		return s.generateRemoteKey(slot, algorithm)
	}
	if s.localEnabled {
		return s.generateLocalKey(slot, algorithm)
	}
	return nil, ErrPIVClientNotSet
}

// ImportCertificate imports a PEM-encoded certificate into the specified slot.
func (s *PIVService) ImportCertificate(slot string, certPEM []byte) error {
	if slot == "" {
		return ErrPIVInvalidSlot
	}
	slot = strings.ToLower(slot)
	if len(certPEM) == 0 {
		return ErrPIVInvalidPEM
	}

	if s.client != nil {
		return s.client.ImportPIVCertificate(s.ctx, &transport.StorePIVCertificateRequest{
			Backend:     s.backend,
			Slot:        slot,
			Certificate: certPEM,
			Format:      "pem",
		})
	}
	if s.localEnabled {
		return xkms.StorePIVCertificate(s.ctx, &transport.StorePIVCertificateRequest{
			Backend:     s.resolveXKMSBackendName(s.localBackend),
			Slot:        slot,
			Certificate: certPEM,
			Format:      "pem",
		})
	}
	return ErrPIVClientNotSet
}

// ExportCertificate exports the PEM-encoded certificate from the specified slot.
func (s *PIVService) ExportCertificate(slot string) ([]byte, error) {
	if slot == "" {
		return nil, ErrPIVInvalidSlot
	}
	slot = strings.ToLower(slot)

	if s.client != nil {
		resp, err := s.client.ExportPIVCertificate(s.ctx, &transport.GetPIVCertificateRequest{
			Backend: s.backend,
			Slot:    slot,
			Format:  "pem",
		})
		if err != nil {
			return nil, ErrPIVNoCertificate
		}
		return resp.Certificate, nil
	}
	if s.localEnabled {
		resp, err := xkms.ExportPIVCertificate(s.ctx, &transport.GetPIVCertificateRequest{
			Backend: s.resolveXKMSBackendName(s.localBackend),
			Slot:    slot,
			Format:  "pem",
		})
		if err != nil {
			return nil, ErrPIVNoCertificate
		}
		return resp.Certificate, nil
	}
	return nil, ErrPIVClientNotSet
}

// GenerateCSR creates a Certificate Signing Request for the specified slot.
func (s *PIVService) GenerateCSR(slot string, subject *CSRSubject) ([]byte, error) {
	if slot == "" {
		return nil, ErrPIVInvalidSlot
	}
	slot = strings.ToLower(slot)
	if subject == nil || subject.CommonName == "" {
		return nil, ErrPIVInvalidSubject
	}

	if s.client != nil {
		resp, err := s.client.GeneratePIVCSR(s.ctx, &transport.GeneratePIVCSRRequest{
			Backend: s.backend,
			Slot:    slot,
			Subject: subject.CommonName,
		})
		if err != nil {
			return nil, err
		}
		return resp.CSR, nil
	}
	if s.localEnabled {
		resp, err := xkms.GeneratePIVCSR(s.ctx, &transport.GeneratePIVCSRRequest{
			Backend: s.resolveXKMSBackendName(s.localBackend),
			Slot:    slot,
			Subject: subject.CommonName,
		})
		if err != nil {
			return nil, err
		}
		return resp.CSR, nil
	}
	return nil, ErrPIVClientNotSet
}

// DeleteCertificate removes the certificate from the specified slot.
func (s *PIVService) DeleteCertificate(slot string) error {
	if slot == "" {
		return ErrPIVInvalidSlot
	}
	slot = strings.ToLower(slot)

	if s.client != nil {
		err := s.client.DeletePIVCertificate(s.ctx, &transport.DeletePIVCertificateRequest{
			Backend: s.backend,
			Slot:    slot,
		})
		if err != nil {
			return ErrPIVNoCertificate
		}
		return nil
	}
	if s.localEnabled {
		err := xkms.DeletePIVCertificate(s.ctx, &transport.DeletePIVCertificateRequest{
			Backend: s.resolveXKMSBackendName(s.localBackend),
			Slot:    slot,
		})
		if err != nil {
			return ErrPIVNoCertificate
		}
		return nil
	}
	return ErrPIVClientNotSet
}

// --- Remote operation methods ---

// getRemoteSlots fetches slot status from the remote server.
func (s *PIVService) getRemoteSlots() ([]PIVSlot, error) {
	resp, err := s.client.ListPIVSlots(s.ctx, &transport.ListPIVSlotsRequest{
		Backend: s.backend,
	})
	if err != nil {
		return nil, err
	}
	return s.mapTransportSlots(resp), nil
}

// getRemoteCertificate fetches a certificate from the remote server.
func (s *PIVService) getRemoteCertificate(slot string) (*PIVCertificate, error) {
	resp, err := s.client.GetPIVCertificate(s.ctx, &transport.GetPIVCertificateRequest{
		Backend: s.backend,
		Slot:    slot,
		Format:  "pem",
	})
	if err != nil {
		return nil, ErrPIVNoCertificate
	}
	return parseCertificateResponse(slot, resp.Certificate)
}

// generateRemoteKey generates a key pair on the remote server.
func (s *PIVService) generateRemoteKey(slot, algorithm string) (*PIVGenerateKeyResult, error) {
	slotName, ok := pivSlotNameMap[slot]
	if !ok {
		slotName = "PIV Key " + slot
	}

	resp, err := s.client.GeneratePIVKey(s.ctx, &transport.GeneratePIVKeyRequest{
		Backend:   s.backend,
		Slot:      slot,
		Algorithm: algorithm,
		Subject:   slotName,
	})
	if err != nil {
		return nil, err
	}
	return buildKeyResult(slot, algorithm, resp.Certificate), nil
}

// --- Local operation methods ---

// getLocalSlots fetches slot status from the local PIV manager.
func (s *PIVService) getLocalSlots() ([]PIVSlot, error) {
	resp, err := xkms.ListPIVSlots(s.ctx, &transport.ListPIVSlotsRequest{
		Backend: s.resolveXKMSBackendName(s.localBackend),
	})
	if err != nil {
		slog.Debug("PIV getLocalSlots failed", "backend", s.localBackend, "error", err)
		// Return empty slot metadata in degraded mode.
		return s.emptySlots(), nil
	}
	// Remap the backend field from xkms category name back to the
	// frontend-facing local backend ID so filtering works correctly.
	for i := range resp.Slots {
		resp.Slots[i].Backend = s.localBackend
	}
	return s.mapTransportSlots(resp), nil
}

// getLocalCertificate retrieves a certificate from the local PIV manager.
func (s *PIVService) getLocalCertificate(slot string) (*PIVCertificate, error) {
	resp, err := xkms.GetPIVCertificate(s.ctx, &transport.GetPIVCertificateRequest{
		Backend: s.resolveXKMSBackendName(s.localBackend),
		Slot:    slot,
		Format:  "pem",
	})
	if err != nil {
		return nil, ErrPIVNoCertificate
	}
	return parseCertificateResponse(slot, resp.Certificate)
}

// generateLocalKey generates a key pair using the local PIV manager.
func (s *PIVService) generateLocalKey(slot, algorithm string) (*PIVGenerateKeyResult, error) {
	slotName, ok := pivSlotNameMap[slot]
	if !ok {
		slotName = "PIV Key " + slot
	}

	// Translate the GUI algorithm name to the local PIV manager format.
	localAlg, ok := algorithmToLocalName[algorithm]
	if !ok {
		return nil, ErrPIVInvalidAlgorithm
	}

	resp, err := xkms.GeneratePIVKey(s.ctx, &transport.GeneratePIVKeyRequest{
		Backend:   s.resolveXKMSBackendName(s.localBackend),
		Slot:      slot,
		Algorithm: localAlg,
		Subject:   slotName,
	})
	if err != nil {
		return nil, err
	}
	return buildKeyResult(slot, algorithm, resp.Certificate), nil
}

// --- Shared helpers ---

// emptySlots returns the primary PIV slot descriptors without certificate data.
func (s *PIVService) emptySlots() []PIVSlot {
	slots := make([]PIVSlot, 0, len(pivSlotMeta))
	for _, meta := range pivSlotMeta {
		slots = append(slots, PIVSlot{
			Slot:               meta.Slot,
			Name:               meta.Name,
			Description:        meta.Description,
			HasCert:            false,
			Backend:            s.localBackend,
			BackendDisplayName: s.resolveBackendDisplayName(s.localBackend),
		})
	}
	return slots
}

// mapTransportSlots converts a ListPIVSlotsResponse into the GUI slot model,
// merging certificate status from the response with static slot metadata.
func (s *PIVService) mapTransportSlots(resp *transport.ListPIVSlotsResponse) []PIVSlot {
	slotStatusMap := make(map[string]transport.PIVSlotStatus, len(resp.Slots))
	for _, status := range resp.Slots {
		slotStatusMap[status.Slot] = status
	}

	slots := make([]PIVSlot, 0, len(pivSlotMeta))
	for _, meta := range pivSlotMeta {
		slot := PIVSlot{
			Slot:        meta.Slot,
			Name:        meta.Name,
			Description: meta.Description,
			HasCert:     false,
		}

		if status, ok := slotStatusMap[meta.Slot]; ok {
			slot.HasCert = status.HasCert
			slot.Subject = status.Subject
			slot.Issuer = status.Issuer
			slot.Algorithm = status.Algorithm
			slot.KeySize = status.KeySize
			slot.NotAfter = status.NotAfter
			slot.Fingerprint = status.Fingerprint
			slot.Backend = status.Backend
			slot.BackendDisplayName = s.resolveBackendDisplayName(status.Backend)
		}

		slots = append(slots, slot)
	}
	return slots
}

// resolveXKMSBackendName translates a backend registry ID to the xkms
// library backend name using the registry's category field. For example,
// "tpm2-default" resolves to "tpm2". When no registry is set or the ID
// is not found, falls back to the backend type resolver (which queries
// AdminService.ListBackends for auto-detected backends not in the registry).
// If all lookups fail, the raw ID is returned unchanged.
func (s *PIVService) resolveXKMSBackendName(registryID string) string {
	if s.registry != nil {
		if rb, err := s.registry.Get(registryID); err == nil {
			return string(rb.Category)
		}
	}
	if s.backendTypeFn != nil {
		if bt := s.backendTypeFn(registryID); bt != "" {
			return bt
		}
	}
	return registryID
}

// resolveBackendDisplayName looks up the display name for a backend ID from
// the registry. Returns an empty string if the registry is nil or the backend
// is not found.
func (s *PIVService) resolveBackendDisplayName(backendID string) string {
	if s.registry == nil || backendID == "" {
		return ""
	}
	rb, err := s.registry.Get(backendID)
	if err != nil {
		return ""
	}
	return rb.DisplayName
}

// parseCertificateResponse decodes a PEM certificate response into a PIVCertificate.
func parseCertificateResponse(slot string, certData []byte) (*PIVCertificate, error) {
	block, _ := pem.Decode(certData)
	if block == nil {
		return nil, ErrPIVNoCertificate
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, ErrPIVNoCertificate
	}

	fingerprint := sha256.Sum256(cert.Raw)

	return &PIVCertificate{
		Slot:         slot,
		Subject:      cert.Subject.String(),
		Issuer:       cert.Issuer.String(),
		SerialNumber: cert.SerialNumber.Text(16),
		Algorithm:    certAlgorithmName(cert),
		KeySize:      certKeySize(cert),
		NotBefore:    cert.NotBefore.Format(time.RFC3339),
		NotAfter:     cert.NotAfter.Format(time.RFC3339),
		Fingerprint:  hex.EncodeToString(fingerprint[:]),
		PEM:          string(certData),
	}, nil
}

// buildKeyResult extracts metadata from a PEM certificate returned by a
// key generation operation and produces a PIVGenerateKeyResult.
func buildKeyResult(slot, algorithm string, certPEM []byte) *PIVGenerateKeyResult {
	var keySize int
	var subject string
	if len(certPEM) > 0 {
		block, _ := pem.Decode(certPEM)
		if block != nil {
			cert, parseErr := x509.ParseCertificate(block.Bytes)
			if parseErr == nil {
				keySize = certKeySize(cert)
				subject = cert.Subject.String()
			}
		}
	}
	return &PIVGenerateKeyResult{
		Slot:      slot,
		Algorithm: algorithm,
		KeySize:   keySize,
		Subject:   subject,
		Message:   fmt.Sprintf("Key generated in slot %s using %s", slot, algorithm),
	}
}

// certAlgorithmName returns the human-readable name for a certificate's public key algorithm.
func certAlgorithmName(cert *x509.Certificate) string {
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		return "RSA"
	case x509.ECDSA:
		return "ECDSA"
	case x509.Ed25519:
		return "Ed25519"
	default:
		return "Unknown"
	}
}

// certKeySize returns the key size in bits for a certificate's public key.
func certKeySize(cert *x509.Certificate) int {
	switch pub := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		return pub.Curve.Params().BitSize
	case interface{ Size() int }:
		// RSA keys implement Size() returning bytes.
		return pub.Size() * 8
	default:
		if cert.PublicKeyAlgorithm == x509.Ed25519 {
			return 256
		}
		return 0
	}
}
