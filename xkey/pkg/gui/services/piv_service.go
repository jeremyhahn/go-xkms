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

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"

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
	HasKey             bool   `json:"has_key"`
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

// PIVGenerateOptions holds the parameters for advanced PIV key generation.
type PIVGenerateOptions struct {
	Slot         string `json:"slot"`
	Algorithm    string `json:"algorithm"`
	Subject      string `json:"subject"`
	Organization string `json:"organization"`
	Country      string `json:"country"`
	OutputFormat string `json:"output_format"` // "self-signed", "public-key", "csr", "ca-signed"
	ValidityDays int    `json:"validity_days"`
	CASource     string `json:"ca_source"` // "local" or "remote"
}

// PIVGenerateAdvancedResult holds the result of an advanced PIV key generation.
type PIVGenerateAdvancedResult struct {
	Slot         string `json:"slot"`
	Algorithm    string `json:"algorithm"`
	KeySize      int    `json:"key_size"`
	Subject      string `json:"subject"`
	Message      string `json:"message"`
	OutputFormat string `json:"output_format"`
	CertPEM      string `json:"cert_pem,omitempty"`
	PublicKeyPEM string `json:"public_key_pem,omitempty"`
	CSRPEM       string `json:"csr_pem,omitempty"`
	ChainPEM     string `json:"chain_pem,omitempty"`
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
	ctx              context.Context
	client           transport.Client
	backend          string
	localBackend     string
	localEnabled     bool
	localCAAvailable bool
	ccidNotifier     CCIDBackendNotifier
	registry         backendregistry.Registry
	backendTypeFn    func(id string) string // resolves backend ID to xkms type (e.g., "softhsm" -> "pkcs11")
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

// SetLocalCAAvailable sets whether a local CA is available for certificate signing.
func (s *PIVService) SetLocalCAAvailable(available bool) {
	s.localCAAvailable = available
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

// GetCAAvailability returns which CA sources are available for certificate signing.
func (s *PIVService) GetCAAvailability() map[string]bool {
	return map[string]bool{
		"local":  s.localEnabled && s.localCAAvailable,
		"remote": s.client != nil,
	}
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

// GenerateKeyAdvanced generates a PIV key with full control over output format,
// subject fields, validity, and CA source. This is the enhanced version of
// GenerateKey that supports all four output formats.
func (s *PIVService) GenerateKeyAdvanced(opts PIVGenerateOptions) (*PIVGenerateAdvancedResult, error) {
	if opts.Slot == "" {
		return nil, ErrPIVInvalidSlot
	}
	opts.Slot = strings.ToLower(opts.Slot)

	if _, ok := validAlgorithms[opts.Algorithm]; !ok {
		return nil, ErrPIVInvalidAlgorithm
	}

	// Map GUI algorithm to xkms name.
	localAlg, ok := algorithmToLocalName[opts.Algorithm]
	if !ok {
		return nil, ErrPIVInvalidAlgorithm
	}

	// Build the transport request.
	req := &transport.GeneratePIVKeyRequest{
		Slot:         opts.Slot,
		Algorithm:    localAlg,
		Subject:      opts.Subject,
		Organization: opts.Organization,
		Country:      opts.Country,
		OutputFormat: opts.OutputFormat,
		ValidityDays: opts.ValidityDays,
	}

	var resp *transport.GeneratePIVKeyResponse
	var err error

	switch {
	case s.client != nil && opts.CASource == "remote":
		// Remote mode: send to server, server handles everything.
		req.Backend = s.backend
		resp, err = s.client.GeneratePIVKey(s.ctx, req)
	case s.localEnabled:
		// Local mode: use xkms in-process.
		req.Backend = s.resolveXKMSBackendName(s.localBackend)
		req.Algorithm = localAlg
		resp, err = xkms.GeneratePIVKey(s.ctx, req)
	default:
		return nil, ErrPIVClientNotSet
	}

	if err != nil {
		slog.Error("PIV generate key failed", "slot", opts.Slot, "algorithm", opts.Algorithm, "error", err)
		if strings.Contains(err.Error(), "CKR_DEVICE_ERROR") {
			return nil, &WrappedError{Msg: "YubiKey device busy — close Yubico Authenticator or other apps using the YubiKey, then retry", Err: err}
		}
		return nil, err
	}

	// Build result from response.
	result := &PIVGenerateAdvancedResult{
		Slot:         opts.Slot,
		Algorithm:    opts.Algorithm,
		OutputFormat: opts.OutputFormat,
		CertPEM:      string(resp.Certificate),
		PublicKeyPEM: string(resp.PublicKey),
		CSRPEM:       string(resp.CSR),
		ChainPEM:     string(resp.ChainPEM),
	}

	// Extract metadata from certificate if present.
	if len(resp.Certificate) > 0 {
		if block, _ := pem.Decode(resp.Certificate); block != nil {
			if cert, parseErr := x509.ParseCertificate(block.Bytes); parseErr == nil {
				result.KeySize = certKeySize(cert)
				result.Subject = cert.Subject.String()
			}
		}
	}

	// Build user-friendly message.
	slotName := pivSlotNameMap[opts.Slot]
	if slotName == "" {
		slotName = "PIV Key " + opts.Slot
	}
	switch opts.OutputFormat {
	case "public-key":
		result.Message = fmt.Sprintf("Public key generated for slot %s (%s)", opts.Slot, slotName)
	case "csr":
		result.Message = fmt.Sprintf("CSR generated for slot %s (%s)", opts.Slot, slotName)
	case "ca-signed":
		result.Message = fmt.Sprintf("CA-signed certificate generated in slot %s (%s)", opts.Slot, slotName)
	default:
		result.Message = fmt.Sprintf("Key generated in slot %s using %s", opts.Slot, opts.Algorithm)
	}

	return result, nil
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
// ExportCertificate returns the PEM-encoded certificate as a string so that
// Wails serializes it as plain text rather than base64-encoding a []byte.
func (s *PIVService) ExportCertificate(slot string) (string, error) {
	if slot == "" {
		return "", ErrPIVInvalidSlot
	}
	slot = strings.ToLower(slot)

	if s.client != nil {
		resp, err := s.client.ExportPIVCertificate(s.ctx, &transport.GetPIVCertificateRequest{
			Backend: s.backend,
			Slot:    slot,
			Format:  "pem",
		})
		if err != nil {
			return "", ErrPIVNoCertificate
		}
		return string(resp.Certificate), nil
	}
	if s.localEnabled {
		resp, err := xkms.ExportPIVCertificate(s.ctx, &transport.GetPIVCertificateRequest{
			Backend: s.resolveXKMSBackendName(s.localBackend),
			Slot:    slot,
			Format:  "pem",
		})
		if err != nil {
			return "", ErrPIVNoCertificate
		}
		return string(resp.Certificate), nil
	}
	return "", ErrPIVClientNotSet
}

// ExportPublicKey returns the PEM-encoded public key for a PIV slot as a
// string (so Wails serializes it as plain text, not a base64-encoded []byte).
// Unlike ExportCertificate, this works for slots that have a key but no
// certificate (e.g., public-key-only or CSR-only generation output).
func (s *PIVService) ExportPublicKey(slot string) (string, error) {
	if slot == "" {
		return "", ErrPIVInvalidSlot
	}
	slot = strings.ToLower(slot)

	if s.localEnabled {
		backend := s.resolveXKMSBackendName(s.localBackend)
		// Match by PIVSlot first (works for YubiKey PKCS#11 where the CKA_ID is
		// the slot byte and the user-chosen subject CN cannot be predicted).
		// Fall back to the software-backend "piv-<slot>" CN convention when the
		// backend does not populate PIVSlot on listed keys.
		cn := "piv-" + slot
		keys, err := xkms.ListKeys(s.ctx, backend)
		if err != nil {
			slog.Error("PIV export public key: list keys failed", "slot", slot, "backend", backend, "error", err)
			return "", &WrappedError{Msg: fmt.Sprintf("pivcert: export public key for slot %s", slot), Err: err}
		}
		for _, ka := range keys {
			if !strings.EqualFold(ka.PIVSlot, slot) && ka.CN != cn {
				continue
			}
			signer, sErr := xkms.Signer(s.ctx, ka)
			if sErr != nil {
				slog.Error("PIV export public key: signer lookup failed", "slot", slot, "cn", ka.CN, "error", sErr)
				return "", &WrappedError{Msg: fmt.Sprintf("pivcert: export public key for slot %s", slot), Err: sErr}
			}
			pubDER, mErr := x509.MarshalPKIXPublicKey(signer.Public())
			if mErr != nil {
				return "", &WrappedError{Msg: "pivcert: marshal public key", Err: mErr}
			}
			return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})), nil
		}
		return "", &MessageError{Msg: fmt.Sprintf("pivcert: no key found in slot %s", slot)}
	}
	return "", ErrPIVClientNotSet
}

// GenerateCSR creates a Certificate Signing Request for the specified slot.
// GenerateCSR returns the PEM-encoded CSR as a string (Wails would base64-encode
// a []byte return, which breaks clipboard paste into standard PEM parsers).
func (s *PIVService) GenerateCSR(slot string, subject *CSRSubject) (string, error) {
	if slot == "" {
		return "", ErrPIVInvalidSlot
	}
	slot = strings.ToLower(slot)
	if subject == nil || subject.CommonName == "" {
		return "", ErrPIVInvalidSubject
	}

	if s.client != nil {
		resp, err := s.client.GeneratePIVCSR(s.ctx, &transport.GeneratePIVCSRRequest{
			Backend:            s.backend,
			Slot:               slot,
			Subject:            subject.CommonName,
			Organization:       subject.Organization,
			OrganizationalUnit: subject.OrganizationalUnit,
			Country:            subject.Country,
			State:              subject.State,
			Locality:           subject.Locality,
		})
		if err != nil {
			return "", err
		}
		return string(resp.CSR), nil
	}
	if s.localEnabled {
		resp, err := xkms.GeneratePIVCSR(s.ctx, &transport.GeneratePIVCSRRequest{
			Backend:            s.resolveXKMSBackendName(s.localBackend),
			Slot:               slot,
			Subject:            subject.CommonName,
			Organization:       subject.Organization,
			OrganizationalUnit: subject.OrganizationalUnit,
			Country:            subject.Country,
			State:              subject.State,
			Locality:           subject.Locality,
		})
		if err != nil {
			return "", err
		}
		return string(resp.CSR), nil
	}
	return "", ErrPIVClientNotSet
}

// certificateAbsent reports whether a failed certificate delete means the slot
// simply held no certificate -- the expected case for a key-only slot, which
// must not block deleting the key.
//
// The question it answers used to be asked as
// strings.Contains(err.Error(), "not found"), which is a fail-open: a
// permission error, a backend path error or a missing BACKEND all contain that
// phrase, so any of them read as "no certificate, carry on" and
// DeleteCertificate reported success having deleted the key and left the
// certificate in place -- the opposite of its contract (#313, shape 4).
//
// Every local backend produces the real sentinel: pkg/pivcert/file wraps
// xkms.ErrPIVCertificateNotFound in a PIVStorageError, and the tpm2 backend
// maps storage.ErrNotFound onto the same sentinel. PIVStorageError implements
// Unwrap and Is, so errors.Is sees through it. That covers the local path and
// the embedded transport, which runs the same code in process.
//
// remoteMessage is the documented gap. A genuinely remote transport (REST,
// gRPC, QUIC, unix) carries the failure as text, and pkg/api/transport's
// ErrorCode vocabulary is about the CONNECTION -- NotConnected, Timeout,
// TLSHandshakeFailed -- with no code meaning "the resource was absent". So
// error identity does not survive the wire for this call and the caller cannot
// ask the typed question at all. Narrowing the remote arm here without a way
// to verify the wire text would risk refusing a legitimate key-only delete
// over a remote transport, so the loose test is kept for that case ONLY, and
// logged when it decides, rather than silently widened to every path.
func certificateAbsent(err error, remoteMessage bool) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, xkms.ErrPIVCertificateNotFound) {
		return true
	}
	if !remoteMessage {
		return false
	}
	// The sentinel's OWN rendered text, and nothing looser. The server puts the
	// error's message in the response body (pkg/api/rest/handlers_piv.go's
	// handlePIVError -> writeError), and a missing certificate renders as
	// "pivcert: ... : pivcert: certificate not found", so this matches the real
	// remote shape while "backend not found: tpm2", "key not found: piv-9a" and
	// a permission error naming a path do not.
	//
	// Anything else fails CLOSED: the caller reports the delete rather than
	// deleting the key and calling the slot empty. That is the right default
	// for a control whose contract is "the slot is now empty".
	return strings.Contains(err.Error(), xkms.ErrPIVCertificateNotFound.Error())
}

// keyListingFailure decides what DeleteCertificate returns when the key listing
// fails after the certificate step.
//
// Both the remote and the in-process path reach this with the same two facts
// and must answer identically, so they ask one function rather than repeating
// the decision (#313).
//
// It exists because the `certNotFound == false` branch used to `return nil`:
// the certificate was deleted, the key was never even INSPECTED, and the
// method -- whose contract is that the slot now holds neither -- reported
// success. A post-operation step whose error is discarded reports an unknown
// outcome as a good one.
func keyListingFailure(slot string, certNotFound bool, listErr error) error {
	if certNotFound {
		// BOTH causes, joined. Wrapping only ErrPIVNoCertificate would leave the
		// listing failure in the message and nowhere else, so a caller asking
		// errors.Is sees a benign "the slot held no certificate" and the fact
		// that the key was never inspected -- and may remain -- is lost. The
		// listing failure is the more actionable of the two and must survive
		// errors.Is as well.
		return &WrappedError{
			Msg: fmt.Sprintf("pivcert: delete slot %s: cert absent, key listing failed, "+
				"the key may remain", slot),
			Err: errors.Join(ErrPIVNoCertificate, listErr),
		}
	}
	return &WrappedError{
		Msg: fmt.Sprintf("pivcert: delete slot %s: certificate deleted but key listing failed, "+
			"the key may remain", slot),
		Err: listErr,
	}
}

// DeleteCertificate removes BOTH the certificate (if present) and the key
// material from the specified PIV slot. For key-only slots (created via the
// public-key or CSR output formats), the certificate deletion is a no-op
// but the underlying key is still removed so the slot becomes fully empty.
func (s *PIVService) DeleteCertificate(slot string) error {
	if slot == "" {
		return ErrPIVInvalidSlot
	}
	slot = strings.ToLower(slot)

	if s.client != nil {
		certErr := s.client.DeletePIVCertificate(s.ctx, &transport.DeletePIVCertificateRequest{
			Backend: s.backend,
			Slot:    slot,
		})
		// A "certificate not found" error is expected for key-only slots and
		// must not block key deletion. Any other error is a real failure.
		// remoteMessage=true: this client may be a wire transport, where the
		// sentinel does not survive (see certificateAbsent).
		certNotFound := certificateAbsent(certErr, true)
		if certErr != nil && !certNotFound {
			slog.Error("PIV delete certificate failed", "slot", slot, "backend", s.backend, "error", certErr)
			return &WrappedError{Msg: fmt.Sprintf("pivcert: delete slot %s", slot), Err: certErr}
		}

		// Delete the underlying key too so the slot becomes fully empty (the
		// contract removes BOTH cert and key). The remote KeyInfo only exposes
		// KeyID, so match the software-backend "piv-<slot>" convention used by
		// key generation and ExportPublicKey.
		cn := "piv-" + slot
		listResp, listErr := s.client.ListKeys(s.ctx, s.backend)
		if listErr != nil {
			slog.Error("PIV delete: remote list keys failed", "slot", slot, "backend", s.backend, "error", listErr)
			return keyListingFailure(slot, certNotFound, listErr)
		}
		keyDeleted := false
		for _, k := range listResp.Keys {
			if !strings.EqualFold(k.KeyID, cn) {
				continue
			}
			if _, delErr := s.client.DeleteKey(s.ctx, s.backend, k.KeyID); delErr != nil {
				slog.Error("PIV delete key failed", "slot", slot, "keyID", k.KeyID, "error", delErr)
				return &WrappedError{Msg: fmt.Sprintf("pivcert: delete key for slot %s", slot), Err: delErr}
			}
			keyDeleted = true
			slog.Info("audit", "component", "audit",
				"operation", "piv_key_deleted", "success", true,
				"timestamp", time.Now().Format(time.RFC3339),
				"slot", slot, "backend", s.backend)
			break
		}
		// Nothing in the slot at all — report not found only when both cert
		// and key were absent.
		if certNotFound && !keyDeleted {
			return &WrappedError{Msg: fmt.Sprintf("pivcert: slot %s has neither certificate nor key", slot), Err: ErrPIVNoCertificate}
		}
		return nil
	}
	if s.localEnabled {
		backend := s.resolveXKMSBackendName(s.localBackend)
		certErr := xkms.DeletePIVCertificate(s.ctx, &transport.DeletePIVCertificateRequest{
			Backend: backend,
			Slot:    slot,
		})
		// A "certificate not found" error is expected for key-only slots and
		// must not block key deletion. Any other error is a real failure.
		// remoteMessage=false: this path calls xkms in process, so the
		// sentinel is always reachable and no text matching is warranted.
		certNotFound := certificateAbsent(certErr, false)
		if certErr != nil && !certNotFound {
			slog.Error("PIV delete certificate failed", "slot", slot, "backend", backend, "error", certErr)
			return &WrappedError{Msg: fmt.Sprintf("pivcert: delete slot %s", slot), Err: certErr}
		}

		// Now delete the underlying key from the key backend.
		cn := "piv-" + slot
		keys, listErr := xkms.ListKeys(s.ctx, backend)
		if listErr != nil {
			slog.Error("PIV delete: list keys failed", "slot", slot, "backend", backend, "error", listErr)
			return keyListingFailure(slot, certNotFound, listErr)
		}
		keyDeleted := false
		for _, ka := range keys {
			// Match by PIVSlot (PKCS#11 YubiKey) or the software-backend CN
			// convention. See ExportPublicKey for the same logic.
			if !strings.EqualFold(ka.PIVSlot, slot) && ka.CN != cn {
				continue
			}
			if err := xkms.DeleteKey(s.ctx, ka); err != nil {
				slog.Error("PIV delete key failed", "slot", slot, "cn", ka.CN, "error", err)
				return &WrappedError{Msg: fmt.Sprintf("pivcert: delete key for slot %s", slot), Err: err}
			}
			keyDeleted = true
			slog.Info("audit", "component", "audit",
				"operation", "piv_key_deleted", "success", true,
				"timestamp", time.Now().Format(time.RFC3339),
				"slot", slot, "backend", backend)
			break
		}
		// Nothing in the slot at all — report not found only when both cert
		// and key were absent.
		if certNotFound && !keyDeleted {
			return &WrappedError{Msg: fmt.Sprintf("pivcert: slot %s has neither certificate nor key", slot), Err: ErrPIVNoCertificate}
		}
		return nil
	}
	return ErrPIVClientNotSet
}

// SelfSignExistingKey creates and stores a self-signed certificate using the
// existing key in the given PIV slot. Use this after a public-key-only or
// CSR-only generation to "graduate" the slot into a key+certificate state
// without regenerating the underlying key material.
func (s *PIVService) SelfSignExistingKey(slot, commonName string, validityDays int) (string, error) {
	if slot == "" {
		return "", ErrPIVInvalidSlot
	}
	slot = strings.ToLower(slot)
	if !s.localEnabled {
		return "", ErrPIVClientNotSet
	}
	backend := s.resolveXKMSBackendName(s.localBackend)
	return xkms.SelfSignExistingPIVKey(s.ctx, backend, slot, commonName, validityDays)
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
		slog.Error("PIV generate local key failed", "slot", slot, "algorithm", algorithm, "error", err)
		if strings.Contains(err.Error(), "CKR_DEVICE_ERROR") {
			return nil, &WrappedError{Msg: "YubiKey device busy — close Yubico Authenticator or other apps using the YubiKey, then retry", Err: err}
		}
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
			slot.HasKey = status.HasCert || status.Algorithm != ""
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
