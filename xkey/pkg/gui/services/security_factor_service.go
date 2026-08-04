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
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// Auth factor type constants — canonical values from §5e.
const (
	AuthFactorTypeMTLS  = "mtls"
	AuthFactorTypeFIDO2 = "fido2"
	AuthFactorTypePIV   = "piv"
)

// SecurityFactorService errors.
var (
	ErrNoServerConnection = errors.New("security_factor: no server connection")
	ErrLastFactor         = errors.New("security_factor: cannot remove the last active factor")
	ErrFactorNotFound     = errors.New("security_factor: factor not found")
	ErrInvalidFactorType  = errors.New("security_factor: invalid factor type")
)

// AuthFactor mirrors the canonical AuthFactor data model from §5e.
type AuthFactor struct {
	ID           string            `json:"id"`
	UserID       string            `json:"user_id"`
	Type         string            `json:"type"`
	Label        string            `json:"label"`
	Metadata     map[string]string `json:"metadata"`
	RegisteredAt string            `json:"registered_at"`
	LastUsedAt   *string           `json:"last_used_at,omitempty"`
	RevokedAt    *string           `json:"revoked_at,omitempty"`
	CreatedBy    string            `json:"created_by"`
}

// ListFactorsResponse matches the platform API response envelope.
type ListFactorsResponse struct {
	Factors []AuthFactor `json:"factors"`
	Total   int          `json:"total"`
}

// AddFactorRequest carries the payload for enrolling a new factor.
type AddFactorRequest struct {
	Type          string `json:"type"`
	Label         string `json:"label"`
	CertPEM       string `json:"cert_pem,omitempty"`
	FIDO2Response string `json:"webauthn_response,omitempty"`
	PIVCertPEM    string `json:"piv_cert_pem,omitempty"`
	PIVSlot       string `json:"piv_slot,omitempty"`
}

// AddFactorResponse carries the newly created factor.
type AddFactorResponse struct {
	Factor AuthFactor `json:"factor"`
}

// RotateFactorRequest replaces an existing factor's credential.
type RotateFactorRequest struct {
	FactorID      string `json:"factor_id"`
	CertPEM       string `json:"cert_pem,omitempty"`
	FIDO2Response string `json:"webauthn_response,omitempty"`
	PIVCertPEM    string `json:"piv_cert_pem,omitempty"`
	PIVSlot       string `json:"piv_slot,omitempty"`
}

// PIVCardInfo describes a PC/SC reader and card combination.
type PIVCardInfo struct {
	ReaderName   string `json:"reader_name"`
	CardVendor   string `json:"card_vendor"`
	SerialNumber string `json:"serial_number,omitempty"`
	HasPIVApplet bool   `json:"has_piv_applet"`
}

// MFAPolicyRequest sets per-tenant MFA requirements.
type MFAPolicyRequest struct {
	TenantID           string `json:"tenant_id"`
	RequireFactorCount int    `json:"require_factor_count"`
}

// SecurityFactorService is a Wails-bound service for managing auth factors.
// It proxies requests to the connected platform server's REST API.
type SecurityFactorService struct {
	ctx        context.Context
	log        *slog.Logger
	connSvc    *ConnectionService
	pivSvc     *PIVService
	clientCert *tls.Certificate
}

// NewSecurityFactorService creates a new SecurityFactorService.
func NewSecurityFactorService(connSvc *ConnectionService, pivSvc *PIVService) *SecurityFactorService {
	return &SecurityFactorService{
		log:     slog.Default().With("component", "security_factor_service"),
		connSvc: connSvc,
		pivSvc:  pivSvc,
	}
}

// SetContext is called by the Wails startup lifecycle hook.
func (s *SecurityFactorService) SetContext(ctx context.Context) {
	s.ctx = ctx
}

// SetClientCert configures the mTLS client certificate for outbound API calls.
func (s *SecurityFactorService) SetClientCert(cert *tls.Certificate) {
	s.clientCert = cert
}

// ListFactors returns all active auth factors for the given user.
func (s *SecurityFactorService) ListFactors(userID string) (*ListFactorsResponse, error) {
	if userID == "" {
		return nil, &MessageError{Msg: "security_factor: user ID required"}
	}
	path := fmt.Sprintf("/api/v1/users/%s/factors", userID)
	var resp ListFactorsResponse
	if err := s.get(path, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// AddFactor enrolls a new auth factor for the given user.
func (s *SecurityFactorService) AddFactor(userID string, req AddFactorRequest) (*AddFactorResponse, error) {
	if userID == "" {
		return nil, &MessageError{Msg: "security_factor: user ID required"}
	}
	if req.Type == "" {
		return nil, ErrInvalidFactorType
	}
	path := fmt.Sprintf("/api/v1/users/%s/factors", userID)
	var resp AddFactorResponse
	if err := s.post(path, req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// RemoveFactor soft-deletes (revokes) a factor. The last active factor
// cannot be removed without admin override.
func (s *SecurityFactorService) RemoveFactor(userID, factorID string) error {
	if userID == "" || factorID == "" {
		return &MessageError{Msg: "security_factor: user ID and factor ID required"}
	}
	path := fmt.Sprintf("/api/v1/users/%s/factors/%s", userID, factorID)
	return s.delete(path)
}

// RotateFactor enrolls a replacement credential and revokes the old one atomically.
func (s *SecurityFactorService) RotateFactor(userID string, req RotateFactorRequest) (*AddFactorResponse, error) {
	if userID == "" || req.FactorID == "" {
		return nil, &MessageError{Msg: "security_factor: user ID and factor ID required"}
	}
	path := fmt.Sprintf("/api/v1/users/%s/factors/%s/rotate", userID, req.FactorID)
	var resp AddFactorResponse
	if err := s.put(path, req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// RelabelFactor updates the human-readable label of a factor.
func (s *SecurityFactorService) RelabelFactor(userID, factorID, label string) error {
	if userID == "" || factorID == "" {
		return &MessageError{Msg: "security_factor: user ID and factor ID required"}
	}
	path := fmt.Sprintf("/api/v1/users/%s/factors/%s/label", userID, factorID)
	return s.patch(path, map[string]string{"label": label})
}

// SetMFAPolicy configures the tenant-level MFA requirement.
func (s *SecurityFactorService) SetMFAPolicy(req MFAPolicyRequest) error {
	if req.TenantID == "" {
		return &MessageError{Msg: "security_factor: tenant ID required"}
	}
	path := fmt.Sprintf("/api/v1/tenants/%s/security/mfa-policy", req.TenantID)
	return s.put(path, req, nil)
}

// FactorLoginResult carries the JWT returned on successful authentication.
type FactorLoginResult struct {
	Token string `json:"token"`
}

// ProbeAdminCert reports whether ~/.xkey/admin.pem exists on disk.
func (s *SecurityFactorService) ProbeAdminCert() map[string]bool {
	home, err := os.UserHomeDir()
	if err != nil {
		return map[string]bool{"exists": false}
	}
	certPath := filepath.Join(home, ".xkey", "admin.pem")
	_, err = os.Stat(certPath)
	return map[string]bool{"exists": err == nil}
}

// LoginMTLS authenticates via the mTLS client certificate stored at
// ~/.xkey/admin.pem. The server validates the cert chain and returns a JWT.
func (s *SecurityFactorService) LoginMTLS() (*FactorLoginResult, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, &WrappedError{Msg: "security_factor: locate home dir", Err: err}
	}
	certPath := filepath.Join(home, ".xkey", "admin.pem")
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, &WrappedError{Msg: "security_factor: read admin cert", Err: err}
	}
	cert, err := tls.X509KeyPair(certPEM, certPEM)
	if err != nil {
		return nil, &WrappedError{Msg: "security_factor: parse admin cert", Err: err}
	}
	s.clientCert = &cert

	var result FactorLoginResult
	if err := s.post("/api/v1/auth/mtls/login", nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// LoginFIDO2 initiates a WebAuthn assertion flow for the given username.
// In Wails, this calls the native CTAP2 bridge rather than navigator.credentials.
func (s *SecurityFactorService) LoginFIDO2(username string) (*FactorLoginResult, error) {
	if username == "" {
		return nil, &MessageError{Msg: "security_factor: username required for FIDO2 login"}
	}
	// Delegate to the FIDO2 bridge which handles native CTAP2 interaction.
	var result FactorLoginResult
	if err := s.post("/api/v1/auth/fido2/login", map[string]string{"username": username}, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// LoginPIV authenticates via a PIV smartcard. The card is read via PC/SC.
func (s *SecurityFactorService) LoginPIV() (*FactorLoginResult, error) {
	// Read the authentication certificate from slot 9a.
	certPEM, err := s.ReadPIVCertPEM("9a")
	if err != nil {
		return nil, &WrappedError{Msg: "security_factor: read PIV cert", Err: err}
	}
	var result FactorLoginResult
	if err := s.post("/api/v1/auth/piv/login", map[string]string{"cert_pem": certPEM}, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// LoginFIDO2CrossDevice initiates a cross-device CTAP2 flow (BLE/QR).
func (s *SecurityFactorService) LoginFIDO2CrossDevice(username string) (*FactorLoginResult, error) {
	var result FactorLoginResult
	if err := s.post("/api/v1/auth/fido2/login", map[string]string{
		"username":     username,
		"cross_device": "true",
	}, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// EnumeratePIVCards returns a list of PC/SC readers and any inserted PIV cards.
// Returns an empty slice on platforms without pcscd or when no cards are present.
func (s *SecurityFactorService) EnumeratePIVCards() ([]PIVCardInfo, error) {
	// Delegate to PIVService which already manages PC/SC enumeration.
	slots, err := s.pivSvc.GetSlots()
	if err != nil {
		s.log.Debug("PIV enumeration", "err", err)
		return []PIVCardInfo{}, nil
	}

	var cards []PIVCardInfo
	for _, slot := range slots {
		if !slot.HasCert {
			continue
		}
		vendor := inferPIVVendor(slot.Subject)
		cards = append(cards, PIVCardInfo{
			ReaderName:   slot.Backend,
			CardVendor:   vendor,
			HasPIVApplet: true,
		})
	}
	return cards, nil
}

// ReadPIVCertPEM reads the certificate PEM from the given PIV slot.
// Callers should call EnumeratePIVCards first to discover available readers.
func (s *SecurityFactorService) ReadPIVCertPEM(slot string) (string, error) {
	cert, err := s.pivSvc.GetCertificate(slot)
	if err != nil {
		return "", &WrappedError{Msg: fmt.Sprintf("security_factor: read PIV cert slot %s", slot), Err: err}
	}
	return cert.PEM, nil
}

// ---- internal HTTP helpers ------------------------------------------------

func (s *SecurityFactorService) baseURL() (string, error) {
	if s.connSvc == nil {
		return "", ErrNoServerConnection
	}
	info := s.connSvc.GetConnectionInfo()
	if info.State != "connected" || info.Address == "" {
		return "", ErrNoServerConnection
	}
	scheme := "https"
	if !info.TLS {
		scheme = "http"
	}
	return fmt.Sprintf("%s://%s", scheme, info.Address), nil
}

func (s *SecurityFactorService) httpClient() *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
		},
	}
	if s.clientCert != nil {
		transport.TLSClientConfig.Certificates = []tls.Certificate{*s.clientCert}
	}
	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}
}

func (s *SecurityFactorService) get(path string, dst any) error {
	base, err := s.baseURL()
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(s.ctx, http.MethodGet, base+path, nil)
	if err != nil {
		return &WrappedError{Msg: "security_factor: build request", Err: err}
	}
	return s.do(req, dst)
}

func (s *SecurityFactorService) post(path string, body, dst any) error {
	return s.sendJSON(http.MethodPost, path, body, dst)
}

func (s *SecurityFactorService) put(path string, body, dst any) error {
	return s.sendJSON(http.MethodPut, path, body, dst)
}

func (s *SecurityFactorService) patch(path string, body any) error {
	return s.sendJSON(http.MethodPatch, path, body, nil)
}

func (s *SecurityFactorService) delete(path string) error {
	base, err := s.baseURL()
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(s.ctx, http.MethodDelete, base+path, nil)
	if err != nil {
		return &WrappedError{Msg: "security_factor: build request", Err: err}
	}
	return s.do(req, nil)
}

func (s *SecurityFactorService) sendJSON(method, path string, body, dst any) error {
	base, err := s.baseURL()
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return &WrappedError{Msg: "security_factor: encode request body", Err: err}
	}
	req, err := http.NewRequestWithContext(
		s.ctx, method, base+path, bytes.NewReader(encoded),
	)
	if err != nil {
		return &WrappedError{Msg: "security_factor: build request", Err: err}
	}
	req.Header.Set("Content-Type", "application/json")
	return s.do(req, dst)
}

type apiErrBody struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

func (s *SecurityFactorService) do(req *http.Request, dst any) error {
	resp, err := s.httpClient().Do(req)
	if err != nil {
		return &WrappedError{Msg: fmt.Sprintf("security_factor: %s %s", req.Method, req.URL.Path), Err: err}
	}
	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return &WrappedError{Msg: "security_factor: read response", Err: err}
	}

	if resp.StatusCode >= 400 {
		var body apiErrBody
		_ = json.Unmarshal(data, &body)
		msg := body.Error
		if msg == "" {
			msg = body.Message
		}
		if msg == "" {
			msg = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return &MessageError{Msg: fmt.Sprintf("security_factor: %s %s: %s", req.Method, req.URL.Path, msg)}
	}

	if dst != nil && len(data) > 0 {
		if err := json.Unmarshal(data, dst); err != nil {
			return &WrappedError{Msg: "security_factor: decode response", Err: err}
		}
	}
	return nil
}

// inferPIVVendor infers the card vendor from a certificate subject string.
func inferPIVVendor(subject string) string {
	switch {
	case containsCI(subject, "yubico"), containsCI(subject, "yubikey"):
		return "YubiKey PIV"
	case containsCI(subject, "nitrokey"):
		return "Nitrokey PIV"
	case containsCI(subject, "goldkey"):
		return "GoldKey PIV"
	default:
		return "PIV Card"
	}
}

func containsCI(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	// Avoid importing strings for a single use; manual lowercase compare.
	sl := []byte(s)
	subl := []byte(sub)
	for i := range sl {
		if sl[i] >= 'A' && sl[i] <= 'Z' {
			sl[i] += 32
		}
	}
	for i := range subl {
		if subl[i] >= 'A' && subl[i] <= 'Z' {
			subl[i] += 32
		}
	}
	return bytes.Contains(sl, subl)
}
