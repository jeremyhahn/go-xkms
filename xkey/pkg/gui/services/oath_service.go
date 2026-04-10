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
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/oath"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/qrscan"
)

// OATH service errors.
var (
	ErrOATHStoreNotSet     = errors.New("oath_service: store not configured")
	ErrOATHInvalidURI      = errors.New("oath_service: invalid otpauth URI")
	ErrOATHInvalidID       = errors.New("oath_service: invalid account ID")
	ErrOATHAccountNotFound = errors.New("oath_service: account not found")
	ErrOATHGenerateFailed  = errors.New("oath_service: code generation failed")
	ErrOATHQRNotFound      = errors.New("oath_service: no QR code found on screen")
	ErrOATHQRInvalidURI    = errors.New("oath_service: QR code does not contain a valid otpauth:// URI")
	ErrOATHQRScanFailed    = errors.New("oath_service: QR scan failed")
	ErrOATHMissingSecret   = errors.New("oath_service: secret key required")
)

// OATHAccount represents an OATH credential as exposed to the frontend.
type OATHAccount struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Issuer      string    `json:"issuer"`
	AccountName string    `json:"account_name"`
	Type        string    `json:"type"`
	Algorithm   string    `json:"algorithm"`
	Digits      int       `json:"digits"`
	Period      int       `json:"period"`
	Counter     uint64    `json:"counter"`
	CreatedAt   time.Time `json:"created_at"`
	BackendID   string    `json:"backend_id"`
}

// TOTPCode holds a generated TOTP code and its remaining validity.
type TOTPCode struct {
	Code      string `json:"code"`
	TimeLeft  int    `json:"time_left"`
	Period    int    `json:"period"`
	AccountID string `json:"account_id"`
}

// HOTPCode holds a generated HOTP code and the new counter value.
type HOTPCode struct {
	Code      string `json:"code"`
	Counter   uint64 `json:"counter"`
	AccountID string `json:"account_id"`
}

// QRScanResult contains the result of scanning for a QR code on screen.
type QRScanResult struct {
	URI          string `json:"uri"`
	DisplayIndex int    `json:"display_index"`
}

// OATHService exposes TOTP/HOTP operations to the frontend.
type OATHService struct {
	ctx      context.Context
	store    oath.Store
	auditLog atomic.Pointer[audit.Logger]
}

// NewOATHService creates a new OATHService. If store is nil, the service
// will return ErrOATHStoreNotSet for operations that require persistence.
func NewOATHService(store oath.Store) *OATHService {
	return &OATHService{
		store: store,
	}
}

// SetContext is called by the Wails startup lifecycle hook.
func (s *OATHService) SetContext(ctx context.Context) {
	s.ctx = ctx
}

// SetStore replaces the OATH store. This is used for deferred initialization
// when the data directory is created after construction.
func (s *OATHService) SetStore(store oath.Store) {
	s.store = store
}

// SetAuditLogger sets the audit logger for security event logging.
func (s *OATHService) SetAuditLogger(l audit.Logger) {
	s.auditLog.Store(&l)
}

// logOATHEvent logs an OATH-related audit event.
func (s *OATHService) logOATHEvent(op audit.OperationType, success bool, err error, details map[string]any) {
	if p := s.auditLog.Load(); p != nil {
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		(*p).Log(audit.Entry{
			Timestamp: time.Now(),
			Operation: op,
			Success:   success,
			Error:     errStr,
			Details:   details,
		})
	}
}

// ListAccounts returns all OATH credentials in the store.
func (s *OATHService) ListAccounts() ([]OATHAccount, error) {
	if s.store == nil {
		return nil, ErrOATHStoreNotSet
	}
	creds, err := s.store.List()
	if err != nil {
		return nil, err
	}
	accounts := make([]OATHAccount, 0, len(creds))
	for _, c := range creds {
		accounts = append(accounts, credentialToAccount(c))
	}
	return accounts, nil
}

// AddAccount parses an otpauth:// URI and adds the credential to the store.
func (s *OATHService) AddAccount(uri string) (*OATHAccount, error) {
	if s.store == nil {
		return nil, ErrOATHStoreNotSet
	}
	if uri == "" {
		return nil, ErrOATHInvalidURI
	}

	cred, err := oath.ParseURI(uri)
	if err != nil {
		return nil, err
	}

	if err := s.store.Add(cred); err != nil {
		s.logOATHEvent(audit.OpOATHCredentialCreated, false, err, map[string]any{"issuer": cred.Issuer, "account": cred.AccountName})
		return nil, err
	}

	acct := credentialToAccount(cred)
	s.logOATHEvent(audit.OpOATHCredentialCreated, true, nil, map[string]any{"issuer": cred.Issuer, "account": cred.AccountName})
	return &acct, nil
}

// DeleteAccount removes an OATH credential by ID.
func (s *OATHService) DeleteAccount(id string) error {
	if s.store == nil {
		return ErrOATHStoreNotSet
	}
	if id == "" {
		return ErrOATHInvalidID
	}
	err := s.store.Delete(id)
	if err != nil {
		s.logOATHEvent(audit.OpOATHCredentialDeleted, false, err, map[string]any{"account_id": id})
		return err
	}
	s.logOATHEvent(audit.OpOATHCredentialDeleted, true, nil, map[string]any{"account_id": id})
	return nil
}

// GenerateTOTP generates a TOTP code for the given account.
func (s *OATHService) GenerateTOTP(id string) (*TOTPCode, error) {
	if s.store == nil {
		return nil, ErrOATHStoreNotSet
	}
	if id == "" {
		return nil, ErrOATHInvalidID
	}

	cred, err := s.store.Get(id)
	if err != nil {
		return nil, err
	}

	if cred.Type != oath.TypeTOTP {
		return nil, ErrOATHGenerateFailed
	}

	gen, err := oath.NewGenerator(cred)
	if err != nil {
		return nil, err
	}

	code, err := gen.Generate()
	if err != nil {
		s.logOATHEvent(audit.OpOATHCodeGenerated, false, err, map[string]any{"account_id": id, "type": "totp"})
		return nil, err
	}

	s.logOATHEvent(audit.OpOATHCodeGenerated, true, nil, map[string]any{"account_id": id, "type": "totp"})
	return &TOTPCode{
		Code:      code,
		TimeLeft:  gen.TimeRemaining(),
		Period:    cred.Period,
		AccountID: cred.ID,
	}, nil
}

// GenerateHOTP generates an HOTP code for the given account and increments
// the counter in the store.
func (s *OATHService) GenerateHOTP(id string) (*HOTPCode, error) {
	if s.store == nil {
		return nil, ErrOATHStoreNotSet
	}
	if id == "" {
		return nil, ErrOATHInvalidID
	}

	cred, err := s.store.Get(id)
	if err != nil {
		return nil, err
	}

	if cred.Type != oath.TypeHOTP {
		return nil, ErrOATHGenerateFailed
	}

	gen, err := oath.NewGenerator(cred)
	if err != nil {
		return nil, err
	}

	code, err := gen.Generate()
	if err != nil {
		s.logOATHEvent(audit.OpOATHCodeGenerated, false, err, map[string]any{"account_id": id, "type": "hotp"})
		return nil, err
	}

	// Increment counter and persist.
	gen.IncrementCounter()
	if updateErr := s.store.Update(cred); updateErr != nil {
		return nil, updateErr
	}

	s.logOATHEvent(audit.OpOATHCodeGenerated, true, nil, map[string]any{"account_id": id, "type": "hotp"})
	return &HOTPCode{
		Code:      code,
		Counter:   cred.Counter,
		AccountID: cred.ID,
	}, nil
}

// ScanQR captures the specified display and scans for an otpauth:// QR code.
// Use displayIndex -1 to scan all displays.
func (s *OATHService) ScanQR(displayIndex int) (*QRScanResult, error) {
	scanner := qrscan.NewScanner()
	results, err := scanner.ScanScreen(displayIndex)
	if err != nil {
		if errors.Is(err, qrscan.ErrNoQRCodeFound) {
			return nil, ErrOATHQRNotFound
		}
		if errors.Is(err, qrscan.ErrInvalidQRContent) {
			return nil, ErrOATHQRInvalidURI
		}
		return nil, fmt.Errorf("%w: %s", ErrOATHQRScanFailed, err.Error())
	}
	if len(results) == 0 {
		return nil, ErrOATHQRNotFound
	}
	return &QRScanResult{
		URI:          results[0].URI,
		DisplayIndex: results[0].DisplayIndex,
	}, nil
}

// AddAccountManual creates and stores an OATH TOTP credential from manually
// entered parameters. This is the fallback when QR code scanning is unavailable.
// Standard TOTP defaults are applied (SHA1, 6 digits, 30-second period).
func (s *OATHService) AddAccountManual(accountName, issuer, secret string) (*OATHAccount, error) {
	if s.store == nil {
		return nil, ErrOATHStoreNotSet
	}
	if secret == "" {
		return nil, ErrOATHMissingSecret
	}

	cred, err := oath.NewCredentialFromManualEntry(accountName, issuer, secret)
	if err != nil {
		return nil, err
	}

	if err := s.store.Add(cred); err != nil {
		s.logOATHEvent(audit.OpOATHCredentialCreated, false, err, map[string]any{"issuer": issuer, "account": accountName})
		return nil, err
	}

	acct := credentialToAccount(cred)
	s.logOATHEvent(audit.OpOATHCredentialCreated, true, nil, map[string]any{"issuer": issuer, "account": accountName})
	return &acct, nil
}

// AddAccountFromURI validates the URI scheme and adds the credential to the
// store. This is a convenience wrapper around AddAccount for use with URIs
// obtained from QR code scanning.
func (s *OATHService) AddAccountFromURI(uri string) (*OATHAccount, error) {
	if uri == "" {
		return nil, ErrOATHInvalidURI
	}
	if !strings.HasPrefix(strings.ToLower(uri), "otpauth://") {
		return nil, ErrOATHQRInvalidURI
	}
	return s.AddAccount(uri)
}

// credentialToAccount maps an oath.Credential to the frontend OATHAccount type.
func credentialToAccount(c *oath.Credential) OATHAccount {
	return OATHAccount{
		ID:          c.ID,
		Name:        c.Name,
		Issuer:      c.Issuer,
		AccountName: c.AccountName,
		Type:        c.Type,
		Algorithm:   c.Algorithm,
		Digits:      c.Digits,
		Period:      c.Period,
		Counter:     c.Counter,
		CreatedAt:   c.CreatedAt,
		BackendID:   c.BackendID,
	}
}
