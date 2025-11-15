// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build pkcs11

package hardware

import (
	"crypto/x509"
	"fmt"
	"sync"

	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/miekg/pkcs11"
)

// PKCS11CertStorage implements HardwareCertStorage for PKCS#11 HSMs.
// Certificates are stored as CKO_CERTIFICATE objects on the token.
//
// Thread Safety:
// All operations are protected by a mutex for exclusive access.
// Note: PKCS#11 sessions are NOT thread-safe - even read operations like
// FindObjectsInit modify session state, so we must serialize all access.
//
// Certificate Storage:
// - Each certificate is stored as a CKO_CERTIFICATE object
// - CKA_ID links certificates to their corresponding private keys
// - CKA_LABEL provides human-readable identification
// - CKA_SUBJECT and CKA_ISSUER enable searching/filtering
//
// Limitations:
// - Chain storage maps to individual certificates with ID relationships
// - Not all HSMs support certificate deletion
// - Capacity depends on token memory/object limits
type PKCS11CertStorage struct {
	ctx        *pkcs11.Ctx          // PKCS#11 context
	session    pkcs11.SessionHandle // Open session handle
	tokenLabel string               // Token identifier
	slotID     uint                 // Slot ID for operations
	mu         sync.Mutex           // Serializes all PKCS#11 session access
	closed     bool                 // Tracks if storage is closed
}

// NewPKCS11CertStorage creates a new PKCS#11 certificate storage instance.
// The session must be authenticated (logged in) before calling this.
//
// Parameters:
//   - ctx: Initialized PKCS#11 context
//   - session: Authenticated session handle
//   - tokenLabel: Token label for identification
//   - slotID: Slot ID for the token
//
// Returns an error if the session is invalid or token is inaccessible.
func NewPKCS11CertStorage(
	ctx *pkcs11.Ctx,
	session pkcs11.SessionHandle,
	tokenLabel string,
	slotID uint,
) (HardwareCertStorage, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}

	// Verify session is valid by getting session info
	_, err := ctx.GetSessionInfo(session)
	if err != nil {
		return nil, NewOperationError("validate session", err)
	}

	return &PKCS11CertStorage{
		ctx:        ctx,
		session:    session,
		tokenLabel: tokenLabel,
		slotID:     slotID,
		closed:     false,
	}, nil
}

// SaveCert stores a certificate as a CKO_CERTIFICATE object.
// If a certificate with the same ID exists, it will be overwritten.
//
// PKCS#11 Attributes Set:
//   - CKA_CLASS = CKO_CERTIFICATE
//   - CKA_CERTIFICATE_TYPE = CKC_X_509
//   - CKA_TOKEN = true (persistent storage)
//   - CKA_ID = certificate ID
//   - CKA_LABEL = certificate ID (for human readability)
//   - CKA_SUBJECT = DER-encoded subject
//   - CKA_ISSUER = DER-encoded issuer
//   - CKA_SERIAL_NUMBER = serial number
//   - CKA_VALUE = DER-encoded certificate
func (p *PKCS11CertStorage) SaveCert(id string, cert *x509.Certificate) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return ErrStorageClosed
	}

	if id == "" {
		return storage.ErrInvalidID
	}

	if cert == nil {
		return storage.ErrInvalidData
	}

	// Check if certificate already exists and delete it first
	existingHandle, err := p.findCertificateHandle(id)
	if err == nil && existingHandle != 0 {
		// Delete existing certificate to overwrite
		if err := p.ctx.DestroyObject(p.session, existingHandle); err != nil {
			return NewOperationError("delete existing certificate", err)
		}
	}

	// Create certificate object template
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
		pkcs11.NewAttribute(pkcs11.CKA_CERTIFICATE_TYPE, pkcs11.CKC_X_509),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(id)),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, []byte(id)),
		pkcs11.NewAttribute(pkcs11.CKA_SUBJECT, cert.RawSubject),
		pkcs11.NewAttribute(pkcs11.CKA_ISSUER, cert.RawIssuer),
		pkcs11.NewAttribute(pkcs11.CKA_SERIAL_NUMBER, cert.SerialNumber.Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, cert.Raw),
	}

	// Create the certificate object
	_, err = p.ctx.CreateObject(p.session, template)
	if err != nil {
		// Check for token full error
		if err == pkcs11.Error(pkcs11.CKR_DEVICE_MEMORY) ||
			err == pkcs11.Error(pkcs11.CKR_TOKEN_WRITE_PROTECTED) {
			return ErrTokenFull
		}
		return NewOperationError("create certificate object", err)
	}

	return nil
}

// GetCert retrieves a certificate by ID using CKA_ID attribute search.
func (p *PKCS11CertStorage) GetCert(id string) (*x509.Certificate, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil, ErrStorageClosed
	}

	if id == "" {
		return nil, storage.ErrInvalidID
	}

	// Find the certificate object
	handle, err := p.findCertificateHandle(id)
	if err != nil {
		return nil, err
	}

	if handle == 0 {
		return nil, storage.ErrNotFound
	}

	// Retrieve the certificate value (DER-encoded)
	attrs, err := p.ctx.GetAttributeValue(p.session, handle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
	})
	if err != nil {
		return nil, NewOperationError("get certificate value", err)
	}

	if len(attrs) == 0 || len(attrs[0].Value) == 0 {
		return nil, ErrInvalidCertificate
	}

	// Parse the DER-encoded certificate
	cert, err := x509.ParseCertificate(attrs[0].Value)
	if err != nil {
		return nil, NewOperationError("parse certificate", err)
	}

	return cert, nil
}

// DeleteCert removes a certificate object from the token.
// Note: Some HSMs may not support certificate deletion.
func (p *PKCS11CertStorage) DeleteCert(id string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return ErrStorageClosed
	}

	if id == "" {
		return storage.ErrInvalidID
	}

	deleted := false

	// Try to find and delete the certificate with exact ID
	handle, err := p.findCertificateHandle(id)
	if err != nil {
		// Error during search
		return NewOperationError("find certificate", err)
	}

	if handle == 0 {
		// Certificate with exact ID not found, check if it's a chain
		chainID := p.chainID(id)
		chainHandles, chainErr := p.findAllCertificatesWithPrefix(chainID)
		if chainErr != nil || len(chainHandles) == 0 {
			// Neither single cert nor chain found
			return storage.ErrNotFound
		}
		// Found chain certificates, delete them
		for _, h := range chainHandles {
			if err := p.ctx.DestroyObject(p.session, h); err != nil {
				return NewOperationError("delete chain certificate", err)
			}
			deleted = true
		}
	} else {
		// Delete the certificate object with exact ID
		if err := p.ctx.DestroyObject(p.session, handle); err != nil {
			return NewOperationError("delete certificate", err)
		}
		deleted = true

		// Also delete chain certificates if they exist
		chainID := p.chainID(id)
		chainHandles, err := p.findAllCertificatesWithPrefix(chainID)
		if err == nil {
			for _, h := range chainHandles {
				p.ctx.DestroyObject(p.session, h) // Best effort, ignore errors
			}
		}
	}

	if !deleted {
		return storage.ErrNotFound
	}

	return nil
}

// SaveCertChain stores a certificate chain as individual certificates
// with ID relationships. The leaf certificate uses the provided ID,
// intermediates use ID-chain-0, ID-chain-1, etc.
func (p *PKCS11CertStorage) SaveCertChain(id string, chain []*x509.Certificate) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return ErrStorageClosed
	}

	if id == "" {
		return storage.ErrInvalidID
	}

	if len(chain) == 0 {
		return storage.ErrInvalidData
	}

	// Validate all certificates in chain
	for i, cert := range chain {
		if cert == nil {
			return fmt.Errorf("certificate at index %d is nil: %w", i, storage.ErrInvalidData)
		}
	}

	// Delete existing chain if present
	chainID := p.chainID(id)
	existingHandles, _ := p.findAllCertificatesWithPrefix(chainID)
	for _, h := range existingHandles {
		p.ctx.DestroyObject(p.session, h)
	}

	// Save each certificate in the chain with indexed IDs
	for i, cert := range chain {
		certID := fmt.Sprintf("%s-%d", chainID, i)
		template := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
			pkcs11.NewAttribute(pkcs11.CKA_CERTIFICATE_TYPE, pkcs11.CKC_X_509),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(certID)),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, []byte(certID)),
			pkcs11.NewAttribute(pkcs11.CKA_SUBJECT, cert.RawSubject),
			pkcs11.NewAttribute(pkcs11.CKA_ISSUER, cert.RawIssuer),
			pkcs11.NewAttribute(pkcs11.CKA_SERIAL_NUMBER, cert.SerialNumber.Bytes()),
			pkcs11.NewAttribute(pkcs11.CKA_VALUE, cert.Raw),
		}

		_, err := p.ctx.CreateObject(p.session, template)
		if err != nil {
			if err == pkcs11.Error(pkcs11.CKR_DEVICE_MEMORY) ||
				err == pkcs11.Error(pkcs11.CKR_TOKEN_WRITE_PROTECTED) {
				return ErrTokenFull
			}
			return NewOperationError(fmt.Sprintf("create certificate chain object %d", i), err)
		}
	}

	return nil
}

// GetCertChain retrieves a certificate chain by loading related certificates.
func (p *PKCS11CertStorage) GetCertChain(id string) ([]*x509.Certificate, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil, ErrStorageClosed
	}

	if id == "" {
		return nil, storage.ErrInvalidID
	}

	chainID := p.chainID(id)
	handles, err := p.findAllCertificatesWithPrefix(chainID)
	if err != nil {
		return nil, err
	}

	if len(handles) == 0 {
		return nil, storage.ErrNotFound
	}

	// Retrieve all certificates in the chain
	chain := make([]*x509.Certificate, len(handles))
	for i, handle := range handles {
		attrs, err := p.ctx.GetAttributeValue(p.session, handle, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
		})
		if err != nil {
			return nil, NewOperationError(fmt.Sprintf("get certificate chain value at index %d", i), err)
		}

		if len(attrs) == 0 || len(attrs[0].Value) == 0 {
			return nil, fmt.Errorf("empty certificate at index %d: %w", i, ErrInvalidCertificate)
		}

		cert, err := x509.ParseCertificate(attrs[0].Value)
		if err != nil {
			return nil, NewOperationError(fmt.Sprintf("parse certificate at index %d", i), err)
		}

		chain[i] = cert
	}

	return chain, nil
}

// ListCerts returns all certificate IDs by enumerating CKO_CERTIFICATE objects.
func (p *PKCS11CertStorage) ListCerts() ([]string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil, ErrStorageClosed
	}

	// Search for all certificate objects
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
	}

	if err := p.ctx.FindObjectsInit(p.session, template); err != nil {
		return nil, NewOperationError("init certificate search", err)
	}
	defer p.ctx.FindObjectsFinal(p.session)

	// Find all certificate objects
	handles, _, err := p.ctx.FindObjects(p.session, 1000)
	if err != nil {
		return nil, NewOperationError("find certificates", err)
	}

	// Extract IDs from certificates
	ids := make(map[string]bool) // Use map to deduplicate
	for _, handle := range handles {
		attrs, err := p.ctx.GetAttributeValue(p.session, handle, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
		})
		if err != nil || len(attrs) == 0 {
			continue
		}

		id := string(attrs[0].Value)
		// Filter out chain certificates (those with -chain- in the ID)
		if !p.isChainCertificate(id) {
			ids[id] = true
		}
	}

	// Convert map to slice
	result := make([]string, 0, len(ids))
	for id := range ids {
		result = append(result, id)
	}

	return result, nil
}

// CertExists checks if a certificate object exists with the given ID.
func (p *PKCS11CertStorage) CertExists(id string) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return false, ErrStorageClosed
	}

	if id == "" {
		return false, storage.ErrInvalidID
	}

	handle, err := p.findCertificateHandle(id)
	if err != nil {
		return false, nil
	}

	return handle != 0, nil
}

// Close releases the PKCS#11 session.
func (p *PKCS11CertStorage) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil
	}

	p.closed = true
	// Note: We don't close the session here as it's managed by the backend
	// The backend is responsible for session lifecycle
	return nil
}

// GetCapacity queries token info for certificate storage capacity.
func (p *PKCS11CertStorage) GetCapacity() (total int, available int, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return 0, 0, ErrStorageClosed
	}

	// Get token info
	tokenInfo, err := p.ctx.GetTokenInfo(p.slotID)
	if err != nil {
		return 0, 0, NewOperationError("get token info", err)
	}

	// Some tokens don't report max/free object counts
	if tokenInfo.MaxSessionCount == pkcs11.CK_UNAVAILABLE_INFORMATION ||
		tokenInfo.MaxSessionCount == pkcs11.CK_EFFECTIVELY_INFINITE {
		return 0, 0, ErrNotSupported
	}

	// Use session count as a proxy for object capacity
	// This is approximate as we can't directly query certificate object limits
	total = int(tokenInfo.MaxSessionCount)
	used := total - int(tokenInfo.SessionCount)
	available = total - used

	return total, available, nil
}

// SupportsChains returns true (PKCS#11 supports chains via relationships).
func (p *PKCS11CertStorage) SupportsChains() bool {
	return true
}

// IsHardwareBacked returns true.
func (p *PKCS11CertStorage) IsHardwareBacked() bool {
	return true
}

// Compact is a no-op for PKCS#11 (returns ErrNotSupported).
func (p *PKCS11CertStorage) Compact() error {
	return ErrNotSupported
}

// Helper functions

// findCertificateHandle finds a certificate object handle by ID.
// Must be called with mutex held (Lock).
func (p *PKCS11CertStorage) findCertificateHandle(id string) (pkcs11.ObjectHandle, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(id)),
	}

	if err := p.ctx.FindObjectsInit(p.session, template); err != nil {
		return 0, NewOperationError("init object search", err)
	}
	defer p.ctx.FindObjectsFinal(p.session)

	handles, _, err := p.ctx.FindObjects(p.session, 1)
	if err != nil {
		return 0, NewOperationError("find objects", err)
	}

	if len(handles) == 0 {
		return 0, nil
	}

	return handles[0], nil
}

// findAllCertificatesWithPrefix finds all certificate handles with IDs starting with prefix.
// Must be called with mutex held (Lock).
func (p *PKCS11CertStorage) findAllCertificatesWithPrefix(prefix string) ([]pkcs11.ObjectHandle, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
	}

	if err := p.ctx.FindObjectsInit(p.session, template); err != nil {
		return nil, NewOperationError("init object search", err)
	}
	defer p.ctx.FindObjectsFinal(p.session)

	allHandles, _, err := p.ctx.FindObjects(p.session, 1000)
	if err != nil {
		return nil, NewOperationError("find objects", err)
	}

	// Filter handles by ID prefix
	var result []pkcs11.ObjectHandle
	for _, handle := range allHandles {
		attrs, err := p.ctx.GetAttributeValue(p.session, handle, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
		})
		if err != nil || len(attrs) == 0 {
			continue
		}

		id := string(attrs[0].Value)
		if len(id) >= len(prefix) && id[:len(prefix)] == prefix {
			result = append(result, handle)
		}
	}

	return result, nil
}

// chainID returns the chain ID prefix for a given certificate ID.
func (p *PKCS11CertStorage) chainID(id string) string {
	return id + "-chain"
}

// isChainCertificate returns true if the ID represents a chain certificate.
// Chain certificates have IDs in the format: base-id-chain-N
func (p *PKCS11CertStorage) isChainCertificate(id string) bool {
	// Look for "-chain-" followed by a digit
	chainSuffix := "-chain-"
	chainIdx := len(id) - len(chainSuffix) - 1 // Position where -chain-N would start
	if chainIdx < 0 {
		return false
	}

	// Check if ID ends with -chain-<digit>
	if len(id) >= len(chainSuffix)+1 {
		for i := 0; i < len(id)-len(chainSuffix); i++ {
			substr := id[i : i+len(chainSuffix)]
			if substr == chainSuffix && i+len(chainSuffix) < len(id) {
				// Check if there's at least one character after "-chain-"
				return true
			}
		}
	}
	return false
}
