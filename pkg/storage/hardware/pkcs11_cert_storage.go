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

//go:build pkcs11

package hardware

import (
	"crypto/x509"
	"fmt"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/miekg/pkcs11"
)

// PKCS11SessionProvider abstracts the SessionPool interface to avoid an
// import cycle between hardware and backend/pkcs11. The backend/pkcs11
// SessionPool satisfies this interface.
type PKCS11SessionProvider interface {
	// WithSession checks out a session, calls fn, and returns the session.
	WithSession(fn func(session pkcs11.SessionHandle) error) error
	// Ctx returns the underlying PKCS#11 context.
	Ctx() *pkcs11.Ctx
	// SlotID returns the slot ID this provider operates on.
	SlotID() uint
}

// PKCS11SOSessionProvider is an optional interface implemented by session
// providers that can execute operations under a CKU_SO (Security Officer)
// login. Required for YubiKey PIV certificate/key deletion, which rejects
// C_DestroyObject under CKU_USER with CKR_USER_TYPE_INVALID.
type PKCS11SOSessionProvider interface {
	WithSOSession(soPin, userPin string, fn func(session pkcs11.SessionHandle) error) error
}

// PKCS11CertStorage implements HardwareCertStorage for PKCS#11 HSMs.
// Certificates are stored as CKO_CERTIFICATE objects on the token.
//
// Thread Safety:
// All operations are serialized through the PKCS11SessionProvider, which
// provides channel-based, lock-free concurrency control over PKCS#11 sessions.
type PKCS11CertStorage struct {
	pool       PKCS11SessionProvider
	tokenLabel string
	soPin      string
	userPin    string
	requireSO  bool
	closed     bool
}

// NewPKCS11CertStorage creates a new PKCS#11 certificate storage instance
// backed by a session pool. The pool must be initialized and logged in.
// This is the backward-compatible constructor that does not use CKU_SO
// elevation for deletes.
func NewPKCS11CertStorage(
	pool PKCS11SessionProvider,
	tokenLabel string,
) (HardwareCertStorage, error) {
	return NewPKCS11CertStorageWithSO(pool, tokenLabel, "", "", false)
}

// NewPKCS11CertStorageWithSO creates a PKCS#11 certificate storage instance
// that can optionally elevate to CKU_SO (Security Officer) for delete
// operations. Required for YubiKey PIV where C_DestroyObject is rejected
// under CKU_USER. When requireSO is true and the supplied pool implements
// PKCS11SOSessionProvider, deletes run via WithSOSession using soPin to
// authenticate as SO and userPin to restore the user login afterwards.
func NewPKCS11CertStorageWithSO(
	pool PKCS11SessionProvider,
	tokenLabel, soPin, userPin string,
	requireSO bool,
) (HardwareCertStorage, error) {
	if pool == nil {
		return nil, ErrNilContext
	}
	return &PKCS11CertStorage{
		pool:       pool,
		tokenLabel: tokenLabel,
		soPin:      soPin,
		userPin:    userPin,
		requireSO:  requireSO,
	}, nil
}

// SaveCert stores a certificate as a CKO_CERTIFICATE object.
// If a certificate with the same ID exists, it will be overwritten.
func (p *PKCS11CertStorage) SaveCert(id string, cert *x509.Certificate) error {
	if p.closed {
		return ErrStorageClosed
	}

	if id == "" {
		return storage.ErrInvalidID
	}

	if cert == nil {
		return storage.ErrInvalidData
	}

	return p.pool.WithSession(func(session pkcs11.SessionHandle) error {
		// Check if certificate already exists and delete it first
		existingHandle, err := p.findCertificateHandle(session, id)
		if err == nil && existingHandle != 0 {
			if err := p.pool.Ctx().DestroyObject(session, existingHandle); err != nil {
				return NewOperationError("delete existing certificate", err)
			}
		}

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

		_, err = p.pool.Ctx().CreateObject(session, template)
		if err != nil {
			if err == pkcs11.Error(pkcs11.CKR_DEVICE_MEMORY) ||
				err == pkcs11.Error(pkcs11.CKR_TOKEN_WRITE_PROTECTED) {
				return ErrTokenFull
			}
			return NewOperationError("create certificate object", err)
		}

		return nil
	})
}

// GetCert retrieves a certificate by ID using CKA_ID attribute search.
func (p *PKCS11CertStorage) GetCert(id string) (*x509.Certificate, error) {
	if p.closed {
		return nil, ErrStorageClosed
	}

	if id == "" {
		return nil, storage.ErrInvalidID
	}

	var cert *x509.Certificate
	err := p.pool.WithSession(func(session pkcs11.SessionHandle) error {
		handle, err := p.findCertificateHandle(session, id)
		if err != nil {
			return err
		}

		if handle == 0 {
			return storage.ErrNotFound
		}

		attrs, err := p.pool.Ctx().GetAttributeValue(session, handle, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
		})
		if err != nil {
			return NewOperationError("get certificate value", err)
		}

		if len(attrs) == 0 || len(attrs[0].Value) == 0 {
			return ErrInvalidCertificate
		}

		cert, err = x509.ParseCertificate(attrs[0].Value)
		if err != nil {
			return NewOperationError("parse certificate", err)
		}

		return nil
	})

	return cert, err
}

// runDelete runs fn with either a CKU_SO elevated session (when requireSO is
// set and the pool supports it) or a normal user session.
func (p *PKCS11CertStorage) runDelete(fn func(session pkcs11.SessionHandle) error) error {
	if p.requireSO && p.soPin != "" {
		if sp, ok := p.pool.(PKCS11SOSessionProvider); ok {
			return sp.WithSOSession(p.soPin, p.userPin, fn)
		}
	}
	return p.pool.WithSession(fn)
}

// DeleteCert removes a certificate object from the token.
//
// After C_DestroyObject returns success, we re-search for the CKA_ID: some
// tokens (notably YubiKey PIV via libykcs11) silently accept DestroyObject
// without actually removing the object. If the object is still present,
// ErrDeleteNotSupportedOnToken is returned so callers can present an
// actionable message instead of a misleading "deleted" result.
func (p *PKCS11CertStorage) DeleteCert(id string) error {
	if p.closed {
		return ErrStorageClosed
	}

	if id == "" {
		return storage.ErrInvalidID
	}

	return p.runDelete(func(session pkcs11.SessionHandle) error {
		deleted := false

		handle, err := p.findCertificateHandle(session, id)
		if err != nil {
			return NewOperationError("find certificate", err)
		}

		if handle == 0 {
			// Check chain form.
			chainID := p.chainID(id)
			chainHandles, chainErr := p.findAllCertificatesWithPrefix(session, chainID)
			if chainErr != nil || len(chainHandles) == 0 {
				return storage.ErrNotFound
			}
			for _, h := range chainHandles {
				if err := p.pool.Ctx().DestroyObject(session, h); err != nil {
					return NewOperationError("delete chain certificate", err)
				}
				deleted = true
			}
			// Verify chain actually gone.
			remaining, _ := p.findAllCertificatesWithPrefix(session, chainID)
			if len(remaining) > 0 {
				return fmt.Errorf("%w: chain %q still present after DestroyObject -- token does not support deletion (YubiKey PIV slots must be overwritten or reset via 'ykman piv reset')",
					ErrDeleteNotSupportedOnToken, id)
			}
		} else {
			if err := p.pool.Ctx().DestroyObject(session, handle); err != nil {
				return NewOperationError("delete certificate", err)
			}
			deleted = true

			// Verify primary cert actually gone.
			if verifyHandle, verr := p.findCertificateHandle(session, id); verr == nil && verifyHandle != 0 {
				return fmt.Errorf("%w: cert %q still present after DestroyObject -- token does not support deletion (YubiKey PIV slots must be overwritten or reset via 'ykman piv reset')",
					ErrDeleteNotSupportedOnToken, id)
			}

			// Also delete chain certificates if they exist (best effort).
			chainID := p.chainID(id)
			chainHandles, err := p.findAllCertificatesWithPrefix(session, chainID)
			if err == nil {
				for _, h := range chainHandles {
					p.pool.Ctx().DestroyObject(session, h)
				}
			}
		}

		if !deleted {
			return storage.ErrNotFound
		}

		return nil
	})
}

// SaveCertChain stores a certificate chain as individual certificates.
func (p *PKCS11CertStorage) SaveCertChain(id string, chain []*x509.Certificate) error {
	if p.closed {
		return ErrStorageClosed
	}

	if id == "" {
		return storage.ErrInvalidID
	}

	if len(chain) == 0 {
		return storage.ErrInvalidData
	}

	for i, cert := range chain {
		if cert == nil {
			return fmt.Errorf("certificate at index %d is nil: %w", i, storage.ErrInvalidData)
		}
	}

	return p.pool.WithSession(func(session pkcs11.SessionHandle) error {
		chainID := p.chainID(id)
		existingHandles, _ := p.findAllCertificatesWithPrefix(session, chainID)
		for _, h := range existingHandles {
			p.pool.Ctx().DestroyObject(session, h)
		}

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

			_, err := p.pool.Ctx().CreateObject(session, template)
			if err != nil {
				if err == pkcs11.Error(pkcs11.CKR_DEVICE_MEMORY) ||
					err == pkcs11.Error(pkcs11.CKR_TOKEN_WRITE_PROTECTED) {
					return ErrTokenFull
				}
				return NewOperationError(fmt.Sprintf("create certificate chain object %d", i), err)
			}
		}

		return nil
	})
}

// GetCertChain retrieves a certificate chain by loading related certificates.
func (p *PKCS11CertStorage) GetCertChain(id string) ([]*x509.Certificate, error) {
	if p.closed {
		return nil, ErrStorageClosed
	}

	if id == "" {
		return nil, storage.ErrInvalidID
	}

	var chain []*x509.Certificate
	err := p.pool.WithSession(func(session pkcs11.SessionHandle) error {
		chainID := p.chainID(id)
		handles, err := p.findAllCertificatesWithPrefix(session, chainID)
		if err != nil {
			return err
		}

		if len(handles) == 0 {
			return storage.ErrNotFound
		}

		chain = make([]*x509.Certificate, len(handles))
		for i, handle := range handles {
			attrs, err := p.pool.Ctx().GetAttributeValue(session, handle, []*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
			})
			if err != nil {
				return NewOperationError(fmt.Sprintf("get certificate chain value at index %d", i), err)
			}

			if len(attrs) == 0 || len(attrs[0].Value) == 0 {
				return fmt.Errorf("empty certificate at index %d: %w", i, ErrInvalidCertificate)
			}

			cert, err := x509.ParseCertificate(attrs[0].Value)
			if err != nil {
				return NewOperationError(fmt.Sprintf("parse certificate at index %d", i), err)
			}

			chain[i] = cert
		}

		return nil
	})

	return chain, err
}

// ListCerts returns all certificate IDs by enumerating CKO_CERTIFICATE objects.
func (p *PKCS11CertStorage) ListCerts() ([]string, error) {
	if p.closed {
		return nil, ErrStorageClosed
	}

	var result []string
	err := p.pool.WithSession(func(session pkcs11.SessionHandle) error {
		template := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
		}

		if err := p.pool.Ctx().FindObjectsInit(session, template); err != nil {
			return NewOperationError("init certificate search", err)
		}
		defer p.pool.Ctx().FindObjectsFinal(session)

		handles, _, err := p.pool.Ctx().FindObjects(session, 1000)
		if err != nil {
			return NewOperationError("find certificates", err)
		}

		ids := make(map[string]bool)
		for _, handle := range handles {
			attrs, err := p.pool.Ctx().GetAttributeValue(session, handle, []*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
			})
			if err != nil || len(attrs) == 0 {
				continue
			}

			id := string(attrs[0].Value)
			if !p.isChainCertificate(id) {
				ids[id] = true
			}
		}

		result = make([]string, 0, len(ids))
		for id := range ids {
			result = append(result, id)
		}

		return nil
	})

	return result, err
}

// CertExists checks if a certificate object exists with the given ID.
func (p *PKCS11CertStorage) CertExists(id string) (bool, error) {
	if p.closed {
		return false, ErrStorageClosed
	}

	if id == "" {
		return false, storage.ErrInvalidID
	}

	var exists bool
	err := p.pool.WithSession(func(session pkcs11.SessionHandle) error {
		handle, err := p.findCertificateHandle(session, id)
		if err != nil {
			return nil
		}
		exists = handle != 0
		return nil
	})

	return exists, err
}

// Close marks the storage as closed.
func (p *PKCS11CertStorage) Close() error {
	if p.closed {
		return nil
	}

	p.closed = true
	return nil
}

// GetCapacity queries token info for certificate storage capacity.
func (p *PKCS11CertStorage) GetCapacity() (total int, available int, err error) {
	if p.closed {
		return 0, 0, ErrStorageClosed
	}

	tokenInfo, err := p.pool.Ctx().GetTokenInfo(p.pool.SlotID())
	if err != nil {
		return 0, 0, NewOperationError("get token info", err)
	}

	if tokenInfo.MaxSessionCount == pkcs11.CK_UNAVAILABLE_INFORMATION ||
		tokenInfo.MaxSessionCount == pkcs11.CK_EFFECTIVELY_INFINITE {
		return 0, 0, ErrNotSupported
	}

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
// Must be called from within a WithSession callback.
func (p *PKCS11CertStorage) findCertificateHandle(session pkcs11.SessionHandle, id string) (pkcs11.ObjectHandle, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(id)),
	}

	if err := p.pool.Ctx().FindObjectsInit(session, template); err != nil {
		return 0, NewOperationError("init object search", err)
	}
	defer p.pool.Ctx().FindObjectsFinal(session)

	handles, _, err := p.pool.Ctx().FindObjects(session, 1)
	if err != nil {
		return 0, NewOperationError("find objects", err)
	}

	if len(handles) == 0 {
		return 0, nil
	}

	return handles[0], nil
}

// findAllCertificatesWithPrefix finds all certificate handles with IDs starting with prefix.
// Must be called from within a WithSession callback.
func (p *PKCS11CertStorage) findAllCertificatesWithPrefix(session pkcs11.SessionHandle, prefix string) ([]pkcs11.ObjectHandle, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
	}

	if err := p.pool.Ctx().FindObjectsInit(session, template); err != nil {
		return nil, NewOperationError("init object search", err)
	}
	defer p.pool.Ctx().FindObjectsFinal(session)

	allHandles, _, err := p.pool.Ctx().FindObjects(session, 1000)
	if err != nil {
		return nil, NewOperationError("find objects", err)
	}

	var result []pkcs11.ObjectHandle
	for _, handle := range allHandles {
		attrs, err := p.pool.Ctx().GetAttributeValue(session, handle, []*pkcs11.Attribute{
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
func (p *PKCS11CertStorage) isChainCertificate(id string) bool {
	chainSuffix := "-chain-"
	chainIdx := len(id) - len(chainSuffix) - 1
	if chainIdx < 0 {
		return false
	}
	if len(id) >= len(chainSuffix)+1 {
		for i := 0; i < len(id)-len(chainSuffix); i++ {
			substr := id[i : i+len(chainSuffix)]
			if substr == chainSuffix && i+len(chainSuffix) < len(id) {
				return true
			}
		}
	}
	return false
}
