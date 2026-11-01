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
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

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

// PKCS11SearchProvider is an optional interface implemented by session
// providers that can run FindObjectsInit/FindObjects/FindObjectsFinal as one
// critical section per session handle, serialized against every other search
// on that handle. The backend/pkcs11 SessionPool satisfies this via
// WithSearch; a provider that doesn't (e.g. a single-session, unpooled
// wrapper) has no concurrent borrower to race, so this storage falls back to
// calling Init/Final directly (see doSearch). See #24.
type PKCS11SearchProvider interface {
	WithSearch(session pkcs11.SessionHandle, template []*pkcs11.Attribute, find func() error) error
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

	// searchLocks serializes doSearch per session handle when pool does not
	// implement PKCS11SearchProvider, as SessionPool.WithSearch does when it
	// does. Entries are never removed; see SessionPool.searchLocks.
	searchLocks sync.Map // pkcs11.SessionHandle -> *sync.Mutex

	// tokenMu orders this store's token writes against everything else it
	// does on the token: runWrite holds it exclusively, runRead shared. A
	// token is entitled to handle concurrent sessions itself under
	// CKF_OS_LOCKING_OK, but SoftHSM2 does not: a C_CreateObject racing a
	// search or another write fails CKR_GENERAL_ERROR and can persist an
	// object whose attributes no later search can read, after which every
	// search on the token fails. Certificate writes are rare and reads still
	// run in parallel, so this costs a pooled store nothing it relies on.
	tokenMu sync.RWMutex
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

// runWrite runs fn under the correct session type for a write operation.
//
// When requireSO is true:
//   - soPin must be non-empty, otherwise ErrSOSessionRequired is returned.
//     This prevents a silent fallthrough to a CKU_USER session that the token
//     would reject with CKR_USER_TYPE_INVALID (e.g. YubiKey PIV).
//   - the pool must implement PKCS11SOSessionProvider; if not, the same
//     typed error is returned because the configured SO requirement cannot
//     be satisfied.
//
// When requireSO is false the normal user session is used.
func (p *PKCS11CertStorage) runWrite(fn func(session pkcs11.SessionHandle) error) error {
	p.tokenMu.Lock()
	defer p.tokenMu.Unlock()

	if p.requireSO {
		if p.soPin == "" {
			return ErrSOSessionRequired
		}
		sp, ok := p.pool.(PKCS11SOSessionProvider)
		if !ok {
			return ErrSOSessionRequired
		}
		return sp.WithSOSession(p.soPin, p.userPin, fn)
	}
	return p.pool.WithSession(fn)
}

// runRead executes a read-only operation on a pooled session. Reads share
// tokenMu, so they run concurrently with each other but never alongside a
// write (see tokenMu).
func (p *PKCS11CertStorage) runRead(fn func(session pkcs11.SessionHandle) error) error {
	p.tokenMu.RLock()
	defer p.tokenMu.RUnlock()
	return p.pool.WithSession(fn)
}

// doSearch runs a FindObjectsInit(template) / find / FindObjectsFinal
// sequence on session as one critical section. When the pool implements
// PKCS11SearchProvider (the backend/pkcs11 SessionPool always does), the
// section is serialized against every other search on the same session
// handle, closing the window that let a search opened by one borrower still
// be active when the same handle reached the next one (#24). For any other
// provider the store serializes its own searches per session handle the same
// way.
//
// Either way a C_FindObjectsInit that fails is followed by a
// C_FindObjectsFinal: a token may mark the session as searching before the
// rest of the Init fails (SoftHSM2 does under concurrent writes), and an
// unfinalized search fails every later Init on the session with
// CKR_OPERATION_ACTIVE.
//
// find must not call FindObjectsInit or FindObjectsFinal itself.
func (p *PKCS11CertStorage) doSearch(session pkcs11.SessionHandle, template []*pkcs11.Attribute, find func() error) (err error) {
	if sp, ok := p.pool.(PKCS11SearchProvider); ok {
		return sp.WithSearch(session, template, find)
	}

	lock, _ := p.searchLocks.LoadOrStore(session, &sync.Mutex{})
	lock.(*sync.Mutex).Lock()
	defer lock.(*sync.Mutex).Unlock()

	ctx := p.pool.Ctx()
	if err := ctx.FindObjectsInit(session, template); err != nil {
		return ClearFailedPKCS11Search(ctx, session, err)
	}
	defer func() {
		// Joined onto find's error rather than discarded, matching
		// SessionPool.WithSearch so this path reports failures the same way.
		if finalErr := ctx.FindObjectsFinal(session); finalErr != nil {
			err = errors.Join(err, finalErr)
		}
	}()

	return find()
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
	if isReservedChainID(id) {
		return &errs.Detail{Err: ErrIDReservedForChain, Detail: fmt.Sprintf("%q", id)}
	}

	if cert == nil {
		return storage.ErrInvalidData
	}

	saveFn := func(session pkcs11.SessionHandle) error {
		// Delete any existing certificate with the same CKA_ID before creating
		// the new one. When requireSO is true, this callback runs under CKU_SO
		// via WithSOSession, so DestroyObject succeeds on YubiKey PIV tokens
		// that reject it under CKU_USER.
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

		_, createErr := p.pool.Ctx().CreateObject(session, template)
		if createErr != nil {
			if isCKR(createErr, pkcs11.CKR_DEVICE_MEMORY) ||
				isCKR(createErr, pkcs11.CKR_TOKEN_WRITE_PROTECTED) {
				return ErrTokenFull
			}
			return NewOperationError("create certificate object", createErr)
		}

		return nil
	}

	return p.runWrite(saveFn)
}

// GetCert retrieves a certificate by ID using CKA_ID attribute search.
func (p *PKCS11CertStorage) GetCert(id string) (*x509.Certificate, error) {
	if p.closed {
		return nil, ErrStorageClosed
	}

	if id == "" {
		return nil, storage.ErrInvalidID
	}
	if isReservedChainID(id) {
		return nil, &errs.Detail{Err: ErrIDReservedForChain, Detail: fmt.Sprintf("%q", id)}
	}

	var cert *x509.Certificate
	err := p.runRead(func(session pkcs11.SessionHandle) error {
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
	if isReservedChainID(id) {
		return &errs.Detail{Err: ErrIDReservedForChain, Detail: fmt.Sprintf("%q", id)}
	}

	// Only the certificate object (CKA_ID == id) is released. The chain
	// objects (CKA_ID == id-chain-<n>) are a separate record of the pair and
	// have their own release, DeleteCertChain; this method used to take them
	// too, so a caller addressing one record destroyed the other.
	//
	// After C_DestroyObject returns success, the CKA_ID is searched again:
	// some tokens (YubiKey PIV) accept the call and keep the object, and that
	// must surface as a refusal rather than a delete that did nothing.
	return p.runWrite(func(session pkcs11.SessionHandle) error {
		handle, err := p.findCertificateHandle(session, id)
		if err != nil {
			return NewOperationError("find certificate", err)
		}
		if handle == 0 {
			return storage.ErrNotFound
		}

		if err := p.pool.Ctx().DestroyObject(session, handle); err != nil {
			return NewOperationError("delete certificate", err)
		}

		verifyHandle, err := p.findCertificateHandle(session, id)
		if err != nil {
			return NewOperationError("verify certificate deletion", err)
		}
		if verifyHandle != 0 {
			return &errs.Detail{Err: ErrDeleteNotSupportedOnToken, Detail: fmt.Sprintf("cert %q still present after DestroyObject -- token does not support deletion (YubiKey PIV slots must be overwritten or reset via 'ykman piv reset')", id)}
		}

		return nil
	})
}

// DeleteCertChain removes the chain objects stored under id (CKA_ID
// id-chain-<n>) and leaves the certificate object in place.
func (p *PKCS11CertStorage) DeleteCertChain(id string) error {
	if p.closed {
		return ErrStorageClosed
	}

	if id == "" {
		return storage.ErrInvalidID
	}
	if isReservedChainID(id) {
		return &errs.Detail{Err: ErrIDReservedForChain, Detail: fmt.Sprintf("%q", id)}
	}

	return p.runWrite(func(session pkcs11.SessionHandle) error {
		chainHandles, err := p.findChainMemberHandles(session, id)
		if err != nil {
			return NewOperationError("find certificate chain", err)
		}
		if len(chainHandles) == 0 {
			return storage.ErrNotFound
		}

		for _, h := range chainHandles {
			if err := p.pool.Ctx().DestroyObject(session, h); err != nil {
				return NewOperationError("delete chain certificate", err)
			}
		}

		// The verification search is the only evidence of the outcome, so a
		// failure there is an unknown outcome and must surface as an error,
		// never fall through to a delete reported as done.
		remaining, err := p.findChainMemberHandles(session, id)
		if err != nil {
			return NewOperationError("verify chain deletion", err)
		}
		if len(remaining) > 0 {
			return &errs.Detail{Err: ErrDeleteNotSupportedOnToken, Detail: fmt.Sprintf("chain %q still present after DestroyObject -- token does not support deletion (YubiKey PIV slots must be overwritten or reset via 'ykman piv reset')", id)}
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
	if isReservedChainID(id) {
		return &errs.Detail{Err: ErrIDReservedForChain, Detail: fmt.Sprintf("%q", id)}
	}

	if len(chain) == 0 {
		return storage.ErrInvalidData
	}

	for i, cert := range chain {
		if cert == nil {
			return &errs.Wrapped{Msg: fmt.Sprintf("certificate at index %d is nil", i), Err: storage.ErrInvalidData}
		}
	}

	return p.runWrite(func(session pkcs11.SessionHandle) error {
		// An overwrite releases the previous members first, and it must know
		// they are gone before it writes the replacements: a member it could
		// not see, or could not destroy, would survive next to the new ones
		// and later reads would return a chain mixed from two writes.
		existingHandles, err := p.findChainMemberHandles(session, id)
		if err != nil {
			return NewOperationError("find existing certificate chain", err)
		}
		for _, h := range existingHandles {
			if err := p.pool.Ctx().DestroyObject(session, h); err != nil {
				return NewOperationError("delete existing chain certificate", err)
			}
		}
		if len(existingHandles) > 0 {
			remaining, err := p.findChainMemberHandles(session, id)
			if err != nil {
				return NewOperationError("verify chain replacement", err)
			}
			if len(remaining) > 0 {
				return &errs.Detail{Err: ErrDeleteNotSupportedOnToken, Detail: fmt.Sprintf("chain %q still present after DestroyObject -- the token did not release the previous members, so the replacement was not written", id)}
			}
		}

		for i, cert := range chain {
			certID := fmt.Sprintf("%s-%d", p.chainID(id), i)
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
				if isCKR(err, pkcs11.CKR_DEVICE_MEMORY) ||
					isCKR(err, pkcs11.CKR_TOKEN_WRITE_PROTECTED) {
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
	if isReservedChainID(id) {
		return nil, &errs.Detail{Err: ErrIDReservedForChain, Detail: fmt.Sprintf("%q", id)}
	}

	var chain []*x509.Certificate
	err := p.runRead(func(session pkcs11.SessionHandle) error {
		handles, err := p.findChainMemberHandles(session, id)
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
				return &errs.Wrapped{Msg: fmt.Sprintf("empty certificate at index %d", i), Err: ErrInvalidCertificate}
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
	err := p.runRead(func(session pkcs11.SessionHandle) error {
		template := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
		}

		var handles []pkcs11.ObjectHandle
		err := p.doSearch(session, template, func() error {
			var findErr error
			handles, findErr = p.findAllObjects(session)
			if findErr != nil {
				return NewOperationError("find certificates", findErr)
			}
			return nil
		})
		if err != nil {
			// A failure from doSearch's own FindObjectsInit surfaces raw, not
			// wrapped by the closure above, so it is distinguishable here.
			if _, ok := err.(*OperationError); ok {
				return err
			}
			return NewOperationError("init certificate search", err)
		}

		ids := make(map[string]bool)
		for _, handle := range handles {
			attrs, err := p.pool.Ctx().GetAttributeValue(session, handle, []*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
			})
			if err != nil {
				// A certificate whose id cannot be read is a listing that is
				// not known to be complete, not one that is shorter.
				return NewOperationError("read certificate id", err)
			}
			if len(attrs) == 0 {
				continue
			}

			id := string(attrs[0].Value)
			if !isChainMemberID(id) {
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
	if isReservedChainID(id) {
		return false, &errs.Detail{Err: ErrIDReservedForChain, Detail: fmt.Sprintf("%q", id)}
	}

	var exists bool
	err := p.runRead(func(session pkcs11.SessionHandle) error {
		handle, err := p.findCertificateHandle(session, id)
		if err != nil {
			// A search that failed did not establish absence. Callers such
			// as the adapter's PutIfAbsent treat false as authoritative, so
			// the failure must reach them as an unknown outcome.
			return NewOperationError("find certificate", err)
		}
		exists = handle != 0
		return nil
	})
	if err != nil {
		return false, err
	}

	return exists, nil
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

	var handles []pkcs11.ObjectHandle
	err := p.doSearch(session, template, func() error {
		var findErr error
		handles, _, findErr = p.pool.Ctx().FindObjects(session, 1)
		if findErr != nil {
			return NewOperationError("find objects", findErr)
		}
		return nil
	})
	if err != nil {
		if _, ok := err.(*OperationError); ok {
			return 0, err
		}
		return 0, NewOperationError("init object search", err)
	}

	if len(handles) == 0 {
		return 0, nil
	}

	return handles[0], nil
}

// findAllObjects drains an object search opened with FindObjectsInit,
// requesting pages until the token returns an empty one. C_FindObjects hands
// back at most the requested count per call, so a single call with a large
// count is still one page: a token holding more objects than that would hide
// the rest, and a chain member on a later page would be invisible to both
// the delete and its verification. Must be called between FindObjectsInit
// and FindObjectsFinal.
func (p *PKCS11CertStorage) findAllObjects(session pkcs11.SessionHandle) ([]pkcs11.ObjectHandle, error) {
	const pageSize = 256
	var all []pkcs11.ObjectHandle
	for {
		page, _, err := p.pool.Ctx().FindObjects(session, pageSize)
		if err != nil {
			return nil, err
		}
		if len(page) == 0 {
			return all, nil
		}
		all = append(all, page...)
	}
}

// findChainMemberHandles returns the handles of the members of id's chain,
// the objects whose CKA_ID is exactly id-chain-<n>, ordered by n. Objects
// that merely start with id-chain (a certificate named id-chain, the chain
// of id-chain2) belong to other records and are never returned.
// Must be called from within a WithSession callback.
func (p *PKCS11CertStorage) findChainMemberHandles(session pkcs11.SessionHandle, id string) ([]pkcs11.ObjectHandle, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
	}
	var allHandles []pkcs11.ObjectHandle
	err := p.doSearch(session, template, func() error {
		var findErr error
		allHandles, findErr = p.findAllObjects(session)
		if findErr != nil {
			return NewOperationError("find objects", findErr)
		}
		return nil
	})
	if err != nil {
		if _, ok := err.(*OperationError); ok {
			return nil, err
		}
		return nil, NewOperationError("init object search", err)
	}

	type member struct {
		index  int
		handle pkcs11.ObjectHandle
	}
	var members []member
	for _, handle := range allHandles {
		attrs, err := p.pool.Ctx().GetAttributeValue(session, handle, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
		})
		if err != nil {
			// The delete selects its objects here and verifies its outcome
			// here; a member whose id could not be read would be invisible
			// to both, so the failure is an unknown outcome, never a
			// shorter chain.
			return nil, NewOperationError("read certificate id", err)
		}
		if len(attrs) == 0 {
			continue
		}
		if index, ok := chainMemberIndex(id, string(attrs[0].Value)); ok {
			members = append(members, member{index: index, handle: handle})
		}
	}
	sort.Slice(members, func(i, j int) bool { return members[i].index < members[j].index })

	result := make([]pkcs11.ObjectHandle, len(members))
	for i, m := range members {
		result[i] = m.handle
	}
	return result, nil
}

// chainID returns the chain ID prefix for a given certificate ID.
func (p *PKCS11CertStorage) chainID(id string) string {
	return id + "-chain"
}

// isCKR reports whether err is, or wraps, a pkcs11.Error carrying the given
// Cryptoki return code (CKR_*). Call sites use this instead of comparing err
// to a pkcs11.Error value with == so a wrapped Cryptoki error still
// classifies correctly.
func isCKR(err error, code uint) bool {
	var ckErr pkcs11.Error
	return errors.As(err, &ckErr) && ckErr == pkcs11.Error(code)
}
