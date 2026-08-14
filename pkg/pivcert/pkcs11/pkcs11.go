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

// Package pkcs11 provides a PKCS#11-backed PIV certificate storage adapter.
//
// This adapter delegates certificate CRUD operations to hardware.PKCS11CertStorage,
// mapping PIV slot identifiers to CKA_ID byte values per NIST SP 800-73-5.
// It uses the shared SessionPool so there is no double-initialization of the
// PKCS#11 library.
package pkcs11

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/hardware"
	p11 "github.com/miekg/pkcs11"
)

// Compile-time interface check.
var _ pivcert.PIVCertificateStorage = (*PKCS11CertStorage)(nil)

// pivSlotToCKAIDMap maps PIV slot identifiers to their CKA_ID byte values.
// This matches the YubiKey PIV PKCS#11 CKA_ID convention used by
// pkg/backend/pkcs11/pkcs11.go createSlotID().
var pivSlotToCKAIDMap = map[pivcert.PIVSlot]byte{
	pivcert.PIVSlotAuthentication:     0x01,
	pivcert.PIVSlotDigitalSignature:   0x02,
	pivcert.PIVSlotKeyManagement:      0x03,
	pivcert.PIVSlotCardAuthentication: 0x04,
	pivcert.PIVSlotAttestation:        0x19,
	pivcert.PIVSlotRetired1:           0x05,
	pivcert.PIVSlotRetired2:           0x06,
	pivcert.PIVSlotRetired3:           0x07,
	pivcert.PIVSlotRetired4:           0x08,
	pivcert.PIVSlotRetired5:           0x09,
	pivcert.PIVSlotRetired6:           0x0a,
	pivcert.PIVSlotRetired7:           0x0b,
	pivcert.PIVSlotRetired8:           0x0c,
	pivcert.PIVSlotRetired9:           0x0d,
	pivcert.PIVSlotRetired10:          0x0e,
	pivcert.PIVSlotRetired11:          0x0f,
	pivcert.PIVSlotRetired12:          0x10,
	pivcert.PIVSlotRetired13:          0x11,
	pivcert.PIVSlotRetired14:          0x12,
	pivcert.PIVSlotRetired15:          0x13,
	pivcert.PIVSlotRetired16:          0x14,
	pivcert.PIVSlotRetired17:          0x15,
	pivcert.PIVSlotRetired18:          0x16,
	pivcert.PIVSlotRetired19:          0x17,
	pivcert.PIVSlotRetired20:          0x18,
}

// ckaIDToPIVSlotMap is the reverse mapping from CKA_ID byte to PIV slot.
var ckaIDToPIVSlotMap map[byte]pivcert.PIVSlot

func init() {
	ckaIDToPIVSlotMap = make(map[byte]pivcert.PIVSlot, len(pivSlotToCKAIDMap))
	for slot, id := range pivSlotToCKAIDMap {
		ckaIDToPIVSlotMap[id] = slot
	}
}

// PIVSlotToCKAID returns the CKA_ID byte for a PIV slot.
// Returns the byte and true if found, or 0 and false if the slot
// has no CKA_ID mapping.
func PIVSlotToCKAID(slot pivcert.PIVSlot) (byte, bool) {
	b, ok := pivSlotToCKAIDMap[slot]
	return b, ok
}

// CKAIDToPIVSlot returns the PIV slot for a CKA_ID byte.
// Returns the slot and true if found, or empty string and false
// if the byte has no PIV slot mapping.
func CKAIDToPIVSlot(id byte) (pivcert.PIVSlot, bool) {
	slot, ok := ckaIDToPIVSlotMap[id]
	return slot, ok
}

// moduleRef tracks process-wide use of a PKCS#11 library so that concurrent
// storages created via New share a single C_Initialize and only the last
// Close finalizes the library. PKCS#11 does not reference-count
// C_Initialize/C_Finalize itself, so finalizing while another storage holds
// sessions would invalidate them.
type moduleRef struct {
	ctx  *p11.Ctx
	refs int
	// ownsInit records whether this package performed C_Initialize. When
	// another consumer initialized the library first
	// (CKR_CRYPTOKI_ALREADY_INITIALIZED), the registry never finalizes it.
	ownsInit bool
}

var (
	modulesMu sync.Mutex
	modules   = make(map[string]*moduleRef)
)

// acquireModule loads and initializes the PKCS#11 library at libPath,
// reusing the existing process-wide context when one is already attached.
func acquireModule(libPath string) (*moduleRef, error) {
	modulesMu.Lock()
	defer modulesMu.Unlock()

	if ref, ok := modules[libPath]; ok {
		ref.refs++
		return ref, nil
	}

	ctx := p11.New(libPath)
	if ctx == nil {
		return nil, pivcert.NewStorageTypeError("New", pivcert.StorageTypePKCS11,
			&errs.Message{Msg: fmt.Sprintf("pkcs11: failed to load library: %s", libPath)})
	}

	ownsInit := true
	if err := ctx.Initialize(); err != nil {
		if !isPKCS11Error(err, p11.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
			ctx.Destroy()
			return nil, pivcert.NewStorageTypeError("New", pivcert.StorageTypePKCS11,
				&errs.Wrapped{Msg: "pkcs11: Initialize", Err: err})
		}
		ownsInit = false
	}

	ref := &moduleRef{ctx: ctx, refs: 1, ownsInit: ownsInit}
	modules[libPath] = ref
	return ref, nil
}

// releaseModule drops one reference to the library at libPath, finalizing
// and unloading it when the last reference is released.
func releaseModule(libPath string) error {
	modulesMu.Lock()
	defer modulesMu.Unlock()

	ref, ok := modules[libPath]
	if !ok {
		return nil
	}
	ref.refs--
	if ref.refs > 0 {
		return nil
	}
	delete(modules, libPath)

	var err error
	if ref.ownsInit {
		if ferr := ref.ctx.Finalize(); ferr != nil {
			err = pivcert.NewStorageTypeError("Close", pivcert.StorageTypePKCS11,
				&errs.Wrapped{Msg: "pkcs11: Finalize", Err: ferr})
		}
	}
	ref.ctx.Destroy()
	return err
}

// PKCS11CertStorage implements PIVCertificateStorage by delegating to
// hardware.PKCS11CertStorage with PIV slot-to-CKA_ID byte mapping.
//
// When created via New, the storage holds a reference on the process-wide
// module registry and releases it (closing the session pool, and finalizing
// the library on last release) in Close. When created via NewFromPool,
// NewFromSession, or NewFromSessionWithSO, the caller retains ownership of
// the context/session and Close releases only the storage itself.
type PKCS11CertStorage struct {
	hw hardware.HardwareCertStorage
	// pool is non-nil only when New created it; Close drains it.
	pool *standalonePool
	// libPath is non-empty only when New acquired a module reference;
	// Close releases it via releaseModule.
	libPath string
	// closed is atomic because PIVCertificateStorage implementations must be
	// safe for concurrent use: every operation reads it while Close writes it.
	closed atomic.Bool
}

// New creates a new PKCS#11-backed PIV certificate storage.
// It initializes the PKCS#11 library, resolves the token slot, creates a
// session pool, and delegates cert operations to hardware.PKCS11CertStorage.
func New(config *pivcert.PKCS11StorageConfig) (*PKCS11CertStorage, error) {
	if config == nil {
		return nil, pivcert.NewStorageTypeError("New", pivcert.StorageTypePKCS11, pivcert.ErrInvalidConfig)
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}

	ref, err := acquireModule(config.LibraryPath)
	if err != nil {
		return nil, err
	}
	ctx := ref.ctx

	// teardown releases this call's module reference on error paths,
	// finalizing the library when this was the last reference.
	teardown := func() {
		if rerr := releaseModule(config.LibraryPath); rerr != nil {
			slog.Warn("pivcert: pkcs11 module release failed", "error", rerr)
		}
	}

	slotID, err := resolveSlot(ctx, config)
	if err != nil {
		teardown()
		return nil, err
	}

	// Create a session pool with a small size (cert ops are infrequent)
	pool, err := newSessionPool(ctx, slotID, config.PIN, 2)
	if err != nil {
		teardown()
		return nil, pivcert.NewStorageTypeError("New", pivcert.StorageTypePKCS11,
			&errs.Wrapped{Msg: "pkcs11: session pool", Err: err})
	}

	var hw hardware.HardwareCertStorage
	if config.RequireSO {
		hw, err = hardware.NewPKCS11CertStorageWithSO(pool, config.TokenLabel, config.SOPIN, config.PIN, true)
	} else {
		hw, err = hardware.NewPKCS11CertStorage(pool, config.TokenLabel)
	}
	if err != nil {
		pool.Close()
		teardown()
		return nil, pivcert.NewStorageTypeError("New", pivcert.StorageTypePKCS11, err)
	}

	return &PKCS11CertStorage{hw: hw, pool: pool, libPath: config.LibraryPath}, nil
}

// NewFromPool creates a PKCS#11 PIV certificate storage that reuses an existing
// session pool. This avoids double-initialization when the PKCS#11 library is
// already managed by the backend or module manager.
func NewFromPool(pool hardware.PKCS11SessionProvider, tokenLabel string) (*PKCS11CertStorage, error) {
	if pool == nil {
		return nil, pivcert.NewStorageTypeError("NewFromPool", pivcert.StorageTypePKCS11, pivcert.ErrInvalidConfig)
	}
	hw, err := hardware.NewPKCS11CertStorage(pool, tokenLabel)
	if err != nil {
		return nil, pivcert.NewStorageTypeError("NewFromPool", pivcert.StorageTypePKCS11, err)
	}
	return &PKCS11CertStorage{hw: hw}, nil
}

// NewFromSession creates a PKCS#11 PIV certificate storage that reuses an
// existing PKCS#11 context and session. This is a convenience wrapper that
// creates a minimal session provider from the raw handles.
func NewFromSession(ctx *p11.Ctx, session p11.SessionHandle, slotID uint) (*PKCS11CertStorage, error) {
	if ctx == nil {
		return nil, pivcert.NewStorageTypeError("NewFromSession", pivcert.StorageTypePKCS11, pivcert.ErrInvalidConfig)
	}
	provider := &singleSessionProvider{ctx: ctx, session: session, slotID: slotID}
	hw, err := hardware.NewPKCS11CertStorage(provider, "")
	if err != nil {
		return nil, pivcert.NewStorageTypeError("NewFromSession", pivcert.StorageTypePKCS11, err)
	}
	return &PKCS11CertStorage{hw: hw}, nil
}

// NewFromSessionWithSO creates a PKCS#11 PIV certificate storage that reuses
// an existing context and session, with SO (Security Officer) session elevation
// for write/delete operations. Required for YubiKey PIV tokens where
// C_CreateObject and C_DestroyObject are rejected under CKU_USER.
func NewFromSessionWithSO(ctx *p11.Ctx, session p11.SessionHandle, slotID uint, soPin, userPin string) (*PKCS11CertStorage, error) {
	if ctx == nil {
		return nil, pivcert.NewStorageTypeError("NewFromSessionWithSO", pivcert.StorageTypePKCS11, pivcert.ErrInvalidConfig)
	}
	provider := &singleSessionProvider{
		ctx:     ctx,
		session: session,
		slotID:  slotID,
		soPin:   soPin,
		userPin: userPin,
	}
	hw, err := hardware.NewPKCS11CertStorageWithSO(provider, "", soPin, userPin, true)
	if err != nil {
		return nil, pivcert.NewStorageTypeError("NewFromSessionWithSO", pivcert.StorageTypePKCS11, err)
	}
	return &PKCS11CertStorage{hw: hw}, nil
}

// pivID converts a PIV slot to the string ID used by HardwareCertStorage.
// The CKA_ID byte value is stored as a single-byte string so that
// hardware.PKCS11CertStorage sets CKA_ID to the exact PIV byte.
func pivID(slot pivcert.PIVSlot) (string, error) {
	b, ok := pivSlotToCKAIDMap[slot]
	if !ok {
		return "", pivcert.ErrInvalidSlot
	}
	return string([]byte{b}), nil
}

// Store stores a certificate for the given PIV slot on the PKCS#11 token.
func (s *PKCS11CertStorage) Store(slot pivcert.PIVSlot, cert *x509.Certificate) error {
	if s.closed.Load() {
		return pivcert.NewStorageError("Store", slot, pivcert.ErrStorageClosed)
	}
	if !slot.IsValid() {
		return pivcert.NewStorageError("Store", slot, pivcert.ErrInvalidSlot)
	}
	if cert == nil {
		return pivcert.NewStorageError("Store", slot, pivcert.ErrInvalidCertificate)
	}
	if len(cert.Raw) > pivcert.MaxCertSizePKCS11 {
		return pivcert.NewStorageError("Store", slot, pivcert.ErrCertificateTooLarge)
	}

	id, err := pivID(slot)
	if err != nil {
		return pivcert.NewStorageError("Store", slot, err)
	}
	if err := s.hw.SaveCert(id, cert); err != nil {
		return pivcert.NewStorageError("Store", slot, err)
	}
	return nil
}

// Retrieve retrieves the certificate for the given PIV slot from the token.
func (s *PKCS11CertStorage) Retrieve(slot pivcert.PIVSlot) (*x509.Certificate, error) {
	if s.closed.Load() {
		return nil, pivcert.NewStorageError("Retrieve", slot, pivcert.ErrStorageClosed)
	}
	if !slot.IsValid() {
		return nil, pivcert.NewStorageError("Retrieve", slot, pivcert.ErrInvalidSlot)
	}

	id, err := pivID(slot)
	if err != nil {
		return nil, pivcert.NewStorageError("Retrieve", slot, err)
	}
	cert, err := s.hw.GetCert(id)
	if err != nil {
		return nil, pivcert.NewStorageError("Retrieve", slot, pivcert.ErrCertificateNotFound)
	}
	return cert, nil
}

// Delete removes the certificate from the given PIV slot on the token.
func (s *PKCS11CertStorage) Delete(slot pivcert.PIVSlot) error {
	if s.closed.Load() {
		return pivcert.NewStorageError("Delete", slot, pivcert.ErrStorageClosed)
	}
	if !slot.IsValid() {
		return pivcert.NewStorageError("Delete", slot, pivcert.ErrInvalidSlot)
	}

	id, err := pivID(slot)
	if err != nil {
		return pivcert.NewStorageError("Delete", slot, err)
	}
	if err := s.hw.DeleteCert(id); err != nil {
		// Translate the hardware-layer not-found sentinel into the pivcert API
		// sentinel callers assert on; surface all other errors (e.g. a token
		// that does not support deletion) unchanged.
		if errors.Is(err, storage.ErrNotFound) {
			return pivcert.NewStorageError("Delete", slot, pivcert.ErrCertificateNotFound)
		}
		return pivcert.NewStorageError("Delete", slot, err)
	}
	return nil
}

// List returns information about all certificate objects stored on the token.
// Only objects whose CKA_ID maps to a known PIV slot are included.
func (s *PKCS11CertStorage) List() ([]pivcert.PIVSlotInfo, error) {
	if s.closed.Load() {
		return nil, pivcert.NewStorageTypeError("List", pivcert.StorageTypePKCS11, pivcert.ErrStorageClosed)
	}

	ids, err := s.hw.ListCerts()
	if err != nil {
		return nil, pivcert.NewStorageTypeError("List", pivcert.StorageTypePKCS11, err)
	}

	var result []pivcert.PIVSlotInfo
	for _, id := range ids {
		// Map CKA_ID byte back to PIV slot
		if len(id) != 1 {
			continue
		}
		slot, ok := ckaIDToPIVSlotMap[id[0]]
		if !ok {
			continue
		}

		cert, err := s.hw.GetCert(id)
		if err != nil {
			continue
		}

		result = append(result, pivcert.NewSlotInfo(slot, cert, time.Now().UTC()))
	}
	return result, nil
}

// Import imports a certificate from external encoding into the given PIV slot.
func (s *PKCS11CertStorage) Import(slot pivcert.PIVSlot, data []byte, format pivcert.CertFormat) error {
	if len(data) == 0 {
		return pivcert.NewStorageError("Import", slot, pivcert.ErrInvalidCertificate)
	}

	cert, err := parseCertificate(slot, data, format)
	if err != nil {
		return err
	}
	return s.Store(slot, cert)
}

// Export exports a certificate from the given PIV slot in the specified format.
func (s *PKCS11CertStorage) Export(slot pivcert.PIVSlot, format pivcert.CertFormat) ([]byte, error) {
	cert, err := s.Retrieve(slot)
	if err != nil {
		return nil, err
	}

	switch format {
	case pivcert.FormatDER:
		return cert.Raw, nil
	case pivcert.FormatPEM:
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), nil
	default:
		return nil, pivcert.NewStorageError("Export", slot, pivcert.ErrInvalidFormat)
	}
}

// Close releases resources. After Close, all methods return ErrStorageClosed.
// When the storage was created via New, Close also drains the session pool
// and releases its module reference (finalizing the PKCS#11 library when the
// last reference is released); storages created from an external pool or
// session leave the caller-owned context untouched.
func (s *PKCS11CertStorage) Close() error {
	// CompareAndSwap so two concurrent Close calls cannot both proceed to tear
	// down the pool and release the module reference.
	if !s.closed.CompareAndSwap(false, true) {
		return pivcert.NewStorageTypeError("Close", pivcert.StorageTypePKCS11, pivcert.ErrStorageClosed)
	}

	err := s.hw.Close()
	if s.pool != nil {
		s.pool.Close()
	}
	if s.libPath != "" {
		if rerr := releaseModule(s.libPath); rerr != nil && err == nil {
			err = rerr
		}
	}
	return err
}

// Type returns the storage type identifier.
func (s *PKCS11CertStorage) Type() pivcert.PIVStorageType {
	return pivcert.StorageTypePKCS11
}

// --- helpers ---

// singleSessionProvider wraps a raw ctx+session for backward compatibility
// with NewFromSession. It does NOT pool sessions — each WithSession call
// reuses the same session handle. When soPin is set, it also implements
// PKCS11SOSessionProvider for YubiKey PIV SO login elevation.
type singleSessionProvider struct {
	ctx     *p11.Ctx
	session p11.SessionHandle
	slotID  uint
	soPin   string
	userPin string
}

func (p *singleSessionProvider) WithSession(fn func(p11.SessionHandle) error) error {
	return fn(p.session)
}
func (p *singleSessionProvider) Ctx() *p11.Ctx { return p.ctx }
func (p *singleSessionProvider) SlotID() uint  { return p.slotID }

// WithSOSession switches the session login from CKU_USER to CKU_SO,
// executes fn, then restores CKU_USER login.
func (p *singleSessionProvider) WithSOSession(soPin, userPin string, fn func(p11.SessionHandle) error) error {
	_ = p.ctx.Logout(p.session)
	if err := p.ctx.Login(p.session, p11.CKU_SO, soPin); err != nil {
		if !isPKCS11Error(err, p11.CKR_USER_ALREADY_LOGGED_IN) {
			_ = p.ctx.Login(p.session, p11.CKU_USER, userPin)
			return &errs.Wrapped{Msg: "pkcs11: SO login", Err: err}
		}
	}

	fnErr := fn(p.session)

	_ = p.ctx.Logout(p.session)
	if userPin != "" {
		if err := p.ctx.Login(p.session, p11.CKU_USER, userPin); err != nil {
			if !isPKCS11Error(err, p11.CKR_USER_ALREADY_LOGGED_IN) {
				return &errs.Affix{Prefix: "pkcs11: user login restore: ", Err: err, Suffix: fmt.Sprintf(" (original: %v)", fnErr)}
			}
		}
	}
	return fnErr
}

// newSessionPool creates a minimal session pool for standalone use.
// It satisfies hardware.PKCS11SessionProvider.
type standalonePool struct {
	ctx    *p11.Ctx
	slotID uint
	ch     chan p11.SessionHandle
}

func newSessionPool(ctx *p11.Ctx, slotID uint, pin string, size int) (*standalonePool, error) {
	pool := &standalonePool{
		ctx:    ctx,
		slotID: slotID,
		ch:     make(chan p11.SessionHandle, size),
	}
	for i := 0; i < size; i++ {
		sess, err := ctx.OpenSession(slotID, p11.CKF_SERIAL_SESSION|p11.CKF_RW_SESSION)
		if err != nil {
			pool.Close()
			return nil, err
		}
		pool.ch <- sess
	}
	if pin != "" {
		sess := <-pool.ch
		err := ctx.Login(sess, p11.CKU_USER, pin)
		pool.ch <- sess
		if err != nil && !isPKCS11Error(err, p11.CKR_USER_ALREADY_LOGGED_IN) {
			pool.Close()
			return nil, err
		}
	}
	return pool, nil
}

func (p *standalonePool) WithSession(fn func(p11.SessionHandle) error) error {
	sess := <-p.ch
	err := fn(sess)
	p.ch <- sess
	return err
}
func (p *standalonePool) Ctx() *p11.Ctx { return p.ctx }
func (p *standalonePool) SlotID() uint  { return p.slotID }

// WithSOSession switches the session login from CKU_USER to CKU_SO,
// executes fn, then restores CKU_USER login.
func (p *standalonePool) WithSOSession(soPin, userPin string, fn func(p11.SessionHandle) error) error {
	sess := <-p.ch
	defer func() { p.ch <- sess }()

	_ = p.ctx.Logout(sess)
	if err := p.ctx.Login(sess, p11.CKU_SO, soPin); err != nil {
		if !isPKCS11Error(err, p11.CKR_USER_ALREADY_LOGGED_IN) {
			_ = p.ctx.Login(sess, p11.CKU_USER, userPin)
			return &errs.Wrapped{Msg: "pkcs11: SO login", Err: err}
		}
	}

	fnErr := fn(sess)

	_ = p.ctx.Logout(sess)
	if userPin != "" {
		if err := p.ctx.Login(sess, p11.CKU_USER, userPin); err != nil {
			if !isPKCS11Error(err, p11.CKR_USER_ALREADY_LOGGED_IN) {
				return &errs.Affix{Prefix: "pkcs11: user login restore: ", Err: err, Suffix: fmt.Sprintf(" (original: %v)", fnErr)}
			}
		}
	}
	return fnErr
}

func (p *standalonePool) Close() {
	for {
		select {
		case sess := <-p.ch:
			p.ctx.CloseSession(sess)
		default:
			return
		}
	}
}

// resolveSlot determines the PKCS#11 slot to use based on the configuration.
func resolveSlot(ctx *p11.Ctx, config *pivcert.PKCS11StorageConfig) (uint, error) {
	if config.SlotID >= 0 {
		return uint(config.SlotID), nil
	}

	slots, err := ctx.GetSlotList(true)
	if err != nil {
		return 0, pivcert.NewStorageTypeError("resolveSlot", pivcert.StorageTypePKCS11,
			&errs.Wrapped{Msg: "pkcs11: GetSlotList", Err: err})
	}
	if len(slots) == 0 {
		return 0, pivcert.NewStorageTypeError("resolveSlot", pivcert.StorageTypePKCS11, pivcert.ErrTokenNotFound)
	}

	if config.TokenLabel == "" {
		return slots[0], nil
	}

	for _, slot := range slots {
		tokenInfo, err := ctx.GetTokenInfo(slot)
		if err != nil {
			continue
		}
		if strings.TrimRight(tokenInfo.Label, " ") == strings.TrimRight(config.TokenLabel, " ") {
			return slot, nil
		}
	}
	return 0, pivcert.NewStorageTypeError("resolveSlot", pivcert.StorageTypePKCS11, pivcert.ErrTokenNotFound)
}

// parseCertificate parses certificate data from the given format.
func parseCertificate(slot pivcert.PIVSlot, data []byte, format pivcert.CertFormat) (*x509.Certificate, error) {
	switch format {
	case pivcert.FormatDER:
		cert, err := x509.ParseCertificate(data)
		if err != nil {
			return nil, pivcert.NewStorageError("Import", slot, pivcert.ErrInvalidCertificate)
		}
		return cert, nil
	case pivcert.FormatPEM:
		block, _ := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, pivcert.NewStorageError("Import", slot, pivcert.ErrInvalidFormat)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, pivcert.NewStorageError("Import", slot, pivcert.ErrInvalidCertificate)
		}
		return cert, nil
	default:
		return nil, pivcert.NewStorageError("Import", slot, pivcert.ErrInvalidFormat)
	}
}

// isPKCS11Error checks if the given error is a specific PKCS#11 return value.
func isPKCS11Error(err error, rv uint) bool {
	if err == nil {
		return false
	}
	p11Err, ok := err.(p11.Error)
	if !ok {
		return false
	}
	return uint(p11Err) == rv
}
