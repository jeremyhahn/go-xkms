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

// Package module provides PKCS#11 (Cryptoki) slot and token management types.
//
// This file implements CK_SLOT_INFO, CK_TOKEN_INFO, and related structures
// according to the OASIS PKCS#11 v3.0 specification. It provides a SlotManager
// for managing virtual slots and tokens used by the PKCS#11 module.
//
// References:
//   - OASIS PKCS#11 v3.0: https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/pkcs11-base-v3.0.html
package module

import (
	"crypto/rand"
	"crypto/subtle"
	"io"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/jeremyhahn/go-enclave"
	"golang.org/x/crypto/argon2"
)

// entropySource is the reader hashPin and generateSerialNumber draw randomness
// from. It defaults to crypto/rand and is a package var only so a test can
// substitute a failing reader to exercise the ErrEntropyUnavailable path.
var entropySource io.Reader = rand.Reader

// SlotID represents a PKCS#11 slot identifier (CK_SLOT_ID).
type SlotID uint64

// Version represents a PKCS#11 version structure (CK_VERSION).
// Used for hardware and firmware version information.
type Version struct {
	// Major is the major version number (integer portion).
	Major byte

	// Minor is the minor version number (one hundredth portion).
	Minor byte
}

// SlotFlag represents slot capability flags (CK_FLAGS for slots).
type SlotFlag uint64

// PKCS#11 v3.0 Slot Flags (CKF_* for C_GetSlotInfo)
const (
	// CKF_TOKEN_PRESENT indicates a token is present in the slot.
	CKF_TOKEN_PRESENT SlotFlag = 0x00000001

	// CKF_REMOVABLE_DEVICE indicates the slot supports removable devices.
	CKF_REMOVABLE_DEVICE SlotFlag = 0x00000002

	// CKF_HW_SLOT indicates a hardware slot (as opposed to software-only).
	CKF_HW_SLOT SlotFlag = 0x00000004
)

// slotFlagNames maps slot flags to their string names.
var slotFlagNames = map[SlotFlag]string{
	CKF_TOKEN_PRESENT:    "CKF_TOKEN_PRESENT",
	CKF_REMOVABLE_DEVICE: "CKF_REMOVABLE_DEVICE",
	CKF_HW_SLOT:          "CKF_HW_SLOT",
}

// String returns a human-readable representation of slot flags.
func (f SlotFlag) String() string {
	if f == 0 {
		return "0x00000000"
	}

	result := ""
	for flag, name := range slotFlagNames {
		if f&flag != 0 {
			if result != "" {
				result += "|"
			}
			result += name
		}
	}

	if result == "" {
		return uitoa(uint64(f))
	}
	return result
}

// Has checks if the specified flag is set.
func (f SlotFlag) Has(flag SlotFlag) bool {
	return f&flag != 0
}

// TokenFlag represents token capability flags (CK_FLAGS for tokens).
type TokenFlag uint64

// PKCS#11 v3.0 Token Flags (CKF_* for C_GetTokenInfo)
const (
	// CKF_RNG indicates the token has a random number generator.
	CKF_RNG TokenFlag = 0x00000001

	// CKF_WRITE_PROTECTED indicates the token is write-protected.
	CKF_WRITE_PROTECTED TokenFlag = 0x00000002

	// CKF_LOGIN_REQUIRED indicates login is required for most operations.
	CKF_LOGIN_REQUIRED TokenFlag = 0x00000004

	// CKF_USER_PIN_INITIALIZED indicates the user PIN has been initialized.
	CKF_USER_PIN_INITIALIZED TokenFlag = 0x00000008

	// CKF_RESTORE_KEY_NOT_NEEDED indicates a successful save of a session's
	// cryptographic operations state always contains all keys needed to
	// restore the state of the session.
	CKF_RESTORE_KEY_NOT_NEEDED TokenFlag = 0x00000020

	// CKF_CLOCK_ON_TOKEN indicates the token has a clock.
	CKF_CLOCK_ON_TOKEN TokenFlag = 0x00000040

	// CKF_PROTECTED_AUTHENTICATION_PATH indicates the token has a protected
	// authentication path (e.g., PIN pad).
	CKF_PROTECTED_AUTHENTICATION_PATH TokenFlag = 0x00000100

	// CKF_DUAL_CRYPTO_OPERATIONS indicates the token supports dual
	// cryptographic operations.
	CKF_DUAL_CRYPTO_OPERATIONS TokenFlag = 0x00000200

	// CKF_TOKEN_INITIALIZED indicates the token has been initialized.
	CKF_TOKEN_INITIALIZED TokenFlag = 0x00000400

	// CKF_SECONDARY_AUTHENTICATION indicates the token supports secondary
	// authentication.
	CKF_SECONDARY_AUTHENTICATION TokenFlag = 0x00000800

	// CKF_USER_PIN_COUNT_LOW indicates an incorrect user PIN has been
	// entered at least once since the last successful authentication.
	CKF_USER_PIN_COUNT_LOW TokenFlag = 0x00010000

	// CKF_USER_PIN_FINAL_TRY indicates supplying an incorrect user PIN
	// will cause it to become locked.
	CKF_USER_PIN_FINAL_TRY TokenFlag = 0x00020000

	// CKF_USER_PIN_LOCKED indicates the user PIN has been locked.
	CKF_USER_PIN_LOCKED TokenFlag = 0x00040000

	// CKF_USER_PIN_TO_BE_CHANGED indicates the user PIN must be changed.
	CKF_USER_PIN_TO_BE_CHANGED TokenFlag = 0x00080000

	// CKF_SO_PIN_COUNT_LOW indicates an incorrect SO PIN has been
	// entered at least once since the last successful authentication.
	CKF_SO_PIN_COUNT_LOW TokenFlag = 0x00100000

	// CKF_SO_PIN_FINAL_TRY indicates supplying an incorrect SO PIN
	// will cause it to become locked.
	CKF_SO_PIN_FINAL_TRY TokenFlag = 0x00200000

	// CKF_SO_PIN_LOCKED indicates the SO PIN has been locked.
	CKF_SO_PIN_LOCKED TokenFlag = 0x00400000

	// CKF_SO_PIN_TO_BE_CHANGED indicates the SO PIN must be changed.
	CKF_SO_PIN_TO_BE_CHANGED TokenFlag = 0x00800000

	// CKF_ERROR_STATE indicates the token is in an error state.
	CKF_ERROR_STATE TokenFlag = 0x01000000
)

// tokenFlagNames maps token flags to their string names.
var tokenFlagNames = map[TokenFlag]string{
	CKF_RNG:                           "CKF_RNG",
	CKF_WRITE_PROTECTED:               "CKF_WRITE_PROTECTED",
	CKF_LOGIN_REQUIRED:                "CKF_LOGIN_REQUIRED",
	CKF_USER_PIN_INITIALIZED:          "CKF_USER_PIN_INITIALIZED",
	CKF_RESTORE_KEY_NOT_NEEDED:        "CKF_RESTORE_KEY_NOT_NEEDED",
	CKF_CLOCK_ON_TOKEN:                "CKF_CLOCK_ON_TOKEN",
	CKF_PROTECTED_AUTHENTICATION_PATH: "CKF_PROTECTED_AUTHENTICATION_PATH",
	CKF_DUAL_CRYPTO_OPERATIONS:        "CKF_DUAL_CRYPTO_OPERATIONS",
	CKF_TOKEN_INITIALIZED:             "CKF_TOKEN_INITIALIZED",
	CKF_SECONDARY_AUTHENTICATION:      "CKF_SECONDARY_AUTHENTICATION",
	CKF_USER_PIN_COUNT_LOW:            "CKF_USER_PIN_COUNT_LOW",
	CKF_USER_PIN_FINAL_TRY:            "CKF_USER_PIN_FINAL_TRY",
	CKF_USER_PIN_LOCKED:               "CKF_USER_PIN_LOCKED",
	CKF_USER_PIN_TO_BE_CHANGED:        "CKF_USER_PIN_TO_BE_CHANGED",
	CKF_SO_PIN_COUNT_LOW:              "CKF_SO_PIN_COUNT_LOW",
	CKF_SO_PIN_FINAL_TRY:              "CKF_SO_PIN_FINAL_TRY",
	CKF_SO_PIN_LOCKED:                 "CKF_SO_PIN_LOCKED",
	CKF_SO_PIN_TO_BE_CHANGED:          "CKF_SO_PIN_TO_BE_CHANGED",
	CKF_ERROR_STATE:                   "CKF_ERROR_STATE",
}

// String returns a human-readable representation of token flags.
func (f TokenFlag) String() string {
	if f == 0 {
		return "0x00000000"
	}

	result := ""
	for flag, name := range tokenFlagNames {
		if f&flag != 0 {
			if result != "" {
				result += "|"
			}
			result += name
		}
	}

	if result == "" {
		return uitoa(uint64(f))
	}
	return result
}

// Has checks if the specified flag is set.
func (f TokenFlag) Has(flag TokenFlag) bool {
	return f&flag != 0
}

// SlotInfo represents PKCS#11 slot information (CK_SLOT_INFO).
// It provides information about a slot.
type SlotInfo struct {
	// SlotDescription is a character string description of the slot.
	// Per PKCS#11 spec, this is a UTF-8 padded string in a 64-byte field.
	SlotDescription [64]byte

	// ManufacturerID is a character string identifier of the slot manufacturer.
	// Per PKCS#11 spec, this is a UTF-8 padded string in a 32-byte field.
	ManufacturerID [32]byte

	// Flags contains bit flags indicating capabilities and status.
	Flags SlotFlag

	// HardwareVersion is the version number of the slot's hardware.
	HardwareVersion Version

	// FirmwareVersion is the version number of the slot's firmware.
	FirmwareVersion Version
}

// GetSlotDescription returns the slot description as a trimmed string.
func (s *SlotInfo) GetSlotDescription() string {
	return trimPaddedString(s.SlotDescription[:])
}

// SetSlotDescription sets the slot description, padding with spaces.
func (s *SlotInfo) SetSlotDescription(desc string) {
	setPaddedString(s.SlotDescription[:], desc)
}

// GetManufacturerID returns the manufacturer ID as a trimmed string.
func (s *SlotInfo) GetManufacturerID() string {
	return trimPaddedString(s.ManufacturerID[:])
}

// SetManufacturerID sets the manufacturer ID, padding with spaces.
func (s *SlotInfo) SetManufacturerID(id string) {
	setPaddedString(s.ManufacturerID[:], id)
}

// TokenInfo represents PKCS#11 token information (CK_TOKEN_INFO).
// It provides information about a token.
type TokenInfo struct {
	// Label is the application-defined label of the token.
	// Per PKCS#11 spec, this is a UTF-8 padded string in a 32-byte field.
	Label [32]byte

	// ManufacturerID is a character string identifier of the token manufacturer.
	// Per PKCS#11 spec, this is a UTF-8 padded string in a 32-byte field.
	ManufacturerID [32]byte

	// Model is a character string identifier of the token model.
	// Per PKCS#11 spec, this is a UTF-8 padded string in a 16-byte field.
	Model [16]byte

	// SerialNumber is a character string containing the token serial number.
	// Per PKCS#11 spec, this is a UTF-8 padded string in a 16-byte field.
	SerialNumber [16]byte

	// Flags contains bit flags indicating capabilities and status.
	Flags TokenFlag

	// MaxSessionCount is the maximum number of sessions that can be
	// opened with the token at once. CK_EFFECTIVELY_INFINITE (0) means
	// there is no maximum.
	MaxSessionCount uint64

	// SessionCount is the number of sessions currently open.
	SessionCount uint64

	// MaxRwSessionCount is the maximum number of read/write sessions.
	// CK_EFFECTIVELY_INFINITE (0) means there is no maximum.
	MaxRwSessionCount uint64

	// RwSessionCount is the number of read/write sessions currently open.
	RwSessionCount uint64

	// MaxPinLen is the maximum length in bytes of the PIN.
	MaxPinLen uint64

	// MinPinLen is the minimum length in bytes of the PIN.
	MinPinLen uint64

	// TotalPublicMemory is the total amount of memory for public objects.
	// CK_UNAVAILABLE_INFORMATION (^uint64(0)) means not available.
	TotalPublicMemory uint64

	// FreePublicMemory is the free memory for public objects.
	// CK_UNAVAILABLE_INFORMATION (^uint64(0)) means not available.
	FreePublicMemory uint64

	// TotalPrivateMemory is the total amount of memory for private objects.
	// CK_UNAVAILABLE_INFORMATION (^uint64(0)) means not available.
	TotalPrivateMemory uint64

	// FreePrivateMemory is the free memory for private objects.
	// CK_UNAVAILABLE_INFORMATION (^uint64(0)) means not available.
	FreePrivateMemory uint64

	// HardwareVersion is the version number of the token's hardware.
	HardwareVersion Version

	// FirmwareVersion is the version number of the token's firmware.
	FirmwareVersion Version

	// UtcTime is the current time in UTC as a character string in the format
	// YYYYMMDDhhmmssxx (16 characters, xx is reserved for future use).
	UtcTime [16]byte
}

// Special PKCS#11 constants.
const (
	// CK_EFFECTIVELY_INFINITE indicates an effectively infinite value.
	CK_EFFECTIVELY_INFINITE uint64 = 0

	// CK_UNAVAILABLE_INFORMATION indicates the information is unavailable.
	CK_UNAVAILABLE_INFORMATION uint64 = ^uint64(0)
)

// GetLabel returns the token label as a trimmed string.
func (t *TokenInfo) GetLabel() string {
	return trimPaddedString(t.Label[:])
}

// SetLabel sets the token label, padding with spaces.
func (t *TokenInfo) SetLabel(label string) {
	setPaddedString(t.Label[:], label)
}

// GetManufacturerID returns the manufacturer ID as a trimmed string.
func (t *TokenInfo) GetManufacturerID() string {
	return trimPaddedString(t.ManufacturerID[:])
}

// SetManufacturerID sets the manufacturer ID, padding with spaces.
func (t *TokenInfo) SetManufacturerID(id string) {
	setPaddedString(t.ManufacturerID[:], id)
}

// GetModel returns the token model as a trimmed string.
func (t *TokenInfo) GetModel() string {
	return trimPaddedString(t.Model[:])
}

// SetModel sets the token model, padding with spaces.
func (t *TokenInfo) SetModel(model string) {
	setPaddedString(t.Model[:], model)
}

// GetSerialNumber returns the serial number as a trimmed string.
func (t *TokenInfo) GetSerialNumber() string {
	return trimPaddedString(t.SerialNumber[:])
}

// SetSerialNumber sets the serial number, padding with spaces.
func (t *TokenInfo) SetSerialNumber(sn string) {
	setPaddedString(t.SerialNumber[:], sn)
}

// GetUtcTime returns the UTC time as a trimmed string.
func (t *TokenInfo) GetUtcTime() string {
	return trimPaddedString(t.UtcTime[:])
}

// SetUtcTime sets the UTC time string.
func (t *TokenInfo) SetUtcTime(utc string) {
	setPaddedString(t.UtcTime[:], utc)
}

// UpdateUtcTime updates the UTC time to the current time.
func (t *TokenInfo) UpdateUtcTime() {
	now := time.Now().UTC()
	timeStr := now.Format("20060102150405") + "00" // YYYYMMDDhhmmss00
	t.SetUtcTime(timeStr)
}

// Token represents a PKCS#11 token with its state and PIN information.
type Token struct {
	// Info contains the token information structure.
	Info TokenInfo

	// SOPinHash contains the hashed Security Officer PIN.
	// Never stored in plaintext for security.
	SOPinHash []byte

	// UserPinHash contains the hashed user PIN.
	// Never stored in plaintext for security.
	UserPinHash []byte

	// Initialized indicates if the token has been initialized via C_InitToken.
	Initialized bool

	// SOLoggedIn indicates if the Security Officer is currently logged in.
	SOLoggedIn bool

	// UserLoggedIn indicates if a user is currently logged in.
	UserLoggedIn bool

	// mu protects concurrent access to the token state.
	mu sync.RWMutex
}

// NewToken creates a new uninitialized token.
func NewToken() *Token {
	token := &Token{
		Info: TokenInfo{
			MaxSessionCount:    CK_EFFECTIVELY_INFINITE,
			SessionCount:       0,
			MaxRwSessionCount:  CK_EFFECTIVELY_INFINITE,
			RwSessionCount:     0,
			MaxPinLen:          256,
			MinPinLen:          4,
			TotalPublicMemory:  CK_UNAVAILABLE_INFORMATION,
			FreePublicMemory:   CK_UNAVAILABLE_INFORMATION,
			TotalPrivateMemory: CK_UNAVAILABLE_INFORMATION,
			FreePrivateMemory:  CK_UNAVAILABLE_INFORMATION,
			HardwareVersion:    Version{Major: 1, Minor: 0},
			FirmwareVersion:    Version{Major: 1, Minor: 0},
			Flags:              CKF_RNG | CKF_LOGIN_REQUIRED,
		},
		Initialized:  false,
		SOLoggedIn:   false,
		UserLoggedIn: false,
	}
	token.Info.SetManufacturerID("go-xkms")
	token.Info.SetModel(tokenModel())
	// CK_TOKEN_INFO's character fields are blank-padded and are not
	// NUL-terminated (v3.2 §3.2), and a token reports a label and a serial
	// number before C_InitToken supplies real ones. Left at their zero value
	// these two were 32 and 16 NUL bytes: pkcs11-tool rendered the label as a
	// run of control characters, p11-kit percent-encoded it into the token URI
	// thirty-two times over, and an application comparing against its own
	// space-padded constant -- the idiomatic C comparison, since the field is
	// not NUL-terminated -- failed to match a token it should have.
	token.Info.SetLabel("")
	token.Info.SetSerialNumber("")
	return token
}

// VerifySOPin verifies the Security Officer PIN.
func (t *Token) VerifySOPin(pin string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if len(t.SOPinHash) == 0 {
		return false
	}
	return verifyPin(t.SOPinHash, pin)
}

// VerifyUserPin verifies the user PIN.
func (t *Token) VerifyUserPin(pin string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if len(t.UserPinHash) == 0 {
		return false
	}
	return verifyPin(t.UserPinHash, pin)
}

// SetSOPin sets the Security Officer PIN (stores hash only).
func (t *Token) SetSOPin(pin string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	h, err := hashPin(pin)
	if err != nil {
		return err
	}
	t.SOPinHash = h
	return nil
}

// SetUserPin sets the user PIN (stores hash only).
func (t *Token) SetUserPin(pin string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	h, err := hashPin(pin)
	if err != nil {
		return err
	}
	t.UserPinHash = h
	t.Info.Flags |= CKF_USER_PIN_INITIALIZED
	return nil
}

// ClearUserPin removes the normal user's PIN, disabling user access until the
// Security Officer sets a new one. C_InitToken requires this (v3.2 §5.5.7).
func (t *Token) ClearUserPin() {
	t.mu.Lock()
	defer t.mu.Unlock()

	enclave.Wipe(t.UserPinHash)
	t.UserPinHash = nil
	t.Info.Flags &^= CKF_USER_PIN_INITIALIZED
}

// IsSOLoggedIn returns whether the Security Officer is logged in.
func (t *Token) IsSOLoggedIn() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.SOLoggedIn
}

// IsUserLoggedIn returns whether a user is logged in.
func (t *Token) IsUserLoggedIn() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.UserLoggedIn
}

// LoginSO logs in the Security Officer.
func (t *Token) LoginSO() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.SOLoggedIn = true
}

// LoginUser logs in the user.
func (t *Token) LoginUser() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.UserLoggedIn = true
}

// LogoutSO logs out the Security Officer.
func (t *Token) LogoutSO() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.SOLoggedIn = false
}

// LogoutUser logs out the user.
func (t *Token) LogoutUser() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.UserLoggedIn = false
}

// Logout logs out all users.
func (t *Token) Logout() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.SOLoggedIn = false
	t.UserLoggedIn = false
}

// IsInitialized returns whether the token has been initialized.
func (t *Token) IsInitialized() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.Initialized
}

// Slot represents a PKCS#11 slot with optional token.
type Slot struct {
	// ID is the slot identifier.
	ID SlotID

	// Info contains the slot information structure.
	Info SlotInfo

	// Token is the token present in the slot, or nil if no token.
	Token *Token

	// mu protects concurrent access to the slot state.
	mu sync.RWMutex
}

// NewSlot creates a new slot with the specified ID.
func NewSlot(id SlotID) *Slot {
	slot := &Slot{
		ID: id,
		Info: SlotInfo{
			Flags:           CKF_TOKEN_PRESENT,
			HardwareVersion: Version{Major: 1, Minor: 0},
			FirmwareVersion: Version{Major: 1, Minor: 0},
		},
	}
	slot.Info.SetSlotDescription("go-xkms Virtual Slot")
	slot.Info.SetManufacturerID("go-xkms")
	return slot
}

// HasToken returns whether a token is present in the slot.
func (s *Slot) HasToken() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Token != nil
}

// GetToken returns the token in the slot (may be nil).
func (s *Slot) GetToken() *Token {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Token
}

// SetToken sets the token in the slot.
func (s *Slot) SetToken(token *Token) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Token = token
	if token != nil {
		s.Info.Flags |= CKF_TOKEN_PRESENT
	} else {
		s.Info.Flags &^= CKF_TOKEN_PRESENT
	}
}

// SlotManager manages PKCS#11 slots and tokens.
// It provides a single virtual slot with a software token.
type SlotManager struct {
	// slots maps slot IDs to Slot instances.
	slots map[SlotID]*Slot

	// supportedMechanisms is the list of mechanisms supported by the token.
	supportedMechanisms []MechanismType

	// mechanismInfo maps mechanism types to their info.
	mechanismInfo map[MechanismType]MechanismInfo

	// mu protects concurrent access to the slot manager.
	mu sync.RWMutex
}

// NewSlotManager creates a new slot manager with a single virtual slot.
func NewSlotManager() *SlotManager {
	sm := &SlotManager{
		slots:               make(map[SlotID]*Slot),
		supportedMechanisms: defaultSupportedMechanisms(),
		mechanismInfo:       defaultMechanismInfo(),
	}

	// Create the default slot (SlotID 0)
	slot := NewSlot(0)
	slot.Token = NewToken()
	sm.slots[0] = slot

	return sm
}

// GetSlotList returns the list of slot IDs.
// If tokenPresent is true, only slots with tokens are returned.
func (sm *SlotManager) GetSlotList(tokenPresent bool) []SlotID {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	var slots []SlotID
	for id, slot := range sm.slots {
		if !tokenPresent || slot.HasToken() {
			slots = append(slots, id)
		}
	}
	return slots
}

// GetSlotInfo returns information about the specified slot.
func (sm *SlotManager) GetSlotInfo(slotID SlotID) (*SlotInfo, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	slot, ok := sm.slots[slotID]
	if !ok {
		return nil, NewPKCS11Error(CKR_SLOT_ID_INVALID)
	}

	slot.mu.RLock()
	defer slot.mu.RUnlock()

	// Return a copy of the slot info
	info := slot.Info
	return &info, nil
}

// GetTokenInfo returns information about the token in the specified slot.
func (sm *SlotManager) GetTokenInfo(slotID SlotID) (*TokenInfo, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	slot, ok := sm.slots[slotID]
	if !ok {
		return nil, NewPKCS11Error(CKR_SLOT_ID_INVALID)
	}

	slot.mu.RLock()
	defer slot.mu.RUnlock()

	if slot.Token == nil {
		return nil, NewPKCS11Error(CKR_TOKEN_NOT_PRESENT)
	}

	slot.Token.mu.Lock()
	defer slot.Token.mu.Unlock()

	// Update UTC time before returning
	slot.Token.Info.UpdateUtcTime()

	// Return a copy of the token info
	info := slot.Token.Info
	return &info, nil
}

// GetMechanismList returns the list of mechanisms supported by the token.
func (sm *SlotManager) GetMechanismList(slotID SlotID) ([]MechanismType, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	slot, ok := sm.slots[slotID]
	if !ok {
		return nil, NewPKCS11Error(CKR_SLOT_ID_INVALID)
	}

	if !slot.HasToken() {
		return nil, NewPKCS11Error(CKR_TOKEN_NOT_PRESENT)
	}

	// Return a copy of the mechanism list
	mechanisms := make([]MechanismType, len(sm.supportedMechanisms))
	copy(mechanisms, sm.supportedMechanisms)
	return mechanisms, nil
}

// GetMechanismInfo returns information about a specific mechanism.
func (sm *SlotManager) GetMechanismInfo(slotID SlotID, mechanism MechanismType) (*MechanismInfo, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	slot, ok := sm.slots[slotID]
	if !ok {
		return nil, NewPKCS11Error(CKR_SLOT_ID_INVALID)
	}

	if !slot.HasToken() {
		return nil, NewPKCS11Error(CKR_TOKEN_NOT_PRESENT)
	}

	info, ok := sm.mechanismInfo[mechanism]
	if !ok {
		return nil, NewPKCS11Error(CKR_MECHANISM_INVALID)
	}

	// Return a copy of the mechanism info
	return &info, nil
}

// GetSlot returns the slot with the specified ID.
func (sm *SlotManager) GetSlot(slotID SlotID) (*Slot, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	slot, ok := sm.slots[slotID]
	if !ok {
		return nil, NewPKCS11Error(CKR_SLOT_ID_INVALID)
	}
	return slot, nil
}

// PIN hashing parameters. PKCS#11 PINs are short and drawn from a small
// alphabet, so the stored form must be salted — otherwise one precomputed table
// breaks every token — and memory-hard, so that an attacker who obtains the
// stored hashes cannot test candidates at hardware speed.
const (
	// pinHashVersion identifies the encoding of a stored PIN hash, so the
	// parameters below can be strengthened later without invalidating tokens
	// that were provisioned under the old ones.
	pinHashVersion = 0x01

	pinSaltLen     = 16
	pinKeyLen      = 32
	pinArgonTime   = 1
	pinArgonMemory = 64 * 1024 // KiB
	pinArgonLanes  = 4
)

// pinHashSlots admits a bounded number of Argon2id derivations at a time.
//
// Memory hardness is the whole point of pinArgonMemory, so the parameter must
// not be weakened; what has to be bounded instead is how many derivations run
// concurrently. Each one allocates its own pinArgonMemory KiB scratch buffer,
// so without admission control N simultaneous C_Login calls cost N times that —
// an unauthenticated caller could exhaust the host's memory simply by opening
// sessions and guessing PINs. Callers queue on this channel instead, which caps
// the token's PIN-hashing footprint at maxPinHashConcurrency scratch buffers no
// matter how many logins arrive.
//
// A buffered channel is used rather than a mutex or golang.org/x/sync/semaphore
// (an indirect dependency only) because a counting semaphore is exactly the
// primitive needed and a channel send/receive is the lock-free form of it.
var pinHashSlots = make(chan struct{}, maxPinHashConcurrency())

// maxPinHashConcurrency returns the number of Argon2id derivations permitted to
// run at once on this machine.
func maxPinHashConcurrency() int {
	return pinHashConcurrencyFor(runtime.NumCPU())
}

// pinHashConcurrencyFor computes the admission limit for a machine with the
// given number of CPUs.
//
// Argon2id already parallelises each derivation across pinArgonLanes lanes, so
// admitting more than one derivation per lane-group buys no additional
// throughput while multiplying the resident memory linearly. The result is
// floored at 1 so the gate always admits somebody: a zero-capacity channel
// would block every login forever, turning a memory-exhaustion defect into a
// total denial of service on a single-core or misreporting host.
func pinHashConcurrencyFor(numCPU int) int {
	limit := numCPU / pinArgonLanes
	if limit < 1 {
		return 1
	}
	return limit
}

// derivePinKey runs one Argon2id derivation under the admission gate.
//
// The gate is released with defer so a derivation that panics — hashPin panics
// when the system entropy source fails — still returns its slot rather than
// permanently shrinking the token's login capacity. Nothing inside the gated
// region acquires a token or slot lock, so a caller that already holds one
// while waiting here cannot deadlock against the goroutine ahead of it.
func derivePinKey(pin string, salt []byte) []byte {
	pinHashSlots <- struct{}{}
	defer func() { <-pinHashSlots }()

	pinDerivationBegan()
	return argon2.IDKey([]byte(pin), salt, pinArgonTime, argonMemoryKiB, pinArgonLanes, pinKeyLen)
}

// pinDerivationBegan is called once a derivation has been admitted through the
// gate and is about to start. It does nothing in a shipped binary.
//
// It exists because a test cannot otherwise know that a derivation is genuinely
// IN FLIGHT. TestLoginDoesNotHoldTheSessionLockDuringPINDerivation samples the
// session lock during one, and sleeping first and hoping made the assertion
// vacuous in the direction that matters: if the probe ran before Login reached
// this line, it found the lock free and recorded a pass even for a Login that
// held the lock across the whole derivation. A signal from the derivation
// itself is the only thing that orders the two.
var pinDerivationBegan = func() {}

// argonMemoryKiB is the Argon2id memory cost actually used, defaulting to the
// production constant.
//
// It is a variable ONLY so the test binary can lower it. At the production
// cost one derivation takes ~24 ms on a development workstation, the suite
// performs roughly 1400 of them, and the race detector -- the only job that
// compiles this package, because `pkcs11` appears in no other job's tag list
// -- multiplies memory-heavy work several times over. That is what makes the
// Race Detector the longest job in CI at 29m33s (measured, run 4384), and why
// it needed `-timeout 30m` to stop going falsely red.
//
// Nothing outside a test may write it. The value is the security parameter
// that makes a stolen PIN verifier expensive to attack, so lowering it in a
// shipped binary would be a silent downgrade of exactly the control this
// derivation exists to provide. TestPINHashCostIsProductionByDefault asserts
// the constant, which no test overrides, so a change to the PRODUCTION cost
// still has to be deliberate.
var argonMemoryKiB uint32 = pinArgonMemory

// hashPin derives a verifier for a PIN using Argon2id with a fresh random salt.
//
// The result is self-describing — version, salt length, salt, derived key — so
// verifyPin can recover the salt without a second stored field. Because the
// salt is random, two calls with the same PIN return different bytes; compare
// with verifyPin, never by comparing two hashPin results.
func hashPin(pin string) ([]byte, error) {
	salt := make([]byte, pinSaltLen)
	if _, err := io.ReadFull(entropySource, salt); err != nil {
		// The only way crypto/rand fails is a broken system entropy source, at
		// which point no security property of this module holds. It is returned
		// rather than panicked so an embedded Go caller gets a clean error.
		return nil, ErrEntropyUnavailable
	}
	return encodePinHash(salt, derivePinKey(pin, salt)), nil
}

// encodePinHash packs a salt and derived key into the stored representation.
func encodePinHash(salt, key []byte) []byte {
	out := make([]byte, 0, 2+len(salt)+len(key))
	out = append(out, pinHashVersion, byte(len(salt)))
	out = append(out, salt...)
	return append(out, key...)
}

// verifyPin reports whether pin matches a stored verifier produced by hashPin.
// The comparison is constant time, and an unparsable or empty stored value
// simply fails to verify rather than erroring, so a caller cannot distinguish
// "no PIN set" from "wrong PIN" by timing or by return type.
func verifyPin(stored []byte, pin string) bool {
	if len(stored) < 2 || stored[0] != pinHashVersion {
		return false
	}

	saltLen := int(stored[1])
	if saltLen == 0 || len(stored) != 2+saltLen+pinKeyLen {
		return false
	}

	salt := stored[2 : 2+saltLen]
	expected := stored[2+saltLen:]
	candidate := derivePinKey(pin, salt)

	return subtle.ConstantTimeCompare(candidate, expected) == 1
}

// serialNumberHexDigits is the alphabet generateSerialNumber renders into.
// Upper case because CK_TOKEN_INFO.serialNumber is displayed verbatim by
// pkcs11-tool and p11-kit.
const serialNumberHexDigits = "0123456789ABCDEF"

// generateSerialNumber returns a unique 16-character serial number for a token.
//
// The value has to distinguish this token from every other one an application
// might address, because CK_TOKEN_INFO.serialNumber is what pkcs11:serial=
// selects on and what a fleet inventory identifies a token by. It is therefore
// drawn from the system CSPRNG rather than from the clock: the previous
// implementation formatted the time to one-second resolution and appended a
// literal "00", so two hosts provisioned by the same automation run in the same
// second received byte-identical serials, and re-provisioning a token reused the
// old one.
func generateSerialNumber() (string, error) {
	var raw [8]byte
	if _, err := io.ReadFull(entropySource, raw[:]); err != nil {
		// A token that cannot reach the system entropy source cannot serve any
		// of its purpose, and a predictable identifier would be worse than
		// stopping. Returned rather than panicked, as hashPin does.
		return "", ErrEntropyUnavailable
	}

	out := make([]byte, 16)
	for i, b := range raw {
		out[2*i] = serialNumberHexDigits[b>>4]
		out[2*i+1] = serialNumberHexDigits[b&0x0F]
	}
	return string(out), nil
}

// trimPaddedString trims trailing spaces and null bytes from a padded string.
func trimPaddedString(b []byte) string {
	// Find the end of the string (trailing spaces or null bytes)
	end := len(b)
	for end > 0 && (b[end-1] == ' ' || b[end-1] == 0) {
		end--
	}
	return string(b[:end])
}

// setPaddedString sets a fixed-length byte array to a string, padding with spaces.
func setPaddedString(b []byte, s string) {
	// Clear the buffer with spaces
	for i := range b {
		b[i] = ' '
	}
	// Copy the string (truncating if necessary)
	copy(b, s)
}

// defaultSupportedMechanisms returns the mechanism types the virtual token
// advertises through C_GetMechanismList.
//
// It projects from defaultMechanismInfo rather than carrying its own list. A
// second hardcoded table was exactly the disagreement the projection exists to
// make unrepresentable, and it had already drifted: the registry applies the
// FIPS filter and the literal did not, so under FIPS C_GetMechanismList offered
// CKM_SHA1_RSA_PKCS while C_GetMechanismInfo on that same mechanism answered
// CKR_MECHANISM_INVALID. The two agreed outside FIPS only by coincidence of
// having identical membership, which is why nothing caught it.
//
// The result is sorted so the list is stable across calls; Go map iteration
// order is randomized, and an application diffing the list between calls would
// otherwise see it churn.
func defaultSupportedMechanisms() []MechanismType {
	info := defaultMechanismInfo()

	mechs := make([]MechanismType, 0, len(info))
	for mechType := range info {
		mechs = append(mechs, mechType)
	}
	sort.Slice(mechs, func(i, j int) bool { return mechs[i] < mechs[j] })

	return mechs
}

// defaultMechanismInfo returns the mechanisms the token advertises, projected
// from the one mechanism registry.
//
// It used to be a second hardcoded table, maintained by hand alongside
// mechanismRegistry, and the two had drifted: they disagreed on the key-size
// range and the capability flags of nearly every RSA and EC mechanism, and the
// registry held dozens of implemented mechanisms this table never listed, so no
// application could discover them. Whichever table a reader consulted, it could
// be the wrong one. Projecting from the registry makes that class of
// disagreement unrepresentable.
//
// Advertising is opt-in: a mechanism appears here only if its descriptor sets
// Advertised, so the advertised surface stays a deliberate choice rather than
// an accident of which table someone edited last.
func defaultMechanismInfo() map[MechanismType]MechanismInfo {
	info := make(map[MechanismType]MechanismInfo, len(mechanismRegistry))
	for mechType, desc := range mechanismRegistry {
		if !desc.Advertised {
			continue
		}
		// In FIPS mode the module offers only approved algorithms, and
		// GetMechanismDescriptor refuses the rest, so withholding them here
		// keeps C_GetMechanismList honest about what the module will do.
		if !desc.FIPSApproved && fipsModeEnabled() {
			continue
		}
		// The advertised key-size range is the effective one, not the raw
		// registry field: a mechanism whose ceiling narrows under FIPS must
		// narrow here too, or C_GetMechanismList describes a maximum
		// C_GetMechanismInfo and the module's own validation both reject.
		minKeySize, maxKeySize := effectiveKeySizeRange(desc)
		info[mechType] = MechanismInfo{
			MinKeySize: minKeySize,
			MaxKeySize: maxKeySize,
			// The advertised flags are the effective ones: a SHA-1 signature
			// mechanism drops CKF_SIGN when weak-hash signing is not allowed, so
			// C_GetMechanismInfo never claims a signing capability the token
			// will then refuse. Same single source as the *Init path.
			Flags: effectiveMechanismFlags(desc),
		}
	}
	return info
}
