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
	"crypto/sha256"
	"crypto/subtle"
	"sync"
	"time"
)

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
	token.Info.SetModel("Virtual Token")
	return token
}

// VerifySOPin verifies the Security Officer PIN.
func (t *Token) VerifySOPin(pin string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if len(t.SOPinHash) == 0 {
		return false
	}
	pinHash := hashPin(pin)
	return subtle.ConstantTimeCompare(pinHash, t.SOPinHash) == 1
}

// VerifyUserPin verifies the user PIN.
func (t *Token) VerifyUserPin(pin string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if len(t.UserPinHash) == 0 {
		return false
	}
	pinHash := hashPin(pin)
	return subtle.ConstantTimeCompare(pinHash, t.UserPinHash) == 1
}

// SetSOPin sets the Security Officer PIN (stores hash only).
func (t *Token) SetSOPin(pin string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.SOPinHash = hashPin(pin)
}

// SetUserPin sets the user PIN (stores hash only).
func (t *Token) SetUserPin(pin string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.UserPinHash = hashPin(pin)
	t.Info.Flags |= CKF_USER_PIN_INITIALIZED
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

// InitToken initializes the token in the specified slot.
// This is the implementation of C_InitToken.
func (sm *SlotManager) InitToken(slotID SlotID, soPin, label string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	slot, ok := sm.slots[slotID]
	if !ok {
		return NewPKCS11Error(CKR_SLOT_ID_INVALID)
	}

	slot.mu.Lock()
	defer slot.mu.Unlock()

	if slot.Token == nil {
		return NewPKCS11Error(CKR_TOKEN_NOT_PRESENT)
	}

	token := slot.Token
	token.mu.Lock()
	defer token.mu.Unlock()

	// Validate PIN length
	pinLen := uint64(len(soPin))
	if pinLen < token.Info.MinPinLen || pinLen > token.Info.MaxPinLen {
		return NewPKCS11Error(CKR_PIN_LEN_RANGE)
	}

	// If token is already initialized, verify the SO PIN
	if token.Initialized {
		if len(token.SOPinHash) > 0 {
			pinHash := hashPin(soPin)
			if subtle.ConstantTimeCompare(pinHash, token.SOPinHash) != 1 {
				return NewPKCS11Error(CKR_PIN_INCORRECT)
			}
		}
	}

	// Initialize the token
	token.Info.SetLabel(label)
	token.SOPinHash = hashPin(soPin)
	token.UserPinHash = nil
	token.Initialized = true
	token.SOLoggedIn = false
	token.UserLoggedIn = false
	token.Info.Flags |= CKF_TOKEN_INITIALIZED
	token.Info.Flags &^= CKF_USER_PIN_INITIALIZED

	// Generate a serial number if not set
	if token.Info.GetSerialNumber() == "" {
		token.Info.SetSerialNumber(generateSerialNumber())
	}

	return nil
}

// InitPIN initializes the user PIN.
// This is the implementation of C_InitPIN (called while SO is logged in).
func (sm *SlotManager) InitPIN(slotID SlotID, pin string) error {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	slot, ok := sm.slots[slotID]
	if !ok {
		return NewPKCS11Error(CKR_SLOT_ID_INVALID)
	}

	slot.mu.RLock()
	defer slot.mu.RUnlock()

	if slot.Token == nil {
		return NewPKCS11Error(CKR_TOKEN_NOT_PRESENT)
	}

	token := slot.Token
	token.mu.Lock()
	defer token.mu.Unlock()

	// Verify SO is logged in
	if !token.SOLoggedIn {
		return NewPKCS11Error(CKR_USER_NOT_LOGGED_IN)
	}

	// Validate PIN length
	pinLen := uint64(len(pin))
	if pinLen < token.Info.MinPinLen || pinLen > token.Info.MaxPinLen {
		return NewPKCS11Error(CKR_PIN_LEN_RANGE)
	}

	// Set the user PIN
	token.UserPinHash = hashPin(pin)
	token.Info.Flags |= CKF_USER_PIN_INITIALIZED

	return nil
}

// SetPIN changes the PIN.
// This is the implementation of C_SetPIN.
func (sm *SlotManager) SetPIN(slotID SlotID, oldPin, newPin string, userType UserType) error {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	slot, ok := sm.slots[slotID]
	if !ok {
		return NewPKCS11Error(CKR_SLOT_ID_INVALID)
	}

	slot.mu.RLock()
	defer slot.mu.RUnlock()

	if slot.Token == nil {
		return NewPKCS11Error(CKR_TOKEN_NOT_PRESENT)
	}

	token := slot.Token
	token.mu.Lock()
	defer token.mu.Unlock()

	// Validate new PIN length
	newPinLen := uint64(len(newPin))
	if newPinLen < token.Info.MinPinLen || newPinLen > token.Info.MaxPinLen {
		return NewPKCS11Error(CKR_PIN_LEN_RANGE)
	}

	switch userType {
	case CKU_SO:
		// Verify old SO PIN
		if len(token.SOPinHash) > 0 {
			oldHash := hashPin(oldPin)
			if subtle.ConstantTimeCompare(oldHash, token.SOPinHash) != 1 {
				return NewPKCS11Error(CKR_PIN_INCORRECT)
			}
		}
		// Set new SO PIN
		token.SOPinHash = hashPin(newPin)

	case CKU_USER:
		// Check if user PIN is initialized
		if !token.Info.Flags.Has(CKF_USER_PIN_INITIALIZED) {
			return NewPKCS11Error(CKR_USER_PIN_NOT_INITIALIZED)
		}
		// Verify old user PIN
		if len(token.UserPinHash) > 0 {
			oldHash := hashPin(oldPin)
			if subtle.ConstantTimeCompare(oldHash, token.UserPinHash) != 1 {
				return NewPKCS11Error(CKR_PIN_INCORRECT)
			}
		}
		// Set new user PIN
		token.UserPinHash = hashPin(newPin)

	default:
		return NewPKCS11Error(CKR_USER_TYPE_INVALID)
	}

	return nil
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

// hashPin hashes a PIN using SHA-256.
// In production, a proper key derivation function like Argon2 should be used.
func hashPin(pin string) []byte {
	hash := sha256.Sum256([]byte(pin))
	return hash[:]
}

// generateSerialNumber generates a unique serial number for a token.
func generateSerialNumber() string {
	now := time.Now()
	// Format: YYYYMMDDHHmmssnn (16 chars)
	return now.Format("20060102150405") + "00"
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

// defaultSupportedMechanisms returns the list of mechanisms supported by the virtual token.
func defaultSupportedMechanisms() []MechanismType {
	return []MechanismType{
		// RSA mechanisms
		CKM_RSA_PKCS_KEY_PAIR_GEN,
		CKM_RSA_PKCS,
		CKM_RSA_PKCS_OAEP,
		CKM_RSA_PKCS_PSS,
		CKM_SHA1_RSA_PKCS,
		CKM_SHA256_RSA_PKCS,
		CKM_SHA384_RSA_PKCS,
		CKM_SHA512_RSA_PKCS,
		CKM_SHA256_RSA_PKCS_PSS,
		CKM_SHA384_RSA_PKCS_PSS,
		CKM_SHA512_RSA_PKCS_PSS,

		// EC mechanisms
		CKM_EC_KEY_PAIR_GEN,
		CKM_ECDSA,
		CKM_ECDSA_SHA256,
		CKM_ECDSA_SHA384,
		CKM_ECDSA_SHA512,
		CKM_ECDH1_DERIVE,

		// Edwards curve mechanisms (Ed25519)
		CKM_EC_EDWARDS_KEY_PAIR_GEN,
		CKM_EDDSA,

		// AES mechanisms
		CKM_AES_KEY_GEN,
		CKM_AES_ECB,
		CKM_AES_CBC,
		CKM_AES_CBC_PAD,
		CKM_AES_GCM,
		CKM_AES_KEY_WRAP,
		CKM_AES_KEY_WRAP_PAD,

		// Digest mechanisms
		CKM_SHA_1,
		CKM_SHA256,
		CKM_SHA384,
		CKM_SHA512,
	}
}

// defaultMechanismInfo returns the default mechanism info map.
func defaultMechanismInfo() map[MechanismType]MechanismInfo {
	return map[MechanismType]MechanismInfo{
		// RSA key generation
		CKM_RSA_PKCS_KEY_PAIR_GEN: {
			MinKeySize: 2048,
			MaxKeySize: 4096,
			Flags:      CKF_GENERATE_KEY_PAIR,
		},
		// RSA PKCS#1 v1.5
		CKM_RSA_PKCS: {
			MinKeySize: 2048,
			MaxKeySize: 4096,
			Flags:      CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY | CKF_WRAP | CKF_UNWRAP,
		},
		// RSA OAEP
		CKM_RSA_PKCS_OAEP: {
			MinKeySize: 2048,
			MaxKeySize: 4096,
			Flags:      CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP,
		},
		// RSA PSS
		CKM_RSA_PKCS_PSS: {
			MinKeySize: 2048,
			MaxKeySize: 4096,
			Flags:      CKF_SIGN | CKF_VERIFY,
		},
		// RSA with SHA-1
		CKM_SHA1_RSA_PKCS: {
			MinKeySize: 2048,
			MaxKeySize: 4096,
			Flags:      CKF_SIGN | CKF_VERIFY,
		},
		// RSA with SHA-256
		CKM_SHA256_RSA_PKCS: {
			MinKeySize: 2048,
			MaxKeySize: 4096,
			Flags:      CKF_SIGN | CKF_VERIFY,
		},
		// RSA with SHA-384
		CKM_SHA384_RSA_PKCS: {
			MinKeySize: 2048,
			MaxKeySize: 4096,
			Flags:      CKF_SIGN | CKF_VERIFY,
		},
		// RSA with SHA-512
		CKM_SHA512_RSA_PKCS: {
			MinKeySize: 2048,
			MaxKeySize: 4096,
			Flags:      CKF_SIGN | CKF_VERIFY,
		},
		// RSA PSS with SHA-256
		CKM_SHA256_RSA_PKCS_PSS: {
			MinKeySize: 2048,
			MaxKeySize: 4096,
			Flags:      CKF_SIGN | CKF_VERIFY,
		},
		// RSA PSS with SHA-384
		CKM_SHA384_RSA_PKCS_PSS: {
			MinKeySize: 2048,
			MaxKeySize: 4096,
			Flags:      CKF_SIGN | CKF_VERIFY,
		},
		// RSA PSS with SHA-512
		CKM_SHA512_RSA_PKCS_PSS: {
			MinKeySize: 2048,
			MaxKeySize: 4096,
			Flags:      CKF_SIGN | CKF_VERIFY,
		},
		// EC key generation
		CKM_EC_KEY_PAIR_GEN: {
			MinKeySize: 256,
			MaxKeySize: 521,
			Flags:      CKF_GENERATE_KEY_PAIR | CKF_EC_F_P,
		},
		// ECDSA
		CKM_ECDSA: {
			MinKeySize: 256,
			MaxKeySize: 521,
			Flags:      CKF_SIGN | CKF_VERIFY | CKF_EC_F_P,
		},
		// ECDSA with SHA-256
		CKM_ECDSA_SHA256: {
			MinKeySize: 256,
			MaxKeySize: 521,
			Flags:      CKF_SIGN | CKF_VERIFY | CKF_EC_F_P,
		},
		// ECDSA with SHA-384
		CKM_ECDSA_SHA384: {
			MinKeySize: 256,
			MaxKeySize: 521,
			Flags:      CKF_SIGN | CKF_VERIFY | CKF_EC_F_P,
		},
		// ECDSA with SHA-512
		CKM_ECDSA_SHA512: {
			MinKeySize: 256,
			MaxKeySize: 521,
			Flags:      CKF_SIGN | CKF_VERIFY | CKF_EC_F_P,
		},
		// ECDH key derivation
		CKM_ECDH1_DERIVE: {
			MinKeySize: 256,
			MaxKeySize: 521,
			Flags:      CKF_DERIVE | CKF_EC_F_P,
		},
		// Edwards curve key generation (Ed25519)
		CKM_EC_EDWARDS_KEY_PAIR_GEN: {
			MinKeySize: 255, // Ed25519 key size
			MaxKeySize: 255,
			Flags:      CKF_GENERATE_KEY_PAIR | CKF_EC_F_P,
		},
		// EdDSA signature
		CKM_EDDSA: {
			MinKeySize: 255, // Ed25519 key size
			MaxKeySize: 255,
			Flags:      CKF_SIGN | CKF_VERIFY | CKF_EC_F_P,
		},
		// AES key generation
		CKM_AES_KEY_GEN: {
			MinKeySize: 128,
			MaxKeySize: 256,
			Flags:      CKF_GENERATE,
		},
		// AES ECB
		CKM_AES_ECB: {
			MinKeySize: 128,
			MaxKeySize: 256,
			Flags:      CKF_ENCRYPT | CKF_DECRYPT,
		},
		// AES CBC
		CKM_AES_CBC: {
			MinKeySize: 128,
			MaxKeySize: 256,
			Flags:      CKF_ENCRYPT | CKF_DECRYPT,
		},
		// AES CBC with PKCS#7 padding
		CKM_AES_CBC_PAD: {
			MinKeySize: 128,
			MaxKeySize: 256,
			Flags:      CKF_ENCRYPT | CKF_DECRYPT,
		},
		// AES GCM
		CKM_AES_GCM: {
			MinKeySize: 128,
			MaxKeySize: 256,
			Flags:      CKF_ENCRYPT | CKF_DECRYPT,
		},
		// AES Key Wrap
		CKM_AES_KEY_WRAP: {
			MinKeySize: 128,
			MaxKeySize: 256,
			Flags:      CKF_WRAP | CKF_UNWRAP,
		},
		// AES Key Wrap with Padding
		CKM_AES_KEY_WRAP_PAD: {
			MinKeySize: 128,
			MaxKeySize: 256,
			Flags:      CKF_WRAP | CKF_UNWRAP,
		},
		// SHA-1
		CKM_SHA_1: {
			MinKeySize: 0,
			MaxKeySize: 0,
			Flags:      CKF_DIGEST,
		},
		// SHA-256
		CKM_SHA256: {
			MinKeySize: 0,
			MaxKeySize: 0,
			Flags:      CKF_DIGEST,
		},
		// SHA-384
		CKM_SHA384: {
			MinKeySize: 0,
			MaxKeySize: 0,
			Flags:      CKF_DIGEST,
		},
		// SHA-512
		CKM_SHA512: {
			MinKeySize: 0,
			MaxKeySize: 0,
			Flags:      CKF_DIGEST,
		},
	}
}
