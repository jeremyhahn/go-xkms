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

package module

import (
	"errors"
	"strings"
	"sync"
	"testing"
)

func TestVersion(t *testing.T) {
	v := Version{Major: 2, Minor: 40}

	if v.Major != 2 {
		t.Errorf("Version.Major = %d, want 2", v.Major)
	}
	if v.Minor != 40 {
		t.Errorf("Version.Minor = %d, want 40", v.Minor)
	}
}

func TestSlotFlag_String(t *testing.T) {
	tests := []struct {
		name string
		flag SlotFlag
		want []string
	}{
		{
			name: "no flags",
			flag: 0,
			want: []string{"0x00000000"},
		},
		{
			name: "token present",
			flag: CKF_TOKEN_PRESENT,
			want: []string{"CKF_TOKEN_PRESENT"},
		},
		{
			name: "removable device",
			flag: CKF_REMOVABLE_DEVICE,
			want: []string{"CKF_REMOVABLE_DEVICE"},
		},
		{
			name: "hardware slot",
			flag: CKF_HW_SLOT,
			want: []string{"CKF_HW_SLOT"},
		},
		{
			name: "multiple flags",
			flag: CKF_TOKEN_PRESENT | CKF_HW_SLOT,
			want: []string{"CKF_TOKEN_PRESENT", "CKF_HW_SLOT"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.flag.String()
			for _, w := range tt.want {
				if !strings.Contains(result, w) {
					t.Errorf("SlotFlag.String() = %q, missing %q", result, w)
				}
			}
		})
	}
}

func TestSlotFlag_Has(t *testing.T) {
	flag := CKF_TOKEN_PRESENT | CKF_HW_SLOT

	if !flag.Has(CKF_TOKEN_PRESENT) {
		t.Error("SlotFlag.Has(CKF_TOKEN_PRESENT) = false, want true")
	}
	if !flag.Has(CKF_HW_SLOT) {
		t.Error("SlotFlag.Has(CKF_HW_SLOT) = false, want true")
	}
	if flag.Has(CKF_REMOVABLE_DEVICE) {
		t.Error("SlotFlag.Has(CKF_REMOVABLE_DEVICE) = true, want false")
	}
}

func TestTokenFlag_String(t *testing.T) {
	tests := []struct {
		name string
		flag TokenFlag
		want []string
	}{
		{
			name: "no flags",
			flag: 0,
			want: []string{"0x00000000"},
		},
		{
			name: "RNG",
			flag: CKF_RNG,
			want: []string{"CKF_RNG"},
		},
		{
			name: "token initialized",
			flag: CKF_TOKEN_INITIALIZED,
			want: []string{"CKF_TOKEN_INITIALIZED"},
		},
		{
			name: "multiple flags",
			flag: CKF_RNG | CKF_LOGIN_REQUIRED | CKF_TOKEN_INITIALIZED,
			want: []string{"CKF_RNG", "CKF_LOGIN_REQUIRED", "CKF_TOKEN_INITIALIZED"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.flag.String()
			for _, w := range tt.want {
				if !strings.Contains(result, w) {
					t.Errorf("TokenFlag.String() = %q, missing %q", result, w)
				}
			}
		})
	}
}

func TestTokenFlag_Has(t *testing.T) {
	flag := CKF_RNG | CKF_TOKEN_INITIALIZED

	if !flag.Has(CKF_RNG) {
		t.Error("TokenFlag.Has(CKF_RNG) = false, want true")
	}
	if !flag.Has(CKF_TOKEN_INITIALIZED) {
		t.Error("TokenFlag.Has(CKF_TOKEN_INITIALIZED) = false, want true")
	}
	if flag.Has(CKF_WRITE_PROTECTED) {
		t.Error("TokenFlag.Has(CKF_WRITE_PROTECTED) = true, want false")
	}
}

func TestSlotInfo_SlotDescription(t *testing.T) {
	info := &SlotInfo{}

	// Test setting and getting slot description
	desc := "Test Slot Description"
	info.SetSlotDescription(desc)

	got := info.GetSlotDescription()
	if got != desc {
		t.Errorf("SlotInfo.GetSlotDescription() = %q, want %q", got, desc)
	}

	// Test truncation for long descriptions
	longDesc := strings.Repeat("A", 100)
	info.SetSlotDescription(longDesc)
	got = info.GetSlotDescription()
	if len(got) > 64 {
		t.Errorf("SlotInfo.GetSlotDescription() length = %d, want <= 64", len(got))
	}
}

func TestSlotInfo_ManufacturerID(t *testing.T) {
	info := &SlotInfo{}

	// Test setting and getting manufacturer ID
	id := "Test Manufacturer"
	info.SetManufacturerID(id)

	got := info.GetManufacturerID()
	if got != id {
		t.Errorf("SlotInfo.GetManufacturerID() = %q, want %q", got, id)
	}

	// Test truncation for long IDs
	longID := strings.Repeat("B", 50)
	info.SetManufacturerID(longID)
	got = info.GetManufacturerID()
	if len(got) > 32 {
		t.Errorf("SlotInfo.GetManufacturerID() length = %d, want <= 32", len(got))
	}
}

func TestTokenInfo_Label(t *testing.T) {
	info := &TokenInfo{}

	// Test setting and getting label
	label := "Test Token Label"
	info.SetLabel(label)

	got := info.GetLabel()
	if got != label {
		t.Errorf("TokenInfo.GetLabel() = %q, want %q", got, label)
	}
}

func TestTokenInfo_ManufacturerID(t *testing.T) {
	info := &TokenInfo{}

	// Test setting and getting manufacturer ID
	id := "Token Manufacturer"
	info.SetManufacturerID(id)

	got := info.GetManufacturerID()
	if got != id {
		t.Errorf("TokenInfo.GetManufacturerID() = %q, want %q", got, id)
	}
}

func TestTokenInfo_Model(t *testing.T) {
	info := &TokenInfo{}

	// Test setting and getting model
	model := "Virtual HSM"
	info.SetModel(model)

	got := info.GetModel()
	if got != model {
		t.Errorf("TokenInfo.GetModel() = %q, want %q", got, model)
	}
}

func TestTokenInfo_SerialNumber(t *testing.T) {
	info := &TokenInfo{}

	// Test setting and getting serial number
	sn := "1234567890123456"
	info.SetSerialNumber(sn)

	got := info.GetSerialNumber()
	if len(got) > 16 {
		t.Errorf("TokenInfo.GetSerialNumber() length = %d, want <= 16", len(got))
	}
}

func TestTokenInfo_UtcTime(t *testing.T) {
	info := &TokenInfo{}

	// Test setting UTC time
	info.SetUtcTime("2025010112000000")
	got := info.GetUtcTime()
	if got != "2025010112000000" {
		t.Errorf("TokenInfo.GetUtcTime() = %q, want %q", got, "2025010112000000")
	}

	// Test updating UTC time
	info.UpdateUtcTime()
	got = info.GetUtcTime()
	if len(got) != 16 {
		t.Errorf("TokenInfo.GetUtcTime() after update length = %d, want 16", len(got))
	}
}

func TestNewToken(t *testing.T) {
	token := NewToken()

	if token == nil {
		t.Fatal("NewToken() returned nil")
	}

	if token.Initialized {
		t.Error("NewToken().Initialized = true, want false")
	}

	if token.SOLoggedIn {
		t.Error("NewToken().SOLoggedIn = true, want false")
	}

	if token.UserLoggedIn {
		t.Error("NewToken().UserLoggedIn = true, want false")
	}

	// Check default flags
	if !token.Info.Flags.Has(CKF_RNG) {
		t.Error("NewToken() missing CKF_RNG flag")
	}
	if !token.Info.Flags.Has(CKF_LOGIN_REQUIRED) {
		t.Error("NewToken() missing CKF_LOGIN_REQUIRED flag")
	}

	// Check default values
	if token.Info.MinPinLen != 4 {
		t.Errorf("NewToken().Info.MinPinLen = %d, want 4", token.Info.MinPinLen)
	}
	if token.Info.MaxPinLen != 256 {
		t.Errorf("NewToken().Info.MaxPinLen = %d, want 256", token.Info.MaxPinLen)
	}

	// Check manufacturer and model
	mfr := token.Info.GetManufacturerID()
	if mfr != "go-xkms" {
		t.Errorf("NewToken().Info.GetManufacturerID() = %q, want %q", mfr, "go-xkms")
	}

	model := token.Info.GetModel()
	if model != "Virtual Token" {
		t.Errorf("NewToken().Info.GetModel() = %q, want %q", model, "Virtual Token")
	}
}

func TestToken_PinOperations(t *testing.T) {
	token := NewToken()

	// Test SO PIN
	soPin := "1234567890"
	token.SetSOPin(soPin)

	if !token.VerifySOPin(soPin) {
		t.Error("Token.VerifySOPin() = false for correct PIN")
	}

	if token.VerifySOPin("wrongpin") {
		t.Error("Token.VerifySOPin() = true for incorrect PIN")
	}

	// Test user PIN
	userPin := "userpass"
	token.SetUserPin(userPin)

	if !token.VerifyUserPin(userPin) {
		t.Error("Token.VerifyUserPin() = false for correct PIN")
	}

	if token.VerifyUserPin("wrongpin") {
		t.Error("Token.VerifyUserPin() = true for incorrect PIN")
	}

	// Verify CKF_USER_PIN_INITIALIZED is set after SetUserPin
	if !token.Info.Flags.Has(CKF_USER_PIN_INITIALIZED) {
		t.Error("CKF_USER_PIN_INITIALIZED not set after SetUserPin()")
	}
}

func TestToken_PinVerificationEmptyHash(t *testing.T) {
	token := NewToken()

	// Before setting PINs, verification should fail
	if token.VerifySOPin("anypin") {
		t.Error("Token.VerifySOPin() = true for unset PIN")
	}
	if token.VerifyUserPin("anypin") {
		t.Error("Token.VerifyUserPin() = true for unset PIN")
	}
}

func TestToken_LoginOperations(t *testing.T) {
	token := NewToken()

	// Initial state
	if token.IsSOLoggedIn() {
		t.Error("Token.IsSOLoggedIn() = true initially")
	}
	if token.IsUserLoggedIn() {
		t.Error("Token.IsUserLoggedIn() = true initially")
	}

	// Login SO
	token.LoginSO()
	if !token.IsSOLoggedIn() {
		t.Error("Token.IsSOLoggedIn() = false after LoginSO()")
	}

	// Logout SO
	token.LogoutSO()
	if token.IsSOLoggedIn() {
		t.Error("Token.IsSOLoggedIn() = true after LogoutSO()")
	}

	// Login user
	token.LoginUser()
	if !token.IsUserLoggedIn() {
		t.Error("Token.IsUserLoggedIn() = false after LoginUser()")
	}

	// Logout user
	token.LogoutUser()
	if token.IsUserLoggedIn() {
		t.Error("Token.IsUserLoggedIn() = true after LogoutUser()")
	}

	// Test Logout() for both
	token.LoginSO()
	token.LoginUser()
	token.Logout()
	if token.IsSOLoggedIn() {
		t.Error("Token.IsSOLoggedIn() = true after Logout()")
	}
	if token.IsUserLoggedIn() {
		t.Error("Token.IsUserLoggedIn() = true after Logout()")
	}
}

func TestToken_IsInitialized(t *testing.T) {
	token := NewToken()

	if token.IsInitialized() {
		t.Error("Token.IsInitialized() = true for new token")
	}

	token.Initialized = true
	if !token.IsInitialized() {
		t.Error("Token.IsInitialized() = false after setting Initialized")
	}
}

func TestNewSlot(t *testing.T) {
	slot := NewSlot(0)

	if slot == nil {
		t.Fatal("NewSlot() returned nil")
	}

	if slot.ID != 0 {
		t.Errorf("NewSlot(0).ID = %d, want 0", slot.ID)
	}

	// Check flags
	if !slot.Info.Flags.Has(CKF_TOKEN_PRESENT) {
		t.Error("NewSlot() missing CKF_TOKEN_PRESENT flag")
	}

	// Check description
	desc := slot.Info.GetSlotDescription()
	if !strings.Contains(desc, "go-xkms") {
		t.Errorf("NewSlot().Info.GetSlotDescription() = %q, want to contain 'go-xkms'", desc)
	}

	// Check manufacturer
	mfr := slot.Info.GetManufacturerID()
	if mfr != "go-xkms" {
		t.Errorf("NewSlot().Info.GetManufacturerID() = %q, want %q", mfr, "go-xkms")
	}
}

func TestSlot_TokenOperations(t *testing.T) {
	slot := NewSlot(0)

	// Initially no token
	if slot.HasToken() {
		t.Error("NewSlot().HasToken() = true, want false")
	}

	if slot.GetToken() != nil {
		t.Error("NewSlot().GetToken() != nil, want nil")
	}

	// Set token
	token := NewToken()
	slot.SetToken(token)

	if !slot.HasToken() {
		t.Error("Slot.HasToken() = false after SetToken()")
	}

	if slot.GetToken() != token {
		t.Error("Slot.GetToken() != token after SetToken()")
	}

	// Check CKF_TOKEN_PRESENT flag is set
	if !slot.Info.Flags.Has(CKF_TOKEN_PRESENT) {
		t.Error("CKF_TOKEN_PRESENT not set after SetToken()")
	}

	// Remove token
	slot.SetToken(nil)
	if slot.HasToken() {
		t.Error("Slot.HasToken() = true after SetToken(nil)")
	}

	// Check CKF_TOKEN_PRESENT flag is cleared
	if slot.Info.Flags.Has(CKF_TOKEN_PRESENT) {
		t.Error("CKF_TOKEN_PRESENT still set after SetToken(nil)")
	}
}

func TestNewSlotManager(t *testing.T) {
	sm := NewSlotManager()

	if sm == nil {
		t.Fatal("NewSlotManager() returned nil")
	}

	// Should have slot 0
	slots := sm.GetSlotList(false)
	if len(slots) != 1 {
		t.Errorf("NewSlotManager().GetSlotList(false) length = %d, want 1", len(slots))
	}

	// Slot 0 should have a token
	slots = sm.GetSlotList(true)
	if len(slots) != 1 {
		t.Errorf("NewSlotManager().GetSlotList(true) length = %d, want 1", len(slots))
	}

	// Check supported mechanisms
	mechanisms, err := sm.GetMechanismList(0)
	if err != nil {
		t.Fatalf("GetMechanismList() error = %v", err)
	}
	if len(mechanisms) == 0 {
		t.Error("GetMechanismList() returned empty list")
	}
}

func TestSlotManager_GetSlotList(t *testing.T) {
	sm := NewSlotManager()

	// Get all slots
	slots := sm.GetSlotList(false)
	if len(slots) != 1 {
		t.Errorf("GetSlotList(false) length = %d, want 1", len(slots))
	}
	if slots[0] != 0 {
		t.Errorf("GetSlotList(false)[0] = %d, want 0", slots[0])
	}

	// Get slots with tokens only
	slots = sm.GetSlotList(true)
	if len(slots) != 1 {
		t.Errorf("GetSlotList(true) length = %d, want 1", len(slots))
	}
}

func TestSlotManager_GetSlotInfo(t *testing.T) {
	sm := NewSlotManager()

	// Valid slot
	info, err := sm.GetSlotInfo(0)
	if err != nil {
		t.Fatalf("GetSlotInfo(0) error = %v", err)
	}
	if info == nil {
		t.Fatal("GetSlotInfo(0) returned nil")
	}

	// Check description
	desc := info.GetSlotDescription()
	if desc == "" {
		t.Error("GetSlotInfo() returned empty description")
	}

	// Invalid slot
	_, err = sm.GetSlotInfo(999)
	if err == nil {
		t.Error("GetSlotInfo(999) expected error")
	}
	var pkcs11Err *PKCS11Error
	if !errors.As(err, &pkcs11Err) || pkcs11Err.Code != CKR_SLOT_ID_INVALID {
		t.Errorf("GetSlotInfo(999) error = %v, want CKR_SLOT_ID_INVALID", err)
	}
}

func TestSlotManager_GetTokenInfo(t *testing.T) {
	sm := NewSlotManager()

	// Valid slot with token
	info, err := sm.GetTokenInfo(0)
	if err != nil {
		t.Fatalf("GetTokenInfo(0) error = %v", err)
	}
	if info == nil {
		t.Fatal("GetTokenInfo(0) returned nil")
	}

	// Check manufacturer
	mfr := info.GetManufacturerID()
	if mfr != "go-xkms" {
		t.Errorf("GetTokenInfo().GetManufacturerID() = %q, want %q", mfr, "go-xkms")
	}

	// Check UTC time is set
	utc := info.GetUtcTime()
	if len(utc) != 16 {
		t.Errorf("GetTokenInfo().GetUtcTime() length = %d, want 16", len(utc))
	}

	// Invalid slot
	_, err = sm.GetTokenInfo(999)
	if err == nil {
		t.Error("GetTokenInfo(999) expected error")
	}
	var pkcs11Err *PKCS11Error
	if !errors.As(err, &pkcs11Err) || pkcs11Err.Code != CKR_SLOT_ID_INVALID {
		t.Errorf("GetTokenInfo(999) error = %v, want CKR_SLOT_ID_INVALID", err)
	}
}

func TestSlotManager_GetTokenInfo_NoToken(t *testing.T) {
	sm := NewSlotManager()

	// Remove the token from slot 0
	slot, _ := sm.GetSlot(0)
	slot.SetToken(nil)

	_, err := sm.GetTokenInfo(0)
	if err == nil {
		t.Error("GetTokenInfo() expected error for slot without token")
	}
	var pkcs11Err *PKCS11Error
	if !errors.As(err, &pkcs11Err) || pkcs11Err.Code != CKR_TOKEN_NOT_PRESENT {
		t.Errorf("GetTokenInfo() error = %v, want CKR_TOKEN_NOT_PRESENT", err)
	}
}

func TestSlotManager_GetMechanismList(t *testing.T) {
	sm := NewSlotManager()

	// Valid slot
	mechanisms, err := sm.GetMechanismList(0)
	if err != nil {
		t.Fatalf("GetMechanismList(0) error = %v", err)
	}
	if len(mechanisms) == 0 {
		t.Error("GetMechanismList() returned empty list")
	}

	// Check for expected mechanisms
	hasRSAGen := false
	hasECGen := false
	hasAESGen := false
	for _, m := range mechanisms {
		switch m {
		case CKM_RSA_PKCS_KEY_PAIR_GEN:
			hasRSAGen = true
		case CKM_EC_KEY_PAIR_GEN:
			hasECGen = true
		case CKM_AES_KEY_GEN:
			hasAESGen = true
		}
	}
	if !hasRSAGen {
		t.Error("GetMechanismList() missing CKM_RSA_PKCS_KEY_PAIR_GEN")
	}
	if !hasECGen {
		t.Error("GetMechanismList() missing CKM_EC_KEY_PAIR_GEN")
	}
	if !hasAESGen {
		t.Error("GetMechanismList() missing CKM_AES_KEY_GEN")
	}

	// Invalid slot
	_, err = sm.GetMechanismList(999)
	if err == nil {
		t.Error("GetMechanismList(999) expected error")
	}
}

func TestSlotManager_GetMechanismList_NoToken(t *testing.T) {
	sm := NewSlotManager()

	// Remove the token from slot 0
	slot, _ := sm.GetSlot(0)
	slot.SetToken(nil)

	_, err := sm.GetMechanismList(0)
	if err == nil {
		t.Error("GetMechanismList() expected error for slot without token")
	}
	var pkcs11Err *PKCS11Error
	if !errors.As(err, &pkcs11Err) || pkcs11Err.Code != CKR_TOKEN_NOT_PRESENT {
		t.Errorf("GetMechanismList() error = %v, want CKR_TOKEN_NOT_PRESENT", err)
	}
}

func TestSlotManager_GetMechanismInfo(t *testing.T) {
	sm := NewSlotManager()

	// Valid mechanism
	info, err := sm.GetMechanismInfo(0, CKM_RSA_PKCS_KEY_PAIR_GEN)
	if err != nil {
		t.Fatalf("GetMechanismInfo() error = %v", err)
	}
	if info == nil {
		t.Fatal("GetMechanismInfo() returned nil")
	}

	// Check RSA key size limits
	if info.MinKeySize != 2048 {
		t.Errorf("RSA MinKeySize = %d, want 2048", info.MinKeySize)
	}
	if info.MaxKeySize != 4096 {
		t.Errorf("RSA MaxKeySize = %d, want 4096", info.MaxKeySize)
	}
	if info.Flags&CKF_GENERATE_KEY_PAIR == 0 {
		t.Error("RSA key gen missing CKF_GENERATE_KEY_PAIR flag")
	}

	// EC mechanism
	ecInfo, err := sm.GetMechanismInfo(0, CKM_EC_KEY_PAIR_GEN)
	if err != nil {
		t.Fatalf("GetMechanismInfo(EC) error = %v", err)
	}
	if ecInfo.MinKeySize != 256 {
		t.Errorf("EC MinKeySize = %d, want 256", ecInfo.MinKeySize)
	}

	// Invalid mechanism
	_, err = sm.GetMechanismInfo(0, MechanismType(0xFFFFFFFF))
	if err == nil {
		t.Error("GetMechanismInfo() expected error for invalid mechanism")
	}
	var pkcs11Err *PKCS11Error
	if !errors.As(err, &pkcs11Err) || pkcs11Err.Code != CKR_MECHANISM_INVALID {
		t.Errorf("GetMechanismInfo() error = %v, want CKR_MECHANISM_INVALID", err)
	}

	// Invalid slot
	_, err = sm.GetMechanismInfo(999, CKM_RSA_PKCS)
	if err == nil {
		t.Error("GetMechanismInfo(999) expected error")
	}
}

func TestSlotManager_GetMechanismInfo_NoToken(t *testing.T) {
	sm := NewSlotManager()

	// Remove the token from slot 0
	slot, _ := sm.GetSlot(0)
	slot.SetToken(nil)

	_, err := sm.GetMechanismInfo(0, CKM_RSA_PKCS)
	if err == nil {
		t.Error("GetMechanismInfo() expected error for slot without token")
	}
	var pkcs11Err *PKCS11Error
	if !errors.As(err, &pkcs11Err) || pkcs11Err.Code != CKR_TOKEN_NOT_PRESENT {
		t.Errorf("GetMechanismInfo() error = %v, want CKR_TOKEN_NOT_PRESENT", err)
	}
}

func TestSlotManager_InitToken(t *testing.T) {
	sm := NewSlotManager()

	soPin := "12345678"
	label := "Test Token"

	// Initialize token
	err := sm.InitToken(0, soPin, label)
	if err != nil {
		t.Fatalf("InitToken() error = %v", err)
	}

	// Get token info and verify
	info, err := sm.GetTokenInfo(0)
	if err != nil {
		t.Fatalf("GetTokenInfo() error = %v", err)
	}

	// Check label
	if info.GetLabel() != label {
		t.Errorf("Token label = %q, want %q", info.GetLabel(), label)
	}

	// Check CKF_TOKEN_INITIALIZED flag
	if !info.Flags.Has(CKF_TOKEN_INITIALIZED) {
		t.Error("CKF_TOKEN_INITIALIZED not set after InitToken()")
	}

	// Check serial number is set
	sn := info.GetSerialNumber()
	if sn == "" {
		t.Error("Serial number not set after InitToken()")
	}

	// Verify SO PIN works
	slot, _ := sm.GetSlot(0)
	token := slot.GetToken()
	if !token.VerifySOPin(soPin) {
		t.Error("SO PIN verification failed after InitToken()")
	}
}

func TestSlotManager_InitToken_InvalidSlot(t *testing.T) {
	sm := NewSlotManager()

	err := sm.InitToken(999, "sopin", "label")
	if err == nil {
		t.Error("InitToken(999) expected error")
	}
	var pkcs11Err *PKCS11Error
	if !errors.As(err, &pkcs11Err) || pkcs11Err.Code != CKR_SLOT_ID_INVALID {
		t.Errorf("InitToken(999) error = %v, want CKR_SLOT_ID_INVALID", err)
	}
}

func TestSlotManager_InitToken_NoToken(t *testing.T) {
	sm := NewSlotManager()

	// Remove the token
	slot, _ := sm.GetSlot(0)
	slot.SetToken(nil)

	err := sm.InitToken(0, "sopin", "label")
	if err == nil {
		t.Error("InitToken() expected error for slot without token")
	}
	var pkcs11Err *PKCS11Error
	if !errors.As(err, &pkcs11Err) || pkcs11Err.Code != CKR_TOKEN_NOT_PRESENT {
		t.Errorf("InitToken() error = %v, want CKR_TOKEN_NOT_PRESENT", err)
	}
}

func TestSlotManager_InitToken_PinLenRange(t *testing.T) {
	sm := NewSlotManager()

	// PIN too short
	err := sm.InitToken(0, "123", "label")
	if err == nil {
		t.Error("InitToken() expected error for short PIN")
	}
	var pkcs11Err *PKCS11Error
	if !errors.As(err, &pkcs11Err) || pkcs11Err.Code != CKR_PIN_LEN_RANGE {
		t.Errorf("InitToken() error = %v, want CKR_PIN_LEN_RANGE", err)
	}
}

func TestSlotManager_InitToken_Reinitialize(t *testing.T) {
	sm := NewSlotManager()

	soPin := "12345678"
	label1 := "Token Label 1"
	label2 := "Token Label 2"

	// Initialize token
	err := sm.InitToken(0, soPin, label1)
	if err != nil {
		t.Fatalf("InitToken() error = %v", err)
	}

	// Re-initialize with same PIN
	err = sm.InitToken(0, soPin, label2)
	if err != nil {
		t.Fatalf("InitToken() re-init error = %v", err)
	}

	// Verify new label
	info, _ := sm.GetTokenInfo(0)
	if info.GetLabel() != label2 {
		t.Errorf("Token label = %q, want %q", info.GetLabel(), label2)
	}

	// Re-initialize with wrong PIN should fail
	err = sm.InitToken(0, "wrongpin", "Another Label")
	if err == nil {
		t.Error("InitToken() expected error for wrong PIN")
	}
	var pkcs11Err *PKCS11Error
	if !errors.As(err, &pkcs11Err) || pkcs11Err.Code != CKR_PIN_INCORRECT {
		t.Errorf("InitToken() error = %v, want CKR_PIN_INCORRECT", err)
	}
}

func TestSlotManager_InitPIN(t *testing.T) {
	sm := NewSlotManager()

	// Initialize token first
	soPin := "sopin123"
	err := sm.InitToken(0, soPin, "Test Token")
	if err != nil {
		t.Fatalf("InitToken() error = %v", err)
	}

	// Get the token and login as SO
	slot, _ := sm.GetSlot(0)
	token := slot.GetToken()
	token.LoginSO()

	// Initialize user PIN
	userPin := "userpin456"
	err = sm.InitPIN(0, userPin)
	if err != nil {
		t.Fatalf("InitPIN() error = %v", err)
	}

	// Verify user PIN
	if !token.VerifyUserPin(userPin) {
		t.Error("User PIN verification failed after InitPIN()")
	}

	// Check CKF_USER_PIN_INITIALIZED flag
	info, _ := sm.GetTokenInfo(0)
	if !info.Flags.Has(CKF_USER_PIN_INITIALIZED) {
		t.Error("CKF_USER_PIN_INITIALIZED not set after InitPIN()")
	}
}

func TestSlotManager_InitPIN_NotLoggedIn(t *testing.T) {
	sm := NewSlotManager()

	// Initialize token but don't login
	err := sm.InitToken(0, "sopin123", "Test Token")
	if err != nil {
		t.Fatalf("InitToken() error = %v", err)
	}

	// Try to init PIN without SO login
	err = sm.InitPIN(0, "userpin")
	if err == nil {
		t.Error("InitPIN() expected error when SO not logged in")
	}
	var pkcs11Err *PKCS11Error
	if !errors.As(err, &pkcs11Err) || pkcs11Err.Code != CKR_USER_NOT_LOGGED_IN {
		t.Errorf("InitPIN() error = %v, want CKR_USER_NOT_LOGGED_IN", err)
	}
}

func TestSlotManager_InitPIN_InvalidSlot(t *testing.T) {
	sm := NewSlotManager()

	err := sm.InitPIN(999, "userpin")
	if err == nil {
		t.Error("InitPIN(999) expected error")
	}
	var pkcs11Err *PKCS11Error
	if !errors.As(err, &pkcs11Err) || pkcs11Err.Code != CKR_SLOT_ID_INVALID {
		t.Errorf("InitPIN(999) error = %v, want CKR_SLOT_ID_INVALID", err)
	}
}

func TestSlotManager_InitPIN_PinLenRange(t *testing.T) {
	sm := NewSlotManager()

	// Initialize token and login as SO
	err := sm.InitToken(0, "sopin123", "Test Token")
	if err != nil {
		t.Fatalf("InitToken() error = %v", err)
	}
	slot, _ := sm.GetSlot(0)
	token := slot.GetToken()
	token.LoginSO()

	// PIN too short
	err = sm.InitPIN(0, "123")
	if err == nil {
		t.Error("InitPIN() expected error for short PIN")
	}
	var pkcs11Err *PKCS11Error
	if !errors.As(err, &pkcs11Err) || pkcs11Err.Code != CKR_PIN_LEN_RANGE {
		t.Errorf("InitPIN() error = %v, want CKR_PIN_LEN_RANGE", err)
	}
}

func TestSlotManager_SetPIN_SO(t *testing.T) {
	sm := NewSlotManager()

	oldPin := "sopin123"
	newPin := "newsopin"

	// Initialize token
	err := sm.InitToken(0, oldPin, "Test Token")
	if err != nil {
		t.Fatalf("InitToken() error = %v", err)
	}

	// Change SO PIN
	err = sm.SetPIN(0, oldPin, newPin, CKU_SO)
	if err != nil {
		t.Fatalf("SetPIN(SO) error = %v", err)
	}

	// Verify new PIN works
	slot, _ := sm.GetSlot(0)
	token := slot.GetToken()
	if !token.VerifySOPin(newPin) {
		t.Error("New SO PIN verification failed after SetPIN()")
	}

	// Verify old PIN no longer works
	if token.VerifySOPin(oldPin) {
		t.Error("Old SO PIN still works after SetPIN()")
	}
}

func TestSlotManager_SetPIN_User(t *testing.T) {
	sm := NewSlotManager()

	soPin := "sopin123"
	oldUserPin := "userpin123"
	newUserPin := "newuserpin"

	// Initialize token and user PIN
	err := sm.InitToken(0, soPin, "Test Token")
	if err != nil {
		t.Fatalf("InitToken() error = %v", err)
	}

	slot, _ := sm.GetSlot(0)
	token := slot.GetToken()
	token.LoginSO()
	err = sm.InitPIN(0, oldUserPin)
	if err != nil {
		t.Fatalf("InitPIN() error = %v", err)
	}
	token.LogoutSO()

	// Change user PIN
	err = sm.SetPIN(0, oldUserPin, newUserPin, CKU_USER)
	if err != nil {
		t.Fatalf("SetPIN(USER) error = %v", err)
	}

	// Verify new PIN works
	if !token.VerifyUserPin(newUserPin) {
		t.Error("New user PIN verification failed after SetPIN()")
	}

	// Verify old PIN no longer works
	if token.VerifyUserPin(oldUserPin) {
		t.Error("Old user PIN still works after SetPIN()")
	}
}

func TestSlotManager_SetPIN_InvalidUserType(t *testing.T) {
	sm := NewSlotManager()

	err := sm.InitToken(0, "sopin123", "Test Token")
	if err != nil {
		t.Fatalf("InitToken() error = %v", err)
	}

	err = sm.SetPIN(0, "oldpin", "newpin", UserType(99))
	if err == nil {
		t.Error("SetPIN() expected error for invalid user type")
	}
	var pkcs11Err *PKCS11Error
	if !errors.As(err, &pkcs11Err) || pkcs11Err.Code != CKR_USER_TYPE_INVALID {
		t.Errorf("SetPIN() error = %v, want CKR_USER_TYPE_INVALID", err)
	}
}

func TestSlotManager_SetPIN_WrongOldPin(t *testing.T) {
	sm := NewSlotManager()

	err := sm.InitToken(0, "sopin123", "Test Token")
	if err != nil {
		t.Fatalf("InitToken() error = %v", err)
	}

	// Try with wrong old PIN
	err = sm.SetPIN(0, "wrongpin", "newpin", CKU_SO)
	if err == nil {
		t.Error("SetPIN() expected error for wrong old PIN")
	}
	var pkcs11Err *PKCS11Error
	if !errors.As(err, &pkcs11Err) || pkcs11Err.Code != CKR_PIN_INCORRECT {
		t.Errorf("SetPIN() error = %v, want CKR_PIN_INCORRECT", err)
	}
}

func TestSlotManager_SetPIN_UserNotInitialized(t *testing.T) {
	sm := NewSlotManager()

	err := sm.InitToken(0, "sopin123", "Test Token")
	if err != nil {
		t.Fatalf("InitToken() error = %v", err)
	}

	// Try to change user PIN when not initialized
	err = sm.SetPIN(0, "oldpin", "newpin", CKU_USER)
	if err == nil {
		t.Error("SetPIN(USER) expected error when user PIN not initialized")
	}
	var pkcs11Err *PKCS11Error
	if !errors.As(err, &pkcs11Err) || pkcs11Err.Code != CKR_USER_PIN_NOT_INITIALIZED {
		t.Errorf("SetPIN() error = %v, want CKR_USER_PIN_NOT_INITIALIZED", err)
	}
}

func TestSlotManager_SetPIN_InvalidSlot(t *testing.T) {
	sm := NewSlotManager()

	err := sm.SetPIN(999, "old", "new", CKU_SO)
	if err == nil {
		t.Error("SetPIN(999) expected error")
	}
	var pkcs11Err *PKCS11Error
	if !errors.As(err, &pkcs11Err) || pkcs11Err.Code != CKR_SLOT_ID_INVALID {
		t.Errorf("SetPIN(999) error = %v, want CKR_SLOT_ID_INVALID", err)
	}
}

func TestSlotManager_SetPIN_PinLenRange(t *testing.T) {
	sm := NewSlotManager()

	err := sm.InitToken(0, "sopin123", "Test Token")
	if err != nil {
		t.Fatalf("InitToken() error = %v", err)
	}

	// New PIN too short
	err = sm.SetPIN(0, "sopin123", "123", CKU_SO)
	if err == nil {
		t.Error("SetPIN() expected error for short new PIN")
	}
	var pkcs11Err *PKCS11Error
	if !errors.As(err, &pkcs11Err) || pkcs11Err.Code != CKR_PIN_LEN_RANGE {
		t.Errorf("SetPIN() error = %v, want CKR_PIN_LEN_RANGE", err)
	}
}

func TestSlotManager_GetSlot(t *testing.T) {
	sm := NewSlotManager()

	// Valid slot
	slot, err := sm.GetSlot(0)
	if err != nil {
		t.Fatalf("GetSlot(0) error = %v", err)
	}
	if slot == nil {
		t.Fatal("GetSlot(0) returned nil")
	}
	if slot.ID != 0 {
		t.Errorf("GetSlot(0).ID = %d, want 0", slot.ID)
	}

	// Invalid slot
	_, err = sm.GetSlot(999)
	if err == nil {
		t.Error("GetSlot(999) expected error")
	}
	var pkcs11Err *PKCS11Error
	if !errors.As(err, &pkcs11Err) || pkcs11Err.Code != CKR_SLOT_ID_INVALID {
		t.Errorf("GetSlot(999) error = %v, want CKR_SLOT_ID_INVALID", err)
	}
}

func TestTrimPaddedString(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{
			name:  "no padding",
			input: []byte("hello"),
			want:  "hello",
		},
		{
			name:  "space padding",
			input: []byte("hello     "),
			want:  "hello",
		},
		{
			name:  "null padding",
			input: []byte("hello\x00\x00\x00"),
			want:  "hello",
		},
		{
			name:  "mixed padding",
			input: []byte("hello \x00 "),
			want:  "hello",
		},
		{
			name:  "empty",
			input: []byte(""),
			want:  "",
		},
		{
			name:  "only spaces",
			input: []byte("   "),
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := trimPaddedString(tt.input)
			if got != tt.want {
				t.Errorf("trimPaddedString(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestSetPaddedString(t *testing.T) {
	tests := []struct {
		name  string
		input string
		size  int
		check func([]byte) bool
	}{
		{
			name:  "normal string",
			input: "hello",
			size:  10,
			check: func(b []byte) bool {
				return string(b[:5]) == "hello" && b[5] == ' '
			},
		},
		{
			name:  "string same as buffer",
			input: "hello",
			size:  5,
			check: func(b []byte) bool {
				return string(b) == "hello"
			},
		},
		{
			name:  "string longer than buffer",
			input: "hello world",
			size:  5,
			check: func(b []byte) bool {
				return string(b) == "hello"
			},
		},
		{
			name:  "empty string",
			input: "",
			size:  5,
			check: func(b []byte) bool {
				return string(b) == "     "
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := make([]byte, tt.size)
			setPaddedString(buf, tt.input)
			if !tt.check(buf) {
				t.Errorf("setPaddedString(%q, %q) result = %q", tt.input, buf, buf)
			}
		})
	}
}

func TestHashPin(t *testing.T) {
	// Test that same PIN gives same hash
	pin := "testpin123"
	hash1 := hashPin(pin)
	hash2 := hashPin(pin)

	if len(hash1) != 32 { // SHA-256 produces 32 bytes
		t.Errorf("hashPin() length = %d, want 32", len(hash1))
	}

	for i := range hash1 {
		if hash1[i] != hash2[i] {
			t.Error("hashPin() not deterministic")
			break
		}
	}

	// Test that different PINs give different hashes
	hash3 := hashPin("differentpin")
	same := true
	for i := range hash1 {
		if hash1[i] != hash3[i] {
			same = false
			break
		}
	}
	if same {
		t.Error("hashPin() collision for different PINs")
	}
}

func TestGenerateSerialNumber(t *testing.T) {
	sn1 := generateSerialNumber()

	// Check length
	if len(sn1) != 16 {
		t.Errorf("generateSerialNumber() length = %d, want 16", len(sn1))
	}

	// Check format (should be numeric)
	for _, c := range sn1 {
		if c < '0' || c > '9' {
			t.Errorf("generateSerialNumber() contains non-numeric: %q", sn1)
			break
		}
	}
}

func TestDefaultSupportedMechanisms(t *testing.T) {
	mechanisms := defaultSupportedMechanisms()

	if len(mechanisms) == 0 {
		t.Error("defaultSupportedMechanisms() returned empty list")
	}

	// Check for key mechanisms
	found := make(map[MechanismType]bool)
	for _, m := range mechanisms {
		found[m] = true
	}

	required := []MechanismType{
		CKM_RSA_PKCS_KEY_PAIR_GEN,
		CKM_EC_KEY_PAIR_GEN,
		CKM_AES_KEY_GEN,
		CKM_SHA256,
	}

	for _, r := range required {
		if !found[r] {
			t.Errorf("defaultSupportedMechanisms() missing %v", r)
		}
	}
}

func TestDefaultMechanismInfo(t *testing.T) {
	info := defaultMechanismInfo()

	if len(info) == 0 {
		t.Error("defaultMechanismInfo() returned empty map")
	}

	// Check RSA info
	rsaInfo, ok := info[CKM_RSA_PKCS_KEY_PAIR_GEN]
	if !ok {
		t.Error("defaultMechanismInfo() missing CKM_RSA_PKCS_KEY_PAIR_GEN")
	} else {
		if rsaInfo.MinKeySize != 2048 {
			t.Errorf("RSA MinKeySize = %d, want 2048", rsaInfo.MinKeySize)
		}
		if rsaInfo.Flags&CKF_GENERATE_KEY_PAIR == 0 {
			t.Error("RSA missing CKF_GENERATE_KEY_PAIR flag")
		}
	}

	// Check EC info
	ecInfo, ok := info[CKM_EC_KEY_PAIR_GEN]
	if !ok {
		t.Error("defaultMechanismInfo() missing CKM_EC_KEY_PAIR_GEN")
	} else {
		if ecInfo.MinKeySize != 256 {
			t.Errorf("EC MinKeySize = %d, want 256", ecInfo.MinKeySize)
		}
		if ecInfo.Flags&CKF_EC_F_P == 0 {
			t.Error("EC missing CKF_EC_F_P flag")
		}
	}

	// Check digest info
	sha256Info, ok := info[CKM_SHA256]
	if !ok {
		t.Error("defaultMechanismInfo() missing CKM_SHA256")
	} else {
		if sha256Info.Flags&CKF_DIGEST == 0 {
			t.Error("SHA256 missing CKF_DIGEST flag")
		}
	}
}

func TestConcurrentSlotManagerAccess(t *testing.T) {
	sm := NewSlotManager()

	// Initialize the token first
	err := sm.InitToken(0, "sopin123", "Test Token")
	if err != nil {
		t.Fatalf("InitToken() error = %v", err)
	}

	var wg sync.WaitGroup
	numGoroutines := 100

	// Concurrent reads
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = sm.GetSlotList(false)
			_, _ = sm.GetSlotInfo(0)
			_, _ = sm.GetTokenInfo(0)
			_, _ = sm.GetMechanismList(0)
			_, _ = sm.GetMechanismInfo(0, CKM_RSA_PKCS)
		}()
	}

	wg.Wait()
}

func TestConcurrentTokenAccess(t *testing.T) {
	token := NewToken()
	token.SetSOPin("sopin123")
	token.SetUserPin("userpin456")

	var wg sync.WaitGroup
	numGoroutines := 100

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = token.VerifySOPin("sopin123")
			_ = token.VerifyUserPin("userpin456")
			_ = token.IsSOLoggedIn()
			_ = token.IsUserLoggedIn()
			_ = token.IsInitialized()
		}()
	}

	wg.Wait()
}

// Note: UserType constants (CKU_SO, CKU_USER, CKU_CONTEXT_SPECIFIC) are
// defined in session.go and tested in session_test.go

func TestSpecialConstants(t *testing.T) {
	if CK_EFFECTIVELY_INFINITE != 0 {
		t.Errorf("CK_EFFECTIVELY_INFINITE = %d, want 0", CK_EFFECTIVELY_INFINITE)
	}
	if CK_UNAVAILABLE_INFORMATION != ^uint64(0) {
		t.Errorf("CK_UNAVAILABLE_INFORMATION = %d, want %d", CK_UNAVAILABLE_INFORMATION, ^uint64(0))
	}
}

func TestSlotFlagConstants(t *testing.T) {
	// Verify slot flag constants match PKCS#11 spec
	if CKF_TOKEN_PRESENT != 0x00000001 {
		t.Errorf("CKF_TOKEN_PRESENT = 0x%08X, want 0x00000001", CKF_TOKEN_PRESENT)
	}
	if CKF_REMOVABLE_DEVICE != 0x00000002 {
		t.Errorf("CKF_REMOVABLE_DEVICE = 0x%08X, want 0x00000002", CKF_REMOVABLE_DEVICE)
	}
	if CKF_HW_SLOT != 0x00000004 {
		t.Errorf("CKF_HW_SLOT = 0x%08X, want 0x00000004", CKF_HW_SLOT)
	}
}

func TestTokenFlagConstants(t *testing.T) {
	// Verify token flag constants match PKCS#11 spec
	if CKF_RNG != 0x00000001 {
		t.Errorf("CKF_RNG = 0x%08X, want 0x00000001", CKF_RNG)
	}
	if CKF_WRITE_PROTECTED != 0x00000002 {
		t.Errorf("CKF_WRITE_PROTECTED = 0x%08X, want 0x00000002", CKF_WRITE_PROTECTED)
	}
	if CKF_LOGIN_REQUIRED != 0x00000004 {
		t.Errorf("CKF_LOGIN_REQUIRED = 0x%08X, want 0x00000004", CKF_LOGIN_REQUIRED)
	}
	if CKF_USER_PIN_INITIALIZED != 0x00000008 {
		t.Errorf("CKF_USER_PIN_INITIALIZED = 0x%08X, want 0x00000008", CKF_USER_PIN_INITIALIZED)
	}
	if CKF_TOKEN_INITIALIZED != 0x00000400 {
		t.Errorf("CKF_TOKEN_INITIALIZED = 0x%08X, want 0x00000400", CKF_TOKEN_INITIALIZED)
	}
	if CKF_PROTECTED_AUTHENTICATION_PATH != 0x00000100 {
		t.Errorf("CKF_PROTECTED_AUTHENTICATION_PATH = 0x%08X, want 0x00000100", CKF_PROTECTED_AUTHENTICATION_PATH)
	}
}
