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

// TestToken_ClearUserPin tests that ClearUserPin zeroizes the stored user PIN
// verifier and clears CKF_USER_PIN_INITIALIZED, per C_InitToken's requirement
// (v3.2 §5.5.7) that the user PIN be invalidated whenever the SO reinitializes
// the token.
func TestToken_ClearUserPin(t *testing.T) {
	token := NewToken()
	token.SetUserPin("userpin")

	if !token.Info.Flags.Has(CKF_USER_PIN_INITIALIZED) {
		t.Fatal("CKF_USER_PIN_INITIALIZED not set after SetUserPin()")
	}
	if !token.VerifyUserPin("userpin") {
		t.Fatal("VerifyUserPin() failed for the PIN that was just set")
	}

	token.ClearUserPin()

	if token.Info.Flags.Has(CKF_USER_PIN_INITIALIZED) {
		t.Error("CKF_USER_PIN_INITIALIZED still set after ClearUserPin()")
	}
	if token.VerifyUserPin("userpin") {
		t.Error("VerifyUserPin() succeeded for a PIN cleared by ClearUserPin()")
	}
	if token.UserPinHash != nil {
		t.Error("UserPinHash not nil after ClearUserPin()")
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
	if info.MinKeySize != rsaModulusBitsMin {
		t.Errorf("RSA MinKeySize = %d, want %d", info.MinKeySize, rsaModulusBitsMin)
	}
	if info.MaxKeySize != rsaModulusBitsMax {
		t.Errorf("RSA MaxKeySize = %d, want %d", info.MaxKeySize, rsaModulusBitsMax)
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

// TestHashPin tests that hashPin produces a self-describing, randomly salted
// verifier: two calls for the same PIN must NOT be byte-identical (a fresh
// salt is drawn every time), and each verifier must still authenticate the
// PIN that produced it via verifyPin. Comparing hashPin outputs directly, as
// this test previously did, is wrong by construction once the salt is random.
func TestHashPin(t *testing.T) {
	pin := "testpin123"
	hash1 := mustHashPin(pin)
	hash2 := mustHashPin(pin)

	if len(hash1) == 0 || len(hash2) == 0 {
		t.Fatal("hashPin() returned an empty verifier")
	}

	identical := len(hash1) == len(hash2)
	if identical {
		for i := range hash1 {
			if hash1[i] != hash2[i] {
				identical = false
				break
			}
		}
	}
	if identical {
		t.Error("hashPin() produced identical verifiers for two calls with the same PIN; salt is not random")
	}

	// Each verifier must authenticate the PIN that produced it.
	if !verifyPin(hash1, pin) {
		t.Error("verifyPin() rejected the PIN against its own verifier (first hashPin call)")
	}
	if !verifyPin(hash2, pin) {
		t.Error("verifyPin() rejected the PIN against its own verifier (second hashPin call)")
	}

	// A different PIN must not verify against either verifier.
	if verifyPin(hash1, "differentpin") {
		t.Error("verifyPin() accepted an incorrect PIN")
	}
	if verifyPin(hash2, "differentpin") {
		t.Error("verifyPin() accepted an incorrect PIN")
	}
}

// TestVerifyPin_MalformedStored tests that verifyPin fails closed -- never
// panicking and never authenticating -- for stored values that are not a
// well-formed hashPin verifier (nil, empty, wrong version byte, or truncated).
// This matters because a corrupted or pre-migration stored PIN must not be
// silently treated as "any PIN accepted".
func TestVerifyPin_MalformedStored(t *testing.T) {
	valid := mustHashPin("somepin")

	tests := []struct {
		name   string
		stored []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"too short", []byte{0x01}},
		{"wrong version byte", append([]byte{0x02}, valid[1:]...)},
		{"zero salt length", []byte{0x01, 0x00, 1, 2, 3, 4}},
		{"truncated after salt length claim", []byte{0x01, 16, 1, 2, 3}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if verifyPin(tt.stored, "somepin") {
				t.Errorf("verifyPin() accepted a PIN against malformed stored value %v", tt.stored)
			}
		})
	}
}

// TestGenerateSerialNumber pins what CK_TOKEN_INFO.serialNumber is for.
//
// The field is CK_CHAR[16] and the spec places no numeric restriction on it;
// what it must do is IDENTIFY the token, because pkcs11:serial= selects on it
// and a fleet inventory distinguishes tokens by it. The implementation this
// replaces formatted the clock to one-second resolution and appended a literal
// "00", so two tokens provisioned in the same second were byte-identical --
// a property no assertion here caught, because uniqueness was never tested.
func TestGenerateSerialNumber(t *testing.T) {
	const samples = 64

	seen := make(map[string]bool, samples)
	for i := 0; i < samples; i++ {
		sn := mustGenerateSerialNumber()

		if len(sn) != 16 {
			t.Fatalf("generateSerialNumber() length = %d, want 16", len(sn))
		}
		for _, c := range sn {
			if (c < '0' || c > '9') && (c < 'A' || c > 'F') {
				t.Fatalf("generateSerialNumber() = %q, want uppercase hex", sn)
			}
		}
		if seen[sn] {
			t.Fatalf("generateSerialNumber() repeated %q within %d calls; "+
				"a serial that collides cannot identify a token", sn, samples)
		}
		seen[sn] = true
	}
}

// TestNewTokenBlankPadsCharacterFields pins PKCS#11 v3.2 §3.2: the character
// arrays in CK_TOKEN_INFO are blank-padded and are NOT NUL-terminated.
//
// A token reports a label and a serial number before C_InitToken supplies real
// ones. Left at their zero value these fields were runs of NUL bytes, which
// pkcs11-tool renders as control characters, p11-kit percent-encodes into the
// token URI, and a C application comparing against its own space-padded
// constant fails to match.
func TestNewTokenBlankPadsCharacterFields(t *testing.T) {
	token := NewToken()

	fields := map[string][]byte{
		"label":          token.Info.Label[:],
		"manufacturerID": token.Info.ManufacturerID[:],
		"model":          token.Info.Model[:],
		"serialNumber":   token.Info.SerialNumber[:],
	}

	for name, field := range fields {
		for i, b := range field {
			if b == 0 {
				t.Errorf("CK_TOKEN_INFO.%s byte %d is NUL; the field must be blank-padded", name, i)
				break
			}
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

	// Provision the token directly. SlotManager no longer carries its own
	// InitToken: Module owns that flow, and the SlotManager copy was a second,
	// weaker implementation whose PIN checks were skipped entirely when the
	// stored hash was empty. What this test needs is a provisioned token, not
	// that particular way of reaching one.
	slot, err := sm.GetSlot(0)
	if err != nil {
		t.Fatalf("GetSlot() error = %v", err)
	}
	slot.Token.SetSOPin("sopin123")
	slot.Token.Info.SetLabel("Test Token")
	slot.Token.Info.Flags |= CKF_TOKEN_INITIALIZED
	slot.Token.Initialized = true

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
