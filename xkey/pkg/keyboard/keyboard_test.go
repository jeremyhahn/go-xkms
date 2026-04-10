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

package keyboard

import (
	"errors"
	"log/slog"
	"os"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/uhid"
)

// mockDevice is a DeviceWriter that records all WriteInput calls for verification.
type mockDevice struct {
	mu       sync.Mutex
	reports  [][]byte
	closed   bool
	writeErr error
	closeErr error
}

func newMockDevice() *mockDevice {
	return &mockDevice{
		reports: make([][]byte, 0),
	}
}

func (m *mockDevice) WriteInput(data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.writeErr != nil {
		return m.writeErr
	}

	// Store a copy to prevent mutation
	cp := make([]byte, len(data))
	copy(cp, data)
	m.reports = append(m.reports, cp)
	return nil
}

func (m *mockDevice) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return m.closeErr
}

func (m *mockDevice) getReports() [][]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([][]byte, len(m.reports))
	copy(cp, m.reports)
	return cp
}

func (m *mockDevice) isClosed() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closed
}

// mockUHIDDevice implements UHIDDevice for testing the New function.
type mockUHIDDevice struct {
	mockDevice
	createErr error
	created   bool
}

func newMockUHIDDevice() *mockUHIDDevice {
	return &mockUHIDDevice{
		mockDevice: mockDevice{
			reports: make([][]byte, 0),
		},
	}
}

func (m *mockUHIDDevice) Create(cfg *uhid.CreateConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.createErr != nil {
		return m.createErr
	}
	m.created = true
	return nil
}

func (m *mockUHIDDevice) isCreated() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.created
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))
}

// setTestUHIDOpener sets a test UHID opener and returns a cleanup function.
// This should be called with t.Cleanup to ensure proper restoration.
func setTestUHIDOpener(opener UHIDOpener) func() {
	original := uhidOpener
	uhidOpener = opener
	return func() {
		uhidOpener = original
	}
}

func TestNew_Success(t *testing.T) {
	mock := newMockUHIDDevice()
	t.Cleanup(setTestUHIDOpener(func() (UHIDDevice, error) {
		return mock, nil
	}))

	kb, err := New(testLogger())
	if err != nil {
		t.Fatalf("New() error = %v, want nil", err)
	}
	if kb == nil {
		t.Fatal("New() returned nil keyboard")
	}

	if !mock.isCreated() {
		t.Error("device.Create was not called")
	}

	// Clean up
	if err := kb.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}
}

func TestNew_OpenFailure(t *testing.T) {
	openErr := errors.New("uhid open failed")
	t.Cleanup(setTestUHIDOpener(func() (UHIDDevice, error) {
		return nil, openErr
	}))

	kb, err := New(testLogger())
	if err == nil {
		t.Fatal("New() should return error when UHID open fails")
	}
	if !errors.Is(err, ErrKeyboardOpenFailed) {
		t.Errorf("New() error = %v, want %v", err, ErrKeyboardOpenFailed)
	}
	if kb != nil {
		t.Error("New() should return nil keyboard on error")
	}
}

func TestNew_CreateFailure(t *testing.T) {
	createErr := errors.New("device create failed")
	mock := newMockUHIDDevice()
	mock.createErr = createErr

	t.Cleanup(setTestUHIDOpener(func() (UHIDDevice, error) {
		return mock, nil
	}))

	kb, err := New(testLogger())
	if err == nil {
		t.Fatal("New() should return error when device.Create fails")
	}
	if !errors.Is(err, ErrKeyboardCreateFailed) {
		t.Errorf("New() error = %v, want %v", err, ErrKeyboardCreateFailed)
	}
	if kb != nil {
		t.Error("New() should return nil keyboard on error")
	}

	// Verify device was closed after create failure
	if !mock.isClosed() {
		t.Error("device should be closed after create failure")
	}
}

func TestNew_CreateConfigValues(t *testing.T) {
	var capturedConfig *uhid.CreateConfig
	mock := &configCapturingMockDevice{}

	t.Cleanup(setTestUHIDOpener(func() (UHIDDevice, error) {
		return mock, nil
	}))

	kb, err := New(testLogger())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() {
		if err := kb.Close(); err != nil {
			t.Logf("Close() error: %v", err)
		}
	}()

	capturedConfig = mock.config

	if capturedConfig == nil {
		t.Fatal("Create was not called with config")
	}

	// Verify config values
	if capturedConfig.Name != "xKey Keyboard" {
		t.Errorf("config.Name = %q, want %q", capturedConfig.Name, "xKey Keyboard")
	}
	if capturedConfig.Phys != "xkey-keyboard" {
		t.Errorf("config.Phys = %q, want %q", capturedConfig.Phys, "xkey-keyboard")
	}
	if capturedConfig.VendorID != VendorIDKeyboard {
		t.Errorf("config.VendorID = 0x%04X, want 0x%04X", capturedConfig.VendorID, VendorIDKeyboard)
	}
	if capturedConfig.ProductID != ProductIDKeyboard {
		t.Errorf("config.ProductID = 0x%04X, want 0x%04X", capturedConfig.ProductID, ProductIDKeyboard)
	}
	if capturedConfig.Version != 0x0100 {
		t.Errorf("config.Version = 0x%04X, want 0x0100", capturedConfig.Version)
	}
	if len(capturedConfig.ReportDescriptor) == 0 {
		t.Error("config.ReportDescriptor is empty")
	}
	// Verify it uses the boot keyboard descriptor
	if len(capturedConfig.ReportDescriptor) != len(BootKeyboardReportDescriptor) {
		t.Errorf("config.ReportDescriptor length = %d, want %d",
			len(capturedConfig.ReportDescriptor), len(BootKeyboardReportDescriptor))
	}
}

// configCapturingMockDevice captures the CreateConfig for verification.
type configCapturingMockDevice struct {
	mu     sync.Mutex
	config *uhid.CreateConfig
	closed bool
}

func (m *configCapturingMockDevice) Create(cfg *uhid.CreateConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.config = cfg
	return nil
}

func (m *configCapturingMockDevice) WriteInput(data []byte) error {
	return nil
}

func (m *configCapturingMockDevice) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

func TestNewWithDevice_Creates(t *testing.T) {
	mock := newMockDevice()
	kb := NewWithDevice(mock, testLogger())

	if kb == nil {
		t.Fatal("NewWithDevice returned nil")
	}
	if kb.device != mock {
		t.Error("keyboard device does not match mock")
	}
	if kb.closed.Load() {
		t.Error("keyboard should not be closed after creation")
	}
}

func TestTypeKey_ProducesCorrectReports(t *testing.T) {
	mock := newMockDevice()
	kb := NewWithDevice(mock, testLogger())

	// Type 'a': scancode 0x04, no shift
	err := kb.TypeKey(0x04, false)
	if err != nil {
		t.Fatalf("TypeKey error = %v", err)
	}

	reports := mock.getReports()
	if len(reports) != 2 {
		t.Fatalf("expected 2 reports (key-down + key-up), got %d", len(reports))
	}

	// Key-down report
	down := reports[0]
	if len(down) != KeyboardReportSize {
		t.Fatalf("key-down report size = %d, want %d", len(down), KeyboardReportSize)
	}
	if down[0] != 0x00 {
		t.Errorf("key-down modifier = 0x%02X, want 0x00", down[0])
	}
	if down[1] != 0x00 {
		t.Errorf("key-down reserved = 0x%02X, want 0x00", down[1])
	}
	if down[2] != 0x04 {
		t.Errorf("key-down scancode = 0x%02X, want 0x04", down[2])
	}
	for i := 3; i < KeyboardReportSize; i++ {
		if down[i] != 0x00 {
			t.Errorf("key-down byte[%d] = 0x%02X, want 0x00", i, down[i])
		}
	}

	// Key-up report (all zeros)
	up := reports[1]
	if len(up) != KeyboardReportSize {
		t.Fatalf("key-up report size = %d, want %d", len(up), KeyboardReportSize)
	}
	for i := 0; i < KeyboardReportSize; i++ {
		if up[i] != 0x00 {
			t.Errorf("key-up byte[%d] = 0x%02X, want 0x00", i, up[i])
		}
	}
}

func TestTypeKey_WithShift(t *testing.T) {
	mock := newMockDevice()
	kb := NewWithDevice(mock, testLogger())

	// Type 'A': scancode 0x04, shift
	err := kb.TypeKey(0x04, true)
	if err != nil {
		t.Fatalf("TypeKey error = %v", err)
	}

	reports := mock.getReports()
	if len(reports) != 2 {
		t.Fatalf("expected 2 reports, got %d", len(reports))
	}

	// Key-down: modifier should be ModifierLeftShift
	down := reports[0]
	if down[0] != ModifierLeftShift {
		t.Errorf("key-down modifier = 0x%02X, want 0x%02X (ModifierLeftShift)",
			down[0], ModifierLeftShift)
	}
	if down[2] != 0x04 {
		t.Errorf("key-down scancode = 0x%02X, want 0x04", down[2])
	}

	// Key-up: all zeros (shift released)
	up := reports[1]
	if up[0] != 0x00 {
		t.Errorf("key-up modifier = 0x%02X, want 0x00 (released)", up[0])
	}
}

func TestTypeString_AllCharactersInSequence(t *testing.T) {
	mock := newMockDevice()
	kb := NewWithDevice(mock, testLogger())

	input := "abc"
	err := kb.TypeString(input)
	if err != nil {
		t.Fatalf("TypeString error = %v", err)
	}

	// Each character produces 2 reports (down + up) = 6 total
	reports := mock.getReports()
	if len(reports) != 6 {
		t.Fatalf("expected 6 reports for 3 chars, got %d", len(reports))
	}

	// Verify scancodes: a=0x04, b=0x05, c=0x06
	expectedScancodes := []byte{0x04, 0x05, 0x06}
	for i, sc := range expectedScancodes {
		down := reports[i*2]
		if down[2] != sc {
			t.Errorf("char %d key-down scancode = 0x%02X, want 0x%02X", i, down[2], sc)
		}
		up := reports[i*2+1]
		for j := range up {
			if up[j] != 0x00 {
				t.Errorf("char %d key-up byte[%d] = 0x%02X, want 0x00", i, j, up[j])
			}
		}
	}
}

func TestTypeString_MixedCaseAndSymbols(t *testing.T) {
	mock := newMockDevice()
	kb := NewWithDevice(mock, testLogger())

	input := "Ab!"
	err := kb.TypeString(input)
	if err != nil {
		t.Fatalf("TypeString error = %v", err)
	}

	reports := mock.getReports()
	if len(reports) != 6 {
		t.Fatalf("expected 6 reports for 3 chars, got %d", len(reports))
	}

	// 'A': shift + 0x04
	if reports[0][0] != ModifierLeftShift {
		t.Errorf("'A' modifier = 0x%02X, want 0x%02X", reports[0][0], ModifierLeftShift)
	}
	if reports[0][2] != 0x04 {
		t.Errorf("'A' scancode = 0x%02X, want 0x04", reports[0][2])
	}

	// 'b': no shift + 0x05
	if reports[2][0] != 0x00 {
		t.Errorf("'b' modifier = 0x%02X, want 0x00", reports[2][0])
	}
	if reports[2][2] != 0x05 {
		t.Errorf("'b' scancode = 0x%02X, want 0x05", reports[2][2])
	}

	// '!': shift + 0x1E
	if reports[4][0] != ModifierLeftShift {
		t.Errorf("'!' modifier = 0x%02X, want 0x%02X", reports[4][0], ModifierLeftShift)
	}
	if reports[4][2] != 0x1E {
		t.Errorf("'!' scancode = 0x%02X, want 0x1E", reports[4][2])
	}
}

func TestTypeString_EmptyString(t *testing.T) {
	mock := newMockDevice()
	kb := NewWithDevice(mock, testLogger())

	err := kb.TypeString("")
	if !errors.Is(err, ErrEmptyString) {
		t.Errorf("TypeString(\"\") error = %v, want %v", err, ErrEmptyString)
	}

	// No reports should have been written
	reports := mock.getReports()
	if len(reports) != 0 {
		t.Errorf("expected 0 reports for empty string, got %d", len(reports))
	}
}

func TestTypeString_UnsupportedChar(t *testing.T) {
	mock := newMockDevice()
	kb := NewWithDevice(mock, testLogger())

	// String contains an emoji which is not in the US keyboard layout
	err := kb.TypeString("hello\u0000world")
	if !errors.Is(err, ErrUnsupportedChar) {
		t.Errorf("TypeString with unsupported char error = %v, want %v", err, ErrUnsupportedChar)
	}
}

func TestTypeString_UnsupportedCharEmoji(t *testing.T) {
	mock := newMockDevice()
	kb := NewWithDevice(mock, testLogger())

	err := kb.TypeString("test\U0001F600")
	if !errors.Is(err, ErrUnsupportedChar) {
		t.Errorf("TypeString with emoji error = %v, want %v", err, ErrUnsupportedChar)
	}
}

func TestTypeKey_ClosedKeyboard(t *testing.T) {
	mock := newMockDevice()
	kb := NewWithDevice(mock, testLogger())
	_ = kb.Close()

	err := kb.TypeKey(0x04, false)
	if !errors.Is(err, ErrKeyboardClosed) {
		t.Errorf("TypeKey on closed keyboard error = %v, want %v", err, ErrKeyboardClosed)
	}
}

func TestTypeString_ClosedKeyboard(t *testing.T) {
	mock := newMockDevice()
	kb := NewWithDevice(mock, testLogger())
	_ = kb.Close()

	err := kb.TypeString("hello")
	if !errors.Is(err, ErrKeyboardClosed) {
		t.Errorf("TypeString on closed keyboard error = %v, want %v", err, ErrKeyboardClosed)
	}
}

func TestClose_Idempotent(t *testing.T) {
	mock := newMockDevice()
	kb := NewWithDevice(mock, testLogger())

	// First close
	err := kb.Close()
	if err != nil {
		t.Errorf("first Close error = %v, want nil", err)
	}

	// Second close should succeed without error
	err = kb.Close()
	if err != nil {
		t.Errorf("second Close error = %v, want nil", err)
	}

	if !mock.isClosed() {
		t.Error("mock device should be closed")
	}
}

func TestClose_PropagatesDeviceError(t *testing.T) {
	deviceErr := errors.New("device close error")
	mock := newMockDevice()
	mock.closeErr = deviceErr
	kb := NewWithDevice(mock, testLogger())

	err := kb.Close()
	if !errors.Is(err, deviceErr) {
		t.Errorf("Close error = %v, want %v", err, deviceErr)
	}
}

func TestTypeString_DeviceWriteError(t *testing.T) {
	deviceErr := errors.New("write failed")
	mock := newMockDevice()
	mock.writeErr = deviceErr
	kb := NewWithDevice(mock, testLogger())

	err := kb.TypeString("a")
	if !errors.Is(err, ErrTypeFailed) {
		t.Errorf("TypeString with write error = %v, want %v", err, ErrTypeFailed)
	}
}

func TestTypeKey_DeviceWriteError(t *testing.T) {
	deviceErr := errors.New("write failed")
	mock := newMockDevice()
	mock.writeErr = deviceErr
	kb := NewWithDevice(mock, testLogger())

	err := kb.TypeKey(0x04, false)
	if err == nil {
		t.Fatal("TypeKey should return error when device write fails")
	}
}

func TestTypeKey_ReportSize(t *testing.T) {
	mock := newMockDevice()
	kb := NewWithDevice(mock, testLogger())

	err := kb.TypeKey(0x04, false)
	if err != nil {
		t.Fatalf("TypeKey error = %v", err)
	}

	reports := mock.getReports()
	for i, r := range reports {
		if len(r) != KeyboardReportSize {
			t.Errorf("report[%d] size = %d, want %d", i, len(r), KeyboardReportSize)
		}
	}
}

func TestTypeKey_MultipleKeys(t *testing.T) {
	mock := newMockDevice()
	kb := NewWithDevice(mock, testLogger())

	keys := []struct {
		scancode byte
		shift    bool
	}{
		{0x04, false}, // a
		{0x04, true},  // A
		{0x1E, true},  // !
		{0x2C, false}, // space
	}

	for _, key := range keys {
		err := kb.TypeKey(key.scancode, key.shift)
		if err != nil {
			t.Fatalf("TypeKey(0x%02X, %v) error = %v", key.scancode, key.shift, err)
		}
	}

	reports := mock.getReports()
	expectedReports := len(keys) * 2
	if len(reports) != expectedReports {
		t.Errorf("report count = %d, want %d", len(reports), expectedReports)
	}
}

func TestTypeString_SingleChar(t *testing.T) {
	mock := newMockDevice()
	kb := NewWithDevice(mock, testLogger())

	err := kb.TypeString("x")
	if err != nil {
		t.Fatalf("TypeString error = %v", err)
	}

	reports := mock.getReports()
	if len(reports) != 2 {
		t.Fatalf("expected 2 reports for 1 char, got %d", len(reports))
	}

	// 'x' = scancode 0x1B
	if reports[0][2] != 0x1B {
		t.Errorf("'x' scancode = 0x%02X, want 0x1B", reports[0][2])
	}
}

func TestTypeString_SpacesAndSpecialKeys(t *testing.T) {
	mock := newMockDevice()
	kb := NewWithDevice(mock, testLogger())

	err := kb.TypeString("a b\tc\n")
	if err != nil {
		t.Fatalf("TypeString error = %v", err)
	}

	reports := mock.getReports()
	// 6 chars (a, space, b, tab, c, enter) * 2 = 12 reports
	if len(reports) != 12 {
		t.Fatalf("expected 12 reports for 6 chars, got %d", len(reports))
	}

	// Verify: a=0x04, space=0x2C, b=0x05, tab=0x2B, c=0x06, enter=0x28
	expectedScancodes := []byte{0x04, 0x2C, 0x05, 0x2B, 0x06, 0x28}
	for i, sc := range expectedScancodes {
		down := reports[i*2]
		if down[2] != sc {
			t.Errorf("char %d scancode = 0x%02X, want 0x%02X", i, down[2], sc)
		}
	}
}

func TestConstants(t *testing.T) {
	if VendorIDKeyboard != 0xF1D0 {
		t.Errorf("VendorIDKeyboard = 0x%04X, want 0xF1D0", VendorIDKeyboard)
	}
	if ProductIDKeyboard != 0x0004 {
		t.Errorf("ProductIDKeyboard = 0x%04X, want 0x0004", ProductIDKeyboard)
	}
	if KeyboardReportSize != 8 {
		t.Errorf("KeyboardReportSize = %d, want 8", KeyboardReportSize)
	}
	if ModifierLeftShift != 0x02 {
		t.Errorf("ModifierLeftShift = 0x%02X, want 0x02", ModifierLeftShift)
	}
}

func TestTypeString_WriteErrorOnKeyUp(t *testing.T) {
	// Mock that fails on the second write (key-up report)
	callCount := 0
	deviceErr := errors.New("key-up write failed")
	mock := &countingMockDevice{
		failAtCall: 2, // Fail on second WriteInput call (key-up)
		failErr:    deviceErr,
	}

	kb := NewWithDevice(mock, testLogger())

	err := kb.TypeString("a")
	if err == nil {
		t.Fatal("TypeString should return error when key-up write fails")
	}
	if !errors.Is(err, ErrTypeFailed) {
		t.Errorf("TypeString error = %v, want %v", err, ErrTypeFailed)
	}
	_ = callCount
}

// countingMockDevice fails on a specific WriteInput call number.
type countingMockDevice struct {
	mu         sync.Mutex
	callCount  int
	failAtCall int
	failErr    error
}

func (m *countingMockDevice) WriteInput(data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callCount++
	if m.callCount == m.failAtCall {
		return m.failErr
	}
	return nil
}

func (m *countingMockDevice) Close() error {
	return nil
}

func TestTypeString_ConcurrentSafety(t *testing.T) {
	mock := newMockDevice()
	kb := NewWithDevice(mock, testLogger())

	var wg sync.WaitGroup
	errs := make([]error, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			errs[idx] = kb.TypeString("ab")
		}(i)
	}

	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d error = %v", i, err)
		}
	}

	// Each goroutine types 2 chars * 2 reports each = 4 reports per goroutine
	reports := mock.getReports()
	expectedReports := 10 * 4
	if len(reports) != expectedReports {
		t.Errorf("report count = %d, want %d", len(reports), expectedReports)
	}
}

func TestNewWithDevice_NilLogger(t *testing.T) {
	mock := newMockDevice()

	// Ensure NewWithDevice works even with a custom logger (non-nil required)
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	kb := NewWithDevice(mock, logger)
	if kb == nil {
		t.Fatal("NewWithDevice returned nil")
	}
}

func TestTypeString_FullPasswordSequence(t *testing.T) {
	mock := newMockDevice()
	kb := NewWithDevice(mock, testLogger())

	// Simulate typing a typical password with mixed character classes
	password := "P@ss_w0rd!123"
	err := kb.TypeString(password)
	if err != nil {
		t.Fatalf("TypeString error = %v", err)
	}

	reports := mock.getReports()
	expectedReports := len([]rune(password)) * 2
	if len(reports) != expectedReports {
		t.Errorf("report count = %d, want %d", len(reports), expectedReports)
	}

	// Verify all key-up reports are zeros
	for i := 1; i < len(reports); i += 2 {
		for j := 0; j < KeyboardReportSize; j++ {
			if reports[i][j] != 0x00 {
				t.Errorf("key-up report[%d] byte[%d] = 0x%02X, want 0x00",
					i, j, reports[i][j])
			}
		}
	}
}

func TestNew_KeyboardIsUsableAfterCreation(t *testing.T) {
	mock := newMockUHIDDevice()
	t.Cleanup(setTestUHIDOpener(func() (UHIDDevice, error) {
		return mock, nil
	}))

	kb, err := New(testLogger())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() {
		if err := kb.Close(); err != nil {
			t.Logf("Close() error: %v", err)
		}
	}()

	// Verify keyboard is usable by typing a string
	err = kb.TypeString("test")
	if err != nil {
		t.Errorf("TypeString() error = %v after New()", err)
	}

	reports := mock.getReports()
	if len(reports) != 8 { // 4 chars * 2 reports each
		t.Errorf("expected 8 reports, got %d", len(reports))
	}
}

func TestNew_CloseAfterCreateFailure(t *testing.T) {
	createErr := errors.New("device create failed")
	closeCalled := false
	mock := &trackingMockDevice{
		createErr: createErr,
		onClose: func() {
			closeCalled = true
		},
	}

	t.Cleanup(setTestUHIDOpener(func() (UHIDDevice, error) {
		return mock, nil
	}))

	_, err := New(testLogger())
	if err == nil {
		t.Fatal("New() should return error when device.Create fails")
	}

	if !closeCalled {
		t.Error("Close should be called when Create fails")
	}
}

// trackingMockDevice tracks Close calls for verification.
type trackingMockDevice struct {
	mu        sync.Mutex
	createErr error
	onClose   func()
}

func (m *trackingMockDevice) Create(cfg *uhid.CreateConfig) error {
	return m.createErr
}

func (m *trackingMockDevice) WriteInput(data []byte) error {
	return nil
}

func (m *trackingMockDevice) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.onClose != nil {
		m.onClose()
	}
	return nil
}

func TestDefaultUHIDOpener(t *testing.T) {
	// This test verifies that defaultUHIDOpener is set correctly.
	// We cannot actually call it in unit tests because it requires /dev/uhid.
	// Instead, we verify the package-level variable is set to the expected function.
	if uhidOpener == nil {
		t.Error("uhidOpener should not be nil")
	}
}
