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

// shared_test_helpers_test.go contains test helpers that were previously
// defined in test files that have been broken by the SealService SDK
// migration (sealMockTPM -> sealMockClient). These helpers are needed
// by still-working test files.

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/pin"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/events"
)

// Default PIN values for tests that need to pass mandatory validation.
const (
	testSOPin   = "123456"
	testUserPin = "654321"
)

// wizardMockPINBackend implements pin.PINBackend for setup wizard tests.
type wizardMockPINBackend struct {
	strategy    pin.StrategyID
	soPINSet    bool
	userPINSet  bool
	initialized bool
	soPIN       string
	userPIN     string

	setSOPINErr   error
	setUserPINErr error
	verifySOErr   error
	verifyUserErr error

	lockoutStatus *pin.LockoutStatus
}

func (m *wizardMockPINBackend) Strategy() pin.StrategyID             { return m.strategy }
func (m *wizardMockPINBackend) SOPINSet() bool                       { return m.soPINSet }
func (m *wizardMockPINBackend) UserPINSet() bool                     { return m.userPINSet }
func (m *wizardMockPINBackend) IsInitialized() bool                  { return m.initialized }
func (m *wizardMockPINBackend) GetLockoutStatus() *pin.LockoutStatus { return m.lockoutStatus }

func (m *wizardMockPINBackend) SetSOPIN(_, newSOPIN string) error {
	if m.setSOPINErr != nil {
		return m.setSOPINErr
	}
	m.soPIN = newSOPIN
	m.soPINSet = true
	m.initialized = true
	return nil
}

func (m *wizardMockPINBackend) SetUserPIN(_, newUserPIN string) error {
	if m.setUserPINErr != nil {
		return m.setUserPINErr
	}
	m.userPIN = newUserPIN
	m.userPINSet = true
	return nil
}

func (m *wizardMockPINBackend) ChangeSOPIN(_, _ string) error   { return nil }
func (m *wizardMockPINBackend) ChangeUserPIN(_, _ string) error { return nil }

func (m *wizardMockPINBackend) VerifySOPIN(p string) error {
	if m.verifySOErr != nil {
		return m.verifySOErr
	}
	if m.soPIN != "" && p != m.soPIN {
		return errors.New("SO PIN mismatch")
	}
	return nil
}

func (m *wizardMockPINBackend) VerifyUserPIN(_ string) error { return m.verifyUserErr }
func (m *wizardMockPINBackend) ResetLockout(_ string) error  { return nil }

// newWizardPINService creates a PINService backed by the given PINBackend.
func newWizardPINService(backend pin.PINBackend) *PINService {
	svc := NewPINService()
	svc.SetContext(context.Background())
	if backend != nil {
		pinSvc := pin.NewService(backend, slog.Default())
		svc.SetPINService(pinSvc)
	}
	return svc
}

// lastEventOfType returns the most recent event matching the given type,
// or nil if no matching event is found.
func lastEventOfType(log *[]*events.Event, eventType events.EventType) *events.Event {
	if log == nil {
		return nil
	}
	for i := len(*log) - 1; i >= 0; i-- {
		if (*log)[i].Type == eventType {
			return (*log)[i]
		}
	}
	return nil
}

// containsSubstring returns true if any string in the slice contains substr.
func containsSubstring(items []string, substr string) bool {
	for _, item := range items {
		if strings.Contains(item, substr) {
			return true
		}
	}
	return false
}

// testConfigData returns a GUIConfigData suitable for auto-unseal tests.
func testConfigData() *GUIConfigData {
	return &GUIConfigData{
		Theme:        "system",
		WindowWidth:  1024,
		WindowHeight: 768,
	}
}

// testConfigDataWithAutoUnseal returns a GUIConfigData with auto-unseal configured.
func testConfigDataWithAutoUnseal(blobID string) *GUIConfigData {
	cfg := testConfigData()
	cfg.AutoUnsealEnabled = true
	cfg.AutoUnsealBlobID = blobID
	cfg.AutoUnsealPCRs = []int{0, 7}
	cfg.AutoUnsealPCRBank = "sha256"
	return cfg
}

// newTestConfigPair creates a config getter and saver backed by the given initial config.
func newTestConfigPair(initial *GUIConfigData) (func() *GUIConfigData, func(*GUIConfigData) error) {
	cfg := initial
	return func() *GUIConfigData { return cfg },
		func(data *GUIConfigData) error { cfg = data; return nil }
}

// testSetupWizard bundles a SetupWizardService with accessor helpers.
type testSetupWizard struct {
	svc        *SetupWizardService
	configFunc func() *GUIConfigData
	eventLog   *[]*events.Event
}

// newTestSetupWizard creates a SetupWizardService wired with in-memory config
// helpers. Use tw.configFunc() to read persisted config state.
func newTestSetupWizard(cfg *GUIConfigData) *testSetupWizard {
	svc := NewSetupWizardService()
	svc.SetContext(context.Background())

	configFunc, configSave := newTestConfigPair(cfg)
	svc.SetConfigFunc(configFunc)
	svc.SetConfigSaveFunc(configSave)

	var eventLog []*events.Event
	svc.SetEventEmitter(func(e events.Event) {
		eventLog = append(eventLog, &e)
	})

	return &testSetupWizard{
		svc:        svc,
		configFunc: configFunc,
		eventLog:   &eventLog,
	}
}
