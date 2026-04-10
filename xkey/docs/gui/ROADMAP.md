# xKey Desktop GUI - Development Roadmap

A phased development checklist for building the xKey Desktop GUI using Wails.

## Quick Reference

| Phase | Description | Status |
|-------|-------------|--------|
| [Phase 0](#phase-0-project-setup) | Project Setup | Complete |
| [Phase 1](#phase-1-core-framework) | Core Framework | Complete |
| [Phase 2](#phase-2-system-tray) | System Tray | Complete |
| [Phase 3](#phase-3-phone-backend) | Phone Backend | Complete |
| [Phase 4](#phase-4-fido2webauthn) | FIDO2/WebAuthn | Complete |
| [Phase 5](#phase-5-oath-totphotp) | OATH TOTP/HOTP | Complete |
| [Phase 6](#phase-6-piv-certificates) | PIV Certificates | Complete |
| [Phase 7](#phase-7-tpm-management) | TPM Management | Complete |
| [Phase 8](#phase-8-admin-features) | Admin Features | Complete |
| [Phase 9](#phase-9-polish--testing) | Polish & Testing | Complete |

---

## Phase 0: Project Setup

### 0.1 Development Environment
- [x] Install Wails CLI (`go install github.com/wailsapp/wails/v2/cmd/wails@latest`)
- [x] Install Node.js 18+ and npm
- [x] Verify CGO is enabled (required for systray)
- [x] Install platform-specific dependencies:
  - [x] Linux: `libgtk-3-dev libwebkit2gtk-4.0-dev`
  - [ ] macOS: Xcode command line tools -- _not yet verified_
  - [ ] Windows: WebView2 runtime -- _not yet verified_

### 0.2 Project Initialization
- [x] Initialize Wails project: `wails init -n xkey-gui -t svelte-ts`
- [x] Move generated files to `xkey/` directory
- [x] Configure `wails.json` for xkey project structure
- [x] Set up proper Go module path

### 0.3 Build System Integration
- [x] Add Makefile targets:
  - [x] `make build-gui` - Production build
  - [x] `make dev-gui` - Development mode
  - [x] `make build-gui-all` - Cross-platform builds
- [ ] Configure GitHub Actions for GUI builds -- _not yet implemented_
- [ ] Set up code signing (macOS/Windows) -- _not yet implemented_

### 0.4 Frontend Setup
- [x] Install dependencies: `npm install`
- [x] Configure TailwindCSS with xKey design system
- [x] Set up CSS variables matching Android colors
- [x] Configure TypeScript
- [ ] Set up ESLint and Prettier -- _not yet configured_
- [x] Create base layout component

---

## Phase 1: Core Framework

### 1.1 Entry Point & Mode Detection
- [x] Modify `cmd/xkey/main.go` (CLI-only entry) and `xkey/main.go` (GUI entry):
  - [x] Add `--no-gui` flag for force CLI mode
  - [x] Implement `hasGUIEnvironment()` detection
  - [x] Conditional launch (CLI vs GUI)
- [x] Create `pkg/gui/app.go`:
  - [x] Wails application setup with full lifecycle hooks
  - [x] Window configuration
  - [x] Menu setup

### 1.2 Configuration Integration
- [x] Create `pkg/gui/config.go`:
  - [x] `GUIConfig` struct
  - [x] `LoadGUIConfig()` function
  - [x] `SaveGUIConfig()` function
  - [x] `DefaultGUIConfig()` function
  - [x] `Validate()` method
- [x] Add GUI config defaults
- [x] Environment variable support
- [x] Command-line flag overrides

### 1.3 Backend Services Structure
- [x] Create `pkg/gui/services/` directory
- [x] Implement base service structure
- [x] Create `app_service.go`:
  - [x] `GetStatus()` method
  - [x] `GetConfig()` method
  - [x] `UpdateConfig()` method
  - [x] `GetTheme()` / `SetTheme()` methods
  - [x] `Quit()` method
- [x] Set up Wails bindings

### 1.4 Event System
- [x] Create `pkg/gui/events/events.go`:
  - [x] Define `EventType` constants (14 event types)
  - [x] Create typed event payloads
  - [x] Implement event emission helper
- [x] Set up frontend event listeners
- [x] Create Svelte stores for reactive state (app, theme, phone, keys, oath, fido2, events, notifications)

### 1.5 Frontend Core
- [x] Create design system CSS (`src/lib/styles/design-system.css`)
- [x] Create base components:
  - [x] `Card.svelte`
  - [x] `Button.svelte`
  - [x] `Input.svelte`
  - [x] `StatusBadge.svelte`
  - [x] `Modal.svelte`
  - [x] `Toast.svelte`
  - [x] `Icon.svelte`
  - [x] `GradientHeader.svelte`
  - [x] `SearchBar.svelte`
  - [x] `EmptyState.svelte`
  - [x] `LoadingSpinner.svelte`
  - [x] `Toggle.svelte`
  - [x] `Sidebar.svelte`
  - [x] `Tabs.svelte`
  - [x] `ProgressRing.svelte`
  - [x] `DeviceCard.svelte`
- [x] Set up routing (SPA store-based navigation in `App.svelte`)
- [x] Create layout template with sidebar

---

## Phase 2: System Tray

### 2.1 Tray Setup
- [x] Add `fyne.io/systray` dependency (v1.12.0)
- [x] Create `pkg/gui/systray.go`:
  - [x] `TrayManager` struct
  - [x] Icon loading (embedded assets)
  - [x] Tooltip management
- [ ] Create tray icon assets (multiple sizes) -- _using placeholder 1x1 PNG; real icons not yet designed_

### 2.2 Tray Menu
- [x] Implement menu structure:
  - [x] Status item (disabled, info only)
  - [x] Phone submenu
  - [x] Keys item
  - [x] FIDO2 submenu
  - [x] OATH submenu
  - [x] PIV item
  - [x] TPM item
  - [x] Separator
  - [x] Settings item
  - [x] Audit Log item
  - [x] Admin item (conditional)
  - [x] Separator
  - [x] Help submenu
  - [x] Quit item

### 2.3 Tray Actions
- [x] Click handlers for each menu item
- [x] Window show/hide on tray click
- [x] Double-click to open dashboard
- [x] Context menu (right-click)

### 2.4 Tray State Updates
- [x] Icon state changes (connected, warning, error)
- [ ] Dynamic menu updates (live TOTP codes in tray) -- _not yet implemented_
- [x] Tooltip updates
- [x] Badge/overlay indicators
- [x] Dynamic phone/key count updates

---

## Phase 3: Phone Backend

### 3.1 Phone Service
- [x] Create `pkg/gui/services/phone_service.go`:
  - [x] `ListDevices()` - list paired devices
  - [x] `GetDeviceStatus()` - connection status
  - [x] `Scan()` - scan for new devices
  - [x] `Pair()` - initiate pairing
  - [x] `Unpair()` - remove pairing
  - [x] `Connect()` - connect to device
  - [x] `Disconnect()` - disconnect
  - [x] `AttestDevice()` - run attestation

### 3.2 Phone Views
- [x] Create `src/views/Devices.svelte`:
  - [x] Device list
  - [x] Add device button
  - [x] Device cards with status
- [x] Create `src/views/DeviceDetail.svelte`:
  - [x] Connection info
  - [x] Security info
  - [x] Attestation status
  - [x] Keys on device
  - [x] Pairing info
  - [x] Actions (disconnect, attest, unpair)

### 3.3 Pairing Flow
- [x] Create `src/components/PairingDialog.svelte`:
  - [x] Scan progress indicator
  - [x] Discovered devices list
  - [x] Fingerprint comparison display
  - [x] Approval buttons
  - [x] Success/error states
  - [x] Multi-step wizard flow

### 3.4 Phone Events
- [x] `phone:connected` event handling
- [x] `phone:disconnected` event handling
- [x] `phone:scan_result` event handling
- [x] `phone:pairing_request` event handling
- [x] Real-time status updates in UI

---

## Phase 4: FIDO2/WebAuthn

### 4.1 FIDO2 Service
- [x] Create `pkg/gui/services/fido2_service.go`:
  - [x] `ListCredentials()` - list all credentials
  - [x] `GetCredential()` - credential details
  - [x] `DeleteCredential()` - remove credential
  - [x] `GetRelyingParties()` - list RPs
  - [x] `StartPhoneBridge()` - start bridge
  - [x] `StopPhoneBridge()` - stop bridge
  - [x] `GetBridgeStatus()` - bridge status

### 4.2 FIDO2 Views
- [x] Create `src/views/FIDO2.svelte`:
  - [x] Tab navigation (Credentials, Bridge, RPs)
  - [x] Credential list with filters
  - [x] Search functionality
- [x] Create `src/views/FIDO2Credential.svelte`:
  - [x] Credential details
  - [x] Usage history
  - [x] Delete action
- [x] Create `src/components/BridgeStatus.svelte`:
  - [x] Bridge on/off toggle
  - [x] Connection status
  - [x] Recent authentications

### 4.3 Bridge Integration
- [x] Bridge start/stop from UI
- [x] Real-time bridge status updates
- [x] Authentication request notifications
- [x] Bridge activity in audit log

---

## Phase 5: OATH TOTP/HOTP

### 5.1 OATH Service
- [x] Create `pkg/gui/services/oath_service.go`:
  - [x] `ListAccounts()` - list all accounts
  - [x] `AddAccount()` - add from URI
  - [x] `DeleteAccount()` - remove account
  - [x] `GenerateTOTP()` - generate code
  - [x] `GenerateHOTP()` - generate and increment
  - [x] `ImportFromQR()` - QR code import

### 5.2 OATH Views
- [x] Create `src/views/OATH.svelte`:
  - [x] Account list with live codes
  - [x] Progress bars for TOTP countdown
  - [x] Copy button for each code
  - [x] Add account button
- [x] Create `src/components/TOTPCard.svelte`:
  - [x] Large code display
  - [x] Countdown progress
  - [x] Copy action
  - [x] Refresh action
- [x] Create `src/components/AddAccountDialog.svelte`:
  - [x] Tab: Scan QR
  - [x] Tab: Enter manually
  - [x] Tab: Import URI

### 5.3 QR Scanning
- [ ] Webcam capture for QR scanning -- _not yet implemented_
- [x] Image file import for QR
- [x] Clipboard paste for URI
- [x] Validation and error handling

### 5.4 Tray TOTP Menu
- [ ] Live TOTP codes in tray menu -- _not yet implemented_
- [ ] Click to copy from tray -- _not yet implemented_
- [ ] Auto-refresh every 30 seconds in tray -- _not yet implemented_

---

## Phase 6: PIV Certificates

### 6.1 PIV Service
- [x] Create `pkg/gui/services/piv_service.go`:
  - [x] `GetSlots()` - list slot status
  - [x] `GetCertificate()` - cert details
  - [x] `GenerateKey()` - generate in slot
  - [x] `ImportCertificate()` - import cert
  - [x] `ExportCertificate()` - export cert
  - [x] `GenerateCSR()` - create CSR
  - [x] `DeleteCertificate()` - remove cert

### 6.2 PIV Views
- [x] Create `src/views/PIV.svelte`:
  - [x] Slot overview cards
  - [x] Slot status indicators
  - [x] Quick actions per slot
- [x] Create `src/views/PIVSlot.svelte`:
  - [x] Certificate details
  - [x] Key info
  - [x] Actions (export, CSR, delete)
- [x] Create `src/components/CSRDialog.svelte`:
  - [x] Subject fields form
  - [x] Algorithm selection
  - [x] Generate and display CSR

---

## Phase 7: TPM Management

### 7.1 TPM Service
- [x] Create `pkg/gui/services/tpm_service.go`:
  - [x] `GetStatus()` - TPM availability
  - [x] `GetInfo()` - hardware info
  - [x] `ListKeys()` - TPM keys
  - [x] `GetPCRs()` - PCR values
  - [x] `GetEKInfo()` - EK details
  - [x] `GetIAKInfo()` - IAK details
  - [x] `GetIDevIDInfo()` - IDevID details
  - [x] `Provision()` - provision keys
  - [x] `GenerateQuote()` - attestation quote

### 7.2 TPM Views
- [x] Create `src/views/TPM.svelte`:
  - [x] Hardware status card
  - [x] Identity keys status
  - [x] PCR banks overview
  - [x] Quick actions
- [x] Create `src/views/TPMInfo.svelte`:
  - [x] Detailed hardware info
  - [x] Capabilities
  - [x] Firmware version
- [x] Create `src/components/PCRViewer.svelte`:
  - [x] Bank selector
  - [x] PCR value table
  - [x] Export options
- [x] Create `src/components/QuoteDialog.svelte`:
  - [x] PCR selection
  - [x] Nonce input
  - [x] Quote display

---

## Phase 8: Admin Features

### 8.1 Admin Service
- [x] Create `pkg/gui/services/admin_service.go`:
  - [x] `IsAdmin()` - check admin status
  - [x] `GetServerStatus()` - server info
  - [x] `ListBackends()` - backend status
  - [x] `GetBackendInfo()` - backend details
  - [x] `GetAuditLogs()` - server audit logs
  - [x] `ExportAuditLogs()` - export logs
- [x] Create `pkg/gui/services/audit_service.go`:
  - [x] `GetEntries()` - get audit entries
  - [x] `ExportEntries()` - export JSON/CSV

### 8.2 Admin Views
- [x] Create `src/views/Admin.svelte`:
  - [x] Server status overview
  - [x] Backend status cards
  - [x] Quick actions
- [x] Create `src/views/AdminBackends.svelte`:
  - [x] Backend list
  - [x] Backend details
  - [x] Key counts
- [x] Conditional display (admin only)

### 8.3 Audit Log Views
- [x] Create `src/views/AuditLog.svelte`:
  - [x] Log entry list
  - [x] Filters (type, device, date)
  - [x] Search
  - [x] Pagination
  - [x] Export buttons
- [x] Create `src/components/AuditEntry.svelte`:
  - [x] Entry card
  - [x] Expandable details
  - [x] Status indicators

---

## Phase 9: Polish & Testing

### 9.1 Dashboard
- [x] Create `src/views/Dashboard.svelte`:
  - [x] Status overview cards
  - [x] Connected device card
  - [x] Recent activity feed
  - [x] Quick action buttons
- [x] Real-time updates via events
- [x] Welcome state (no devices paired)

### 9.2 Settings
- [x] Create `src/views/Settings.svelte`:
  - [x] Settings category navigation (6 categories)
  - [x] General settings section
  - [x] Appearance settings (theme selector)
  - [x] Phone settings
  - [x] Security settings
  - [x] Advanced settings
- [x] Settings persistence
- [x] Restart prompts when needed

### 9.3 Accessibility
- [x] Keyboard navigation
- [x] Focus indicators
- [x] Screen reader labels (ARIA)
- [ ] High contrast mode support -- _not yet implemented_
- [ ] Reduced motion support -- _not yet implemented_

### 9.4 Error Handling
- [ ] Global error boundary -- _not yet implemented_
- [x] Error dialog component
- [x] Toast notifications
- [x] Error recovery actions
- [x] Error event handling and logging

### 9.5 Testing
- [x] Unit tests for Go services (97 tests passing)
- [x] Integration tests for Wails bindings
- [ ] E2E tests with Playwright -- _not yet implemented_
- [ ] Visual regression tests -- _not yet implemented_
- [ ] Cross-platform testing -- _not yet verified_

### 9.6 Documentation
- [x] Update user documentation
- [x] API documentation for bindings
- [x] Developer setup guide
- [x] Troubleshooting guide

### 9.7 Release Preparation
- [ ] Version bumping -- _not yet started_
- [ ] Changelog updates -- _not yet started_
- [ ] Release notes -- _not yet started_
- [ ] Platform-specific installers -- _not yet started_
- [ ] Code signing verification -- _not yet started_

---

## Milestone Targets

### MVP (Phases 0-3) -- Complete
- Working Wails app with systray
- Phone backend integration
- Basic dashboard
- All core components and services implemented

### Beta (Phases 4-6) -- Complete
- FIDO2 credential management
- OATH TOTP codes with live countdown
- PIV certificate management with CSR generation

### 1.0 Release (Phases 7-9) -- In Progress
- Full TPM support: complete
- Admin features and audit logging: complete
- Polish and testing: substantially complete (see remaining items below)

### Remaining Items
- Tray icon assets (real icons, not placeholder)
- Live TOTP codes in system tray menu
- Webcam QR code scanning
- High contrast and reduced motion accessibility modes
- Global error boundary
- Playwright E2E tests and visual regression tests
- Cross-platform verification (macOS, Windows)
- ESLint/Prettier configuration
- GitHub Actions for GUI builds
- Code signing and release preparation

---

## Dependencies

### Go Dependencies
```go
require (
    github.com/wailsapp/wails/v2 v2.11.0
    fyne.io/systray v1.12.0
)
```

### Frontend Dependencies
```json
{
  "dependencies": {
    "@mdi/js": "^7.4.47"
  },
  "devDependencies": {
    "@sveltejs/vite-plugin-svelte": "^3.1.1",
    "@tsconfig/svelte": "^5.0.4",
    "autoprefixer": "^10.4.19",
    "postcss": "^8.4.38",
    "svelte": "^4.2.18",
    "svelte-check": "^3.8.4",
    "tailwindcss": "^3.4.4",
    "tslib": "^2.6.3",
    "typescript": "^5.5.3",
    "vite": "^5.3.4"
  }
}
```

---

## Notes

- Update this checklist as remaining tasks are completed
- Mark completed items with `[x]`
- Add new items as requirements evolve
- Reference this file in commit messages
- Review weekly during development

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025-02-06 | Initial roadmap creation |
| 2.0 | 2026-02-06 | All phases 0-9 implemented. Updated status to reflect complete implementation: 25 Go service files, 39 Svelte components/views, 8 Svelte stores, 97 Go unit tests passing. Remaining items tracked under Phase 9 and Remaining Items section. Updated dependency versions to actuals. |
