# xKey Desktop GUI - Architecture

## Overview

The xKey Desktop GUI is built using Wails v2, combining a Go backend with a Svelte frontend. This architecture provides native performance, cross-platform compatibility, and a premium user experience matching the Android app.

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Operating System                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────┐    ┌──────────────────────────────────────────────────┐   │
│  │   Systray   │    │              Wails Application                    │   │
│  │  (Optional) │    │  ┌────────────────────────────────────────────┐  │   │
│  │             │    │  │            Frontend (WebView)               │  │   │
│  │  ┌───────┐  │    │  │  ┌──────────────────────────────────────┐  │  │   │
│  │  │ Icon  │  │    │  │  │         Svelte Application           │  │  │   │
│  │  └───────┘  │    │  │  │  ┌────────┐ ┌────────┐ ┌────────┐   │  │  │   │
│  │  ┌───────┐  │    │  │  │  │ Stores │ │  Views │ │ Comps  │   │  │  │   │
│  │  │ Menu  │──┼────┼──┼──│  └────────┘ └────────┘ └────────┘   │  │  │   │
│  │  └───────┘  │    │  │  └──────────────────────────────────────┘  │  │   │
│  └─────────────┘    │  └────────────────────────────────────────────┘  │   │
│                     │                      │ Wails Bindings            │   │
│                     │                      ▼                           │   │
│                     │  ┌────────────────────────────────────────────┐  │   │
│                     │  │              Go Backend                     │  │   │
│                     │  │  ┌──────────┐ ┌──────────┐ ┌──────────┐   │  │   │
│                     │  │  │   App    │ │  Phone   │ │  Crypto  │   │  │   │
│                     │  │  │ Service  │ │ Backend  │ │ Backend  │   │  │   │
│                     │  │  └──────────┘ └──────────┘ └──────────┘   │  │   │
│                     │  │  ┌──────────┐ ┌──────────┐ ┌──────────┐   │  │   │
│                     │  │  │  FIDO2   │ │   OATH   │ │   PIV    │   │  │   │
│                     │  │  │ Service  │ │ Service  │ │ Service  │   │  │   │
│                     │  │  └──────────┘ └──────────┘ └──────────┘   │  │   │
│                     │  │  ┌──────────┐ ┌──────────┐ ┌──────────┐   │  │   │
│                     │  │  │   TPM    │ │  Audit   │ │  Admin   │   │  │   │
│                     │  │  │ Service  │ │ Service  │ │ Service  │   │  │   │
│                     │  │  └──────────┘ └──────────┘ └──────────┘   │  │   │
│                     │  └────────────────────────────────────────────┘  │   │
│                     └──────────────────────────────────────────────────┘   │
│                                          │                                  │
│                     ┌────────────────────┴───────────────────┐             │
│                     ▼                    ▼                   ▼              │
│              ┌───────────┐        ┌───────────┐       ┌───────────┐        │
│              │   Phone   │        │  Hardware │       │ xkmsd │        │
│              │   (BLE)   │        │   (TPM)   │       │  Server   │        │
│              └───────────┘        └───────────┘       └───────────┘        │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Directory Structure

```
xkey/
├── cmd/
│   └── xkey/
│       ├── main.go              # Entry point with GUI detection
│       └── cmd/
│           └── root.go          # Cobra root command (existing)
├── pkg/
│   └── gui/
│       ├── app.go               # Wails application setup
│       ├── systray.go           # System tray management
│       ├── services/
│       │   ├── app_service.go   # Application state & lifecycle
│       │   ├── phone_service.go # Phone backend operations
│       │   ├── fido2_service.go # FIDO2/WebAuthn operations
│       │   ├── oath_service.go  # TOTP/HOTP operations
│       │   ├── piv_service.go   # PIV certificate operations
│       │   ├── tpm_service.go   # TPM2 operations
│       │   ├── audit_service.go # Audit log operations
│       │   └── admin_service.go # xkmsd admin operations
│       └── bindings/
│           └── bindings.go      # Wails binding exports
├── frontend/
│   ├── package.json
│   ├── svelte.config.js
│   ├── tailwind.config.js       # Android design system colors
│   ├── src/
│   │   ├── main.ts
│   │   ├── App.svelte
│   │   ├── lib/
│   │   │   ├── stores/          # Svelte stores
│   │   │   │   ├── app.ts       # Application state
│   │   │   │   ├── phone.ts     # Phone connection state
│   │   │   │   ├── keys.ts      # Keys state
│   │   │   │   └── theme.ts     # Theme state
│   │   │   ├── components/      # Reusable components
│   │   │   │   ├── Card.svelte
│   │   │   │   ├── Button.svelte
│   │   │   │   ├── StatusBadge.svelte
│   │   │   │   ├── KeyListItem.svelte
│   │   │   │   ├── DeviceCard.svelte
│   │   │   │   └── ...
│   │   │   └── utils/
│   │   │       ├── theme.ts     # Theme utilities
│   │   │       └── format.ts    # Formatting utilities
│   │   ├── views/
│   │   │   ├── Dashboard.svelte
│   │   │   ├── Keys.svelte
│   │   │   ├── Devices.svelte
│   │   │   ├── FIDO2.svelte
│   │   │   ├── OATH.svelte
│   │   │   ├── PIV.svelte
│   │   │   ├── TPM.svelte
│   │   │   ├── Settings.svelte
│   │   │   ├── AuditLog.svelte
│   │   │   └── Admin.svelte
│   │   └── assets/
│   │       ├── icons/
│   │       └── images/
│   └── wailsjs/                 # Auto-generated Wails bindings
└── build/
    └── appicon.png              # Application icon
```

## Entry Point Flow

```go
// cmd/xkey/main.go
func main() {
    // Parse early flags for mode detection
    args := os.Args[1:]

    // Check for explicit mode flags
    forceGUI := hasFlag(args, "--tray")
    forceCLI := hasFlag(args, "--no-tray") || hasFlag(args, "--help") || hasFlag(args, "-h")

    // Detect GUI environment
    if !forceCLI && (forceGUI || hasGUIEnvironment()) {
        // Launch Wails application with systray
        gui.Run()
    } else {
        // Execute CLI via cobra
        cmd.Execute()
    }
}

// hasGUIEnvironment detects if a display server is available
func hasGUIEnvironment() bool {
    switch runtime.GOOS {
    case "windows":
        // Windows always has GUI unless running in WSL/container
        return os.Getenv("WT_SESSION") != "" ||
               os.Getenv("TERM_PROGRAM") == "" ||
               !isRunningInContainer()
    case "darwin":
        // macOS: check for display
        return os.Getenv("DISPLAY") != "" ||
               os.Getenv("TERM_PROGRAM") != ""
    case "linux":
        // Linux: check for X11 or Wayland
        return os.Getenv("DISPLAY") != "" ||
               os.Getenv("WAYLAND_DISPLAY") != ""
    default:
        return false
    }
}
```

## Backend Services

Each service wraps existing CLI functionality and exposes it to the frontend via Wails bindings.

### AppService

```go
// pkg/gui/services/app_service.go
type AppService struct {
    ctx     context.Context
    config  *viper.Viper
    audit   *audit.SlogLogger
    runtime wailsruntime.Runtime
}

// Exposed methods (Wails bindings)
func (s *AppService) GetStatus() *AppStatus
func (s *AppService) GetConfig() *GUIConfig
func (s *AppService) UpdateConfig(cfg *GUIConfig) error
func (s *AppService) GetTheme() string
func (s *AppService) SetTheme(theme string) error
func (s *AppService) Quit()
```

### PhoneService

```go
// pkg/gui/services/phone_service.go
type PhoneService struct {
    ctx     context.Context
    backend *phone.PhoneKeyBackend
    audit   *audit.SlogLogger
}

// Exposed methods
func (s *PhoneService) ListDevices() ([]PairedDevice, error)
func (s *PhoneService) GetDeviceStatus(name string) (*DeviceStatus, error)
func (s *PhoneService) Scan(timeout time.Duration) ([]DiscoveredDevice, error)
func (s *PhoneService) Pair(address string) (*PairedDevice, error)
func (s *PhoneService) Unpair(name string) error
func (s *PhoneService) Connect(name string) error
func (s *PhoneService) Disconnect(name string) error
func (s *PhoneService) AttestDevice(name string) (*AttestationResult, error)
```

### FIDO2Service

```go
// pkg/gui/services/fido2_service.go
type FIDO2Service struct {
    ctx   context.Context
    audit *audit.SlogLogger
}

// Exposed methods
func (s *FIDO2Service) ListCredentials() ([]FIDO2Credential, error)
func (s *FIDO2Service) GetCredential(id string) (*FIDO2Credential, error)
func (s *FIDO2Service) DeleteCredential(id string) error
func (s *FIDO2Service) GetRelyingParties() ([]RelyingParty, error)
func (s *FIDO2Service) StartPhoneBridge() error
func (s *FIDO2Service) StopPhoneBridge() error
func (s *FIDO2Service) GetBridgeStatus() *BridgeStatus
```

### OATHService

```go
// pkg/gui/services/oath_service.go
type OATHService struct {
    ctx   context.Context
    store *oath.Store
    audit *audit.SlogLogger
}

// Exposed methods
func (s *OATHService) ListAccounts() ([]OATHAccount, error)
func (s *OATHService) AddAccount(uri string) (*OATHAccount, error)
func (s *OATHService) DeleteAccount(id string) error
func (s *OATHService) GenerateTOTP(id string) (*TOTPCode, error)
func (s *OATHService) GenerateHOTP(id string) (*HOTPCode, error)
func (s *OATHService) ImportFromQR(imageData []byte) (*OATHAccount, error)
```

### TPMService

```go
// pkg/gui/services/tpm_service.go
type TPMService struct {
    ctx   context.Context
    tpm   *tpm2.TPM
    audit *audit.SlogLogger
}

// Exposed methods
func (s *TPMService) GetStatus() (*TPMStatus, error)
func (s *TPMService) GetInfo() (*TPMInfo, error)
func (s *TPMService) ListKeys() ([]TPMKey, error)
func (s *TPMService) GetPCRs() ([]PCRValue, error)
func (s *TPMService) GetEKInfo() (*EKInfo, error)
func (s *TPMService) GetIAKInfo() (*IAKInfo, error)
func (s *TPMService) GetIDevIDInfo() (*IDevIDInfo, error)
func (s *TPMService) Provision(opts *ProvisionOptions) error
func (s *TPMService) GenerateQuote(nonce []byte, pcrs []int) (*Quote, error)
```

### AdminService

```go
// pkg/gui/services/admin_service.go
type AdminService struct {
    ctx    context.Context
    client transport.Client
    audit  *audit.SlogLogger
}

// Exposed methods (requires admin role)
func (s *AdminService) IsAdmin() bool
func (s *AdminService) GetServerStatus() (*ServerStatus, error)
func (s *AdminService) ListBackends() ([]BackendInfo, error)
func (s *AdminService) GetBackendInfo(id string) (*BackendInfo, error)
func (s *AdminService) ListUsers() ([]User, error)
func (s *AdminService) CreateUser(user *CreateUserRequest) error
func (s *AdminService) DeleteUser(id string) error
func (s *AdminService) GetAuditLogs(filter *AuditFilter) ([]AuditEntry, error)
func (s *AdminService) ExportAuditLogs(format string) ([]byte, error)
```

## Systray Integration

```go
// pkg/gui/systray.go
package gui

import (
    "fyne.io/systray"
)

type TrayManager struct {
    app        *App
    mStatus    *systray.MenuItem
    mPhone     *systray.MenuItem
    mKeys      *systray.MenuItem
    mFIDO2     *systray.MenuItem
    mOATH      *systray.MenuItem
    mPIV       *systray.MenuItem
    mTPM       *systray.MenuItem
    mSettings  *systray.MenuItem
    mAuditLog  *systray.MenuItem
    mAdmin     *systray.MenuItem
    mQuit      *systray.MenuItem
}

func (t *TrayManager) Setup() {
    systray.SetIcon(icon.Data)
    systray.SetTitle("xKey")
    systray.SetTooltip("xKey - Hardware Security Key")

    // Status section
    t.mStatus = systray.AddMenuItem("Status: Ready", "Current status")
    t.mStatus.Disable()

    systray.AddSeparator()

    // Phone section
    t.mPhone = systray.AddMenuItem("📱 Phone: Not Connected", "Phone backend")

    // Keys section
    t.mKeys = systray.AddMenuItem("🔑 Keys (0)", "Manage keys")

    systray.AddSeparator()

    // Protocol sections
    t.mFIDO2 = systray.AddMenuItem("🛡️ FIDO2", "FIDO2/WebAuthn")
    t.mOATH = systray.AddMenuItem("🔢 OATH TOTP", "One-time passwords")
    t.mPIV = systray.AddMenuItem("💳 PIV", "Smart card certificates")
    t.mTPM = systray.AddMenuItem("🔒 TPM", "TPM operations")

    systray.AddSeparator()

    // Settings & Admin
    t.mSettings = systray.AddMenuItem("⚙️ Settings...", "Configure xKey")
    t.mAuditLog = systray.AddMenuItem("📋 Audit Log...", "View audit log")
    t.mAdmin = systray.AddMenuItem("🔧 Server Admin...", "Manage xkmsd")
    t.mAdmin.Hide() // Only show if admin

    systray.AddSeparator()

    t.mQuit = systray.AddMenuItem("❌ Quit", "Exit xKey")
}

func (t *TrayManager) Run() {
    systray.Run(t.Setup, t.onExit)
}
```

## Event System

The GUI uses a reactive event system for real-time updates.

```go
// pkg/gui/events/events.go
type EventType string

const (
    EventPhoneConnected    EventType = "phone:connected"
    EventPhoneDisconnected EventType = "phone:disconnected"
    EventKeyCreated        EventType = "key:created"
    EventKeyDeleted        EventType = "key:deleted"
    EventKeyUsed           EventType = "key:used"
    EventTOTPGenerated     EventType = "oath:totp_generated"
    EventBridgeStarted     EventType = "fido2:bridge_started"
    EventBridgeStopped     EventType = "fido2:bridge_stopped"
    EventAttestationResult EventType = "attestation:result"
    EventSettingsChanged   EventType = "settings:changed"
    EventAuditEntry        EventType = "audit:entry"
)

type Event struct {
    Type    EventType      `json:"type"`
    Payload interface{}    `json:"payload"`
    Time    time.Time      `json:"time"`
}

// Emit events to frontend
func (a *App) EmitEvent(event Event) {
    wailsruntime.EventsEmit(a.ctx, string(event.Type), event)
}
```

## Frontend Event Handling

```typescript
// frontend/src/lib/stores/events.ts
import { EventsOn } from '../../wailsjs/runtime/runtime';

export function setupEventListeners() {
    EventsOn('phone:connected', (event) => {
        phoneStore.update(s => ({ ...s, connected: true, device: event.payload }));
    });

    EventsOn('phone:disconnected', (event) => {
        phoneStore.update(s => ({ ...s, connected: false, device: null }));
    });

    EventsOn('key:used', (event) => {
        addRecentActivity(event);
    });

    // ... more event handlers
}
```

## Configuration Integration

The GUI reads and writes to the same configuration as the CLI.

```go
// pkg/gui/config.go
type GUIConfig struct {
    AutoTray        bool   `mapstructure:"auto_tray"`
    Theme           string `mapstructure:"theme"` // light, dark, system
    StartMinimized  bool   `mapstructure:"start_minimized"`
    Notifications   bool   `mapstructure:"notifications"`
    WindowWidth     int    `mapstructure:"window_width"`
    WindowHeight    int    `mapstructure:"window_height"`
    RememberPosition bool  `mapstructure:"remember_position"`
    WindowX         int    `mapstructure:"window_x"`
    WindowY         int    `mapstructure:"window_y"`
}

func LoadGUIConfig() *GUIConfig {
    cfg := &GUIConfig{
        AutoTray:       true,
        Theme:          "system",
        StartMinimized: false,
        Notifications:  true,
        WindowWidth:    1200,
        WindowHeight:   800,
        RememberPosition: true,
    }

    if err := viper.UnmarshalKey("gui", cfg); err != nil {
        slog.Warn("failed to load GUI config, using defaults", "error", err)
    }

    return cfg
}

func SaveGUIConfig(cfg *GUIConfig) error {
    viper.Set("gui", cfg)
    return viper.WriteConfig()
}
```

## Build System

```makefile
# xkey/Makefile additions

.PHONY: build-gui dev-gui

# Build GUI application
build-gui:
	@echo "Building xKey GUI..."
	cd frontend && npm install && npm run build
	wails build -platform $(GOOS)/$(GOARCH) -o xkey

# Development mode with hot reload
dev-gui:
	wails dev

# Build for all platforms
build-gui-all:
	wails build -platform windows/amd64 -o xkey.exe
	wails build -platform darwin/amd64 -o xkey-darwin-amd64
	wails build -platform darwin/arm64 -o xkey-darwin-arm64
	wails build -platform linux/amd64 -o xkey-linux-amd64
```

## Security Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Security Boundaries                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────────┐      ┌──────────────────┐                │
│  │    Frontend      │      │     Backend      │                │
│  │    (WebView)     │      │      (Go)        │                │
│  │                  │      │                  │                │
│  │  • UI rendering  │      │  • Crypto ops    │                │
│  │  • User input    │◄────►│  • Key access    │                │
│  │  • Display only  │ IPC  │  • TPM access    │                │
│  │                  │      │  • Phone comms   │                │
│  │  NO access to:   │      │                  │                │
│  │  - Private keys  │      │  Protected by:   │                │
│  │  - TPM handles   │      │  - OS process    │                │
│  │  - Raw crypto    │      │  - Memory safety │                │
│  │                  │      │  - Audit logging │                │
│  └──────────────────┘      └──────────────────┘                │
│                                    │                            │
│                                    ▼                            │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                    Hardware Security                       │  │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────────────────────┐  │  │
│  │  │   TPM   │  │  Phone  │  │  xkmsd (optional)   │  │  │
│  │  │ (local) │  │ (BLE)   │  │  (gRPC/Unix socket)     │  │  │
│  │  └─────────┘  └─────────┘  └─────────────────────────┘  │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Performance Considerations

1. **Lazy Loading**: Views are loaded on-demand
2. **Efficient Updates**: Only changed data is sent to frontend
3. **Background Processing**: Heavy operations run in goroutines
4. **Caching**: Frequently accessed data is cached
5. **Debouncing**: Rapid UI events are debounced

## Testing Strategy

1. **Unit Tests**: Go services tested independently
2. **Integration Tests**: Wails bindings tested with mock frontend
3. **E2E Tests**: Playwright tests for full UI flows
4. **Snapshot Tests**: UI component visual regression testing
