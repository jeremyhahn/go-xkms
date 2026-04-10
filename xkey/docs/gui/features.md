# xKey Desktop GUI - Features

Comprehensive feature specifications for the xKey Desktop GUI, designed to match and exceed the capabilities of the YubiKey Authenticator while maintaining visual parity with the xKey Android app.

## Feature Overview

| Category | Features | Priority |
|----------|----------|----------|
| **Core** | System Tray, Dashboard, Settings | P0 |
| **Phone** | Device Pairing, Connection, Attestation | P0 |
| **FIDO2** | Credential Management, Phone Bridge | P0 |
| **OATH** | TOTP/HOTP Accounts, Code Generation | P1 |
| **PIV** | Certificate Management, CSR Generation | P1 |
| **TPM** | Status, Keys, Attestation, Provisioning | P1 |
| **Admin** | Server Management, User Management | P2 |
| **Audit** | Log Viewing, Export, Filtering | P2 |

---

## 1. System Tray

### 1.1 Tray Icon

- **Icon States**:
  - Default: xKey logo (navy)
  - Connected: Green dot overlay
  - Warning: Yellow dot overlay
  - Error: Red dot overlay
  - Processing: Animated indicator

- **Tooltip**: "xKey - [Status]"
  - "xKey - Ready"
  - "xKey - Connected to Pixel 8 Pro"
  - "xKey - Authenticating..."

### 1.2 Tray Menu Structure

```
┌────────────────────────────────────────┐
│ 🔐 Status: Ready                       │ (disabled, info only)
├────────────────────────────────────────┤
│ 📱 Phone: Pixel 8 Pro ✓               │ → submenu
│    ├─ Disconnect                       │
│    ├─ Attest Device                    │
│    └─ Device Info...                   │
├────────────────────────────────────────┤
│ 🔑 Keys (12)                          │ → opens Keys window
│ 🛡️ FIDO2                              │ → submenu
│    ├─ Start Bridge                     │
│    ├─ Credentials...                   │
│    └─ Relying Parties...               │
│ 🔢 OATH TOTP                          │ → submenu
│    ├─ [Account 1] 123 456  ⏱ 15s      │
│    ├─ [Account 2] 789 012  ⏱ 15s      │
│    ├─ ─────────────────────            │
│    └─ Manage Accounts...               │
│ 💳 PIV                                │ → opens PIV window
│ 🔒 TPM                                │ → opens TPM window
├────────────────────────────────────────┤
│ ⚙️ Settings...                        │ → opens Settings window
│ 📋 Audit Log...                       │ → opens Audit window
│ 🔧 Server Admin...                    │ → opens Admin window (if admin)
├────────────────────────────────────────┤
│ 📖 Help                               │ → opens docs URL
│ ℹ️ About xKey                         │ → opens About dialog
├────────────────────────────────────────┤
│ ❌ Quit                               │
└────────────────────────────────────────┘
```

### 1.3 Quick Actions

- **Single-click on tray icon**: Toggle main window
- **Double-click**: Open dashboard
- **Right-click**: Show menu

---

## 2. Dashboard View

The main landing page showing system status at a glance.

### 2.1 Layout

```
┌─────────────────────────────────────────────────────────────────┐
│ [Gradient Header]                                                │
│  xKey                                                           │
│  Hardware Security Key                                          │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│ Status Overview                                                  │
│ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐│
│ │ 📱 Phone    │ │ 🔑 Keys     │ │ 🛡️ FIDO2    │ │ 🔒 TPM      ││
│ │ Connected ✓ │ │ 12 keys    │ │ Bridge ON   │ │ Available ✓ ││
│ └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘│
└─────────────────────────────────────────────────────────────────┘

┌──────────────────────────────┐ ┌────────────────────────────────┐
│ Connected Device             │ │ Recent Activity                 │
│ ┌──────────────────────────┐ │ │ ┌────────────────────────────┐ │
│ │ 📱 Pixel 8 Pro           │ │ │ │ 🔑 Signed (github.com)     │ │
│ │ Status: Connected ✓      │ │ │ │    2 minutes ago           │ │
│ │ Security: StrongBox      │ │ │ ├────────────────────────────┤ │
│ │ Last Attestation: Today  │ │ │ │ 🔢 TOTP generated (AWS)    │ │
│ │                          │ │ │ │    5 minutes ago           │ │
│ │ [Disconnect] [Attest]    │ │ │ ├────────────────────────────┤ │
│ └──────────────────────────┘ │ │ │ 📱 Device connected        │ │
└──────────────────────────────┘ │ │    15 minutes ago          │ │
                                 │ └────────────────────────────┘ │
                                 │ [View All]                      │
                                 └────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│ Quick Actions                                                    │
│ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐│
│ │ Pair Device │ │ Add TOTP    │ │ View Keys   │ │ Settings    ││
│ │      +      │ │      +      │ │     🔑      │ │      ⚙️     ││
│ └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 Status Cards

Each status card shows:
- Icon with color-coded status
- Short status text
- Click to open detail view

### 2.3 Recent Activity

- Last 10 operations
- Real-time updates via events
- Timestamp with relative time
- Click to view in audit log

---

## 3. Phone Backend

### 3.1 Device List

```
┌─────────────────────────────────────────────────────────────────┐
│ Paired Devices                                         [+ Pair] │
├─────────────────────────────────────────────────────────────────┤
│ ┌─────────────────────────────────────────────────────────────┐ │
│ │ 📱 Pixel 8 Pro                           [Connected ✓]     │ │
│ │ Address: AA:BB:CC:DD:EE:FF                                  │ │
│ │ Paired: 2025-01-15 14:30                                    │ │
│ │ Security: StrongBox | Attestation: Valid                    │ │
│ │                                                              │ │
│ │ [Disconnect]  [Attest]  [Details]  [🗑️ Unpair]              │ │
│ └─────────────────────────────────────────────────────────────┘ │
│                                                                  │
│ ┌─────────────────────────────────────────────────────────────┐ │
│ │ 📱 Galaxy S24                            [Disconnected]     │ │
│ │ Address: 11:22:33:44:55:66                                  │ │
│ │ Paired: 2025-01-10 09:15                                    │ │
│ │ Security: TEE | Attestation: Expired                        │ │
│ │                                                              │ │
│ │ [Connect]  [Set Default]  [Details]  [🗑️ Unpair]            │ │
│ └─────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

### 3.2 Pairing Flow

1. **Scan**: User clicks "Pair New Device"
2. **Discovery**: Shows spinner, lists discovered devices
3. **Select**: User selects device from list
4. **Confirm**: Display fingerprint comparison
5. **Approve**: User confirms on both devices
6. **Complete**: Show success, run initial attestation

### 3.3 Device Detail View

```
┌─────────────────────────────────────────────────────────────────┐
│ Device Details                                          [Close] │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  📱 Pixel 8 Pro                                                 │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ Connection                                                   ││
│  │ Status:         Connected ✓                                 ││
│  │ BLE Address:    AA:BB:CC:DD:EE:FF                          ││
│  │ Signal:         Strong (-45 dBm)                            ││
│  │ Connected For:  2h 15m                                      ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                  │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ Security                                                     ││
│  │ Keystore:       StrongBox                                   ││
│  │ Biometrics:     Available                                   ││
│  │ Boot State:     Verified ✓                                  ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                  │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ Attestation                                                  ││
│  │ Last Attested:  Today 14:30                                 ││
│  │ Boot Hash:      a1b2c3d4...                                 ││
│  │ Status:         Valid ✓                                     ││
│  │                                                              ││
│  │ [Attest Now]                                                ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                  │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ Keys on Device                                               ││
│  │ Total Keys:     12                                          ││
│  │ FIDO2:          5                                           ││
│  │ Signing:        4                                           ││
│  │ Encryption:     3                                           ││
│  │                                                              ││
│  │ [View Keys]                                                 ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                  │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ Pairing                                                      ││
│  │ Paired:         2025-01-15 14:30                            ││
│  │ Fingerprint:    SHA256:abc123...                            ││
│  │ Default Device: Yes                                          ││
│  │                                                              ││
│  │ [Set as Default]  [🗑️ Unpair Device]                        ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

---

## 4. FIDO2/WebAuthn

### 4.1 Credential List

```
┌─────────────────────────────────────────────────────────────────┐
│ FIDO2 Credentials                                               │
├─────────────────────────────────────────────────────────────────┤
│ Filter: [All ▾]  [Phone ▾]  Search: [________________]          │
├─────────────────────────────────────────────────────────────────┤
│ ┌─────────────────────────────────────────────────────────────┐ │
│ │ 🌐 github.com                                                │ │
│ │ User: john@example.com                                       │ │
│ │ Created: 2025-01-10 | Last used: Today                       │ │
│ │ Backend: Phone (Pixel 8 Pro)                                 │ │
│ │                                         [Details] [🗑️ Delete]│ │
│ └─────────────────────────────────────────────────────────────┘ │
│ ┌─────────────────────────────────────────────────────────────┐ │
│ │ 🌐 google.com                                                │ │
│ │ User: john.doe@gmail.com                                     │ │
│ │ Created: 2025-01-08 | Last used: Yesterday                   │ │
│ │ Backend: Phone (Pixel 8 Pro)                                 │ │
│ │                                         [Details] [🗑️ Delete]│ │
│ └─────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

### 4.2 Phone Bridge

```
┌─────────────────────────────────────────────────────────────────┐
│ FIDO2 Phone Bridge                                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Status: [Running ✓]                                            │
│                                                                  │
│  The phone bridge allows your phone to act as a FIDO2           │
│  authenticator for this computer. When a website requests       │
│  authentication, your phone will prompt for biometric           │
│  verification.                                                   │
│                                                                  │
│  Device: Pixel 8 Pro                                            │
│  Connection: BLE (Encrypted)                                    │
│  Uptime: 2h 15m                                                 │
│                                                                  │
│  Recent Authentications:                                        │
│  • github.com - 2 minutes ago                                   │
│  • google.com - 15 minutes ago                                  │
│  • aws.amazon.com - 1 hour ago                                  │
│                                                                  │
│  [Stop Bridge]  [View Audit Log]                                │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 5. OATH TOTP/HOTP

### 5.1 Account List

```
┌─────────────────────────────────────────────────────────────────┐
│ OATH Accounts                                        [+ Add]    │
├─────────────────────────────────────────────────────────────────┤
│ ┌─────────────────────────────────────────────────────────────┐ │
│ │ 🔢 GitHub                                                    │ │
│ │ john@example.com                                             │ │
│ │                                                              │ │
│ │    ┌─────────────────────────────────────────────┐          │ │
│ │    │         1 2 3   4 5 6                       │          │ │
│ │    └─────────────────────────────────────────────┘          │ │
│ │                                                              │ │
│ │    [████████████████████░░░░░░░░] 15s remaining             │ │
│ │                                                              │ │
│ │    [📋 Copy]  [🔄 Refresh]                    [⋮ More]       │ │
│ └─────────────────────────────────────────────────────────────┘ │
│                                                                  │
│ ┌─────────────────────────────────────────────────────────────┐ │
│ │ 🔢 AWS                                                       │ │
│ │ admin@company.com                                            │ │
│ │                                                              │ │
│ │    ┌─────────────────────────────────────────────┐          │ │
│ │    │         7 8 9   0 1 2                       │          │ │
│ │    └─────────────────────────────────────────────┘          │ │
│ │                                                              │ │
│ │    [████████░░░░░░░░░░░░░░░░░░░░] 8s remaining              │ │
│ │                                                              │ │
│ │    [📋 Copy]  [🔄 Refresh]                    [⋮ More]       │ │
│ └─────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

### 5.2 Add Account

Options:
- **Scan QR Code**: Use webcam or paste image
- **Enter Manually**: Form with issuer, account, secret, algorithm
- **Import from URI**: Paste otpauth:// URI

### 5.3 Account Details

- Issuer and account name (editable)
- Algorithm (SHA1, SHA256, SHA512)
- Digits (6 or 8)
- Period (TOTP) or counter (HOTP)
- Creation date
- Last used
- Usage count

---

## 6. PIV Certificates

### 6.1 Slot Overview

```
┌─────────────────────────────────────────────────────────────────┐
│ PIV Smart Card                                                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐             │
│  │ Slot 9A      │ │ Slot 9C      │ │ Slot 9D      │             │
│  │ Authentication│ │ Signature    │ │ Key Mgmt     │             │
│  │              │ │              │ │              │             │
│  │ [Empty]      │ │ ✓ Loaded     │ │ [Empty]      │             │
│  │              │ │              │ │              │             │
│  │ [Generate]   │ │ [View]       │ │ [Import]     │             │
│  └──────────────┘ └──────────────┘ └──────────────┘             │
│                                                                  │
│  ┌──────────────┐                                               │
│  │ Slot 9E      │                                               │
│  │ Card Auth    │                                               │
│  │              │                                               │
│  │ ✓ Loaded     │                                               │
│  │              │                                               │
│  │ [View]       │                                               │
│  └──────────────┘                                               │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 6.2 Certificate Details

```
┌─────────────────────────────────────────────────────────────────┐
│ Certificate - Slot 9C (Digital Signature)              [Close]  │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Subject:    CN=John Doe, O=Example Corp                        │
│  Issuer:     CN=Example CA, O=Example Corp                      │
│  Serial:     01:23:45:67:89:AB:CD:EF                            │
│  Algorithm:  ECDSA P-256                                        │
│                                                                  │
│  Validity:                                                       │
│  Not Before: 2025-01-01 00:00:00 UTC                            │
│  Not After:  2026-01-01 00:00:00 UTC                            │
│  Status:     Valid ✓ (340 days remaining)                       │
│                                                                  │
│  Key Usage:                                                      │
│  ☑ Digital Signature                                            │
│  ☐ Key Encipherment                                             │
│  ☐ Data Encipherment                                            │
│                                                                  │
│  Fingerprint (SHA-256):                                         │
│  AB:CD:EF:12:34:56:78:90:...                                    │
│                                                                  │
│  [Export Cert]  [Generate CSR]  [🗑️ Delete]                     │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 6.3 CSR Generation

Form fields:
- Common Name (required)
- Organization
- Organizational Unit
- Country
- State/Province
- Locality
- Email
- Key Algorithm (RSA 2048, RSA 4096, ECDSA P-256, ECDSA P-384)

---

## 7. TPM

### 7.1 TPM Status

```
┌─────────────────────────────────────────────────────────────────┐
│ TPM 2.0 Status                                                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ Hardware                                                     ││
│  │ Manufacturer:  Intel                                        ││
│  │ Model:         TPM 2.0                                      ││
│  │ Firmware:      7.85.3126                                    ││
│  │ Status:        Available ✓                                  ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                  │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ Identity Keys                                                ││
│  │ EK:       Provisioned ✓                                     ││
│  │ IAK:      Provisioned ✓                                     ││
│  │ IDevID:   Not provisioned                                   ││
│  │                                                              ││
│  │ [View EK Info]  [View IAK Info]  [Provision IDevID]         ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                  │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ PCR Banks                                                    ││
│  │ SHA-1:    24 registers                                      ││
│  │ SHA-256:  24 registers                                      ││
│  │ SHA-384:  Disabled                                          ││
│  │                                                              ││
│  │ [View PCR Values]                                           ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                  │
│  [Generate Quote]  [Full TPM Info]                              │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 7.2 PCR Viewer

```
┌─────────────────────────────────────────────────────────────────┐
│ PCR Values                                              [Close] │
├─────────────────────────────────────────────────────────────────┤
│ Bank: [SHA-256 ▾]                                               │
├─────────────────────────────────────────────────────────────────┤
│ PCR 0:  3A7E...1B2C  (BIOS)                                    │
│ PCR 1:  5D8F...4E3A  (BIOS Configuration)                      │
│ PCR 2:  2C4D...7F8E  (Option ROMs)                             │
│ PCR 3:  0000...0000  (Option ROM Configuration)                │
│ PCR 4:  8B9C...2A1D  (MBR)                                     │
│ PCR 5:  4E7F...9C8B  (MBR Configuration)                       │
│ PCR 6:  0000...0000  (State Transitions)                       │
│ PCR 7:  1A2B...3C4D  (Secure Boot)                             │
│ PCR 8:  6F7E...8D9C  (GRUB)                                    │
│ PCR 9:  0000...0000  (Initrd)                                  │
│ ...                                                              │
├─────────────────────────────────────────────────────────────────┤
│ [Export PCRs]  [Generate Quote]                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 8. Settings

### 8.1 Settings Categories

```
┌─────────────────────────────────────────────────────────────────┐
│ Settings                                                         │
├────────────────────┬────────────────────────────────────────────┤
│                    │                                             │
│  ┌──────────────┐  │  General                                   │
│  │ 📋 General   │  │  ────────────────────────────────────────  │
│  └──────────────┘  │                                             │
│  ┌──────────────┐  │  Theme                                     │
│  │ 🎨 Appearance│  │  ○ Light  ○ Dark  ● System                 │
│  └──────────────┘  │                                             │
│  ┌──────────────┐  │  Start with System                         │
│  │ 📱 Phone     │  │  [✓] Launch xKey when you log in           │
│  └──────────────┘  │                                             │
│  ┌──────────────┐  │  Start Minimized                           │
│  │ 🛡️ Security  │  │  [✓] Start minimized to system tray        │
│  └──────────────┘  │                                             │
│  ┌──────────────┐  │  Notifications                             │
│  │ 🔔 Notifs    │  │  [✓] Show notifications for operations     │
│  └──────────────┘  │                                             │
│  ┌──────────────┐  │  Auto-connect                              │
│  │ 🔧 Advanced  │  │  [✓] Automatically connect to default      │
│  └──────────────┘  │      phone on startup                       │
│                    │                                             │
└────────────────────┴────────────────────────────────────────────┘
```

### 8.2 Phone Settings

- Default device selection
- Auto-connect on startup
- Attestation policy:
  - Require attestation: Always / Grace period / Never
  - Grace period duration
  - Minimum security level

### 8.3 Security Settings

- LUKS encryption status
- Lock timeout
- Require authentication for:
  - Viewing keys
  - Signing operations
  - Deleting keys

### 8.4 Advanced Settings

- xkmsd URL
- Default backend
- Log level
- Log file path
- Debug mode

---

## 9. Audit Log

### 9.1 Log Viewer

```
┌─────────────────────────────────────────────────────────────────┐
│ Audit Log                                                        │
├─────────────────────────────────────────────────────────────────┤
│ Filter: [All Operations ▾]  Device: [All ▾]  [Today ▾]          │
│ Search: [_______________________]  [🔍]                          │
├─────────────────────────────────────────────────────────────────┤
│ ┌─────────────────────────────────────────────────────────────┐ │
│ │ ✓ SIGN_REQUEST                           Today 14:32:15     │ │
│ │ Key: github.com/john                                         │ │
│ │ Device: Pixel 8 Pro                                          │ │
│ │ Duration: 245ms                                               │ │
│ └─────────────────────────────────────────────────────────────┘ │
│ ┌─────────────────────────────────────────────────────────────┐ │
│ │ ✓ CONNECTION_ESTABLISHED                  Today 14:30:00    │ │
│ │ Device: Pixel 8 Pro                                          │ │
│ │ Connection type: BLE                                         │ │
│ └─────────────────────────────────────────────────────────────┘ │
│ ┌─────────────────────────────────────────────────────────────┐ │
│ │ ✓ DEVICE_ATTESTED                        Today 14:30:05     │ │
│ │ Device: Pixel 8 Pro                                          │ │
│ │ Security level: StrongBox                                    │ │
│ └─────────────────────────────────────────────────────────────┘ │
│ ┌─────────────────────────────────────────────────────────────┐ │
│ │ ⚠ POLICY_DENIED                          Today 12:15:30     │ │
│ │ Reason: Device attestation expired                           │ │
│ │ Device: Galaxy S24                                           │ │
│ └─────────────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────────┤
│ Showing 50 of 1,247 entries                    [Export JSON/CSV]│
└─────────────────────────────────────────────────────────────────┘
```

### 9.2 Filters

- Operation type (all defined in audit package)
- Date range
- Device
- Key
- Success/failure
- Full-text search

### 9.3 Export

- JSON format
- CSV format
- Date range selection
- Filter preservation

---

## 10. Admin (Server Management)

### 10.1 Server Status

```
┌─────────────────────────────────────────────────────────────────┐
│ xkmsd Server Administration                                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Server Status                                                   │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ URL:      unix:///var/run/xkmsd.sock                    ││
│  │ Status:   Running ✓                                         ││
│  │ Uptime:   5d 12h 34m                                        ││
│  │ Version:  1.2.3                                             ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                  │
│  Backends                                                        │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ ┌────────────┐ ┌────────────┐ ┌────────────┐               ││
│  │ │ software   │ │ tpm2       │ │ pkcs11     │               ││
│  │ │ Available  │ │ Available  │ │ Available  │               ││
│  │ │ 45 keys    │ │ 12 keys    │ │ 3 keys     │               ││
│  │ └────────────┘ └────────────┘ └────────────┘               ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                  │
│  Quick Actions                                                   │
│  [View All Keys]  [View Audit Logs]  [Server Logs]              │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 10.2 User Management

- List users
- Create user (with role assignment)
- Edit user (role, permissions)
- Delete user
- View user activity

### 10.3 Backend Management

- View backend status
- Backend-specific configuration
- Key migration between backends

---

## 11. Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+Q` / `Cmd+Q` | Quit application |
| `Ctrl+,` / `Cmd+,` | Open settings |
| `Ctrl+L` / `Cmd+L` | Open audit log |
| `Ctrl+D` / `Cmd+D` | Open dashboard |
| `Ctrl+P` / `Cmd+P` | Pair new device |
| `Ctrl+T` / `Cmd+T` | Generate TOTP (focused account) |
| `Ctrl+C` / `Cmd+C` | Copy current TOTP code |
| `Escape` | Close current dialog/view |
| `F5` | Refresh current view |

---

## 12. Notifications

### 12.1 Types

| Type | Example | Priority |
|------|---------|----------|
| **Info** | "Device connected" | Low |
| **Success** | "Authentication successful" | Normal |
| **Warning** | "Attestation expires soon" | High |
| **Error** | "Connection failed" | Urgent |
| **Action** | "Authentication request from github.com" | Urgent |

### 12.2 Notification Actions

- Click: Opens relevant view
- Action buttons: "Approve" / "Deny" for auth requests
- Dismiss: Clear notification

---

## 13. Error Handling

### 13.1 Error Dialog

```
┌─────────────────────────────────────────────────────────────────┐
│ ⚠ Connection Error                                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Failed to connect to Pixel 8 Pro                               │
│                                                                  │
│  The device may be out of range or Bluetooth may be disabled.  │
│                                                                  │
│  Error details:                                                  │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ bluetooth: connection timeout after 30s                     ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                  │
│                           [Copy Details]  [Retry]  [Dismiss]    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 13.2 Error Recovery

- Automatic retry with exponential backoff
- Clear error state on success
- "Try Again" action in error dialogs
- Detailed error logging for debugging
