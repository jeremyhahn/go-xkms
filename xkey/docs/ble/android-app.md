# xkey Android App

## Overview

The xkey Android app runs as a BLE peripheral (GATT server) that securely stores and uses FIDO2 signing keys in the Android Keystore with biometric protection.

## Requirements

- Android 9+ (API 28)
- Biometric hardware (fingerprint or face)
- Bluetooth Low Energy support
- StrongBox or TEE (recommended)

## Building

### Prerequisites

- Android Studio Arctic Fox or later
- JDK 17+
- Android SDK 34

### Build Steps

1. Open the project in Android Studio:
   ```
   xkey-android/
   ```

2. Generate Gradle wrapper (if missing):
   ```bash
   cd xkey-android
   gradle wrapper --gradle-version 8.5
   ```

3. Build debug APK:
   ```bash
   ./gradlew assembleDebug
   ```

4. Install on device:
   ```bash
   ./gradlew installDebug
   ```

### Release Build

1. Create keystore for signing:
   ```bash
   keytool -genkey -v -keystore xkey-release.keystore \
     -alias xkey -keyalg RSA -keysize 2048 -validity 10000
   ```

2. Configure signing in `app/build.gradle.kts`:
   ```kotlin
   signingConfigs {
       create("release") {
           storeFile = file("xkey-release.keystore")
           storePassword = System.getenv("KEYSTORE_PASSWORD")
           keyAlias = "xkey"
           keyPassword = System.getenv("KEY_PASSWORD")
       }
   }
   ```

3. Build release APK:
   ```bash
   ./gradlew assembleRelease
   ```

## App Structure

```
app/src/main/kotlin/com/xkey/
├── XkeyApplication.kt      # Application class
├── ble/
│   ├── GattServer.kt          # BLE GATT server
│   ├── Advertiser.kt          # BLE advertising manager
│   ├── NoiseSession.kt        # Noise protocol implementation
│   └── FragmentReassembler.kt # BLE packet reassembly
├── crypto/
│   ├── KeystoreManager.kt     # Android Keystore operations
│   ├── BiometricHelper.kt     # Biometric authentication
│   └── CborEncoder.kt         # COSE key encoding
├── protocol/
│   ├── Messages.kt            # JSON-RPC message types
│   └── Handler.kt             # Request dispatcher
└── ui/
    └── MainActivity.kt        # Main UI activity
```

## Usage

### First Launch

1. Open xkey app
2. Grant Bluetooth permissions when prompted
3. App starts advertising as "xkey"
4. Status shows "Waiting for connection..."

### Pairing with Desktop

1. Ensure app is running and advertising
2. On desktop, run: `xkey phone pair`
3. Confirm pairing on both devices
4. OS-level BLE pairing establishes link encryption
5. Noise handshake exchanges application keys
6. Status shows "Paired with: [device name]"

### Subsequent Connections

1. Open app (or it runs in background)
2. Desktop auto-connects to bonded device
3. Status shows "Connected"

### Signing Operations

When a signing request arrives:

1. Phone vibrates/notifies
2. Dialog shows: "xkey: Sign in to [site]?"
3. Biometric prompt appears
4. User authenticates with fingerprint/face
5. Signature sent to desktop
6. Dialog closes automatically

### Managing Keys

The app displays:
- Number of stored credentials
- Paired desktop devices
- Connection status

## Permissions

Required permissions in `AndroidManifest.xml`:

```xml
<uses-permission android:name="android.permission.BLUETOOTH" />
<uses-permission android:name="android.permission.BLUETOOTH_ADMIN" />
<uses-permission android:name="android.permission.BLUETOOTH_ADVERTISE" />
<uses-permission android:name="android.permission.BLUETOOTH_CONNECT" />
<uses-permission android:name="android.permission.USE_BIOMETRIC" />
<uses-permission android:name="android.permission.FOREGROUND_SERVICE" />
```

## Security Considerations

### Key Storage

- Keys generated in Android Keystore
- StrongBox used when available (hardware security module)
- Keys marked as non-exportable
- Keys bound to biometric authentication

### Biometric Binding

```kotlin
KeyGenParameterSpec.Builder(alias, PURPOSE_SIGN)
    .setUserAuthenticationRequired(true)
    .setUserAuthenticationParameters(
        0,  // timeout: require auth every time
        AUTH_BIOMETRIC_STRONG
    )
    .setInvalidatedByBiometricEnrollment(true)
```

### BLE Security

- Advertising only when app is active
- Requires bonding before operations
- LE Secure Connections for link encryption
- Noise protocol for application layer

## Troubleshooting

### "Bluetooth not available"

- Enable Bluetooth in system settings
- Check device supports BLE (most modern phones do)

### "Pairing failed"

- Ensure phone is advertising (app open)
- Check Bluetooth is enabled on both devices
- Try removing old pairing and re-pair

### "Biometric not available"

- Register fingerprint/face in system settings
- Device must have biometric hardware
- Some devices require screen lock

### "StrongBox not available"

- Not all devices have StrongBox
- App falls back to TEE (still secure)
- Pixel 3+ and Samsung S10+ have StrongBox

### Connection drops

- Keep app in foreground during initial setup
- After pairing, app can run in background
- Check battery optimization settings

## Development

### Running Tests

```bash
./gradlew test
./gradlew connectedAndroidTest
```

### Debugging BLE

Enable BLE HCI snoop log:
1. Settings → Developer options
2. Enable "Bluetooth HCI snoop log"
3. Reproduce issue
4. Run: `adb bugreport`

### Logcat Filters

```bash
adb logcat -s xkey:V BluetoothGatt:V
```
