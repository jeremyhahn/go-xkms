# User Management CLI

## Overview

The `user` command group provides comprehensive user account management for the go-keychain system. It supports passwordless authentication using FIDO2 security keys, enabling secure access without the need for traditional passwords.

The first user registered automatically receives the admin role. Subsequent users receive the user role by default unless explicitly specified.

## Prerequisites

- A FIDO2-compatible security key (USB, NFC, or Bluetooth)
- go-keychain CLI installed
- Proper permissions to access FIDO2 devices (typically requires root or udev rules)

## Commands

### user register

Register a new user account with FIDO2 authentication.

```bash
keychain user register <username> [flags]
```

**Arguments:**
- `username` - Unique username for the account (required)

**Flags:**
- `--display-name <name>` - User-friendly display name (defaults to username)
- `--role <role>` - User role: admin, operator, auditor, user, readonly, guest (default: user, except first user gets admin)
- `--rp-id <id>` - Relying Party ID (default: "go-keychain")
- `--rp-name <name>` - Relying Party name (default: "Go Keychain")
- `--timeout <duration>` - FIDO2 timeout for user presence (default: 30s)
- `--device <path>` - Specific FIDO2 device path to use
- `--user-verification` - Require user verification (PIN) on the security key
- `--storage-path <path>` - Path to keychain storage (default: $KEYCHAIN_STORAGE_PATH or /var/lib/keychain)

**Examples:**

Register first admin user:
```bash
keychain user register admin@example.com --display-name "System Administrator"
```

Register operator with specific role:
```bash
keychain user register ops@example.com --role operator --display-name "Operations Team"
```

Register with PIN verification required:
```bash
keychain user register secure@example.com --user-verification --display-name "Security Admin"
```

Register using specific FIDO2 device:
```bash
keychain user register user@example.com --device /dev/hidraw0
```

**Output:**

Text format:
```
Registering new user...
  Username: admin@example.com
  Display Name: System Administrator
  Role: admin

Please touch your security key to register...

User registered successfully!

User ID: eXVlcnR5dWlvcGFzZGZnaGprbA
Username: admin@example.com
Role: admin
Credential ID: bXVlcnR5dWlvcGFzZGZnaGprbA

You can now use this security key to authenticate.
```

JSON format (--output json):
```json
{
  "success": true,
  "username": "admin@example.com",
  "display_name": "System Administrator",
  "role": "admin",
  "user_id": "eXVlcnR5dWlvcGFzZGZnaGprbA",
  "credential_id": "bXVlcnR5dWlvcGFzZGZnaGprbA",
  "first_user": true
}
```

### user login

Authenticate using FIDO2 and prepare for JWT token generation.

```bash
keychain user login [flags]
```

**Flags:**
- `--credential-id <id>` - Credential ID (base64 or hex encoded) (required)
- `--salt <salt>` - Salt value (base64 or hex encoded) (required)
- `--rp-id <id>` - Relying Party ID (default: "go-keychain")
- `--timeout <duration>` - FIDO2 timeout for user presence (default: 30s)
- `--device <path>` - Specific FIDO2 device path to use
- `--user-verification` - Require user verification (PIN)
- `--storage-path <path>` - Path to keychain storage

**Examples:**

Login with credential:
```bash
keychain user login --credential-id 'bXVlcnR5dWlvcGFzZGZnaGprbA' --salt 'c2FsdHZhbHVlYXNkZg'
```

**Note:** This command validates the FIDO2 credential locally. For JWT token generation, use the WebAuthn REST API endpoints:
- POST /api/v1/webauthn/login/begin
- POST /api/v1/webauthn/login/finish

**Output:**

```
Please touch your security key to authenticate...

FIDO2 authentication successful!

To get a JWT token, use the WebAuthn login endpoints:
  POST /api/v1/webauthn/login/begin
  POST /api/v1/webauthn/login/finish
```

### user list

List all user accounts in the system.

```bash
keychain user list [flags]
```

**Flags:**
- `--storage-path <path>` - Path to keychain storage

**Examples:**

List all users:
```bash
keychain user list
```

List with custom storage path:
```bash
keychain user list --storage-path /custom/path
```

**Output:**

Text format:
```
ID                                       USERNAME             ROLE         ENABLED  CREDS
------------------------------------------------------------------------------------------
eXVlcnR5dWlvcGFz...                     admin@example.com    admin        true     1
bXVlcnR5dWlvcGFz...                     ops@example.com      operator     true     1
Y2RlcnR5dWlvcGFz...                     user@example.com     user         false    1

Total: 3 user(s)
```

JSON format (--output json):
```json
{
  "users": [
    {
      "id": "eXVlcnR5dWlvcGFzZGZnaGprbA",
      "username": "admin@example.com",
      "display_name": "System Administrator",
      "role": "admin",
      "enabled": true,
      "credential_count": 1,
      "created_at": "2025-01-15T10:30:00Z",
      "last_login_at": "2025-01-20T14:22:00Z"
    }
  ],
  "total": 3
}
```

### user get

Get detailed information about a specific user account.

```bash
keychain user get <username> [flags]
```

**Arguments:**
- `username` - Username to retrieve (required)

**Flags:**
- `--storage-path <path>` - Path to keychain storage

**Examples:**

Get user details:
```bash
keychain user get admin@example.com
```

**Output:**

Text format:
```
User Details:
  ID:           eXVlcnR5dWlvcGFzZGZnaGprbA
  Username:     admin@example.com
  Display Name: System Administrator
  Role:         admin
  Enabled:      true
  Created:      2025-01-15T10:30:00Z
  Last Login:   2025-01-20T14:22:00Z

  Credentials (1):
    1. Security Key
       ID: bXVlcnR5dWlvcGFzZGZnaGprbA
       Salt: c2FsdHZhbHVlYXNkZg
       Created: 2025-01-15T10:30:00Z
       Last Used: 2025-01-20T14:22:00Z
```

JSON format (--output json):
```json
{
  "id": "eXVlcnR5dWlvcGFzZGZnaGprbA",
  "username": "admin@example.com",
  "display_name": "System Administrator",
  "role": "admin",
  "enabled": true,
  "credential_count": 1,
  "created_at": "2025-01-15T10:30:00Z",
  "last_login_at": "2025-01-20T14:22:00Z",
  "credentials": [
    {
      "id": "bXVlcnR5dWlvcGFzZGZnaGprbA",
      "name": "Security Key",
      "created_at": "2025-01-15T10:30:00Z",
      "last_used_at": "2025-01-20T14:22:00Z",
      "salt": "c2FsdHZhbHVlYXNkZg"
    }
  ]
}
```

### user delete

Delete a user account from the system.

```bash
keychain user delete <username> [flags]
```

**Arguments:**
- `username` - Username to delete (required)

**Flags:**
- `--storage-path <path>` - Path to keychain storage

**Examples:**

Delete a user:
```bash
keychain user delete user@example.com
```

**Output:**

```
User 'user@example.com' deleted successfully.
```

**Note:** You cannot delete the last administrator account.

### user disable

Disable a user account, preventing authentication.

```bash
keychain user disable <username> [flags]
```

**Arguments:**
- `username` - Username to disable (required)

**Flags:**
- `--storage-path <path>` - Path to keychain storage

**Examples:**

Disable a user:
```bash
keychain user disable ops@example.com
```

**Output:**

```
User 'ops@example.com' has been disabled.
```

### user enable

Enable a previously disabled user account.

```bash
keychain user enable <username> [flags]
```

**Arguments:**
- `username` - Username to enable (required)

**Flags:**
- `--storage-path <path>` - Path to keychain storage

**Examples:**

Enable a user:
```bash
keychain user enable ops@example.com
```

**Output:**

```
User 'ops@example.com' has been enabled.
```

### user status

Show the user setup status of the system.

```bash
keychain user status [flags]
```

**Flags:**
- `--storage-path <path>` - Path to keychain storage

**Examples:**

Check system status:
```bash
keychain user status
```

**Output:**

Not configured:
```
Status: NOT CONFIGURED

No users configured.
Run 'keychain user register <username>' to create the first administrator.
```

Configured:
```
Status: CONFIGURED
User accounts: 5
Admin accounts: 2
```

JSON format (--output json):
```json
{
  "requires_setup": false,
  "user_count": 5,
  "admin_count": 2,
  "message": "System is configured and ready."
}
```

### user credentials

Get credential configuration needed for login.

```bash
keychain user credentials <username> [flags]
```

**Arguments:**
- `username` - Username to get credentials for (required)

**Flags:**
- `--storage-path <path>` - Path to keychain storage

**Examples:**

Get credential information:
```bash
keychain user credentials admin@example.com
```

**Output:**

Text format:
```
Credential configuration for admin@example.com:

  Credential Name: Security Key
  Credential ID:   bXVlcnR5dWlvcGFzZGZnaGprbA
  Salt:            c2FsdHZhbHVlYXNkZg

Use with login command:
  keychain user login --credential-id 'bXVlcnR5dWlvcGFzZGZnaGprbA' --salt 'c2FsdHZhbHVlYXNkZg'
```

JSON format (--output json):
```json
{
  "username": "admin@example.com",
  "credential_id": "bXVlcnR5dWlvcGFzZGZnaGprbA",
  "salt": "c2FsdHZhbHVlYXNkZg",
  "name": "Security Key",
  "created_at": "2025-01-15T10:30:00Z"
}
```

## User Roles

go-keychain supports the following user roles:

| Role | Description |
|------|-------------|
| admin | Full system access, can manage all resources and users |
| operator | Can manage keys and certificates, limited user management |
| auditor | Read-only access for compliance and auditing |
| user | Standard user access to their own resources |
| readonly | Read-only access to permitted resources |
| guest | Limited temporary access |

The first user registered automatically receives the `admin` role.

## Global Flags

All user commands support these global flags:

- `--output <format>` - Output format: text, json (default: text)
- `--verbose` - Enable verbose logging
- `--config <path>` - Path to configuration file

## Security Considerations

### FIDO2 Security Keys

- Use security keys from reputable vendors (Yubico, Google Titan, etc.)
- Store security keys securely when not in use
- Consider using PIN protection (--user-verification flag)
- Register backup security keys for critical accounts

### Credential Storage

- The credential ID and salt are stored in the user database
- Keep regular backups of the keychain storage directory
- Protect the storage directory with appropriate file permissions
- Consider encrypting the storage directory at rest

### Best Practices

1. Register the first admin user immediately after installation
2. Use descriptive display names for easier identification
3. Enable user verification (PIN) for high-security environments
4. Regularly review user accounts with `user list`
5. Disable unused accounts rather than deleting them
6. Use role-based access control appropriate to user needs
7. Keep the credential ID and salt from `user credentials` secure

## Troubleshooting

### FIDO2 Device Not Found

If you get "no FIDO2 devices found":

1. Ensure the security key is properly inserted
2. Check device permissions: `ls -la /dev/hidraw*`
3. Add udev rules for non-root access:
   ```bash
   # /etc/udev/rules.d/70-u2f.rules
   KERNEL=="hidraw*", SUBSYSTEM=="hidraw", MODE="0660", GROUP="plugdev", TAG+="uaccess"
   ```
4. Reload udev rules: `sudo udevadm control --reload-rules`
5. Replug the security key

### Permission Denied

Run with sudo or ensure your user is in the appropriate groups:
```bash
sudo usermod -aG plugdev $USER
```

### Timeout During Registration

If registration times out:

1. Increase the timeout: `--timeout 60s`
2. Ensure the security key is functioning properly
3. Try a different USB port
4. Check for conflicting browser or application FIDO2 sessions

### Cannot Delete Last Admin

The system prevents deletion of the last administrator account to avoid lockout. Create another admin user before deleting.

## Examples

### Complete User Workflow

1. Check system status:
   ```bash
   keychain user status
   ```

2. Register first admin:
   ```bash
   keychain user register admin@example.com --display-name "Primary Admin"
   ```

3. Register additional users:
   ```bash
   keychain user register ops@example.com --role operator
   keychain user register audit@example.com --role auditor
   ```

4. List all users:
   ```bash
   keychain user list
   ```

5. Get credential information for login:
   ```bash
   keychain user credentials admin@example.com
   ```

6. Login (for scripting/automation):
   ```bash
   CRED_ID="bXVlcnR5dWlvcGFzZGZnaGprbA"
   SALT="c2FsdHZhbHVlYXNkZg"
   keychain user login --credential-id "$CRED_ID" --salt "$SALT"
   ```

### Automation with JSON Output

Get user information in scripts:
```bash
# Get all users as JSON
users=$(keychain user list --output json)
echo "$users" | jq '.total'

# Get specific user details
user_info=$(keychain user get admin@example.com --output json)
echo "$user_info" | jq '.role'

# Check if setup is required
status=$(keychain user status --output json)
if [ "$(echo "$status" | jq -r '.requires_setup')" = "true" ]; then
  echo "System requires setup"
fi
```

## See Also

- [Admin Management CLI](./admin.md) - Administrator-specific commands
- [WebAuthn Guide](../webauthn.md) - WebAuthn integration and API usage
- [Getting Started](../getting-started.md) - Initial setup and configuration
