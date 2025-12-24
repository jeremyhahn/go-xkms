# Administrator Management CLI

## Overview

The `admin` command group provides dedicated administrator account management for the go-keychain system. All accounts created through these commands automatically receive the admin role with full system access.

Use `admin` commands when you specifically need to create administrator accounts. For general user management with role flexibility, see the [User Management CLI](./user.md).

## Prerequisites

- A FIDO2-compatible security key (USB, NFC, or Bluetooth)
- go-keychain CLI installed
- Proper permissions to access FIDO2 devices (typically requires root or udev rules)
- Existing admin credentials (except for initial bootstrap)

## Commands

### admin create

Create a new administrator account with FIDO2 authentication.

```bash
keychain admin create <username> [flags]
```

**Arguments:**
- `username` - Unique username for the administrator (required)

**Flags:**
- `--display-name <name>` - Administrator display name (defaults to username)
- `--rp-id <id>` - Relying Party ID (default: "go-keychain")
- `--rp-name <name>` - Relying Party name (default: "Go Keychain")
- `--timeout <duration>` - FIDO2 timeout for user presence (default: 30s)
- `--device <path>` - Specific FIDO2 device path to use
- `--user-verification` - Require user verification (PIN) on the security key
- `--storage-path <path>` - Path to keychain storage (default: $KEYCHAIN_STORAGE_PATH or /var/lib/keychain)

**Examples:**

Create primary administrator:
```bash
keychain admin create admin@example.com --display-name "System Administrator"
```

Create admin with PIN verification:
```bash
keychain admin create security@example.com \
  --display-name "Security Admin" \
  --user-verification
```

Create admin using specific FIDO2 device:
```bash
keychain admin create backup@example.com \
  --device /dev/hidraw1 \
  --display-name "Backup Administrator"
```

Create admin with extended timeout:
```bash
keychain admin create remote@example.com \
  --timeout 60s \
  --display-name "Remote Admin"
```

**Output:**

Text format:
```
Creating administrator account...
Username: admin@example.com
Display Name: System Administrator

Please touch your security key to register...

Administrator created successfully!

Admin ID: eXVlcnR5dWlvcGFzZGZnaGprbA
Username: admin@example.com
Role: admin
Credential ID: bXVlcnR5dWlvcGFzZGZnaGprbA

You can now use this security key to authenticate to the keychain web UI.
```

JSON format (--output json):
```json
{
  "success": true,
  "username": "admin@example.com",
  "display_name": "System Administrator",
  "role": "admin",
  "credential_id": "bXVlcnR5dWlvcGFzZGZnaGprbA"
}
```

### admin list

List all administrator accounts in the system.

```bash
keychain admin list [flags]
```

**Flags:**
- `--storage-path <path>` - Path to keychain storage

**Examples:**

List all administrators:
```bash
keychain admin list
```

List with JSON output:
```bash
keychain admin list --output json
```

**Output:**

Text format:
```
ID                                       USERNAME             ROLE         ENABLED  CREDS
------------------------------------------------------------------------------------------
eXVlcnR5dWlvcGFz...                     admin@example.com    admin        true     1
bXVlcnR5dWlvcGFz...                     security@example.com admin        true     2
Y2RlcnR5dWlvcGFz...                     backup@example.com   admin        false    1

Total: 3 administrator(s)
```

JSON format (--output json):
```json
{
  "admins": [
    {
      "id": "eXVlcnR5dWlvcGFzZGZnaGprbA",
      "username": "admin@example.com",
      "display_name": "System Administrator",
      "role": "admin",
      "enabled": true,
      "credential_count": 1,
      "created_at": "2025-01-15T10:30:00Z",
      "last_login_at": "2025-01-20T14:22:00Z"
    },
    {
      "id": "bXVlcnR5dWlvcGFzZGZnaGprbA",
      "username": "security@example.com",
      "display_name": "Security Admin",
      "role": "admin",
      "enabled": true,
      "credential_count": 2,
      "created_at": "2025-01-16T09:15:00Z",
      "last_login_at": "2025-01-20T15:10:00Z"
    }
  ],
  "total": 3
}
```

### admin get

Get detailed information about a specific administrator account.

```bash
keychain admin get <username> [flags]
```

**Arguments:**
- `username` - Administrator username to retrieve (required)

**Flags:**
- `--storage-path <path>` - Path to keychain storage

**Examples:**

Get administrator details:
```bash
keychain admin get admin@example.com
```

Get details with JSON output:
```bash
keychain admin get admin@example.com --output json
```

**Output:**

Text format:
```
Administrator Details:
  ID:           eXVlcnR5dWlvcGFzZGZnaGprbA
  Username:     admin@example.com
  Display Name: System Administrator
  Role:         admin
  Enabled:      true
  Created:      2025-01-15T10:30:00Z
  Last Login:   2025-01-20T14:22:00Z

  Credentials (1):
    1. Security Key
       ID: bXVlcnR5dWlvcGFz...
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
      "last_used_at": "2025-01-20T14:22:00Z"
    }
  ]
}
```

### admin delete

Delete an administrator account from the system.

```bash
keychain admin delete <username> [flags]
```

**Arguments:**
- `username` - Administrator username to delete (required)

**Flags:**
- `--storage-path <path>` - Path to keychain storage

**Examples:**

Delete an administrator:
```bash
keychain admin delete backup@example.com
```

**Output:**

```
Administrator 'backup@example.com' deleted successfully.
```

**Important:** You cannot delete the last administrator account. This prevents system lockout. Ensure at least one other admin account exists before deletion.

### admin disable

Disable an administrator account, preventing authentication.

```bash
keychain admin disable <username> [flags]
```

**Arguments:**
- `username` - Administrator username to disable (required)

**Flags:**
- `--storage-path <path>` - Path to keychain storage

**Examples:**

Disable an administrator:
```bash
keychain admin disable backup@example.com
```

**Output:**

```
Administrator 'backup@example.com' has been disabled.
```

**Note:** Disabled administrators cannot authenticate but their account and credentials remain in the system. Use `admin enable` to restore access.

### admin enable

Enable a previously disabled administrator account.

```bash
keychain admin enable <username> [flags]
```

**Arguments:**
- `username` - Administrator username to enable (required)

**Flags:**
- `--storage-path <path>` - Path to keychain storage

**Examples:**

Enable an administrator:
```bash
keychain admin enable backup@example.com
```

**Output:**

```
Administrator 'backup@example.com' has been enabled.
```

### admin status

Show the administrator setup status of the system.

```bash
keychain admin status [flags]
```

**Flags:**
- `--storage-path <path>` - Path to keychain storage

**Examples:**

Check administrator status:
```bash
keychain admin status
```

**Output:**

Not configured:
```
Status: NOT CONFIGURED

No administrators configured.
Run 'keychain admin create <username>' to create an administrator.
```

Configured:
```
Status: CONFIGURED
Administrator accounts: 3
```

JSON format (--output json):
```json
{
  "requires_setup": false,
  "admin_count": 3,
  "message": "System is configured and ready."
}
```

## Global Flags

All admin commands support these global flags:

- `--output <format>` - Output format: text, json (default: text)
- `--verbose` - Enable verbose logging
- `--config <path>` - Path to configuration file

## Admin vs User Commands

### When to use `admin` commands:

- **Bootstrap**: Creating the very first administrator during initial setup
- **Dedicated Admins**: Creating accounts that must have admin privileges
- **Admin-Specific Operations**: Working exclusively with administrator accounts
- **Simplified Workflow**: When role selection is not needed

### When to use `user` commands:

- **Flexible Roles**: Creating accounts with different permission levels
- **First User**: The first user registered via `user register` becomes admin automatically
- **General Management**: Managing all types of user accounts
- **Role Assignment**: When you need to specify non-admin roles

**Note:** Under the hood, both command groups use the same user store. The `admin` commands are a convenience wrapper that always assigns the admin role.

## Security Considerations

### Administrator Privileges

Administrators have full system access including:
- Creating and managing all user accounts
- Managing all cryptographic keys and certificates
- Modifying system configuration
- Accessing audit logs
- Performing administrative operations

### Best Practices

1. **Minimum Necessary**: Create only the minimum number of admin accounts needed
2. **Strong Authentication**: Always use FIDO2 security keys, preferably with PIN (--user-verification)
3. **Named Accounts**: Use identifiable usernames (e.g., admin@example.com, not just "admin")
4. **Regular Audits**: Periodically review admin accounts with `admin list`
5. **Disable, Don't Delete**: Disable unused admin accounts rather than deleting them for audit trail
6. **Multiple Keys**: Register backup security keys for critical admin accounts
7. **Separation of Duties**: Consider using operator or auditor roles for users who don't need full admin access
8. **Activity Monitoring**: Track admin logins via the last_login_at field

### Protection Against Lockout

The system enforces these safety measures:

1. **Last Admin Protection**: Cannot delete the last administrator account
2. **Disable Warning**: System warns when disabling reduces active admins
3. **Credential Backup**: Store credential recovery information securely
4. **Emergency Access**: Document emergency recovery procedures

## Troubleshooting

### FIDO2 Device Issues

If you encounter FIDO2 device problems:

1. **Device Not Found**:
   ```bash
   # Check devices
   ls -la /dev/hidraw*

   # Verify permissions
   sudo chmod 660 /dev/hidraw*
   ```

2. **Permission Denied**:
   ```bash
   # Add user to plugdev group
   sudo usermod -aG plugdev $USER

   # Apply udev rules
   sudo udevadm control --reload-rules
   sudo udevadm trigger
   ```

3. **Timeout**:
   ```bash
   # Increase timeout
   keychain admin create admin@example.com --timeout 60s
   ```

### Cannot Delete Last Admin

Error: "cannot delete last administrator"

**Solution**: Create another admin account first:
```bash
keychain admin create backup@example.com
keychain admin delete old@example.com
```

### Admin Already Exists

Error: "user admin@example.com already exists"

**Solutions**:
1. Use a different username
2. Delete the existing account (if appropriate)
3. Use `admin get` to view existing account details

### Storage Path Issues

Error: "failed to create user storage"

**Solutions**:
```bash
# Verify storage path exists
mkdir -p /var/lib/keychain

# Set proper permissions
sudo chown -R $USER:$USER /var/lib/keychain

# Use custom path
keychain admin create admin@example.com --storage-path /custom/path
```

## Examples

### Initial System Bootstrap

Complete setup for a new go-keychain installation:

```bash
# Check if admin setup is needed
keychain admin status

# Create first administrator
keychain admin create admin@example.com \
  --display-name "Primary Administrator" \
  --user-verification

# Verify creation
keychain admin list

# Get admin details
keychain admin get admin@example.com
```

### Creating Backup Admin

Ensure continuity with a backup administrator:

```bash
# Create backup admin with different security key
keychain admin create backup@example.com \
  --display-name "Backup Administrator" \
  --device /dev/hidraw1

# Verify both admins exist
keychain admin list
```

### Admin Rotation

Replace an admin account:

```bash
# Create new admin
keychain admin create newadmin@example.com \
  --display-name "New Admin"

# Verify new admin works
keychain admin get newadmin@example.com

# Disable old admin (keep for audit)
keychain admin disable oldadmin@example.com

# Or delete if appropriate
# keychain admin delete oldadmin@example.com
```

### Monitoring and Auditing

Track administrator activity:

```bash
# List all administrators with their status
keychain admin list --output json | jq '.admins[] | {username, enabled, last_login_at}'

# Check for inactive admins (basic example)
keychain admin list --output json | \
  jq '.admins[] | select(.last_login_at == null) | .username'

# Count total administrators
keychain admin status --output json | jq '.admin_count'
```

### Emergency Admin Creation

Script for automated admin creation (with caution):

```bash
#!/bin/bash
# emergency-admin.sh - Create emergency admin account

set -e

ADMIN_USER="emergency@example.com"
DISPLAY_NAME="Emergency Administrator"

echo "Creating emergency administrator..."
keychain admin create "$ADMIN_USER" \
  --display-name "$DISPLAY_NAME" \
  --timeout 60s \
  --user-verification

if [ $? -eq 0 ]; then
  echo "Emergency admin created successfully"
  keychain admin get "$ADMIN_USER"
else
  echo "Failed to create emergency admin" >&2
  exit 1
fi
```

## Related Documentation

- [User Management CLI](./user.md) - General user account management with flexible roles
- [WebAuthn Guide](../webauthn.md) - WebAuthn/FIDO2 integration details
- [Getting Started](../getting-started.md) - Initial system setup and configuration

## Additional Resources

### FIDO2 Resources

- [FIDO Alliance](https://fidoalliance.org/) - FIDO2 specification and certification
- [WebAuthn Guide](https://webauthn.guide/) - WebAuthn introduction and examples
- [Yubico Developer](https://developers.yubico.com/) - YubiKey documentation

### Security Key Vendors

- [Yubico](https://www.yubico.com/) - YubiKey security keys
- [Google Titan](https://cloud.google.com/titan-security-key) - Google Titan keys
- [Feitian](https://www.ftsafe.com/) - FIDO2 security keys
- [SoloKeys](https://solokeys.com/) - Open-source security keys
