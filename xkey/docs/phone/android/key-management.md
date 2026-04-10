# Unified Key Store

## Overview

The Android app uses a single Room database table (`keys`) as the unified source of truth for all key types. This replaces the FIDO2-only `credential_metadata` table with a general-purpose key entity that supports FIDO2 credentials, SSH keys, TLS certificates, signing keys, encryption keys, and symmetric keys.

## KeyEntity Schema

```kotlin
@Entity(tableName = "keys", indices = [
    Index(value = ["key_id"], unique = true),
    Index(value = ["key_type"]),
    Index(value = ["algorithm"]),
])
data class KeyEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    @ColumnInfo(name = "key_id") val keyId: String,
    @ColumnInfo(name = "key_type") val keyType: String,       // "fido2", "ssh", "tls", "signing", "encryption", "symmetric"
    @ColumnInfo(name = "algorithm") val algorithm: String,    // "ES256", "ES384", "ES512", "RS256", etc.
    @ColumnInfo(name = "label") val label: String,
    @ColumnInfo(name = "public_key_der") val publicKeyDer: ByteArray? = null,
    @ColumnInfo(name = "public_key_cose") val publicKeyCose: ByteArray? = null,
    @ColumnInfo(name = "key_size_bits") val keySizeBits: Int,
    @ColumnInfo(name = "strongbox_backed") val strongBoxBacked: Boolean = false,
    @ColumnInfo(name = "biometric_required") val biometricRequired: Boolean = true,
    @ColumnInfo(name = "auth_duration_seconds") val authDurationSeconds: Int = 5,
    @ColumnInfo(name = "exportable") val exportable: Boolean = false,
    @ColumnInfo(name = "shareable") val shareable: Boolean = false,
    @ColumnInfo(name = "source") val source: String,          // "local", "remote_ble", "remote_usb", "xkmsd"
    @ColumnInfo(name = "use_count") val useCount: Long = 0,
    @ColumnInfo(name = "created_at") val createdAt: Long,
    @ColumnInfo(name = "last_used_at") val lastUsedAt: Long = 0,
    // FIDO2-specific
    @ColumnInfo(name = "rp_id") val rpId: String? = null,
    @ColumnInfo(name = "rp_name") val rpName: String? = null,
    @ColumnInfo(name = "user_id") val userId: String? = null,
    @ColumnInfo(name = "user_name") val userName: String? = null,
    @ColumnInfo(name = "user_display_name") val userDisplayName: String? = null,
    @ColumnInfo(name = "is_discoverable") val isDiscoverable: Boolean = false,
    @ColumnInfo(name = "sign_count") val signCount: Long = 0,
)
```

## Key Types

| Type | Description | Algorithms |
|------|-------------|------------|
| `fido2` | WebAuthn/FIDO2 credentials | ES256, ES384, ES512 |
| `ssh` | SSH authentication keys | ES256, ES384, RS256 |
| `tls` | TLS client certificates | EC, RSA |
| `signing` | General-purpose signing | EC, RSA |
| `encryption` | RSA encryption | RSA2048-4096 |
| `symmetric` | Symmetric encryption/HMAC | AES128, AES256, HMAC-SHA256/512 |

## Key Sources

| Source | Description | Key Material Location |
|--------|-------------|----------------------|
| `local` | Created by CredentialProvider | Android Keystore |
| `remote_ble` | Created by laptop over BLE | Android Keystore |
| `remote_usb` | Created by laptop over USB | Android Keystore |
| `xkmsd` | Reference to laptop key | Laptop xkmsd backend |

Keys with `source = "xkmsd"` are references only. The private key material lives on the laptop. All cryptographic operations on these keys are proxied through `RemoteKeyClient` over the Noise-encrypted channel.

## KeyDao Queries

```kotlin
@Dao
interface KeyDao {
    @Query("SELECT * FROM keys ORDER BY last_used_at DESC")
    fun observeAll(): Flow<List<KeyEntity>>

    @Query("SELECT * FROM keys WHERE key_type = :type ORDER BY last_used_at DESC")
    suspend fun getByType(type: String): List<KeyEntity>

    @Query("SELECT * FROM keys WHERE key_id = :keyId")
    suspend fun getByKeyId(keyId: String): KeyEntity?

    @Query("SELECT * FROM keys WHERE key_type = 'fido2' AND rp_id = :rpId")
    suspend fun getFido2ByRpId(rpId: String): List<KeyEntity>

    @Query("SELECT * FROM keys WHERE key_type = 'fido2' AND rp_id = :rpId AND shareable = 1")
    suspend fun getShareableFido2ByRpId(rpId: String): List<KeyEntity>

    @Query("SELECT * FROM keys WHERE key_type = 'fido2' AND rp_id = :rpId AND is_discoverable = 1")
    suspend fun getDiscoverableFido2ByRpId(rpId: String): List<KeyEntity>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(key: KeyEntity): Long

    @Query("UPDATE keys SET use_count = use_count + 1, last_used_at = :timestamp WHERE key_id = :keyId")
    suspend fun recordUsage(keyId: String, timestamp: Long)

    @Query("UPDATE keys SET sign_count = :signCount WHERE key_id = :keyId")
    suspend fun updateSignCount(keyId: String, signCount: Long)

    @Query("DELETE FROM keys WHERE key_id = :keyId")
    suspend fun deleteByKeyId(keyId: String)

    @Query("SELECT COUNT(*) FROM keys")
    suspend fun count(): Int

    @Query("SELECT DISTINCT key_type FROM keys")
    suspend fun getKeyTypes(): List<String>
}
```

## Database Migration (v1 to v2)

The migration preserves existing FIDO2 credentials while introducing the unified schema.

**Steps:**

1. Create the `keys` table with the full schema and indices
2. Migrate existing `credential_metadata` rows into `keys` with `key_type = "fido2"` and `source = "local"`
3. Retain `credential_metadata` table for backward compatibility with `CredentialProviderService`

```kotlin
val MIGRATION_1_2 = object : Migration(1, 2) {
    override fun migrate(db: SupportSQLiteDatabase) {
        db.execSQL("""
            CREATE TABLE IF NOT EXISTS keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                key_id TEXT NOT NULL,
                key_type TEXT NOT NULL,
                algorithm TEXT NOT NULL,
                -- ... remaining columns ...
                UNIQUE(key_id)
            )
        """)
        db.execSQL("CREATE INDEX IF NOT EXISTS index_keys_key_id ON keys (key_id)")
        db.execSQL("CREATE INDEX IF NOT EXISTS index_keys_key_type ON keys (key_type)")
        db.execSQL("CREATE INDEX IF NOT EXISTS index_keys_algorithm ON keys (algorithm)")

        db.execSQL("""
            INSERT INTO keys (key_id, key_type, algorithm, label, public_key_cose,
                key_size_bits, strongbox_backed, biometric_required, source,
                created_at, rp_id, rp_name, user_id, user_name,
                user_display_name, is_discoverable, sign_count)
            SELECT credential_id, 'fido2', algorithm, rp_name, public_key_cose,
                256, strongbox_backed, 1, 'local',
                created_at, rp_id, rp_name, user_id, user_name,
                user_display_name, is_discoverable, sign_count
            FROM credential_metadata
        """)
    }
}
```

## Sync with CredentialProviderService

The `keys` table stays in sync with Android's Credential Provider framework.

**After registration (`CreateCredentialHandler`):**

1. CredentialProvider creates the FIDO2 credential in Android Keystore
2. Inserts metadata into `credential_metadata` (for CredentialProvider queries)
3. Inserts into `keys` table with `key_type = "fido2"`, `source = "local"`

**After authentication (`GetCredentialHandler`):**

1. CredentialProvider performs the assertion
2. Updates `use_count` and `last_used_at` in `keys` via `KeyDao.recordUsage()`
3. Updates `sign_count` via `KeyDao.updateSignCount()`

This dual-write ensures both the CredentialProvider framework and the unified key management UI have consistent data.
