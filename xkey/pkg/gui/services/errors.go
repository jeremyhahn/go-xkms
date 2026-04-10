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

import "errors"

// AppService errors.
var (
	// ErrAppConfigNil indicates a nil configuration was provided.
	ErrAppConfigNil = errors.New("app_service: nil configuration")

	// ErrAppFIDO2ToggleUnavailable indicates the FIDO2 toggle function has not been configured.
	ErrAppFIDO2ToggleUnavailable = errors.New("app_service: FIDO2 toggle function not configured")
)

// ConnectionService errors.
var (
	// ErrServerNotConnected indicates there is no active server connection.
	ErrServerNotConnected = errors.New("connection_service: not connected")

	// ErrServerAlreadyConnected indicates a connection is already active.
	ErrServerAlreadyConnected = errors.New("connection_service: already connected")

	// ErrInvalidProtocol indicates an unrecognized server protocol.
	ErrInvalidProtocol = errors.New("connection_service: invalid protocol")

	// ErrInvalidAddress indicates an empty or malformed server address.
	ErrInvalidAddress = errors.New("connection_service: invalid address")

	// ErrHealthCheckFailed indicates the server health check did not succeed.
	ErrHealthCheckFailed = errors.New("connection_service: health check failed")
)

// KeyService errors.
var (
	// ErrKeyServiceNoClient indicates the key service has no connected client.
	ErrKeyServiceNoClient = errors.New("key_service: no connected client")

	// ErrKeyInvalidRequest indicates the key service received an invalid request.
	ErrKeyInvalidRequest = errors.New("key_service: invalid request")

	// ErrKeyServiceNoLocalClient indicates the key service has no local client configured.
	ErrKeyServiceNoLocalClient = errors.New("key_service: no local client")

	// ErrFileReadFailed indicates that reading a file for a key operation failed.
	ErrFileReadFailed = errors.New("key_service: file read failed")

	// ErrFileWriteFailed indicates that writing a file for a key operation failed.
	ErrFileWriteFailed = errors.New("key_service: file write failed")

	// ErrKeyServiceNoRegistry indicates the key service has no backend registry configured.
	ErrKeyServiceNoRegistry = errors.New("key_service: registry not set")
)

// StorageService errors.
var (
	// ErrStorageRequiresRoot indicates the operation requires root privileges.
	ErrStorageRequiresRoot = errors.New("storage_service: operation requires root privileges")

	// ErrStorageInvalidSize indicates the volume size is outside the allowed range (1-100 GB).
	ErrStorageInvalidSize = errors.New("storage_service: invalid volume size")

	// ErrStorageWeakPassphrase indicates the passphrase is too short.
	ErrStorageWeakPassphrase = errors.New("storage_service: passphrase too short (minimum 8 characters)")

	// ErrStorageInvalidStandard indicates an unrecognized wipe standard.
	ErrStorageInvalidStandard = errors.New("storage_service: invalid wipe standard")
)

// TPMService errors for Phase 2 operations.
var (
	// ErrTPMDataDirNotSet indicates the data directory has not been configured.
	ErrTPMDataDirNotSet = errors.New("tpm_service: data directory not set")

	// ErrTPMInvalidHandle indicates an invalid TPM handle value was provided.
	ErrTPMInvalidHandle = errors.New("tpm_service: invalid handle")

	// ErrTPMInvalidAuth indicates an empty or missing authorization value.
	ErrTPMInvalidAuth = errors.New("tpm_service: invalid authorization value")

	// ErrTPMInvalidNVHandle indicates a handle outside the NV index range.
	ErrTPMInvalidNVHandle = errors.New("tpm_service: invalid NV index handle")

	// ErrTPMInvalidNVSize indicates an invalid NV data size.
	ErrTPMInvalidNVSize = errors.New("tpm_service: invalid NV data size")

	// ErrTPMInvalidNVData indicates empty or nil NV data.
	ErrTPMInvalidNVData = errors.New("tpm_service: invalid NV data")

	// ErrTPMInvalidProvisionMode indicates an unrecognized provision mode.
	ErrTPMInvalidProvisionMode = errors.New("tpm_service: invalid provision mode")

	// ErrTPMLockoutResetFailed indicates the lockout reset operation failed.
	ErrTPMLockoutResetFailed = errors.New("tpm_service: lockout reset failed")

	// ErrTPMClearFailed indicates the TPM clear operation failed.
	ErrTPMClearFailed = errors.New("tpm_service: TPM clear failed")

	// ErrTPMForceClearFailed indicates the TPM force clear via PPI failed.
	ErrTPMForceClearFailed = errors.New("tpm_service: TPM force clear via PPI failed")

	// ErrTPMElevationRequired indicates the operation requires privilege elevation.
	ErrTPMElevationRequired = errors.New("tpm_service: operation requires privilege elevation")

	// ErrTPMElevationUnavailable indicates privilege elevation is not available.
	ErrTPMElevationUnavailable = errors.New("tpm_service: privilege elevation unavailable")

	// ErrTPMInvalidCACert indicates an invalid CA certificate was provided.
	ErrTPMInvalidCACert = errors.New("tpm_service: invalid CA certificate")

	// ErrTPMHandleDescriptionFailed indicates failure to persist handle descriptions.
	ErrTPMHandleDescriptionFailed = errors.New("tpm_service: failed to persist handle description")

	// ErrTPMAuthRequired indicates the TPM operation requires hierarchy authorization.
	ErrTPMAuthRequired = errors.New("tpm_service: authorization required")

	// ErrTPMFactoryResetFailed indicates the factory reset operation failed.
	ErrTPMFactoryResetFailed = errors.New("tpm_service: factory reset failed")

	// ErrTPMProvisionIAKFailed indicates IAK provisioning failed.
	ErrTPMProvisionIAKFailed = errors.New("tpm_service: IAK provisioning failed")

	// ErrTPMProvisionIDevIDFailed indicates IDevID provisioning failed.
	ErrTPMProvisionIDevIDFailed = errors.New("tpm_service: IDevID provisioning failed")

	// ErrTPMInvalidPolicyName indicates an empty or invalid policy name.
	ErrTPMInvalidPolicyName = errors.New("tpm_service: invalid policy name")

	// ErrTPMPolicyExists indicates a policy with this name already exists.
	ErrTPMPolicyExists = errors.New("tpm_service: policy already exists")

	// ErrTPMPolicyNotFound indicates the requested policy was not found.
	ErrTPMPolicyNotFound = errors.New("tpm_service: policy not found")

	// ErrTPMPolicyExportFailed indicates the policy could not be exported.
	ErrTPMPolicyExportFailed = errors.New("tpm_service: policy export failed")

	// ErrTPMInvalidPolicyOperator indicates an invalid composite policy operator.
	ErrTPMInvalidPolicyOperator = errors.New("tpm_service: invalid policy operator (must be AND, OR, or SINGLE)")

	// ErrTPMInvalidPolicyType indicates an invalid policy type.
	ErrTPMInvalidPolicyType = errors.New("tpm_service: invalid policy type")

	// ErrTPMPasswordVerifyFailed indicates password verification failed.
	ErrTPMPasswordVerifyFailed = errors.New("tpm_service: password verification failed")

	// ErrTPMEventLogReplayFailed indicates the event log replay operation failed.
	ErrTPMEventLogReplayFailed = errors.New("tpm_service: event log replay failed")

	// ErrTPMPolicyNoDigests indicates the policy has no saved PCR digests to compare.
	ErrTPMPolicyNoDigests = errors.New("tpm_service: policy has no saved digests")

	// ErrTPMPolicyImportFailed indicates the policy file could not be imported.
	ErrTPMPolicyImportFailed = errors.New("tpm_service: policy import failed")

	// ErrTPMPolicyImportCancelled indicates the user cancelled the file dialog.
	ErrTPMPolicyImportCancelled = errors.New("tpm_service: import cancelled")

	// ErrTPMPolicySaveCancelled indicates the user cancelled the save dialog.
	ErrTPMPolicySaveCancelled = errors.New("tpm_service: save cancelled")
)

// OIDCService errors.
var (
	// ErrOIDCProviderNotFound indicates the requested OIDC provider was not found.
	ErrOIDCProviderNotFound = errors.New("oidc_service: provider not found")

	// ErrOIDCProviderExists indicates a provider with this name already exists.
	ErrOIDCProviderExists = errors.New("oidc_service: provider already exists")

	// ErrOIDCProviderNameRequired indicates the provider name is required.
	ErrOIDCProviderNameRequired = errors.New("oidc_service: provider name is required")

	// ErrOIDCInvalidProvider indicates an invalid provider configuration.
	ErrOIDCInvalidProvider = errors.New("oidc_service: invalid provider configuration")

	// ErrOIDCInvalidIssuer indicates an empty or invalid issuer URL.
	ErrOIDCInvalidIssuer = errors.New("oidc_service: invalid issuer URL")

	// ErrOIDCDiscoveryFailed indicates OIDC provider discovery failed.
	ErrOIDCDiscoveryFailed = errors.New("oidc_service: discovery failed")

	// ErrOIDCLoginFailed indicates the login operation failed.
	ErrOIDCLoginFailed = errors.New("oidc_service: login failed")

	// ErrOIDCCallbackFailed indicates the OAuth2 callback failed.
	ErrOIDCCallbackFailed = errors.New("oidc_service: callback failed")

	// ErrOIDCCallbackTimeout indicates the callback timed out waiting for the authorization code.
	ErrOIDCCallbackTimeout = errors.New("oidc_service: callback timeout")

	// ErrOIDCCallbackNoCode indicates no authorization code was received.
	ErrOIDCCallbackNoCode = errors.New("oidc_service: no authorization code received")

	// ErrOIDCStateMismatch indicates the state parameter did not match.
	ErrOIDCStateMismatch = errors.New("oidc_service: state mismatch")

	// ErrOIDCTokenExchangeFailed indicates the authorization code exchange failed.
	ErrOIDCTokenExchangeFailed = errors.New("oidc_service: token exchange failed")

	// ErrOIDCTokenNotFound indicates no token was found for the provider.
	ErrOIDCTokenNotFound = errors.New("oidc_service: token not found")

	// ErrOIDCTokenStoreUnavailable indicates the token store is not initialized.
	ErrOIDCTokenStoreUnavailable = errors.New("oidc_service: token store unavailable")

	// ErrOIDCNoRefreshToken indicates the stored token has no refresh token.
	ErrOIDCNoRefreshToken = errors.New("oidc_service: no refresh token available")

	// ErrOIDCRefreshFailed indicates the token refresh operation failed.
	ErrOIDCRefreshFailed = errors.New("oidc_service: token refresh failed")

	// ErrOIDCLogoutFailed indicates the logout operation failed.
	ErrOIDCLogoutFailed = errors.New("oidc_service: logout failed")

	// ErrOIDCAutoRefreshDisabled indicates auto-refresh is not configured for this provider.
	ErrOIDCAutoRefreshDisabled = errors.New("oidc_service: auto-refresh disabled for this provider")

	// ErrOIDCRefreshAlreadyRunning indicates a refresh loop is already active.
	ErrOIDCRefreshAlreadyRunning = errors.New("oidc_service: refresh already running")

	// ErrOIDCExecEmpty indicates an empty script was provided.
	ErrOIDCExecEmpty = errors.New("oidc_service: script is empty")

	// ErrOIDCExecFailed indicates script execution failed.
	ErrOIDCExecFailed = errors.New("oidc_service: script execution failed")

	// ErrOIDCUnsupportedAWSLogin indicates AWS login is not yet supported in the GUI.
	ErrOIDCUnsupportedAWSLogin = errors.New("oidc_service: AWS login not supported in GUI")

	// ErrOIDCTemplateNotFound indicates the requested provider template was not found.
	ErrOIDCTemplateNotFound = errors.New("oidc_service: template not found")

	// ErrOIDCScriptNameRequired indicates the script name is required.
	ErrOIDCScriptNameRequired = errors.New("oidc_service: script name is required")

	// ErrOIDCScriptContentRequired indicates the script content is required.
	ErrOIDCScriptContentRequired = errors.New("oidc_service: script content is required")

	// ErrOIDCScriptNotFound indicates the saved script was not found.
	ErrOIDCScriptNotFound = errors.New("oidc_service: script not found")

	// ErrOIDCScriptDirUnavailable indicates the script directory is not available.
	ErrOIDCScriptDirUnavailable = errors.New("oidc_service: script directory unavailable")
)

// ClipboardService errors.
var (
	// ErrClipboardToolUnavailable indicates no clipboard tool (xclip, xsel, wl-copy) was found.
	ErrClipboardToolUnavailable = errors.New("clipboard_service: no clipboard tool available")

	// ErrClipboardWriteFailed indicates writing to the clipboard failed.
	ErrClipboardWriteFailed = errors.New("clipboard_service: write failed")

	// ErrClipboardReadFailed indicates reading from the clipboard failed.
	ErrClipboardReadFailed = errors.New("clipboard_service: read failed")
)

// PINService errors.
var (
	// ErrPINServiceNotConfigured indicates the PIN service has not been wired.
	ErrPINServiceNotConfigured = errors.New("pin_service: not configured")
)

// CertificateService errors.
var (
	// ErrCertServiceNoClient indicates the certificate service has no connected client.
	ErrCertServiceNoClient = errors.New("certificate_service: no connected client")
)

// SetupWizardService errors.
var (
	// ErrSetupAlreadyComplete indicates setup has already been completed.
	ErrSetupAlreadyComplete = errors.New("setup_wizard: setup already complete")

	// ErrSetupInvalidMode indicates an invalid operating mode was specified.
	ErrSetupInvalidMode = errors.New("setup_wizard: invalid mode")

	// ErrSetupStorageFailed indicates encrypted storage creation failed.
	ErrSetupStorageFailed = errors.New("setup_wizard: storage creation failed")

	// ErrSetupPasswordFailed indicates master password setup failed.
	ErrSetupPasswordFailed = errors.New("setup_wizard: master password setup failed")

	// ErrSetupUserPINRequired indicates that a user PIN is required for setup.
	ErrSetupUserPINRequired = errors.New("setup_wizard: user PIN is required")

	// ErrSetupSOPINRequired indicates that an SO PIN is required for setup.
	ErrSetupSOPINRequired = errors.New("setup_wizard: SO PIN is required")

	// ErrSetupPINGenerationFailed indicates that random PIN generation failed.
	ErrSetupPINGenerationFailed = errors.New("setup_wizard: PIN generation failed")
)

// BarrierService errors.
var (
	// ErrBarrierNotInitialized indicates the barrier has not been initialized.
	ErrBarrierNotInitialized = errors.New("barrier_service: not initialized")

	// ErrBarrierAlreadyInit indicates the barrier has already been initialized.
	ErrBarrierAlreadyInit = errors.New("barrier_service: already initialized")

	// ErrBarrierPasswordRequired indicates a password is required for the software strategy.
	ErrBarrierPasswordRequired = errors.New("barrier_service: password required for software strategy")

	// ErrBarrierResealFailed indicates the barrier root key re-seal failed
	// during a password change operation.
	ErrBarrierResealFailed = errors.New("barrier_service: barrier re-seal failed")
)

// ErrBarrierStrategyUnavailable indicates the selected barrier strategy
// could not be created (e.g. TPM not available or CanSeal returned false).
type ErrBarrierStrategyUnavailable struct {
	Strategy string
}

func (e *ErrBarrierStrategyUnavailable) Error() string {
	return "barrier_service: strategy unavailable: " + e.Strategy
}

// AuthService errors.
var (
	// ErrAuthRequired indicates the user must authenticate before proceeding.
	ErrAuthRequired = errors.New("auth_service: authentication required")

	// ErrAuthSORequired indicates SO PIN authentication is required for this operation.
	ErrAuthSORequired = errors.New("auth_service: SO PIN authentication required")

	// ErrAuthInvalidCredentials indicates the provided credentials were incorrect.
	ErrAuthInvalidCredentials = errors.New("auth_service: invalid credentials")

	// ErrAuthAlreadyLoggedIn indicates the user is already authenticated.
	ErrAuthAlreadyLoggedIn = errors.New("auth_service: already logged in")
)

// AppLockService errors.
var (
	// ErrAppLockAlreadyLocked indicates the app is already locked.
	ErrAppLockAlreadyLocked = errors.New("app_lock: already locked")

	// ErrAppLockAlreadyUnlocked indicates the app is already unlocked.
	ErrAppLockAlreadyUnlocked = errors.New("app_lock: already unlocked")

	// ErrAppLockPINRequired indicates a PIN is required to unlock the app.
	ErrAppLockPINRequired = errors.New("app_lock: PIN required")

	// ErrAppLockPINInvalid indicates the provided PIN was incorrect.
	ErrAppLockPINInvalid = errors.New("app_lock: invalid PIN")

	// ErrAppLockSetupIncomplete indicates the app setup is incomplete.
	// This occurs when the barrier was never initialized or the PIN was
	// never set. The user should reset their config and re-run the wizard.
	ErrAppLockSetupIncomplete = errors.New("app_lock: setup incomplete - please reset config and re-run setup wizard")

	// ErrAppLockBarrierInitFailed indicates that the barrier could not be
	// initialized during unlock. This is a critical error that prevents
	// data from being stored securely.
	ErrAppLockBarrierInitFailed = errors.New("app_lock: barrier initialization failed - encrypted storage unavailable")
)

// CustodianService errors.
var (
	// ErrCustodianServiceNoClient indicates the custodian service has no connected client.
	ErrCustodianServiceNoClient = errors.New("custodian_service: no connected client")

	// ErrCustodianGroupNameRequired indicates a group name is required.
	ErrCustodianGroupNameRequired = errors.New("custodian_service: group name is required")

	// ErrCustodianGroupIDRequired indicates a group ID is required.
	ErrCustodianGroupIDRequired = errors.New("custodian_service: group ID is required")

	// ErrCustodianUserIDRequired indicates a user ID is required.
	ErrCustodianUserIDRequired = errors.New("custodian_service: user ID is required")

	// ErrCustodianInvalidThreshold indicates the threshold must be at least 1.
	ErrCustodianInvalidThreshold = errors.New("custodian_service: threshold must be at least 1")

	// ErrCustodianInvalidTotal indicates the total must be at least threshold.
	ErrCustodianInvalidTotal = errors.New("custodian_service: total must be >= threshold")
)

// TenantService errors.
var (
	// ErrTenantServiceNoClient indicates the tenant service has no connected client.
	ErrTenantServiceNoClient = errors.New("tenant_service: no connected client")

	// ErrTenantNameRequired indicates a tenant name is required.
	ErrTenantNameRequired = errors.New("tenant_service: tenant name is required")

	// ErrTenantIDRequired indicates a tenant ID is required.
	ErrTenantIDRequired = errors.New("tenant_service: tenant ID is required")
)

// SetupWizardService enterprise errors.
var (
	// ErrSetupInvalidDeploymentMode indicates an invalid deployment mode was specified.
	ErrSetupInvalidDeploymentMode = errors.New("setup_wizard: invalid deployment mode")

	// ErrSetupSOPINVerifyFailed indicates the SO PIN verification failed during user onboarding.
	ErrSetupSOPINVerifyFailed = errors.New("setup_wizard: SO PIN verification failed")

	// ErrSetupNotSOProvisioned indicates SO provisioning has not been completed yet.
	ErrSetupNotSOProvisioned = errors.New("setup_wizard: SO provisioning not completed")

	// ErrPolicyTamperDetected indicates the security policy has been tampered with.
	ErrPolicyTamperDetected = errors.New("setup_wizard: policy tamper detected")

	// ErrPolicyVerificationRequired indicates the policy must be verified before proceeding.
	ErrPolicyVerificationRequired = errors.New("setup_wizard: policy verification required")
)

// BackupService errors.
var (
	// ErrBackupInvalidPath indicates an empty or invalid backup file path.
	ErrBackupInvalidPath = errors.New("staticpw_service: invalid backup file path")

	// ErrBackupPasswordRequired indicates a password is required for encrypted backups.
	ErrBackupPasswordRequired = errors.New("staticpw_service: password required for encrypted backup")

	// ErrBackupInvalidAlgorithm indicates an unrecognized encryption algorithm.
	ErrBackupInvalidAlgorithm = errors.New("staticpw_service: invalid algorithm (use aes-128, aes-192, or aes-256)")

	// ErrBackupFailed indicates the backup operation failed.
	ErrBackupFailed = errors.New("staticpw_service: backup failed")

	// ErrRestoreInvalidPath indicates an empty or invalid restore file path.
	ErrRestoreInvalidPath = errors.New("staticpw_service: invalid restore file path")

	// ErrRestoreDecryptFailed indicates decryption of the backup file failed (wrong password or corrupt data).
	ErrRestoreDecryptFailed = errors.New("staticpw_service: decryption failed (wrong password or corrupt file)")

	// ErrRestoreParseFailed indicates the backup file could not be parsed as valid JSON.
	ErrRestoreParseFailed = errors.New("staticpw_service: failed to parse backup file")

	// ErrRestoreFailed indicates the restore operation failed.
	ErrRestoreFailed = errors.New("staticpw_service: restore failed")
)

// TPM handle allocator errors.
var (
	// ErrTPMInvalidHierarchy indicates an unrecognized TPM hierarchy name.
	ErrTPMInvalidHierarchy = errors.New("tpm_handle_allocator: invalid hierarchy")

	// ErrTPMHandleRangeExhausted indicates all handles in the hierarchy range have been allocated.
	ErrTPMHandleRangeExhausted = errors.New("tpm_handle_allocator: handle range exhausted")

	// ErrTPMHandleOutOfRange indicates the provided handle value is outside the valid range.
	ErrTPMHandleOutOfRange = errors.New("tpm_handle_allocator: handle out of range")
)

// NV index allocator errors.
var (
	// ErrNVIndexRangeExhausted indicates all NV indices in the owner-defined range have been allocated.
	ErrNVIndexRangeExhausted = errors.New("nv_index_allocator: NV index range exhausted")

	// ErrNVIndexOutOfRange indicates the provided NV index value is outside the valid range.
	ErrNVIndexOutOfRange = errors.New("nv_index_allocator: NV index out of valid range")
)
