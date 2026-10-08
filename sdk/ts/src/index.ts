// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

// The xterm-backed SSH console lives on the "@go-xkms/sdk/ssh-console"
// subpath, not here. It is a client-side terminal (xkey renders it against
// xkey's own loopback bridge — the xkms server never terminates SSH), and
// re-exporting it from the root would drag xterm into the initial bundle of
// every consumer that only talks to the REST API.

export {
  parseControl,
  encodeResize,
  encodeHostKeyResponse,
  type ServerControl,
  type HostKeyMode,
} from './protocol.js';

// ---------------------------------------------------------------------------
// REST client core
// ---------------------------------------------------------------------------

export {
  XkmsApiError,
  XkmsNetworkError,
  parseErrorEnvelope,
  type ErrorEnvelope,
} from './errors.js';

export {
  DEFAULT_AUTH_PATHS,
  resolveAuthPaths,
  type AuthPaths,
  type TokenProvider,
  type XkmsClientConfig,
} from './config.js';

export {
  HttpCore,
  buildURL,
  encodePathSegment,
  type HttpMethod,
  type HttpResult,
  type QueryParams,
  type RequestOptions,
} from './http.js';

export { isWailsRuntime } from './wails.js';

export { XkmsClient, createClient } from './client.js';

// ---------------------------------------------------------------------------
// WebAuthn wire bridge (go-webauthn base64url JSON <-> browser BufferSource)
// ---------------------------------------------------------------------------

export {
  WebAuthnEnvelopeError,
  base64urlToBuffer,
  bufferToBase64url,
  encodeAssertionResponse,
  encodeAttestationResponse,
  parseCreationOptions,
  parseRequestOptions,
  type AssertionCredentialJSON,
  type AttestationCredentialJSON,
} from './webauthn.js';

// ---------------------------------------------------------------------------
// Password-vault passkeys in the browser (WebAuthn PRF)
// ---------------------------------------------------------------------------

export {
  VAULT_PASSKEY_RP_NAME,
  VaultPasskeyPrfUnsupportedError,
  VaultPasskeyUnavailableError,
  bufferToBase64,
  enrollVaultPasskey,
  relyingPartyServes,
  unlockVaultPasskey,
  type EnrollVaultPasskeyOptions,
  type VaultPasskeyPlatform,
} from './vaultPasskey.js';

export {
  XKEY_PING_TIMEOUT_MS,
  XKEY_UNLOCK_TIMEOUT_MS,
  XkeyBridgeError,
  XkeyExtensionUnavailableError,
  detectXkeyExtension,
  keyFactorFingerprints,
  unlockWithXkey,
  type BridgeWindow,
} from './vaultBridge.js';

// ---------------------------------------------------------------------------
// Domain clients
// ---------------------------------------------------------------------------

export { HealthClient } from './clients/health.js';
export { CapabilitiesClient } from './clients/capabilities.js';
export { AuthClient, HEADER_SESSION_ID } from './clients/auth.js';
export { BackendsClient } from './clients/backends.js';
export { KeysClient } from './clients/keys.js';
export { KeyVersionsClient } from './clients/keyVersions.js';
export { CertsClient } from './clients/certs.js';
export { SealClient } from './clients/seal.js';
export { FrostClient } from './clients/frost.js';
export { PinClient } from './clients/pin.js';
export { PivClient } from './clients/piv.js';
export { CaClient } from './clients/ca.js';
export { TenantsClient } from './clients/tenants.js';
export { PasswordsClient } from './clients/passwords.js';
export {
  OidcCredentialClient,
  OIDCDeviceLoginError,
  type OIDCDeviceLoginFailure,
  type WaitForDeviceLoginOptions,
} from './clients/oidcCredential.js';
export { PlatformClient } from './clients/platform.js';
export { TpmPolicyClient, pcrBranch } from './clients/tpmPolicy.js';
export { CredentialsClient } from './clients/credentials.js';
export { UsersClient } from './clients/users.js';
export { SshClient } from './clients/ssh.js';

// ---------------------------------------------------------------------------
// Wire types (request/response DTOs mirroring the Go json tags)
// ---------------------------------------------------------------------------

export type * from './types/common.js';
export type * from './types/health.js';
export type * from './types/backends.js';
export type * from './types/keys.js';
export type * from './types/keyVersions.js';
export type * from './types/certs.js';
export type * from './types/seal.js';
export type * from './types/frost.js';
export type * from './types/pin.js';
export type * from './types/piv.js';
export type * from './types/ca.js';
export type * from './types/tenants.js';
export type * from './types/passwords.js';
export type * from './types/oidcCredential.js';
export type * from './types/platform.js';
export type * from './types/tpmPolicy.js';
export type * from './types/credentials.js';
export type * from './types/users.js';
export type * from './types/auth.js';
export type * from './types/ssh.js';
