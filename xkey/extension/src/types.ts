// xKey AutoFill Extension - Shared Type Definitions
//
// Native messaging host name for Chrome/Firefox native messaging API.
export const NATIVE_HOST_NAME = 'com.automatethethings.xkey';

// ---------------------------------------------------------------------------
// Extension internal message types (background <-> content script <-> popup)
// ---------------------------------------------------------------------------

export type ExtensionMessage =
  | { type: 'search'; domain: string }
  | { type: 'fill'; id: string; challenge?: string }
  | { type: 'totp'; domain: string }
  | { type: 'totp_by_id'; id: string }
  | { type: 'status' }
  | { type: 'pairing_submit'; code: string }
  | { type: 'reconnect' }
  // Save-on-submit messages (content script -> background)
  | { type: 'check_credential'; domain: string; username: string }
  | { type: 'save_credential'; domain: string; username: string; password: string; title: string }
  | { type: 'ignore_domain'; domain: string }
  // Responses
  | { type: 'credentials'; data: Credential[] }
  | { type: 'fill_result'; data: FillResult }
  | { type: 'totp_result'; data: TOTPResult }
  | { type: 'status_result'; data: StatusResult }
  | { type: 'pairing_status'; required: boolean }
  | { type: 'reconnect_result'; connected: boolean; locked: boolean }
  | { type: 'check_result'; exists: boolean }
  | { type: 'save_result'; success: boolean }
  | { type: 'error'; message: string };

// ---------------------------------------------------------------------------
// Credential and result types
// ---------------------------------------------------------------------------

/** Credential returned from a search query. */
export interface Credential {
  id: string;
  title: string;
  username: string;
  url: string;
  has_totp: boolean;
  totp_id?: string;
}

/** Decrypted credential data for form filling. */
export interface FillResult {
  username: string;
  password: string;
  assertion?: {
    auth_data: string;
    signature: string;
    credential_id: string;
    public_key?: string;
  };
}

/** Time-based one-time password result. */
export interface TOTPResult {
  code: string;
  time_left: number;
  period: number;
  account_id: string;
  issuer: string;
}

/** Current status of the xKey autofill system. */
export interface StatusResult {
  available: boolean;
  app_locked: boolean;
  fill_mode: FillMode;
  extension_enabled: boolean;
}

// ---------------------------------------------------------------------------
// Policy types
// ---------------------------------------------------------------------------

/** Autofill policy returned from the native host. */
export interface AutoFillPolicy {
  fill_mode: FillMode;
  totp_policy: TOTPPolicy;
  session_timeout_sec: number;
  require_authentication: boolean;
  allowed_domains: string[];
  blocked_domains: string[];
  max_fills_per_minute: number;
  audit_enabled: boolean;
}

export type FillMode = 'click_to_fill' | 'auto_fill' | 'popup_only' | 'disabled';
export type TOTPPolicy = 'auto' | 'prompt' | 'disabled';

// ---------------------------------------------------------------------------
// Native messaging wire format (after session encryption layer)
// ---------------------------------------------------------------------------

/** Request sent to the native messaging host. */
export interface NativeRequest {
  type: string;       // IPC message type: "autofill"
  autofill: {
    action: string;   // "search", "get", "totp", "totp_by_id", "status", "policy"
    domain?: string;
    id?: string;
    challenge?: string;  // base64-encoded 32-byte random challenge for CTAP2 auth
  };
}

/** Response received from the native messaging host. */
export interface NativeResponse {
  status: string;     // "ok" or "error"
  error?: string;
  autofill?: {
    credentials?: Credential[];
    fill?: FillResult;
    totp?: TOTPResult;
    status?: StatusResult;
    policy?: AutoFillPolicy;
  };
}

// ---------------------------------------------------------------------------
// Pairing protocol message types
// ---------------------------------------------------------------------------

/** Host-to-extension: pairing required before session can proceed. */
export interface HandshakePairMessage {
  type: 'handshake_pair';
  pubkey: string;
  pairing_required: true;
}

/** Extension-to-host: submit pairing code with identity key. */
export interface PairingConfirmMessage {
  type: 'pairing_confirm';
  code: string;
  identity_key: string;
}

/** Host-to-extension: pairing result. */
export interface PairingResultMessage {
  type: 'pairing_ok' | 'pairing_failed';
  error?: string;
}

// ---------------------------------------------------------------------------
// Session encryption wire types
// ---------------------------------------------------------------------------

/** Encrypted message on the native messaging pipe (after handshake). */
export interface EncryptedMessage {
  type: 'encrypted';
  nonce: number;
  ciphertext: string; // base64-encoded AES-256-GCM ciphertext
}

/** Client-to-host handshake initiation. */
export interface HandshakeMessage {
  type: 'handshake';
  pubkey: string;         // base64-encoded X25519 public key
  identity_key?: string;  // base64-encoded Ed25519 public key
  identity_sig?: string;  // base64-encoded Ed25519 signature over handshake binding
  origin?: string;        // chrome-extension://ID/
}

/** Host-to-client handshake acknowledgement. */
export interface HandshakeOKMessage {
  type: 'handshake_ok';
  pubkey: string;     // base64-encoded X25519 public key
}
