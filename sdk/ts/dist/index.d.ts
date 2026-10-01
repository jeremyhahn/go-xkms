/**
 * The WebSocket console protocol (implemented by the go-xkms console bridge,
 * pkg/ssh/console):
 *   - BINARY message  = raw terminal bytes (server→client: output; client→server: keystrokes)
 *   - TEXT message    = JSON control frame
 *       client→server: { "type": "resize", "rows": R, "cols": C }
 *       client→server: { "type": "hostkey-response", "accept": true|false }
 *       server→client: { "type": "error", "message": "..." } | { "type": "exit" }
 *       server→client: { "type": "hostkey", "host": "...", "key_type": "...",
 *                         "fingerprint": "SHA256:...", "known": false,
 *                         "mode": "confirm"|"notify" }
 *
 * The "hostkey" frame's mode determines the semantics: "confirm" means the
 * server has paused the SSH handshake awaiting a "hostkey-response" frame
 * (subject to a server-side timeout); "notify" means the server already
 * decided under its own accept-new policy and is only informing the client
 * — no response is expected (sending one anyway is harmless; the server
 * ignores unknown or late frames).
 *
 * These helpers are framework- and DOM-free so the protocol can be tested and
 * reused independently of xterm.js.
 */
/** hostkey confirmation mode: "confirm" pauses the handshake for a response; "notify" is informational only. */
type HostKeyMode = 'confirm' | 'notify';
/** A server→client control frame. */
type ServerControl = {
    type: 'error';
    message?: string | undefined;
} | {
    type: 'exit';
} | {
    type: 'hostkey';
    host: string;
    key_type: string;
    fingerprint: string;
    known: boolean;
    mode: HostKeyMode;
};
/** parseControl parses a TEXT control frame; returns null if not a known control. */
declare function parseControl(data: string): ServerControl | null;
/** encodeResize renders a client→server resize control frame. */
declare function encodeResize(rows: number, cols: number): string;
/** encodeHostKeyResponse renders a client→server hostkey-response control frame. */
declare function encodeHostKeyResponse(accept: boolean): string;

/**
 * Error types shared by every domain client.
 *
 * The xkms REST server writes a small JSON envelope on failure
 * (pkg/api/rest/errors.go writeError / writeErrorWithMessage):
 *
 *   { "error": "<error string>", "message": "<optional detail>", "code": <http status> }
 *
 * The SSH routes use a sibling envelope (pkg/api/rest/handlers_ssh.go
 * sshErrorEnvelope) that carries additional context fields, and the WebAuthn
 * routes use { "error": "<code>", "message": "<detail>" }. All three shapes
 * funnel into XkmsApiError.
 */
/** The REST error envelope as written by the server. */
interface ErrorEnvelope {
    error: string;
    message?: string;
    code?: number;
    /** SSH envelope extras (409 host-key mismatch, 404 resource, ...). */
    resource?: string;
    host?: string;
    expected?: string;
    received?: string;
}
/**
 * XkmsApiError is thrown when the server answered with a non-2xx status.
 * `code` is the machine-readable error string from the envelope's `error`
 * member (or `http_<status>` when the body was not a JSON envelope);
 * `message` prefers the envelope's human-readable `message`, then `error`,
 * then the HTTP status text. `correlationId` carries the X-Correlation-ID
 * response header when the server emitted one.
 */
declare class XkmsApiError extends Error {
    readonly status: number;
    readonly code: string;
    readonly correlationId: string | undefined;
    /** The parsed error envelope, when the body was JSON. */
    readonly envelope: ErrorEnvelope | undefined;
    constructor(status: number, code: string, message: string, correlationId?: string, envelope?: ErrorEnvelope);
}
/**
 * XkmsNetworkError is thrown when the request never produced an HTTP
 * response (DNS failure, refused connection, aborted fetch, CORS block).
 */
declare class XkmsNetworkError extends Error {
    readonly cause2: unknown;
    constructor(message: string, cause?: unknown);
}
/**
 * parseErrorEnvelope maps a failed HTTP response body to an XkmsApiError.
 * Tolerates non-JSON bodies (proxies, HTML error pages).
 */
declare function parseErrorEnvelope(status: number, statusText: string, bodyText: string, correlationId?: string): XkmsApiError;

/**
 * TokenProvider yields the current bearer token. It runs once per request so
 * a refreshing session store can always hand out the newest access token.
 * Return an empty string (or undefined-equivalent empty value) to send the
 * request without an Authorization header.
 */
type TokenProvider = () => string | Promise<string>;
/** Session/auth endpoint paths, overridable per deployment. */
interface AuthPaths {
    loginCert: string;
    refresh: string;
    validate: string;
    logout: string;
    me: string;
    capabilities: string;
}
/** The default auth endpoint paths served by xkmsd's REST transport. */
declare const DEFAULT_AUTH_PATHS: AuthPaths;
/** XkmsClientConfig configures the XkmsClient facade and every domain client. */
interface XkmsClientConfig {
    /** Server origin, e.g. `https://xkms.example.com:8443`. */
    baseURL: string;
    /** Optional bearer token source, resolved per request. */
    token?: TokenProvider;
    /** Injectable fetch (tests, Node polyfills). Defaults to globalThis.fetch. */
    fetch?: typeof fetch;
    /** Auth endpoint path overrides; missing members use DEFAULT_AUTH_PATHS. */
    authPaths?: Partial<AuthPaths>;
}
/** resolveAuthPaths merges configured overrides over the defaults. */
declare function resolveAuthPaths(overrides?: Partial<AuthPaths>): AuthPaths;

/**
 * The single HTTP request core every domain client routes through. Nothing
 * else in the SDK builds URLs, attaches Authorization headers, or decodes
 * error envelopes — this module is the one place those concerns live.
 */

/** Query values; undefined / null / '' members are omitted from the URL. */
type QueryParams = Record<string, string | number | boolean | undefined | null>;
/** HTTP methods used by the xkms REST surface. */
type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'HEAD';
/** Per-request options for the core. */
interface RequestOptions {
    /** Query string parameters appended to the path. */
    query?: QueryParams;
    /** JSON body; serialized when not undefined. */
    body?: unknown;
    /** Extra request headers (e.g. X-Session-Id for WebAuthn ceremonies). */
    headers?: Record<string, string>;
    /** Attach `Authorization: Bearer <token>` (default true when a token provider exists). */
    auth?: boolean;
    /** fetch credentials mode (loginCert uses 'include' for the mTLS exchange). */
    credentials?: RequestCredentials;
    /** How to decode a successful response body. Default 'json'; 204 always yields undefined. */
    parse?: 'json' | 'text' | 'void';
    /** Non-2xx statuses that resolve instead of throwing (e.g. HEAD 404 existence probes). */
    okOn?: number[];
}
/** A decoded response paired with the raw Response (for header access). */
interface HttpResult<T> {
    data: T;
    response: Response;
}
/** buildURL joins baseURL + path and encodes query parameters. */
declare function buildURL(baseURL: string, path: string, query?: QueryParams): string;
/** encodePathSegment escapes a single URL path segment (share server URLs, hostnames, ...). */
declare function encodePathSegment(segment: string): string;
/** HttpCore issues authenticated JSON requests against one xkms server. */
declare class HttpCore {
    readonly baseURL: string;
    private readonly token;
    private readonly fetchImpl;
    constructor(config: Pick<XkmsClientConfig, 'baseURL' | 'token' | 'fetch'>);
    /** request performs a call and returns the decoded body. */
    request<T>(method: HttpMethod, path: string, opts?: RequestOptions): Promise<T>;
    /** requestRaw performs a call and returns the decoded body plus the Response. */
    requestRaw<T>(method: HttpMethod, path: string, opts?: RequestOptions): Promise<HttpResult<T>>;
}

/**
 * isWailsRuntime reports whether the page is being served inside a Wails
 * desktop shell (window.go bindings / window.runtime bridge present). Web
 * UIs that ship both as a hosted SPA and as a desktop app use this to pick
 * between the REST client and native Wails bindings.
 */
declare function isWailsRuntime(): boolean;

/**
 * Shared wire primitives. Go `[]byte` members marshal as standard base64
 * strings; Go `time.Time` members marshal as RFC 3339 strings.
 */
/** A Go []byte on the wire: standard base64 (encoding/json default). */
type Base64 = string;
/** A Go time.Time on the wire: RFC 3339 timestamp string. */
type RFC3339 = string;
/**
 * Pagination query parameters accepted by list endpoints
 * (pkg/api/transport/pagination.go PageRequestFromQuery): page, page_size,
 * sort_field, sort_order ('desc'/'1' = descending). page and page_size must
 * be integers on the wire -- a non-numeric value is rejected with 400
 * rather than silently defaulting to an unpaginated request.
 */
interface PageQuery {
    page?: number;
    page_size?: number;
    sort_field?: string;
    sort_order?: 'asc' | 'desc';
}
/** Mirrors pkg/api/transport/pagination.go PageResponse. */
interface PageResponse {
    page: number;
    page_size: number;
    total: number;
    has_more: boolean;
}
/** Mirrors pkg/api/rest/types.go SuccessResponse. */
interface SuccessResponse {
    success: boolean;
    message?: string;
}

/**
 * Audit chain DTOs. Mirrors pkg/api/rest/handlers_audit.go and
 * pkg/api/transport/types.go (AuditEvent / AuditFilter / AuditPage). There is
 * deliberately no request/response pair for writing an event: audit records
 * are produced server-side as a side effect of the operation being audited.
 */

/**
 * One record from the tamper-evident audit chain. `prev_hash` is the chain
 * link that makes the log verifiable — carry it through, never drop it.
 */
interface AuditEvent {
    timestamp: RFC3339;
    actor: string;
    tenant_id?: string;
    role?: string;
    resource: string;
    action: string;
    outcome: string;
    attributes?: Record<string, unknown>;
    client_ip?: string;
    request_id?: string;
    prev_hash?: string;
}
/**
 * Query filter for GET /api/v1/audit/. Every field is optional; a zero/empty
 * field must be omitted from the request entirely rather than sent blank.
 */
interface AuditFilter {
    /** RFC3339 lower bound (inclusive), unbounded when absent. */
    from?: RFC3339;
    /** RFC3339 upper bound (exclusive), unbounded when absent. */
    to?: RFC3339;
    actor?: string;
    resource?: string;
    action?: string;
    outcome?: string;
    tenant_id?: string;
    /** Server clamps: absent/0 -> 100, max 1000. */
    limit?: number;
    /** Opaque continuation token from a previous page's `next`. */
    cursor?: string;
}
/**
 * One page of audit events. `next` is empty/absent on the last page; it is a
 * cursor, not an offset, because an append-only chain shifts under an offset
 * between pages.
 */
interface AuditPage {
    events: AuditEvent[];
    next?: string;
    total: number;
}

/**
 * Read access to the tamper-evident audit chain owned by the embedded
 * go-qrdb node. There is no write method here, and there should never be
 * one: audit events are recorded server-side as a side effect of the
 * operation being audited, so a caller cannot forge a record or backdate the
 * chain.
 */
declare class AuditClient {
    private readonly http;
    constructor(http: HttpCore);
    /**
     * GET /api/v1/audit/
     *
     * Every filter field is an optional query parameter; `buildURL` drops
     * undefined/null/empty-string values, so an absent field is simply not
     * sent rather than sent blank. Paging is by opaque cursor: pass a prior
     * page's `next` back as `cursor` to continue, and stop once `next` is
     * empty or absent.
     */
    query(filter?: AuditFilter): Promise<AuditPage>;
    /**
     * queryAll follows the `next` cursor across pages, yielding each
     * AuditPage.query() returns, and stops as soon as a page's `next` is
     * empty/absent (the last page). `maxPages` bounds the number of requests
     * this can issue — an append-only chain that never stops handing back a
     * `next` cursor would otherwise loop forever — and defaults to
     * DEFAULT_MAX_PAGES (100).
     */
    queryAll(filter?: AuditFilter, maxPages?: number): AsyncGenerator<AuditPage, void, void>;
}

/**
 * Session / WebAuthn DTOs. Mirrors pkg/api/rest/handlers_auth.go and
 * pkg/webauthn/http/types.go.
 */
/** Mirrors handlers_auth.go authTokenResponse (login/piv, refresh). */
interface TokenResponse {
    access_token: string;
    refresh_token: string;
    token_type: string;
    expires_in: number;
}
/** Mirrors handlers_auth.go authRefreshRequest (refresh, logout). */
interface RefreshRequest {
    refresh_token: string;
}
/** Mirrors handlers_auth.go authMeResponse (GET /api/v1/auth/me). */
interface AuthMeResponse {
    subject: string;
    tenant_id?: string;
    username?: string;
    /** Canonical tenant-unique login key; absent for principals without one. */
    email?: string;
    display_name?: string;
    auth_method?: string;
    roles?: string[];
    /** "resource:action" -> allowed */
    permissions: Record<string, boolean>;
    /** capability flag -> wired */
    capabilities: Record<string, boolean>;
}
/** Mirrors handlers_auth.go authValidateResponse (GET /api/v1/auth/validate). */
interface AuthValidateResponse {
    subject: string;
    tenant_id?: string;
}
/** Mirrors pkg/webauthn/http/types.go BeginRegistrationRequest. */
interface WebAuthnBeginRegistrationRequest {
    email: string;
    display_name?: string;
}
/** Mirrors pkg/webauthn/http/types.go BeginLoginRequest. */
interface WebAuthnBeginLoginRequest {
    /** base64-encoded user ID (optional; omit for discoverable-credential flow) */
    user_id?: string;
    /** email alternative to user_id */
    email?: string;
}
/** Mirrors pkg/webauthn/http/types.go AuthResponse (finish registration/login). */
interface WebAuthnAuthResponse {
    token: string;
    refresh_token?: string;
    user_id: string;
}
/**
 * A begin-ceremony result: the raw go-webauthn options envelope (feed it to
 * parseCreationOptions / parseRequestOptions) plus the session correlation
 * value the server returned via the X-Session-Id header.
 */
interface WebAuthnCeremonyStart {
    /** Raw options envelope ({ publicKey: { challenge, ... } }). */
    options: unknown;
    /** X-Session-Id header value; echo it back on the finish call. */
    sessionId: string;
}

/**
 * Shared WebAuthn (FIDO2) serialisation helpers.
 *
 * The browser's Web Authentication API speaks BufferSource (ArrayBuffer /
 * TypedArray) for every binary member, while the xkms server speaks
 * base64url-encoded JSON strings. The server side is the go-webauthn library
 * (github.com/go-webauthn/webauthn), whose wire types decode binary members
 * with base64.RawURLEncoding and whose challenge options are wrapped in a
 * top-level `publicKey` envelope (CredentialCreation / CredentialAssertion).
 *
 * This module is the SINGLE place that bridges the two representations. Every
 * view that calls navigator.credentials.create()/get() must route through it
 * so there is exactly one correct encode/decode implementation.
 *
 * Two classes of bug this module exists to prevent:
 *
 *   1. Envelope leak — the server returns `{ "publicKey": { challenge, ... } }`.
 *      Passing that object straight to navigator.credentials.create() leaves
 *      options.publicKey.challenge undefined (the real challenge is one level
 *      deeper), so the browser throws:
 *        "Failed to read the 'challenge' property ... Required member is undefined."
 *      parseCreationOptions / parseRequestOptions unwrap the envelope.
 *
 *   2. Binary encoding — challenge, user.id, allowCredentials[].id,
 *      excludeCredentials[].id are base64url strings on the wire but must be
 *      ArrayBuffers for the API; the credential the API returns has ArrayBuffer
 *      members that must be re-encoded as base64url strings for the finish call.
 *      The encoded field names match go-webauthn exactly (rawId,
 *      attestationObject, clientDataJSON, authenticatorData, signature,
 *      userHandle) — NOT snake_case and NOT number[] arrays.
 */
/**
 * base64urlToBuffer decodes a base64url (RFC 4648 §5, unpadded) string into an
 * ArrayBuffer. Standard base64 (with +/ and = padding) is also accepted so the
 * helper is tolerant of either server emission.
 */
declare function base64urlToBuffer(value: string): ArrayBuffer;
/**
 * bufferToBase64url encodes an ArrayBuffer (or ArrayBufferView) into an
 * unpadded base64url string, the form go-webauthn's URLEncodedBase64 decoder
 * (base64.RawURLEncoding) expects.
 */
declare function bufferToBase64url(buffer: ArrayBuffer | ArrayBufferView): string;
/**
 * WebAuthnEnvelopeError is thrown when the server's challenge options are not
 * in the expected go-webauthn `{ publicKey: { challenge, ... } }` shape (or the
 * already-unwrapped shape with a top-level challenge). It signals a transport
 * or version mismatch rather than a user-cancel, so callers can surface a
 * distinct message.
 */
declare class WebAuthnEnvelopeError extends Error {
    constructor(message: string);
}
/**
 * parseCreationOptions unwraps the server's registration challenge envelope and
 * decodes its binary members (challenge, user.id, excludeCredentials[].id) into
 * ArrayBuffers so the result can be passed directly to
 * navigator.credentials.create({ publicKey }).
 */
declare function parseCreationOptions(raw: unknown): PublicKeyCredentialCreationOptions;
/**
 * parseRequestOptions unwraps the server's login challenge envelope and decodes
 * its binary members (challenge, allowCredentials[].id) into ArrayBuffers so the
 * result can be passed directly to navigator.credentials.get({ publicKey }).
 */
declare function parseRequestOptions(raw: unknown): PublicKeyCredentialRequestOptions;
/**
 * AttestationCredentialJSON is the registration response shape go-webauthn's
 * ParseCredentialCreationResponseBytes expects: base64url string members under
 * camelCase keys.
 */
interface AttestationCredentialJSON {
    id: string;
    rawId: string;
    type: string;
    authenticatorAttachment?: string;
    response: {
        clientDataJSON: string;
        attestationObject: string;
        transports?: string[];
    };
    clientExtensionResults: AuthenticationExtensionsClientOutputs;
}
/**
 * AssertionCredentialJSON is the login response shape go-webauthn's
 * ParseCredentialRequestResponseBytes expects.
 */
interface AssertionCredentialJSON {
    id: string;
    rawId: string;
    type: string;
    authenticatorAttachment?: string;
    response: {
        clientDataJSON: string;
        authenticatorData: string;
        signature: string;
        userHandle?: string;
    };
    clientExtensionResults: AuthenticationExtensionsClientOutputs;
}
/**
 * encodeAttestationResponse serialises the PublicKeyCredential returned by
 * navigator.credentials.create() into the base64url JSON go-webauthn parses.
 * When the authenticator reports transports they are included (go-webauthn
 * reads response.transports).
 */
declare function encodeAttestationResponse(credential: PublicKeyCredential): AttestationCredentialJSON;
/**
 * encodeAssertionResponse serialises the PublicKeyCredential returned by
 * navigator.credentials.get() into the base64url JSON go-webauthn parses.
 * userHandle is included only when the authenticator returned one
 * (discoverable-credential flow).
 */
declare function encodeAssertionResponse(credential: PublicKeyCredential): AssertionCredentialJSON;

/** WebAuthn session correlation header (pkg/webauthn/http/types.go). */
declare const HEADER_SESSION_ID = "X-Session-Id";
/**
 * Session and WebAuthn authentication client.
 *
 * The token-pair endpoints (loginCert, refresh) ARE the authentication, so
 * they never send a bearer token; loginCert additionally sends
 * `credentials: 'include'` so the browser presents the TLS client
 * certificate / ambient cookies for the mTLS exchange. The introspection
 * endpoints (me, validate, logout) ride the configured TokenProvider.
 */
declare class AuthClient {
    private readonly http;
    private readonly paths;
    constructor(http: HttpCore, paths: AuthPaths);
    /**
     * POST {authPaths.loginCert} — exchange the TLS-verified client
     * certificate (PIV / mTLS identity) for a bearer token pair.
     */
    loginCert(): Promise<TokenResponse>;
    /** POST {authPaths.refresh} — rotate a refresh token into a new pair. */
    refresh(refreshToken: string): Promise<TokenResponse>;
    /** GET {authPaths.me} — identity, effective UI permissions, capability flags. */
    me(): Promise<AuthMeResponse>;
    /** GET {authPaths.validate} — lightweight boot-time session probe. */
    validate(): Promise<AuthValidateResponse>;
    /** POST {authPaths.logout} — revoke the refresh-token family (204). */
    logout(refreshToken?: string): Promise<void>;
    /**
     * POST /api/v1/webauthn/registration/begin — enrolls an account's FIRST
     * passkey without a session. Returns the raw go-webauthn creation options
     * envelope plus the session ID from the X-Session-Id response header.
     * Feed `options` to parseCreationOptions. An account that already has a
     * passkey is refused with 403 `registration_refused`; add further passkeys
     * with webAuthnAddCredentialBegin.
     */
    webAuthnRegisterBegin(req: WebAuthnBeginRegistrationRequest): Promise<WebAuthnCeremonyStart>;
    /**
     * POST /api/v1/webauthn/credentials/begin — start adding a passkey to the
     * signed-in account. Rides the configured TokenProvider: the account is the
     * session's own, never one named in the request. Complete the ceremony with
     * webAuthnRegisterFinish under the returned session ID.
     */
    webAuthnAddCredentialBegin(): Promise<WebAuthnCeremonyStart>;
    /**
     * POST /api/v1/webauthn/registration/finish — submit the encoded
     * attestation (encodeAttestationResponse) under the session's
     * X-Session-Id header.
     */
    webAuthnRegisterFinish(sessionId: string, credential: AttestationCredentialJSON): Promise<WebAuthnAuthResponse>;
    /**
     * POST /api/v1/webauthn/login/begin — returns the raw go-webauthn
     * request options envelope plus X-Session-Id. Feed `options` to
     * parseRequestOptions. Omit the request body for the discoverable-credential
     * flow. The response never reveals whether the account exists; the user ID
     * arrives only with a successful webAuthnFinishLogin.
     */
    webAuthnBeginLogin(req?: WebAuthnBeginLoginRequest): Promise<WebAuthnCeremonyStart>;
    /**
     * POST /api/v1/webauthn/login/finish — submit the encoded assertion
     * (encodeAssertionResponse) under the session's X-Session-Id header.
     */
    webAuthnFinishLogin(sessionId: string, credential: AssertionCredentialJSON): Promise<WebAuthnAuthResponse>;
}

/**
 * Mirrors pkg/types/types.go Capabilities. The Go struct has no json tags,
 * so members marshal under their exported (PascalCase) field names.
 */
interface BackendCapabilities {
    Keys: boolean;
    HardwareBacked: boolean;
    Signing: boolean;
    Decryption: boolean;
    KeyRotation: boolean;
    SymmetricEncryption: boolean;
    Sealing: boolean;
    Import: boolean;
    Export: boolean;
    KeyAgreement: boolean;
    ECIES: boolean;
    Attestation: boolean;
    QuantumSigning: boolean;
    KeyEncapsulation: boolean;
}
/** Mirrors pkg/api/rest/types.go BackendInfo. */
interface BackendInfo {
    id: string;
    type: string;
    hardware_backed: boolean;
    capabilities: BackendCapabilities;
}
/** Mirrors pkg/api/rest/types.go ListBackendsResponse. */
interface ListBackendsResponse {
    backends: BackendInfo[];
    pagination: PageResponse;
}

/** Crypto backend discovery. */
declare class BackendsClient {
    private readonly http;
    constructor(http: HttpCore);
    /** GET /api/v1/backends */
    list(page?: PageQuery): Promise<ListBackendsResponse>;
    /** GET /api/v1/backends/{id} */
    get(id: string): Promise<BackendInfo>;
}

/**
 * Barrier DTOs. Sources:
 *  - pkg/api/rest/handlers_barrier_pin.go (initialize / unseal / status)
 *  - pkg/api/rest/handlers_barrier_shamir.go (Shamir / rekey / recovery)
 *  - go-quicraft/pkg/seal (ShamirInitResult, QuorumProgress) and
 *    go-qrdb/pkg/seal (ShamirInitParams, RecoveryKeyResult, RootToken),
 *    which the handlers serialize verbatim.
 *  - pkg/api/transport/types.go BarrierEnableEncryption{Request,Response}.
 */

/**
 * Mirrors pkg/api/rest/handlers_barrier_pin.go BarrierInitializeRequest.
 * `password_b64` is a base64-encoded passphrase consumed via a secure buffer
 * server-side; prefer it over `secret` for new integrations.
 */
interface BarrierInitializeRequest {
    secret?: string;
    password_b64?: Base64;
}
/** Mirrors pkg/api/rest/handlers_barrier_pin.go BarrierUnsealRequest. */
interface BarrierUnsealRequest {
    secret?: string;
    password_b64?: Base64;
}
/** Mirrors pkg/api/rest/handlers_barrier_pin.go BarrierStatusResponse. */
interface BarrierStatusResponse {
    sealed: boolean;
    strategy: string;
    hardware_backed: boolean;
    initialized_at: RFC3339;
}
/** Mirrors pkg/api/rest/handlers_barrier_shamir.go BarrierInitializeShamirRequest. */
interface BarrierInitializeShamirRequest {
    secret?: string;
}
/** Mirrors go-quicraft/pkg/seal ShamirInitResult (Shamir initialize response). */
interface ShamirInitResult {
    shares: string[];
    threshold: number;
    total_shares: number;
}
/** Mirrors pkg/api/rest/handlers_barrier_shamir.go BarrierUnsealShareRequest. */
interface BarrierUnsealShareRequest {
    share: string;
}
/** Mirrors go-quicraft/pkg/seal QuorumProgress (unseal-share response). */
interface QuorumProgress {
    required: number;
    submitted: number;
    complete: boolean;
}
/** Mirrors pkg/api/rest/handlers_barrier_shamir.go BarrierUnsealSharesRequest. */
interface BarrierUnsealSharesRequest {
    shares: string[];
}
/** Mirrors pkg/api/rest/handlers_barrier_shamir.go BarrierRekeyRequest. */
interface BarrierRekeyRequest {
    threshold: number;
    total: number;
}
/** Mirrors go-qrdb/pkg/seal ShamirInitParams (rekey response). */
interface ShamirInitParams {
    threshold: number;
    total_shares: number;
    share_count?: number;
}
/** Mirrors pkg/api/rest/handlers_barrier_shamir.go BarrierGenerateRecoveryKeysRequest. */
interface BarrierGenerateRecoveryKeysRequest {
    threshold: number;
    total: number;
}
/** Mirrors go-qrdb/pkg/seal RecoveryKeyResult (recovery/generate response). */
interface RecoveryKeyResult {
    share_count: number;
    threshold: number;
    total_shares: number;
}
/** Mirrors pkg/api/rest/handlers_barrier_shamir.go BarrierRecoverWithKeysRequest. */
interface BarrierRecoverWithKeysRequest {
    keys: string[];
}
/** Mirrors pkg/api/rest/handlers_barrier_shamir.go BarrierGenerateRootTokenRequest. */
interface BarrierGenerateRootTokenRequest {
    shares: string[];
}
/** Mirrors go-qrdb/pkg/seal RootToken (recovery/root-token response). */
interface RootToken {
    token: string;
    created_at: RFC3339;
}
/** Mirrors pkg/api/transport/types.go BarrierEnableEncryptionRequest. */
interface BarrierEnableEncryptionRequest {
    tenant_id?: string;
    strategy: string;
    mechanism?: string;
    availability?: string;
    passphrase?: string;
    shamir_threshold?: number;
    shamir_total?: number;
}
/** Mirrors pkg/api/transport/types.go BarrierEnableEncryptionResponse. */
interface BarrierEnableEncryptionResponse {
    status: string;
    scope: string;
}

/** System barrier lifecycle (initialize / seal / unseal / Shamir / recovery). */
declare class BarrierClient {
    private readonly http;
    constructor(http: HttpCore);
    /** POST /api/v1/barrier/initialize */
    initialize(req: BarrierInitializeRequest): Promise<SuccessResponse>;
    /** POST /api/v1/barrier/unseal */
    unseal(req: BarrierUnsealRequest): Promise<SuccessResponse>;
    /** POST /api/v1/barrier/seal */
    seal(): Promise<SuccessResponse>;
    /** GET /api/v1/barrier/status */
    status(): Promise<BarrierStatusResponse>;
    /** POST /api/v1/barrier/shamir/initialize */
    shamirInitialize(req: BarrierInitializeShamirRequest): Promise<ShamirInitResult>;
    /** POST /api/v1/barrier/shamir/unseal-share (stateful quorum accumulation). */
    shamirUnsealShare(req: BarrierUnsealShareRequest): Promise<QuorumProgress>;
    /** POST /api/v1/barrier/shamir/unseal-shares (stateless batch unseal). */
    shamirUnsealShares(req: BarrierUnsealSharesRequest): Promise<SuccessResponse>;
    /** POST /api/v1/barrier/rekey */
    rekey(req: BarrierRekeyRequest): Promise<ShamirInitParams>;
    /** POST /api/v1/barrier/recovery/generate */
    generateRecoveryKeys(req: BarrierGenerateRecoveryKeysRequest): Promise<RecoveryKeyResult>;
    /** POST /api/v1/barrier/recovery/recover */
    recoverWithKeys(req: BarrierRecoverWithKeysRequest): Promise<SuccessResponse>;
    /** DELETE /api/v1/barrier/recovery/keys */
    deleteRecoveryKeys(): Promise<SuccessResponse>;
    /** POST /api/v1/barrier/recovery/root-token */
    generateRootToken(req: BarrierGenerateRootTokenRequest): Promise<RootToken>;
    /** POST /api/v1/barrier/enable-encryption (async migration; poll status). */
    enableEncryption(req: BarrierEnableEncryptionRequest): Promise<BarrierEnableEncryptionResponse>;
}

/**
 * CA and TCG DTOs. The REST CA handlers (pkg/api/rest/handlers_ca.go,
 * handlers_ca_tcg.go) decode and encode pkg/api/transport/types.go shapes
 * directly.
 */

interface GetCABundleResponse {
    bundle_pem: Base64;
    certificates: Base64[];
    content_type: string;
}
interface GetCACertificateResponse {
    certificate_pem: Base64;
    subject: string;
    issuer: string;
    serial_number: string;
    not_before: string;
    not_after: string;
    is_ca: boolean;
}
interface SignCSRRequest {
    csr_pem: Base64;
    profile?: string;
    validity_days?: number;
    tenant_id?: string;
    attestation_format?: string;
    attestation_chain?: Base64[];
    attestation_data?: Base64;
    attestation_sig?: Base64;
    attestation_nonce?: Base64;
}
interface SignCSRResponse {
    certificate_pem: Base64;
    chain_pem: Base64;
    serial_number: string;
}
interface IssueCertificateRequest {
    profile: string;
    common_name: string;
    organization?: string;
    sans?: string[];
    validity_days?: number;
    algorithm?: string;
    tenant_id?: string;
}
interface IssueCertificateResponse {
    certificate_pem: Base64;
    chain_pem: Base64;
    private_key_pem?: Base64;
    serial_number: string;
}
interface RevokeCertificateRequest {
    serial_number: string;
    reason: number;
    tenant_id?: string;
}
interface RevokeCertificateResponse {
    success: boolean;
    message?: string;
}
interface GenerateCRLRequest {
    tenant_id?: string;
}
interface GenerateCRLResponse {
    crl_pem: Base64;
}
interface IsRevokedResponse {
    revoked: boolean;
    reason?: number;
    message?: string;
}
interface IssueEKCertificateRequest {
    common_name: string;
    organization?: string;
    ek_public_key: Base64;
    tenant_id?: string;
}
interface IssueEKCertificateResponse {
    certificate_der: Base64;
    certificate_pem: Base64;
    serial_number: string;
}
interface IssueAKCertificateRequest {
    common_name: string;
    organization?: string;
    public_key: Base64;
    tenant_id?: string;
}
interface IssueAKCertificateResponse {
    certificate_der: Base64;
    certificate_pem: Base64;
    serial_number: string;
}
interface SignTCGCSRRequest {
    common_name: string;
    organization?: string;
    tcg_csr: Base64;
    tenant_id?: string;
}
interface SignTCGCSRResponse {
    iak_cert_der: Base64;
    idevid_cert_der: Base64;
}
interface EnrollDeviceRequest {
    common_name: string;
    organization?: string;
    packed_csr: Base64;
    tenant_id?: string;
}
interface EnrollDeviceResponse {
    iak_cert_der: Base64;
    idevid_cert_der: Base64;
    credential_blob: Base64;
    encrypted_secret: Base64;
    plain_secret: Base64;
}

/** TrustedCA operations, including the TCG (TPM EK/AK/IDevID) surface. */
declare class CaClient {
    private readonly http;
    constructor(http: HttpCore);
    /** GET /api/v1/ca/bundle?store_type=&algorithm= */
    bundle(storeType?: string, algorithm?: string): Promise<GetCABundleResponse>;
    /** GET /api/v1/ca/certificate?identity= */
    certificate(identity?: string): Promise<GetCACertificateResponse>;
    /** POST /api/v1/ca/sign-csr */
    signCSR(req: SignCSRRequest): Promise<SignCSRResponse>;
    /** POST /api/v1/ca/issue */
    issue(req: IssueCertificateRequest): Promise<IssueCertificateResponse>;
    /** POST /api/v1/ca/revoke */
    revoke(req: RevokeCertificateRequest): Promise<RevokeCertificateResponse>;
    /** POST /api/v1/ca/crl */
    generateCRL(req?: GenerateCRLRequest): Promise<GenerateCRLResponse>;
    /** GET /api/v1/ca/revoked/{serial} */
    isRevoked(serial: string): Promise<IsRevokedResponse>;
    /** POST /api/v1/ca/tcg/ek */
    issueEK(req: IssueEKCertificateRequest): Promise<IssueEKCertificateResponse>;
    /** POST /api/v1/ca/tcg/ak */
    issueAK(req: IssueAKCertificateRequest): Promise<IssueAKCertificateResponse>;
    /** POST /api/v1/ca/tcg/sign-csr */
    signTCGCSR(req: SignTCGCSRRequest): Promise<SignTCGCSRResponse>;
    /** POST /api/v1/ca/tcg/enroll */
    enrollDevice(req: EnrollDeviceRequest): Promise<EnrollDeviceResponse>;
    /**
     * GET /v1/ca/bootstrap — the unauthenticated go-truststrap bootstrap
     * endpoint; returns the raw PEM bundle text
     * (application/pem-certificate-chain), not JSON.
     */
    bootstrapBundle(): Promise<string>;
}

/**
 * Deployment capability flags: which optional subsystems (webauthn, ca,
 * tenants, ssh, ...) this server wired. The canonical source is the
 * `capabilities` member of GET /api/v1/auth/me (handlers_auth.go
 * capabilityFlags); deployments that expose a dedicated capabilities
 * endpoint serve the same map at the configured `authPaths.capabilities`
 * path (default /api/v1/capabilities).
 */
declare class CapabilitiesClient {
    private readonly http;
    private readonly paths;
    constructor(http: HttpCore, paths: AuthPaths);
    /** GET {authPaths.capabilities} -> { "<capability>": boolean, ... } */
    get(): Promise<Record<string, boolean>>;
}

/** Mirrors pkg/api/rest/types.go SaveCertRequest. */
interface SaveCertRequest {
    backend?: string;
    certificate_pem: string;
}
/** Mirrors pkg/api/rest/types.go GetCertResponse. */
interface GetCertResponse {
    key_id: string;
    certificate_pem: string;
}
/** Mirrors pkg/api/rest/types.go CertificateInfo. */
interface CertificateInfo {
    key_id: string;
    subject?: string;
    issuer?: string;
    not_before?: string;
    not_after?: string;
    serial_number?: string;
    certificate_pem?: string;
}
/** Mirrors pkg/api/rest/types.go ListCertsResponse. */
interface ListCertsResponse {
    certificates: CertificateInfo[];
    pagination: PageResponse;
}
/** Mirrors pkg/api/rest/types.go SaveCertChainRequest. */
interface SaveCertChainRequest {
    backend?: string;
    cert_chain_pem: string[];
}
/** Mirrors pkg/api/rest/types.go GetCertChainResponse. */
interface GetCertChainResponse {
    key_id: string;
    cert_chain_pem: string[];
}
/** Mirrors pkg/api/rest/types.go GetTLSCertificateResponse (GET /api/v1/tls/{id}). */
interface GetTLSCertificateResponse {
    key_id: string;
    certificate_pem: string;
    chain_pem?: string[];
}

/** Certificate storage attached to backend keys. */
declare class CertsClient {
    private readonly http;
    constructor(http: HttpCore);
    /**
     * POST /api/v1/certs?key_id=&backend= — the handler reads key_id and
     * backend from the query string; the body carries the PEM.
     */
    save(keyId: string, backend: string, req: SaveCertRequest): Promise<SuccessResponse>;
    /** GET /api/v1/certs?backend= */
    list(backend?: string, page?: PageQuery): Promise<ListCertsResponse>;
    /** GET /api/v1/certs/{id}?backend= */
    get(id: string, backend: string): Promise<GetCertResponse>;
    /** DELETE /api/v1/certs/{id}?backend= */
    delete(id: string, backend: string): Promise<SuccessResponse>;
    /** HEAD /api/v1/certs/{id}?backend= — true when the certificate exists. */
    exists(id: string, backend: string): Promise<boolean>;
    /** POST /api/v1/certs/{id}/chain */
    saveChain(id: string, req: SaveCertChainRequest): Promise<SuccessResponse>;
    /** GET /api/v1/certs/{id}/chain?backend= */
    getChain(id: string, backend?: string): Promise<GetCertChainResponse>;
    /** GET /api/v1/tls/{id}?backend= — private key + cert + chain bundle. */
    tlsBundle(id: string, backend?: string): Promise<GetTLSCertificateResponse>;
}

/**
 * Cluster DTOs — read-only. Mirrors pkg/api/transport/types_cluster.go
 * exactly: the shard-scoped fields (shard_id, leader_id, has_leader,
 * replica_id, address, api_endpoints, is_leader) are go-qrdb's own
 * ClusterClient/Member vocabulary passed through unchanged; node_id and
 * clustered are the servicer's own facts about the responding node.
 *
 * There are deliberately no membership-mutation DTOs: REST never mutates
 * Raft membership, so there is no request/response shape to model — see
 * ClusterClient in clients/cluster.ts.
 */
interface ClusterStatusInfo {
    shard_id: number;
    leader_id: number;
    has_leader: boolean;
    node_id: number;
    clustered: boolean;
}
interface ClusterStatusResponse {
    status: ClusterStatusInfo;
}
interface ClusterMemberInfo {
    replica_id: number;
    address: string;
    api_endpoints?: Record<string, string>;
    is_leader: boolean;
}
interface ListClusterMembersResponse {
    members: ClusterMemberInfo[];
}

/**
 * Cluster status and membership — read-only. Membership mutation is never
 * exposed over REST, by design: it goes through go-qrdb's own control plane
 * exclusively, via `xkmsctl cluster add`/`remove`.
 */
declare class ClusterClient {
    private readonly http;
    constructor(http: HttpCore);
    /** GET /api/v1/cluster/status */
    status(): Promise<ClusterStatusResponse>;
    /** GET /api/v1/cluster/members */
    members(): Promise<ListClusterMembersResponse>;
}

/** Credential-service DTOs. Mirrors pkg/api/rest/handlers_credentials.go. */

interface CredentialSubmitRequest {
    name: string;
    /** base64-encoded credential value */
    value: Base64;
}
interface CredentialSubmitResponse {
    status: string;
}
interface CredentialStrategyResponse {
    strategy: string;
    auto_unseal: boolean;
}

/** Boot-credential submission (unseal secrets, PINs). */
declare class CredentialsClient {
    private readonly http;
    constructor(http: HttpCore);
    /** POST /api/v1/credentials/submit */
    submit(req: CredentialSubmitRequest): Promise<CredentialSubmitResponse>;
    /** GET /api/v1/credentials/strategy */
    strategy(): Promise<CredentialStrategyResponse>;
}

/**
 * Custodian group DTOs. Requests mirror pkg/api/rest/handlers_custodian.go
 * local shapes; the group/member info mirrors go-qrdb/sdk/go/transport
 * custodian_types.go (aliased through pkg/api/transport/types_custodian.go).
 */

interface CustodianMemberInfo {
    share_index: number;
    user_id: string;
    username: string;
    assigned_at: RFC3339;
    received_at?: RFC3339;
    method: string;
}
interface CustodianGroupInfo {
    id: string;
    tenant_id?: string;
    name: string;
    purpose: string;
    threshold: number;
    total: number;
    members: CustodianMemberInfo[];
    created_at: RFC3339;
    updated_at: RFC3339;
}
interface CreateCustodianGroupRequest {
    id: string;
    tenant_id?: string;
    name: string;
    purpose: string;
    threshold: number;
    total: number;
}
interface CreateCustodianGroupResponse {
    group: CustodianGroupInfo;
}
interface GetCustodianGroupResponse {
    group: CustodianGroupInfo;
}
interface ListCustodianGroupsResponse {
    groups: CustodianGroupInfo[];
    pagination: PageResponse;
}
interface AddCustodianMemberRequest {
    user_id: string;
    username: string;
    method: string;
}
interface AddCustodianMemberResponse {
    member: CustodianMemberInfo;
}
interface DistributeSharesResponse {
    distributed: number;
}

/** Custodian (Shamir share officer) group management. */
declare class CustodianClient {
    private readonly http;
    constructor(http: HttpCore);
    /** POST /api/v1/custodian/groups/ */
    createGroup(req: CreateCustodianGroupRequest): Promise<CreateCustodianGroupResponse>;
    /** GET /api/v1/custodian/groups/ */
    listGroups(page?: PageQuery): Promise<ListCustodianGroupsResponse>;
    /** GET /api/v1/custodian/groups/{id} */
    getGroup(id: string): Promise<GetCustodianGroupResponse>;
    /** DELETE /api/v1/custodian/groups/{id} (204) */
    deleteGroup(id: string): Promise<void>;
    /** POST /api/v1/custodian/groups/{id}/members */
    addMember(id: string, req: AddCustodianMemberRequest): Promise<AddCustodianMemberResponse>;
    /** DELETE /api/v1/custodian/groups/{id}/members/{userID} (204) */
    removeMember(id: string, userId: string): Promise<void>;
    /** POST /api/v1/custodian/groups/{id}/distribute */
    distributeShares(id: string): Promise<DistributeSharesResponse>;
}

/**
 * User N-factor DTOs. Mirrors pkg/api/rest/handlers_authfactor.go, which
 * proxies go-qrdb's transport.AuthFactor* types verbatim — the wire shape is
 * qrdb's, so field names must track go-qrdb/sdk/go/transport/auth_factor_types.go.
 *
 * Go `[]byte` fields marshal to base64 strings, so `credential`,
 * `spki_credential`, and `lookup_key` are base64 here, not hex.
 */

/** The factor kinds qrdb recognises. */
type AuthFactorType = 'mtls' | 'fido2' | 'piv';
interface AuthFactorRecord {
    id: string;
    user_id: number;
    type: AuthFactorType | string;
    label?: string;
    /** base64 — canonical lookup-key bytes */
    credential: string;
    /** base64 — SHA-256 of the certificate SPKI (mtls/piv only) */
    spki_credential?: string;
    metadata?: Record<string, string>;
    registered_at: RFC3339;
    last_used_at?: RFC3339;
    revoked_at?: RFC3339;
    /** provenance: "self", "admin", "ceremony" */
    created_by?: string;
}
interface AuthFactorAddRequest {
    user_id: number;
    type: AuthFactorType | string;
    label?: string;
    /** base64 */
    credential: string;
    /** base64 */
    spki_credential?: string;
    metadata?: Record<string, string>;
    created_by?: string;
}
interface AuthFactorAddResponse {
    factor: AuthFactorRecord;
}
interface AuthFactorListResponse {
    factors: AuthFactorRecord[];
    total: number;
}
interface AuthFactorGetResponse {
    factor: AuthFactorRecord;
}
interface AuthFactorRemoveResponse {
    /** "revoked" on success */
    status: string;
}
interface AuthFactorRotateRequest {
    new_factor: AuthFactorAddRequest;
}
interface AuthFactorRotateResponse {
    new_factor: AuthFactorRecord;
}
interface AuthFactorRelabelRequest {
    label: string;
}
interface AuthFactorRelabelResponse {
    factor: AuthFactorRecord;
}
interface AuthFactorLoginRequest {
    type: AuthFactorType | string;
    /** base64 */
    lookup_key: string;
}
interface AuthFactorLoginResponse {
    user_id: number;
    username: string;
    email?: string;
    tenant_id?: string;
    roles?: string[];
    active: boolean;
}

/**
 * User N-factor management. Factor state is owned by the embedded go-qrdb
 * node; xkmsd proxies it so identity is reachable on the same endpoint as
 * everything else.
 */
declare class FactorsClient {
    private readonly http;
    constructor(http: HttpCore);
    /**
     * GET /api/v1/factors?user_id=N
     *
     * The owner is a QUERY parameter, not a path segment — the server parses
     * `user_id` off the query string and rejects a missing or zero value.
     */
    list(userID: number): Promise<AuthFactorListResponse>;
    /** POST /api/v1/factors — the owning user comes from the BODY. */
    add(req: AuthFactorAddRequest): Promise<AuthFactorAddResponse>;
    /** GET /api/v1/factors/{factorID} */
    get(factorID: string): Promise<AuthFactorGetResponse>;
    /**
     * DELETE /api/v1/factors/{factorID}
     *
     * qrdb refuses to revoke a user's last active factor; `force` asks it to
     * stand down, which also moves the user to inactive.
     */
    remove(factorID: string, force?: boolean): Promise<AuthFactorRemoveResponse>;
    /**
     * PATCH /api/v1/factors/{factorID}
     *
     * The server takes the factor id from the path and overwrites whatever the
     * body carries, so only the label needs sending.
     */
    relabel(factorID: string, req: AuthFactorRelabelRequest): Promise<AuthFactorRelabelResponse>;
    /**
     * POST /api/v1/factors/{factorID}/rotate — atomically revoke and replace.
     * The old factor id comes from the path; the body carries only new_factor.
     */
    rotate(factorID: string, req: AuthFactorRotateRequest): Promise<AuthFactorRotateResponse>;
    /**
     * POST /api/v1/factors/login
     *
     * Resolves a (type, lookup_key) pair to a principal and NOTHING more. This
     * is not proof of possession: the hardware challenge must already have been
     * verified before the result is treated as an authenticated identity.
     */
    login(req: AuthFactorLoginRequest): Promise<AuthFactorLoginResponse>;
}

/** FROST threshold-signature DTOs. Mirrors pkg/api/rest/handlers_frost.go. */

interface FrostGenerateKeyRequest {
    key_id?: string;
    algorithm?: string;
    threshold: number;
    total: number;
    participants?: string[];
    participant_id?: number;
    dealer_mode?: boolean;
}
interface FrostKeyPackage {
    key_id: string;
    algorithm: string;
    threshold: number;
    total: number;
    participant_id: number;
    participant_name?: string;
    /** hex-encoded */
    secret_share: string;
    /** hex-encoded */
    group_public_key: string;
    /** participant id -> hex-encoded verification share */
    verification_shares: Record<string, string>;
}
interface FrostGenerateKeyResponse {
    key_id: string;
    algorithm: string;
    threshold: number;
    total: number;
    /** hex-encoded */
    group_public_key: string;
    participant_id?: number;
    /** dealer mode only */
    packages?: FrostKeyPackage[];
    created_at: RFC3339;
}
interface FrostKeyInfo {
    key_id: string;
    algorithm: string;
    threshold: number;
    total: number;
    participant_id: number;
    /** hex-encoded */
    group_public_key: string;
    participants?: string[];
    created_at: RFC3339;
}
interface FrostImportKeyRequest {
    package: FrostKeyPackage;
}
interface FrostImportKeyResponse {
    success: boolean;
    message: string;
    key_id: string;
    participant_id: number;
    /** hex-encoded */
    group_public_key: string;
}
interface FrostListKeysResponse {
    keys: FrostKeyInfo[];
    total: number;
    pagination: PageResponse;
}
interface FrostDeleteKeyResponse {
    success: boolean;
    message: string;
}
interface FrostGenerateNoncesResponse {
    participant_id: number;
    session_id: string;
    /** hex-encoded (secret) */
    hiding_nonce: string;
    /** hex-encoded (secret) */
    binding_nonce: string;
    /** hex-encoded (public) */
    hiding_commitment: string;
    /** hex-encoded (public) */
    binding_commitment: string;
}
interface FrostCommitment {
    participant_id: number;
    /** hex-encoded */
    hiding_commitment: string;
    /** hex-encoded */
    binding_commitment: string;
}
interface FrostSignRoundRequest {
    key_id: string;
    /** hex-encoded */
    message: string;
    session_id: string;
    /** hex-encoded */
    hiding_nonce: string;
    /** hex-encoded */
    binding_nonce: string;
    /** hex-encoded */
    hiding_commitment: string;
    /** hex-encoded */
    binding_commitment: string;
    commitments: FrostCommitment[];
}
interface FrostSignRoundResponse {
    participant_id: number;
    session_id: string;
    /** hex-encoded */
    signature_share: string;
}
interface FrostSignatureShare {
    participant_id: number;
    session_id: string;
    /** hex-encoded */
    share: string;
}
interface FrostAggregateRequest {
    key_id: string;
    /** hex-encoded */
    message: string;
    commitments: FrostCommitment[];
    shares: FrostSignatureShare[];
    verify: boolean;
}
interface FrostAggregateResponse {
    /** hex-encoded */
    signature: string;
    verified: boolean;
}
interface FrostVerifyRequest {
    key_id: string;
    /** hex-encoded */
    message: string;
    /** hex-encoded */
    signature: string;
}
interface FrostVerifyResponse {
    valid: boolean;
    message: string;
}

/** FROST threshold signatures. */
declare class FrostClient {
    private readonly http;
    constructor(http: HttpCore);
    /** POST /api/v1/frost/keys */
    generateKey(req: FrostGenerateKeyRequest): Promise<FrostGenerateKeyResponse>;
    /** POST /api/v1/frost/keys/import */
    importKey(req: FrostImportKeyRequest): Promise<FrostImportKeyResponse>;
    /** GET /api/v1/frost/keys */
    listKeys(page?: PageQuery): Promise<FrostListKeysResponse>;
    /** GET /api/v1/frost/keys/{id} */
    getKey(id: string): Promise<FrostKeyInfo>;
    /** DELETE /api/v1/frost/keys/{id} */
    deleteKey(id: string): Promise<FrostDeleteKeyResponse>;
    /** POST /api/v1/frost/keys/{id}/nonces */
    generateNonces(id: string): Promise<FrostGenerateNoncesResponse>;
    /** POST /api/v1/frost/keys/{id}/sign */
    signRound(id: string, req: FrostSignRoundRequest): Promise<FrostSignRoundResponse>;
    /** POST /api/v1/frost/aggregate */
    aggregate(req: FrostAggregateRequest): Promise<FrostAggregateResponse>;
    /** POST /api/v1/frost/verify */
    verify(req: FrostVerifyRequest): Promise<FrostVerifyResponse>;
}

/** Mirrors pkg/api/rest/types.go HealthResponse (GET /health). */
interface HealthResponse {
    status: string;
    version?: string;
}
/** One health-check probe result (qrdb sdk HealthCheckResult). */
interface HealthCheckResult {
    name: string;
    status: string;
    message?: string;
    [key: string]: unknown;
}
/**
 * Mirrors pkg/api/rest/health_handlers.go HealthCheckResponse
 * (GET /health/live | /health/ready | /health/startup).
 */
interface HealthCheckResponse {
    status: string;
    message?: string;
    checks?: HealthCheckResult[];
}
/** Mirrors pkg/types/algorithm_discovery.go AlgorithmInfo. */
interface AlgorithmInfo {
    algorithm: string;
    curves?: string[];
    key_sizes?: number[];
    backends: string[];
    post_quantum?: boolean;
}
/** Mirrors pkg/types/algorithm_discovery.go AlgorithmsResponse (GET /api/v1/algorithms). */
interface AlgorithmsResponse {
    signing: AlgorithmInfo[];
    key_encapsulation: AlgorithmInfo[];
}

/** Health probes and public algorithm discovery (no auth required). */
declare class HealthClient {
    private readonly http;
    constructor(http: HttpCore);
    /** GET /health */
    health(): Promise<HealthResponse>;
    /** GET /health/live */
    live(): Promise<HealthCheckResponse>;
    /** GET /health/ready */
    ready(): Promise<HealthCheckResponse>;
    /** GET /health/startup */
    startup(): Promise<HealthCheckResponse>;
    /** GET /api/v1/algorithms */
    algorithms(): Promise<AlgorithmsResponse>;
}

/** Init-ceremony DTOs. Mirrors pkg/api/rest/handlers_init.go. */

interface InitStatusResponse {
    state: string;
}
interface ClaimCertBeginRequest {
    username: string;
}
interface ClaimCertBeginResponse {
    nonce: string;
    username: string;
    expires_at: RFC3339;
}
interface ClaimCertCompleteRequest {
    username: string;
    nonce: string;
    /** base64-encoded signature over the nonce */
    signature: Base64;
}
interface ClaimCertCompleteResponse {
    cert_pem: string;
    ca_cert_pem: string;
}
interface ClaimShareBeginRequest {
    username: string;
}
interface ClaimShareBeginResponse {
    nonce: string;
    username: string;
    expires_at: RFC3339;
}
interface ClaimShareCompleteRequest {
    username: string;
    nonce: string;
    /** base64-encoded signature over the nonce */
    signature: Base64;
}
interface ClaimShareCompleteResponse {
    share_index: number;
    /** Opaque JSON share payload (json.RawMessage server-side). */
    share: unknown;
}
interface SignCSRInitRequest {
    username: string;
    so_pin: string;
    csr_pem: string;
    role: string;
}
interface SignCSRInitResponse {
    cert_pem: string;
}

/** First-boot init ceremony (officer cert + share claims). */
declare class InitClient {
    private readonly http;
    constructor(http: HttpCore);
    /** GET /api/v1/init/status */
    status(): Promise<InitStatusResponse>;
    /** POST /api/v1/init/claim-cert/begin */
    claimCertBegin(req: ClaimCertBeginRequest): Promise<ClaimCertBeginResponse>;
    /** POST /api/v1/init/claim-cert/complete */
    claimCertComplete(req: ClaimCertCompleteRequest): Promise<ClaimCertCompleteResponse>;
    /** POST /api/v1/init/claim-share/begin (requires the officer's mTLS cert). */
    claimShareBegin(req: ClaimShareBeginRequest): Promise<ClaimShareBeginResponse>;
    /** POST /api/v1/init/claim-share/complete (requires the officer's mTLS cert). */
    claimShareComplete(req: ClaimShareCompleteRequest): Promise<ClaimShareCompleteResponse>;
    /** POST /api/v1/init/sign-csr (authenticated; RBAC ceremony:sign_csr). */
    signCSR(req: SignCSRInitRequest): Promise<SignCSRInitResponse>;
}

/**
 * Key-version DTOs, served under /api/v1/keys/{id}/versions and
 * /api/v1/keys/rotate-all. Source: pkg/api/transport/types_keyversion.go
 * (the REST handlers encode the transport types directly).
 */
/** A key version's lifecycle state. */
type KeyVersionState = 'enabled' | 'disabled' | 'retired';
/** Mirrors pkg/api/transport KeyVersionInfo. */
interface KeyVersionInfo {
    version: number;
    state: KeyVersionState;
    /** Whether this is the version sign and encrypt use. */
    current?: boolean;
    /** RFC 3339 in UTC; absent for version 1 of a key rotated before it was recorded. */
    created_at?: string;
    created_by?: string;
    /** The version's public key, for an asymmetric version that is not retired. */
    public_key_pem?: string;
}
/** Mirrors pkg/api/transport ListKeyVersionsResponse. */
interface ListKeyVersionsResponse {
    key_id: string;
    backend: string;
    current_version: number;
    versions: KeyVersionInfo[];
}
/** Mirrors pkg/api/transport KeyVersionStateResponse. */
interface KeyVersionStateResponse {
    key_id: string;
    version: number;
    state: KeyVersionState;
    /** False when the version already had the state. */
    changed: boolean;
}
/** Mirrors pkg/api/transport AllKeyVersionsResponse. */
interface AllKeyVersionsResponse {
    key_id: string;
    state: KeyVersionState;
    /** The versions whose state changed, ascending. */
    versions: number[];
    count: number;
}
/**
 * A key rotation result's state (pkg/api/transport KeyRotation*): rotated,
 * skipped on purpose (reason says why: another subsystem names the key
 * exactly, or it has a certificate), or failed (error says why).
 */
type KeyRotationState = 'rotated' | 'skipped' | 'failed';
/** Mirrors pkg/api/transport KeyRotationResult. */
interface KeyRotationResult {
    backend: string;
    key_id: string;
    state: KeyRotationState;
    /** The new current version; absent unless rotated. */
    key_version?: number;
    /** Why a skipped key was left alone. */
    reason?: string;
    /** Why the key was not rotated; absent unless failed. */
    error?: string;
}
/** Mirrors pkg/api/transport RotateScopeKeysResponse. */
interface RotateScopeKeysResponse {
    tenant_id: string;
    results: KeyRotationResult[];
    rotated: number;
    skipped: number;
    failed: number;
}

/**
 * Key versions. A version is its own backend key: rotating a key
 * (`keys.rotate`) creates its next version and makes it current. Every call
 * acts in the caller's tenant; `rotateAll` alone may name another tenant,
 * which only a system caller may do.
 */
declare class KeyVersionsClient {
    private readonly http;
    constructor(http: HttpCore);
    /** GET /api/v1/keys/{id}/versions?backend= */
    list(id: string, backend: string): Promise<ListKeyVersionsResponse>;
    /** POST /api/v1/keys/{id}/versions/{version}/enable?backend= */
    enable(id: string, version: number, backend: string): Promise<KeyVersionStateResponse>;
    /** POST /api/v1/keys/{id}/versions/{version}/disable?backend= — the current version cannot be disabled. */
    disable(id: string, version: number, backend: string): Promise<KeyVersionStateResponse>;
    /** POST /api/v1/keys/{id}/versions/{version}/retire?backend= — deletes the version's key material for good. */
    retire(id: string, version: number, backend: string): Promise<KeyVersionStateResponse>;
    /** POST /api/v1/keys/{id}/versions/enable-all?backend= */
    enableAll(id: string, backend: string): Promise<AllKeyVersionsResponse>;
    /** POST /api/v1/keys/{id}/versions/disable-all?backend= — never reaches the current version. */
    disableAll(id: string, backend: string): Promise<AllKeyVersionsResponse>;
    /** POST /api/v1/keys/rotate-all — rotates every key of the caller's tenant, or of tenantId (system callers only). */
    rotateAll(tenantId?: string): Promise<RotateScopeKeysResponse>;
}

/**
 * Key and crypto-operation DTOs. Sources:
 *  - pkg/api/rest/types.go (the REST-local shapes the handlers decode/encode)
 *  - pkg/api/transport/types.go (the hardware-capability keyops handlers in
 *    pkg/api/rest/handlers_keyops.go decode transport.* directly)
 */

/** Mirrors pkg/api/rest/types.go GenerateKeyRequest. */
interface GenerateKeyRequest {
    key_id: string;
    backend?: string;
    key_type: string;
    key_size?: number;
    curve?: string;
    hash?: string;
    algorithm?: string;
    exportable?: boolean;
    /** Names the TPM policy a TPM2 key is bound to; empty is the built-in "platform" policy. */
    tpm_policy?: string;
}
/** Mirrors pkg/api/rest/types.go GenerateKeyResponse. */
interface GenerateKeyResponse {
    key_id: string;
    key_type: string;
    public_key_pem?: string;
    message?: string;
}
/** Mirrors pkg/api/rest/types.go KeyInfo. */
interface KeyInfo {
    key_id: string;
    key_type: string;
    algorithm: string;
    backend: string;
    public_key_pem?: string;
    /** The key's current version, the one sign and encrypt use. */
    key_version?: number;
}
/** Mirrors pkg/api/rest/types.go ListKeysResponse. */
interface ListKeysResponse {
    keys: KeyInfo[];
    pagination: PageResponse;
}
/** Mirrors pkg/api/rest/types.go GetKeyResponse (KeyInfo embedded flat). */
type GetKeyResponse = KeyInfo;
/** Mirrors pkg/api/rest/types.go DeleteKeyResponse. */
interface DeleteKeyResponse {
    success: boolean;
    message?: string;
}
/** Mirrors pkg/api/rest/types.go SignRequest. */
interface SignRequest {
    backend?: string;
    data: Base64;
    hash?: string;
    padding?: string;
    salt_length?: number;
    data_is_digest?: boolean;
}
/** Mirrors pkg/api/rest/types.go SignResponse. */
interface SignResponse {
    signature: Base64;
    algorithm?: string;
    /** The key version that produced the signature: always the current one. */
    key_version?: number;
}
/** Mirrors pkg/api/rest/types.go VerifyRequest. */
interface VerifyRequest {
    backend?: string;
    data: Base64;
    signature: Base64;
    hash?: string;
    padding?: string;
    salt_length?: number;
    data_is_digest?: boolean;
    /** Verify with this enabled version; omitted tries every enabled version, newest first. */
    key_version?: number;
}
/** Mirrors pkg/api/rest/types.go VerifyResponse. */
interface VerifyResponse {
    valid: boolean;
    message?: string;
    /** The key version the signature verified under; 0 or absent when it did not verify. */
    key_version?: number;
}
/** Mirrors pkg/api/rest/types.go RotateKeyResponse. */
interface RotateKeyResponse {
    success: boolean;
    key_id: string;
    key_type: string;
    public_key_pem?: string;
    message?: string;
    /** The version the rotation created, now current. */
    key_version?: number;
    /**
     * The key has a certificate, which still certifies the previous version:
     * issue a new one for the new version.
     */
    certificate_reissue_required?: boolean;
}
/** Mirrors pkg/api/rest/types.go EncryptRequest. */
interface EncryptRequest {
    backend?: string;
    plaintext: Base64;
    additional_data?: Base64;
    nonce?: Base64;
    mode?: string;
    iv?: Base64;
    tag_size?: number;
}
/** Mirrors pkg/api/rest/types.go EncryptResponse. */
interface EncryptResponse {
    ciphertext: Base64;
    nonce: Base64;
    tag: Base64;
    iv?: Base64;
    gcm_nonce_mode?: string;
    /**
     * The key version that produced the ciphertext: always the current one.
     * Keep it: AES-CBC ciphertext needs it to decrypt once the key has more
     * than one enabled version.
     */
    key_version?: number;
}
/** Mirrors pkg/api/rest/types.go DecryptRequest. */
interface DecryptRequest {
    backend?: string;
    ciphertext: Base64;
    additional_data?: Base64;
    nonce?: Base64;
    tag?: Base64;
    mode?: string;
    iv?: Base64;
    tag_size?: number;
    gcm_nonce_mode?: string;
    /** RSA decryption padding: "" or "pkcs1v15" (default), or "oaep". */
    padding?: string;
    /** The OAEP digest. */
    hash?: string;
    /** The OAEP label. */
    label?: Base64;
    /**
     * Decrypt with this enabled version. Omitted tries every enabled version,
     * newest first, for AEAD and RSA-OAEP ciphertext, and requires exactly one
     * enabled version for AES-CBC and RSA PKCS#1 v1.5 ciphertext.
     */
    key_version?: number;
}
/** Mirrors pkg/api/rest/types.go DecryptResponse. */
interface DecryptResponse {
    plaintext: Base64;
    /** The key version that decrypted the ciphertext. */
    key_version?: number;
}
/** Mirrors pkg/api/rest/types.go EncryptAsymRequest. */
interface EncryptAsymRequest {
    backend?: string;
    plaintext: Base64;
    hash?: string;
}
/** Mirrors pkg/api/rest/types.go EncryptAsymResponse. */
interface EncryptAsymResponse {
    ciphertext: Base64;
    /** The key version whose public key encrypted: always the current one. */
    key_version?: number;
}
/** Mirrors pkg/api/rest/types.go GetImportParametersRequest. */
interface GetImportParametersRequest {
    backend: string;
    key_id: string;
    key_type: string;
    algorithm: string;
    key_size?: number;
    curve?: string;
    hash?: string;
    aes_key_size?: number;
}
/** Mirrors pkg/api/rest/types.go GetImportParametersResponse. */
interface GetImportParametersResponse {
    wrapping_public_key_pem: string;
    import_token?: Base64;
    algorithm: string;
    expires_at?: string;
}
/** Mirrors pkg/api/rest/types.go WrapKeyRequest. */
interface WrapKeyRequest {
    backend: string;
    key_material: Base64;
    wrapping_public_key_pem: string;
    import_token?: Base64;
    algorithm: string;
}
/** Mirrors pkg/api/rest/types.go WrapKeyResponse. */
interface WrapKeyResponse {
    wrapped_key: Base64;
    algorithm: string;
    import_token?: Base64;
}
/** Mirrors pkg/api/rest/types.go UnwrapKeyRequest. */
interface UnwrapKeyRequest {
    backend: string;
    wrapped_key: Base64;
    wrapping_public_key_pem: string;
    import_token?: Base64;
    algorithm: string;
}
/** Mirrors pkg/api/rest/types.go UnwrapKeyResponse. */
interface UnwrapKeyResponse {
    key_material: Base64;
}
/** Mirrors pkg/api/rest/types.go ImportKeyRequest. */
interface ImportKeyRequest {
    backend: string;
    key_id: string;
    key_type: string;
    wrapped_key: Base64;
    import_token?: Base64;
    algorithm: string;
    key_size?: number;
    curve?: string;
    hash?: string;
    aes_key_size?: number;
}
/** Mirrors pkg/api/rest/types.go ImportKeyResponse. */
interface ImportKeyResponse {
    success: boolean;
    key_id: string;
    message?: string;
    public_key_pem?: string;
}
/** Mirrors pkg/api/rest/types.go ExportKeyRequest. */
interface ExportKeyRequest {
    backend?: string;
    algorithm: string;
}
/** Mirrors pkg/api/rest/types.go ExportKeyResponse. */
interface ExportKeyResponse {
    key_id: string;
    wrapped_key: Base64;
    algorithm: string;
    import_token?: Base64;
}
/**
 * Mirrors pkg/api/rest/types.go CopyKeyRequest. It names the source key, the
 * destination, and the wrapping algorithm, and nothing about the key itself:
 * the copy takes its algorithm, size, curve, hash and partition from the
 * source key (XKMSService.CopyKey). key_type, key_size, curve, hash and
 * aes_key_size were removed rather than kept as fields the server has never
 * read (go-xkms#1223).
 */
interface CopyKeyRequest {
    source_backend: string;
    source_key_id: string;
    dest_backend: string;
    dest_key_id: string;
    algorithm: string;
}
/** Mirrors pkg/api/rest/types.go CopyKeyResponse. */
interface CopyKeyResponse {
    success: boolean;
    message: string;
}
/** Mirrors pkg/api/transport/types.go AttestKeyRequest (POST /api/v1/attest). */
interface AttestKeyRequest {
    backend: string;
    key_id: string;
    nonce: Base64;
    tenant_id?: string;
}
/** Mirrors pkg/api/transport/types.go AttestKeyResponse. */
interface AttestKeyResponse {
    format: string;
    certificate_chain: Base64[];
    attestation_data: Base64;
    signature: Base64;
    signature_algorithm?: string;
    nonce: Base64;
    backend: string;
}
/** Mirrors pkg/api/transport/types.go DeriveKeyECDHRequest. */
interface DeriveKeyECDHRequest {
    key_id: string;
    backend: string;
    peer_public_key: Base64;
    kdf_algorithm?: string;
    kdf_hash?: string;
    kdf_salt?: Base64;
    kdf_info?: Base64;
    kdf_label?: Base64;
    key_length?: number;
    tenant_id?: string;
    /** Agree with this enabled version of the local key; omitted uses the current one. */
    key_version?: number;
}
/** Mirrors pkg/api/transport/types.go DeriveKeyECDHResponse. */
interface DeriveKeyECDHResponse {
    derived_key: Base64;
    /** The version of the local key the agreement used. */
    key_version?: number;
}
/** Mirrors pkg/api/transport/types.go ExportKeyMaterialResponse. */
interface ExportKeyMaterialResponse {
    key_material: Base64;
    key_type: string;
    key_size: number;
}
/** Mirrors pkg/api/transport/types.go WrapKeyByIDRequest. */
interface WrapKeyByIDRequest {
    wrapping_key_id: string;
    wrapping_key_backend: string;
    target_key_id: string;
    target_key_backend: string;
    target_key_material?: Base64;
    algorithm: string;
    iv?: Base64;
    aad?: Base64;
    tag_bits?: number;
    oaep_label?: Base64;
    tenant_id?: string;
}
/** Mirrors pkg/api/transport/types.go WrapKeyByIDResponse. */
interface WrapKeyByIDResponse {
    wrapped_key: Base64;
    algorithm: string;
    /** The wrapping key version that wrapped: always the current one. Pass it back on unwrap. */
    wrapping_key_version?: number;
}
/** Mirrors pkg/api/transport/types.go UnwrapKeyByIDRequest. */
interface UnwrapKeyByIDRequest {
    wrapped_key: Base64;
    unwrapping_key_id: string;
    unwrapping_key_backend: string;
    algorithm: string;
    iv?: Base64;
    aad?: Base64;
    tag_bits?: number;
    oaep_label?: Base64;
    target_key_id: string;
    target_key_backend: string;
    target_key_type: string;
    target_key_size?: number;
    target_curve?: string;
    target_partition?: string;
    target_exportable?: boolean;
    tenant_id?: string;
    /**
     * Unwrap with this enabled version. Omitted tries every enabled version for
     * AES-KW, AES-KWP, AES-GCM and RSA-OAEP, and requires exactly one enabled
     * version for AES-CBC and RSA PKCS#1 v1.5.
     */
    unwrapping_key_version?: number;
}
/** Mirrors pkg/api/transport/types.go UnwrapKeyByIDResponse. */
interface UnwrapKeyByIDResponse {
    key_id: string;
    backend: string;
    success: boolean;
    message?: string;
}

/** Key lifecycle and crypto operations. */
declare class KeysClient {
    private readonly http;
    /** A key's versions: list, enable, disable, retire, and rotate a whole tenant. */
    readonly versions: KeyVersionsClient;
    constructor(http: HttpCore);
    /** POST /api/v1/keys */
    generate(req: GenerateKeyRequest): Promise<GenerateKeyResponse>;
    /** GET /api/v1/keys?backend= */
    list(backend?: string, page?: PageQuery): Promise<ListKeysResponse>;
    /** GET /api/v1/keys/{id}?backend= */
    get(id: string, backend?: string): Promise<GetKeyResponse>;
    /** DELETE /api/v1/keys/{id}?backend= */
    delete(id: string, backend?: string): Promise<DeleteKeyResponse>;
    /**
     * POST /api/v1/keys/{id}/sign — the backend rides both the body and the
     * `?backend=` query (the handler honors the query override; clustered
     * deployments require it).
     */
    sign(id: string, req: SignRequest): Promise<SignResponse>;
    /** POST /api/v1/keys/{id}/verify */
    verify(id: string, req: VerifyRequest): Promise<VerifyResponse>;
    /**
     * POST /api/v1/keys/{id}/rotate?backend= (backend query is required) —
     * creates the key's next version and makes it current; earlier versions
     * stay enabled.
     */
    rotate(id: string, backend: string): Promise<RotateKeyResponse>;
    /** POST /api/v1/keys/{id}/encrypt */
    encrypt(id: string, req: EncryptRequest): Promise<EncryptResponse>;
    /** POST /api/v1/keys/{id}/decrypt */
    decrypt(id: string, req: DecryptRequest): Promise<DecryptResponse>;
    /** POST /api/v1/keys/{id}/encrypt-asym */
    encryptAsym(id: string, req: EncryptAsymRequest): Promise<EncryptAsymResponse>;
    /** POST /api/v1/keys/import-params */
    importParams(req: GetImportParametersRequest): Promise<GetImportParametersResponse>;
    /** POST /api/v1/keys/wrap */
    wrap(req: WrapKeyRequest): Promise<WrapKeyResponse>;
    /** POST /api/v1/keys/unwrap */
    unwrap(req: UnwrapKeyRequest): Promise<UnwrapKeyResponse>;
    /** POST /api/v1/keys/import */
    import(req: ImportKeyRequest): Promise<ImportKeyResponse>;
    /** POST /api/v1/keys/{id}/export */
    export(id: string, req: ExportKeyRequest): Promise<ExportKeyResponse>;
    /** POST /api/v1/keys/copy */
    copy(req: CopyKeyRequest): Promise<CopyKeyResponse>;
    /** POST /api/v1/attest */
    attest(req: AttestKeyRequest): Promise<AttestKeyResponse>;
    /** POST /api/v1/keys/derive-ecdh */
    deriveECDH(req: DeriveKeyECDHRequest): Promise<DeriveKeyECDHResponse>;
    /** POST /api/v1/keys/{id}/export-material?backend= */
    exportMaterial(id: string, backend: string): Promise<ExportKeyMaterialResponse>;
    /** POST /api/v1/keys/wrap-by-id */
    wrapById(req: WrapKeyByIDRequest): Promise<WrapKeyByIDResponse>;
    /** POST /api/v1/keys/unwrap-by-id */
    unwrapById(req: UnwrapKeyByIDRequest): Promise<UnwrapKeyByIDResponse>;
}

/**
 * Server-side OIDC credential DTOs. Mirrors
 * pkg/api/transport/types_oidc_credential.go — served over REST at
 * /api/v1/oidc/credentials and /api/v1/oidc/credentials/{scope}/{name}.
 *
 * A credential is a named OAuth/OIDC login xkmsd holds on the tenant barrier
 * and refreshes itself. Consumers ask for a current access token by
 * reference; the server never hands out the refresh token.
 */

/** Credential scope: "tenant" (shared) or "user" (personal, owner-only). */
type OIDCCredentialScope = 'tenant' | 'user';
/** Credential status (pkg/api/transport OIDCCredentialStatus*). */
type OIDCCredentialStatus = 'pending' | 'active' | 'relogin_required' | 'expired';
/** Mirrors transport.OIDCCredentialRef: names a credential. */
interface OIDCCredentialRef {
    /** The tenant holding the credential; empty is the caller's. */
    tenant_id?: string;
    scope: OIDCCredentialScope;
    /** The owning subject of a personal credential; empty is the caller. */
    owner?: string;
    name: string;
}
/**
 * Mirrors transport.OIDCCredentialConfig: a credential's provider
 * configuration. A template fills every field left empty; endpoints left
 * empty are discovered from the issuer at creation.
 */
interface OIDCCredentialConfig {
    template?: string;
    issuer?: string;
    client_id?: string;
    /** Write-only: never returned on a credential's public view. */
    client_secret?: string;
    scopes?: string[];
    authorization_endpoint?: string;
    token_endpoint?: string;
    device_authorization_endpoint?: string;
    /** "form" (default) or "json". */
    token_encoding?: 'form' | 'json';
    /** "rfc8628" (default) or "openai". */
    device_style?: 'rfc8628' | 'openai';
    /** A provider whose tokens cannot be refreshed. */
    no_refresh?: boolean;
    /** Dates an imported opaque token of a no_refresh provider. */
    token_lifetime_seconds?: number;
    /** How long before expiry the server refreshes; 0 is five minutes. */
    refresh_margin_seconds?: number;
}
/** Mirrors transport.OIDCCredentialTokens: tokens imported into a credential. */
interface OIDCCredentialTokens {
    access_token: string;
    refresh_token?: string;
    id_token?: string;
    token_type?: string;
    scope?: string;
    /** Absent: read from a JWT access token or the template's token lifetime. */
    expires_at?: RFC3339;
}
/** Mirrors transport.OIDCCredentialCreateRequest. */
interface OIDCCredentialCreateRequest extends OIDCCredentialRef {
    config: OIDCCredentialConfig;
    /** Present for an import-at-create; absent leaves the credential pending. */
    tokens?: OIDCCredentialTokens;
}
/** Mirrors transport.OIDCDeviceLogin: what the user needs to approve a device login. */
interface OIDCDeviceLogin {
    user_code: string;
    verification_uri: string;
    verification_uri_complete?: string;
    interval_seconds: number;
    expires_at: RFC3339;
}
/** Mirrors transport.OIDCCredential: a credential's public view (no tokens, no client secret). */
interface OIDCCredential extends OIDCCredentialRef {
    config: OIDCCredentialConfig;
    status: OIDCCredentialStatus;
    status_reason?: string;
    expires_at?: RFC3339;
    refreshable: boolean;
    last_refresh?: RFC3339;
    last_error?: string;
    device_login?: OIDCDeviceLogin;
    created_at: RFC3339;
    updated_at: RFC3339;
    created_by?: string;
}
/** Mirrors transport.OIDCCredentialListResponse. */
interface OIDCCredentialListResponse {
    credentials: OIDCCredential[];
}
/** Mirrors transport.OIDCAccessToken: a current access token of a credential. */
interface OIDCAccessToken {
    access_token: string;
    token_type: string;
    expires_at?: RFC3339;
    /** The login's ID token, when it has one. */
    id_token?: string;
    scope?: string;
}

/** Why waitForDeviceLogin gave up on a device login that is still pending. */
type OIDCDeviceLoginFailure = 'expired' | 'not_started';
/**
 * OIDCDeviceLoginError is thrown by waitForDeviceLogin when a credential is
 * still pending but no approval can arrive: its device login passed its
 * expiry ("expired"), or it has no device login in progress
 * ("not_started").
 */
declare class OIDCDeviceLoginError extends Error {
    readonly reason: OIDCDeviceLoginFailure;
    constructor(reason: OIDCDeviceLoginFailure, name: string);
}
/** Options of OidcCredentialClient.waitForDeviceLogin. */
interface WaitForDeviceLoginOptions {
    /** Aborts the wait; the promise rejects with the signal's reason. */
    signal?: AbortSignal;
    /** Called with each poll's credential while it is still pending. */
    onPending?: (credential: OIDCCredential) => void;
}
/**
 * Server-side OIDC credentials: named OAuth/OIDC logins xkmsd holds on the
 * tenant barrier and refreshes itself, tenant-shared (scope "tenant") or
 * personal (scope "user", visible only to its owner). Consumers get a current
 * access token by reference; the server never hands out the refresh token.
 * Mirrors pkg/api/rest/handlers_oidc_credential.go.
 */
declare class OidcCredentialClient {
    private readonly http;
    constructor(http: HttpCore);
    /** GET /api/v1/oidc/credentials?tenant_id= — the shared credentials and the caller's personal ones. */
    list(tenantId?: string): Promise<OIDCCredentialListResponse>;
    /**
     * POST /api/v1/oidc/credentials (201). With tokens the credential is
     * active at once; without, it is pending a device login or an import.
     */
    create(req: OIDCCredentialCreateRequest): Promise<OIDCCredential>;
    /** GET /api/v1/oidc/credentials/{scope}/{name}?tenant_id=&owner= — the public view (no tokens). */
    get(ref: OIDCCredentialRef): Promise<OIDCCredential>;
    /** DELETE /api/v1/oidc/credentials/{scope}/{name}?tenant_id=&owner= (204). */
    delete(ref: OIDCCredentialRef): Promise<void>;
    /**
     * POST /api/v1/oidc/credentials/{scope}/{name}/import — replaces the
     * credential's login with tokens obtained elsewhere and makes it active.
     */
    importTokens(ref: OIDCCredentialRef, tokens: OIDCCredentialTokens): Promise<OIDCCredential>;
    /** POST /api/v1/oidc/credentials/{scope}/{name}/refresh — refreshes now. */
    refresh(ref: OIDCCredentialRef): Promise<OIDCCredential>;
    /**
     * POST /api/v1/oidc/credentials/{scope}/{name}/token — a current access
     * token, refreshed first when inside its refresh margin. The answer is a
     * bearer secret: hold it no longer than its use.
     */
    getAccessToken(ref: OIDCCredentialRef): Promise<OIDCAccessToken>;
    /**
     * POST /api/v1/oidc/credentials/{scope}/{name}/device — starts a device
     * login; the returned credential's device_login carries the user code and
     * verification URI.
     */
    startDeviceLogin(ref: OIDCCredentialRef): Promise<OIDCCredential>;
    /**
     * POST /api/v1/oidc/credentials/{scope}/{name}/device/poll — polls the
     * device login once; the credential stays pending until the user approves.
     */
    pollDeviceLogin(ref: OIDCCredentialRef): Promise<OIDCCredential>;
    /**
     * waitForDeviceLogin polls a device login until the credential leaves
     * "pending" and resolves with it — "active" once the user approved, or
     * whatever status the server settled on. It waits the device login's
     * interval_seconds before every poll (re-read from each poll, so a
     * server-side slow-down is honoured), and never polls in a busy loop.
     *
     * Pass the credential startDeviceLogin returned so the first wait uses its
     * interval. Rejects with OIDCDeviceLoginError when the credential is still
     * pending past its device login's expiry or has no device login, with the
     * signal's reason when aborted, and with the poll's error when one fails.
     */
    waitForDeviceLogin(credential: OIDCCredentialRef | OIDCCredential, opts?: WaitForDeviceLoginOptions): Promise<OIDCCredential>;
}

/** Password store DTOs. Mirrors pkg/api/rest/password_handlers.go. */

interface PasswordAddRequest {
    name: string;
    title?: string;
    username?: string;
    password: string;
    url?: string;
    notes?: string;
    folder_path?: string;
    shared?: boolean;
}
interface PasswordAddResponse {
    id: string;
    name: string;
    message: string;
}
interface PasswordInfo {
    id: string;
    name: string;
    title?: string;
    username?: string;
    url?: string;
    folder_path?: string;
    owner_id?: string;
    shared?: boolean;
    created_at: string;
    updated_at: string;
}
interface PasswordListResponse {
    passwords: PasswordInfo[];
    total: number;
}
interface PasswordDetailResponse {
    id: string;
    name: string;
    title?: string;
    username?: string;
    password: string;
    url?: string;
    notes?: string;
    folder_path?: string;
    owner_id?: string;
    shared?: boolean;
    read_only?: boolean;
    created_at: string;
    updated_at: string;
}
/** All members optional: only supplied fields are updated (Go *string semantics). */
interface PasswordUpdateRequest {
    name?: string;
    title?: string;
    username?: string;
    password?: string;
    url?: string;
    notes?: string;
    folder_path?: string;
}
interface PasswordUpdateResponse {
    id: string;
    name: string;
    message: string;
}
interface PasswordDeleteResponse {
    message: string;
}
/**
 * A factor of the caller's personal password vault. Mirrors
 * pkg/api/transport PasswordVaultCredential.
 *
 * - `passphrase`: set `passphrase`.
 * - `passkey`: a FIDO2 credential with the hmac-secret / WebAuthn PRF
 *   extension. Set `credential_id` and `secret` (the 32-byte PRF output the
 *   authenticator evaluated over the factor's 32-byte `prf_salt`); enrolling
 *   a passkey also sets `prf_salt` and `rp_id` (the server's
 *   `passkey_rp_id`). See `vaultPasskey.ts`.
 * - `piv` / `certificate` / `tpm` (key factors): enrolled by xkey or xkmsctl
 *   with the key's `public_key` or `certificate`; unlocked with
 *   `key_fingerprint` and the `secret` the private key recovered -- in a
 *   browser only through the xkey extension (`vaultBridge.ts`).
 */
interface PasswordVaultCredential {
    factor: PasswordVaultFactorType;
    passphrase?: string;
    credential_id?: Base64;
    prf_salt?: Base64;
    secret?: Base64;
    label?: string;
    rp_id?: string;
    public_key?: Base64;
    certificate?: Base64;
    key_fingerprint?: string;
    key_ref?: PasswordVaultKeyRef;
}
/** The vault factor types a client can enroll or unlock with. */
type PasswordVaultFactorType = 'passphrase' | 'passkey' | PasswordVaultKeyFactorType;
/** Key factors: a secret only the factor's private key recovers. */
type PasswordVaultKeyFactorType = 'piv' | 'certificate' | 'tpm';
/** Where a key factor's private key lives on the client (a selection hint). */
interface PasswordVaultKeyRef {
    backend?: string;
    key_id?: string;
    tpm_policy?: string;
}
/** POST /api/v1/password-vault/unlock opens the caller's session with one of their vault factors. */
type PasswordStoreUnlockRequest = PasswordVaultCredential;
/**
 * The factor types a vault status lists: the enrollable ones plus the
 * recovery code every vault holds, which is never removed or unlocked with.
 */
type PasswordVaultFactorInfoType = PasswordVaultFactorType | 'recovery';
/** One enrolled vault factor (never key material). */
interface PasswordVaultFactor {
    id: string;
    factor: PasswordVaultFactorInfoType;
    label?: string;
    created_at: RFC3339;
    /** Passkey factors only: the credential to request from the authenticator. */
    credential_id?: Base64;
    /** Passkey factors only: the salt to evaluate the PRF over when unlocking. */
    prf_salt?: Base64;
    /** Passkey factors only: the relying party ID the passkey was created for. */
    rp_id?: string;
    /** Key factors only: what the private key's holder recovers the secret from. */
    key_fingerprint?: string;
    key_algorithm?: string;
    key_challenge?: Base64;
    key_check?: Base64;
    key_ref?: PasswordVaultKeyRef;
    certificate_subject?: string;
}
/** GET /api/v1/password-vault */
interface PasswordVaultStatusResponse {
    initialized: boolean;
    unlocked: boolean;
    factors: PasswordVaultFactor[];
    /**
     * The relying party ID a new passkey must be created for -- the console's
     * domain. Absent when the deployment offers no passkeys.
     */
    passkey_rp_id?: string;
}
/** POST /api/v1/password-vault/factors */
type PasswordVaultEnrollRequest = PasswordVaultCredential;
/**
 * The enrolled (or rotated, or recovered) factor. `recovery_code` is present
 * only on the first enrollment and on a recovery, and is shown exactly once.
 */
interface PasswordVaultEnrollResponse {
    factor: PasswordVaultFactor;
    recovery_code?: string;
}
/** PUT /api/v1/password-vault/factors/{id}: a new secret of the same factor type. */
type PasswordVaultRotateRequest = PasswordVaultCredential;
/** POST /api/v1/password-vault/recover */
interface PasswordVaultRecoverRequest extends PasswordVaultCredential {
    recovery_code: string;
}
interface PasswordStoreAccessModeRequest {
    mode: string;
}
interface PasswordStoreAccessModeResponse {
    mode: string;
    message: string;
}
interface PasswordStoreStatusResponse {
    available: boolean;
    is_locked: boolean;
    barrier_sealed: boolean;
    password_count: number;
    message: string;
}
interface PasswordGenerateRequest {
    length?: number;
    charset?: string;
}
interface PasswordGenerateResponse {
    password: string;
    length: number;
}

/** Password store management. */
declare class PasswordsClient {
    private readonly http;
    constructor(http: HttpCore);
    /** POST /api/v1/passwords/ */
    add(req: PasswordAddRequest): Promise<PasswordAddResponse>;
    /** GET /api/v1/passwords/?folder=&scope= */
    list(folder?: string, scope?: string): Promise<PasswordListResponse>;
    /** GET /api/v1/passwords/{id} */
    get(id: string): Promise<PasswordDetailResponse>;
    /** PUT /api/v1/passwords/{id} */
    update(id: string, req: PasswordUpdateRequest): Promise<PasswordUpdateResponse>;
    /** DELETE /api/v1/passwords/{id} */
    delete(id: string): Promise<PasswordDeleteResponse>;
    /** POST /api/v1/password-vault/unlock -- opens the caller's session with one of their vault factors. */
    unlock(req: PasswordStoreUnlockRequest): Promise<PasswordStoreStatusResponse>;
    /** GET /api/v1/password-vault */
    vaultStatus(): Promise<PasswordVaultStatusResponse>;
    /**
     * POST /api/v1/password-vault/factors -- the first enrollment initializes
     * the vault, opens the session and returns the one-time recovery code.
     */
    vaultEnroll(req: PasswordVaultEnrollRequest): Promise<PasswordVaultEnrollResponse>;
    /** PUT /api/v1/password-vault/factors/{id} */
    vaultRotate(factorId: string, req: PasswordVaultRotateRequest): Promise<PasswordVaultEnrollResponse>;
    /** DELETE /api/v1/password-vault/factors/{id} (204 No Content) */
    vaultRemoveFactor(factorId: string): Promise<void>;
    /** POST /api/v1/password-vault/recover -- returns the replacement recovery code. */
    vaultRecover(req: PasswordVaultRecoverRequest): Promise<PasswordVaultEnrollResponse>;
    /** POST /api/v1/password-vault/lock */
    lock(): Promise<PasswordStoreStatusResponse>;
    /** GET /api/v1/password-vault/session -- the caller's session and the entries it can read now. */
    status(): Promise<PasswordStoreStatusResponse>;
    /** POST /api/v1/passwords/access-mode */
    setAccessMode(req: PasswordStoreAccessModeRequest): Promise<PasswordStoreAccessModeResponse>;
    /** POST /api/v1/passwords/generate */
    generate(req: PasswordGenerateRequest): Promise<PasswordGenerateResponse>;
}

/** PIN management DTOs. Mirrors pkg/api/rest/handlers_barrier_pin.go. */

interface SetSOPINRequest {
    current_so_pin: string;
    new_so_pin: string;
}
interface SetUserPINRequest {
    so_pin: string;
    new_user_pin: string;
}
interface ChangeSOPINRequest {
    current_so_pin: string;
    new_so_pin: string;
}
interface ChangeUserPINRequest {
    current_user_pin: string;
    new_user_pin: string;
}
/** Mirrors pkg/api/rest/handlers_barrier_pin.go VerifyPINRequest. */
interface VerifyPINRequest {
    pin: string;
}
interface ResetLockoutRequest {
    so_pin: string;
}
/** Mirrors pkg/api/rest/handlers_barrier_pin.go LockoutStatusResponse. */
interface LockoutStatusResponse {
    failed_attempts: number;
    max_attempts: number;
    is_locked: boolean;
    lockout_until?: RFC3339;
    recovery_seconds: number;
}

/** SO / User PIN management. */
declare class PinClient {
    private readonly http;
    constructor(http: HttpCore);
    /** POST /api/v1/pin/so/set */
    setSO(req: SetSOPINRequest): Promise<SuccessResponse>;
    /** POST /api/v1/pin/user/set */
    setUser(req: SetUserPINRequest): Promise<SuccessResponse>;
    /** POST /api/v1/pin/so/change */
    changeSO(req: ChangeSOPINRequest): Promise<SuccessResponse>;
    /** POST /api/v1/pin/user/change */
    changeUser(req: ChangeUserPINRequest): Promise<SuccessResponse>;
    /** POST /api/v1/pin/so/verify */
    verifySO(req: VerifyPINRequest): Promise<SuccessResponse>;
    /** POST /api/v1/pin/user/verify */
    verifyUser(req: VerifyPINRequest): Promise<SuccessResponse>;
    /** GET /api/v1/pin/lockout */
    lockoutStatus(): Promise<LockoutStatusResponse>;
    /** POST /api/v1/pin/lockout/reset */
    resetLockout(req: ResetLockoutRequest): Promise<SuccessResponse>;
}

/** PIV smart-card DTOs. Mirrors pkg/api/transport/types.go PIV shapes. */

interface PIVSlotStatus {
    slot: string;
    name: string;
    description: string;
    has_cert: boolean;
    has_key: boolean;
    subject?: string;
    issuer?: string;
    algorithm?: string;
    key_size?: number;
    not_after?: string;
    fingerprint?: string;
    backend?: string;
}
interface ListPIVSlotsResponse {
    slots: PIVSlotStatus[];
    page: number;
    page_size: number;
    total: number;
    has_more: boolean;
}
interface GetPIVCertificateResponse {
    slot: string;
    certificate: Base64;
    format: string;
}
/** Body for POST /piv/slots/{slot}/certificate and /import. */
interface StorePIVCertificateRequest {
    backend?: string;
    slot?: string;
    certificate: Base64;
    format: string;
    tenant_id?: string;
}
interface GeneratePIVKeyRequest {
    backend?: string;
    slot?: string;
    algorithm: string;
    subject: string;
    organization?: string;
    country?: string;
    output_format?: string;
    validity_days?: number;
    tenant_id?: string;
}
interface GeneratePIVKeyResponse {
    slot: string;
    certificate: Base64;
    public_key: Base64;
    csr?: Base64;
    chain_pem?: Base64;
}
interface GeneratePIVCSRRequest {
    backend?: string;
    slot?: string;
    subject: string;
    organization?: string;
    organizational_unit?: string;
    country?: string;
    state?: string;
    locality?: string;
    tenant_id?: string;
}
interface GeneratePIVCSRResponse {
    slot: string;
    csr: Base64;
}

/** PIV smart-card slot operations. */
declare class PivClient {
    private readonly http;
    constructor(http: HttpCore);
    /** GET /api/v1/piv/slots?backend= */
    listSlots(backend?: string): Promise<ListPIVSlotsResponse>;
    /** GET /api/v1/piv/slots/{slot}/certificate?backend=&format= */
    getCertificate(slot: string, backend?: string, format?: string): Promise<GetPIVCertificateResponse>;
    /** POST /api/v1/piv/slots/{slot}/certificate */
    storeCertificate(slot: string, req: StorePIVCertificateRequest): Promise<SuccessResponse>;
    /** DELETE /api/v1/piv/slots/{slot}/certificate?backend= */
    deleteCertificate(slot: string, backend?: string): Promise<SuccessResponse>;
    /** POST /api/v1/piv/slots/{slot}/generate */
    generateKey(slot: string, req: GeneratePIVKeyRequest): Promise<GeneratePIVKeyResponse>;
    /** POST /api/v1/piv/slots/{slot}/import */
    importCertificate(slot: string, req: StorePIVCertificateRequest): Promise<SuccessResponse>;
    /** GET /api/v1/piv/slots/{slot}/export?backend=&format= */
    exportCertificate(slot: string, backend?: string, format?: string): Promise<GetPIVCertificateResponse>;
    /** POST /api/v1/piv/slots/{slot}/csr */
    generateCSR(slot: string, req: GeneratePIVCSRRequest): Promise<GeneratePIVCSRResponse>;
}

/** Sealed platform store DTOs. Mirrors pkg/api/rest/seal_store_handlers.go. */

interface SealStorePutRequest {
    name: string;
    /** base64-encoded secret bytes */
    secret: Base64;
}
interface SealStorePutResponse {
    name: string;
    message: string;
}
interface SealStoreGetResponse {
    name: string;
    /** base64-encoded secret bytes */
    secret: Base64;
}
interface SealStoreListResponse {
    names: string[];
    total: number;
}
interface SealStoreDeleteResponse {
    message: string;
}
interface SealStoreResealResponse {
    name: string;
    message: string;
}
interface SealStoreStatusResponse {
    available: boolean;
    names: string[];
    total: number;
}

/** Sealed platform credential store. */
declare class PlatformClient {
    private readonly http;
    constructor(http: HttpCore);
    /** PUT /api/v1/platform/secrets/{key} */
    putSecret(key: string, req: SealStorePutRequest): Promise<SealStorePutResponse>;
    /** GET /api/v1/platform/secrets/{key} */
    getSecret(key: string): Promise<SealStoreGetResponse>;
    /** DELETE /api/v1/platform/secrets/{key} */
    deleteSecret(key: string): Promise<SealStoreDeleteResponse>;
    /** GET /api/v1/platform/secrets */
    listSecrets(): Promise<SealStoreListResponse>;
    /** POST /api/v1/platform/secrets/{key}/reseal */
    resealSecret(key: string): Promise<SealStoreResealResponse>;
    /** GET /api/v1/platform/status */
    status(): Promise<SealStoreStatusResponse>;
}

/** Mirrors pkg/api/rest/types.go SealRequest. */
interface SealRequest {
    backend: string;
    key_id?: string;
    data: Base64;
    aad?: Base64;
    /** The sealed object's authorization value (TPM2-specific). */
    password?: string;
    /** Names the TPM policy a TPM2 sealed object is bound to (TPM2 backends only). */
    tpm_policy?: string;
}
/** Mirrors pkg/api/rest/types.go SealResponse. */
interface SealResponse {
    backend: string;
    ciphertext: Base64;
    nonce?: Base64;
    tag?: Base64;
    metadata?: Record<string, Base64>;
    key_id?: string;
    /** The sealing key version; absent for a TPM2 sealed object. Pass it back on unseal. */
    key_version?: number;
}
/** Mirrors pkg/api/rest/types.go UnsealRequest. */
interface UnsealRequest {
    backend: string;
    key_id?: string;
    ciphertext: Base64;
    nonce?: Base64;
    tag?: Base64;
    aad?: Base64;
    metadata?: Record<string, Base64>;
    /** The sealing key version the seal reported; omitted tries every enabled version. */
    key_version?: number;
}
/** Mirrors pkg/api/rest/types.go UnsealResponse. */
interface UnsealResponse {
    plaintext: Base64;
}
/** Mirrors pkg/api/rest/types.go CanSealResponse (GET /api/v1/seal/capability). */
interface CanSealResponse {
    can_seal: boolean;
    backend?: string;
}

/** Hardware-backed data sealing. */
declare class SealClient {
    private readonly http;
    constructor(http: HttpCore);
    /** POST /api/v1/seal */
    seal(req: SealRequest): Promise<SealResponse>;
    /** POST /api/v1/unseal */
    unseal(req: UnsealRequest): Promise<UnsealResponse>;
    /** GET /api/v1/seal/capability?backend= */
    capability(backend?: string): Promise<CanSealResponse>;
}

/** Custodian share DTOs. Mirrors pkg/api/rest/handlers_share.go. */

interface SubmitShareRequest {
    server_url: string;
    group_id: string;
    group_name?: string;
    share_index: number;
    share_data: Base64;
    purpose?: string;
    tenant_id?: string;
}
/** The share status shape returned by submit / get / list (share data omitted). */
interface ShareStatusResponse {
    server_url: string;
    group_id: string;
    group_name?: string;
    share_index: number;
    purpose?: string;
    received_at: string;
    tenant_id?: string;
}
interface ListSharesResponse {
    shares: ShareStatusResponse[];
    pagination: PageResponse;
}
interface ShareCollectionStatusResponse {
    group_id: string;
    collected: number;
}

/** Custodian share submission and inspection. */
declare class SharesClient {
    private readonly http;
    constructor(http: HttpCore);
    /** POST /api/v1/shares/submit */
    submit(req: SubmitShareRequest): Promise<ShareStatusResponse>;
    /** GET /api/v1/shares/ */
    list(page?: PageQuery): Promise<ListSharesResponse>;
    /** GET /api/v1/shares/{serverURL}/{groupID}/{shareIndex} (serverURL is path-escaped). */
    get(serverURL: string, groupId: string, shareIndex: number): Promise<ShareStatusResponse>;
    /** DELETE /api/v1/shares/{serverURL}/{groupID}/{shareIndex} (204). */
    delete(serverURL: string, groupId: string, shareIndex: number): Promise<void>;
    /** GET /api/v1/shares/status/{groupID} */
    collectionStatus(groupId: string): Promise<ShareCollectionStatusResponse>;
}

/**
 * SSH DTOs for the REST routes under /xkms/v1/ssh. Mirrors
 * sdk/go/client/ssh/types.go and the REST-local wire shapes in
 * pkg/api/rest/handlers_ssh.go.
 */

/** Mirrors sdk/go/client/ssh types.go Key. */
interface SSHKey {
    scope: string;
    owner: string;
    name: string;
    algorithm: string;
    public_key: string;
    fingerprint: string;
    created_at: RFC3339;
    comment?: string;
    backend?: string;
    backend_key_id?: string;
}
/** Mirrors sdk/go/client/ssh types.go PublicKey (export-public response). */
interface SSHPublicKey {
    algorithm: string;
    line: string;
    fingerprint: string;
}
/** Mirrors sdk/go/client/ssh types.go Pin (known-host pin). */
interface SSHPin {
    scope: string;
    owner: string;
    host: string;
    fingerprint: string;
    algorithm?: string;
    added_at: RFC3339;
    source?: string;
}
/** Mirrors sdk/go/client/ssh types.go AuthorizedEntry. */
interface SSHAuthorizedEntry {
    scope: string;
    owner: string;
    name: string;
    line: string;
    options?: string[];
    comment?: string;
}
/** Mirrors sdk/go/client/ssh types.go GenerateRequest. */
interface SSHGenerateKeyRequest {
    scope: string;
    owner: string;
    name: string;
    algorithm: string;
    rsa_bits?: number;
    comment?: string;
    backend?: string;
}
/** Mirrors pkg/api/rest/handlers_ssh.go restImportDTO. */
interface SSHImportKeyRequest {
    scope: string;
    owner: string;
    name: string;
    comment?: string;
    /** base64-encoded PEM bytes */
    pem: Base64;
    /** base64-encoded passphrase (decoded server-side into a secure buffer) */
    passphrase_b64?: Base64;
}
/** Mirrors pkg/api/rest/handlers_ssh.go restSignRequestDTO. */
interface SSHSignRequest {
    /** base64-encoded digest bytes */
    digest: Base64;
}
/** Mirrors pkg/api/rest/handlers_ssh.go restSignResponseDTO. */
interface SSHSignResponse {
    format: string;
    blob: Base64;
    rest?: Base64;
}
/** Mirrors sdk/go/client/ssh types.go AddKnownHostRequest. */
interface SSHAddKnownHostRequest {
    scope: string;
    owner: string;
    host: string;
    fingerprint: string;
    algorithm?: string;
    source?: string;
}
/** Mirrors pkg/api/rest/handlers_ssh.go restVerifyRequestDTO. */
interface SSHVerifyKnownHostRequest {
    scope: string;
    owner: string;
    fingerprint: string;
    algorithm?: string;
}
/** Mirrors sdk/go/client/ssh types.go AddAuthorizedKeyRequest. */
interface SSHAddAuthorizedKeyRequest {
    scope: string;
    owner: string;
    name: string;
    line: string;
    options?: string[];
}
/** Mirrors sdk/go/client/ssh types.go EmitRequest. */
interface SSHEmitRequest {
    public_key: string;
    options?: string[];
    comment?: string;
}
/** Mirrors pkg/api/rest/handlers_ssh.go restEmitResponseDTO. */
interface SSHEmitResponse {
    line: string;
}
/** Mirrors pkg/api/rest/handlers_ssh.go restAuthVerifyRequestDTO. */
interface SSHVerifyAuthorizedRequest {
    scope: string;
    owner: string;
    fingerprint: string;
    algorithm?: string;
}
/** List envelopes ({items: [...]}) used by the SSH list routes. */
interface SSHKeyListResponse {
    items: SSHKey[];
}
interface SSHPinListResponse {
    items: SSHPin[];
}
interface SSHAuthorizedListResponse {
    items: SSHAuthorizedEntry[];
}

/** SSH key, known-host, and authorized-key management over REST (/xkms/v1/ssh). */
declare class SshClient {
    private readonly http;
    constructor(http: HttpCore);
    /** POST /xkms/v1/ssh/keys */
    generateKey(req: SSHGenerateKeyRequest): Promise<SSHKey>;
    /** POST /xkms/v1/ssh/keys/import */
    importKey(req: SSHImportKeyRequest): Promise<SSHKey>;
    /** GET /xkms/v1/ssh/keys?scope=&owner= */
    listKeys(scope?: string, owner?: string): Promise<SSHKeyListResponse>;
    /** GET /xkms/v1/ssh/keys/{scope}/{owner}/{name} */
    getKey(scope: string, owner: string, name: string): Promise<SSHKey>;
    /** DELETE /xkms/v1/ssh/keys/{scope}/{owner}/{name} (204). */
    deleteKey(scope: string, owner: string, name: string): Promise<void>;
    /** GET /xkms/v1/ssh/keys/{scope}/{owner}/{name}/public */
    exportPublic(scope: string, owner: string, name: string): Promise<SSHPublicKey>;
    /** POST /xkms/v1/ssh/keys/{scope}/{owner}/{name}/sign */
    sign(scope: string, owner: string, name: string, req: SSHSignRequest): Promise<SSHSignResponse>;
    /** POST /xkms/v1/ssh/known-hosts (201). */
    addKnownHost(req: SSHAddKnownHostRequest): Promise<void>;
    /** GET /xkms/v1/ssh/known-hosts?scope=&owner= */
    listKnownHosts(scope?: string, owner?: string): Promise<SSHPinListResponse>;
    /** DELETE /xkms/v1/ssh/known-hosts/{host}?scope=&owner= (204). */
    removeKnownHost(host: string, scope?: string, owner?: string): Promise<void>;
    /**
     * POST /xkms/v1/ssh/known-hosts/{host}/verify — resolves on match (204);
     * a mismatch surfaces as an XkmsApiError with status 409 whose envelope
     * carries expected/received fingerprints.
     */
    verifyKnownHost(host: string, req: SSHVerifyKnownHostRequest): Promise<void>;
    /** POST /xkms/v1/ssh/authorized-keys (201). */
    addAuthorizedKey(req: SSHAddAuthorizedKeyRequest): Promise<void>;
    /** GET /xkms/v1/ssh/authorized-keys?scope=&owner= */
    listAuthorizedKeys(scope?: string, owner?: string): Promise<SSHAuthorizedListResponse>;
    /** GET /xkms/v1/ssh/authorized-keys/{scope}/{owner}/{name} */
    getAuthorizedKey(scope: string, owner: string, name: string): Promise<SSHAuthorizedEntry>;
    /** DELETE /xkms/v1/ssh/authorized-keys/{scope}/{owner}/{name} (204). */
    removeAuthorizedKey(scope: string, owner: string, name: string): Promise<void>;
    /** POST /xkms/v1/ssh/authorized-keys/emit */
    emitAuthorizedKey(req: SSHEmitRequest): Promise<SSHEmitResponse>;
    /** POST /xkms/v1/ssh/authorized-keys/verify — returns the matching entry. */
    verifyAuthorizedKey(req: SSHVerifyAuthorizedRequest): Promise<SSHAuthorizedEntry>;
}

/**
 * Tenant DTOs. Requests/responses mirror pkg/api/rest/handlers_tenant.go
 * local shapes; entitlements/quotas mirror go-qrdb/sdk/go/transport
 * tenant_types.go (the handlers decode/encode those transport shapes
 * directly for PUT entitlements/quotas).
 */

/** Mirrors pkg/api/rest/handlers_tenant.go createTenantRequest. */
interface CreateTenantRequest {
    id: string;
    name: string;
    isolation_type?: string;
    barrier_auto_unseal?: boolean;
}
/** Mirrors pkg/api/rest/handlers_tenant.go tenantInfoResponse. */
interface TenantInfoResponse {
    id: string;
    name?: string;
    sealed: boolean;
    isolation_type?: string;
    created_at?: string;
    updated_at?: string;
}
/** Mirrors pkg/api/rest/handlers_tenant.go wrappedTenantResponse. */
interface WrappedTenantResponse {
    tenant: TenantInfoResponse;
}
/** Mirrors pkg/api/rest/handlers_tenant.go listTenantsResponse. */
interface ListTenantsResponse {
    tenants: TenantInfoResponse[];
    pagination: PageResponse;
}
/** Mirrors pkg/api/rest/handlers_tenant.go tenantBarrierStatusResponse. */
interface TenantBarrierStatusResponse {
    tenant_id: string;
    sealed: boolean;
    strategy?: string;
    hardware_backed: boolean;
    /** Present when the servicer path reports full status (qrdb transport shape). */
    initialized?: boolean;
    shamir_threshold?: number;
    shamir_total?: number;
}
/** Mirrors pkg/api/rest/handlers_tenant.go tenantBarrierInitRequest. */
interface TenantBarrierInitRequest {
    passphrase?: string;
    strategy?: string;
    threshold?: number;
    shares?: number;
}
/** Mirrors pkg/api/rest/handlers_tenant.go tenantBarrierUnsealRequest. */
interface TenantBarrierUnsealRequest {
    share?: Base64;
    key?: Base64;
}
/** Mirrors go-qrdb/sdk/go/transport tenant_types.go TenantQuotas. */
interface TenantQuotas {
    max_databases: number;
    max_raft_groups: number;
    max_replicas_per_group: number;
    max_total_replicas: number;
    max_collections: number;
    max_keys: number;
    max_storage_bytes: number;
    max_database_size_bytes: number;
    max_users: number;
    max_roles: number;
    max_certificates: number;
    max_backups: number;
    max_vector_dims: number;
    max_ts_metrics: number;
    system_barrier_quota: number;
    max_dedicated_wal_groups: number;
}
/** Mirrors go-qrdb/sdk/go/transport tenant_types.go TenantEntitlements. */
interface TenantEntitlements {
    allowed_isolation_modes?: string[];
    allow_dedicated_raft?: boolean;
    allow_volume_storage?: boolean;
    allow_system_managed_barrier?: boolean;
    allowed_barrier_modes?: string[];
    allow_dedicated_wal?: boolean;
}
/** Mirrors go-qrdb/sdk/go/transport tenant_types.go TenantInfo. */
interface TenantInfo {
    id: string;
    name: string;
    isolation_type?: string;
    data_root?: string;
    quotas?: TenantQuotas;
    entitlements?: TenantEntitlements;
    created_at: RFC3339;
    updated_at: RFC3339;
}
/** Mirrors go-qrdb transport UpdateTenantEntitlementsRequest. */
interface UpdateTenantEntitlementsRequest {
    tenant_id: string;
    entitlements: TenantEntitlements;
}
/** Mirrors go-qrdb transport UpdateTenantEntitlementsResponse. */
interface UpdateTenantEntitlementsResponse {
    tenant: TenantInfo;
}
/** Mirrors go-qrdb transport UpdateTenantQuotasRequest. */
interface UpdateTenantQuotasRequest {
    tenant_id: string;
    quotas: TenantQuotas;
}
/** Mirrors go-qrdb transport UpdateTenantQuotasResponse. */
interface UpdateTenantQuotasResponse {
    tenant: TenantInfo;
}
/**
 * Mirrors pkg/api/transport/types.go TenantTPMModeResponse. System-scope
 * only: a tenant-scoped caller is refused even for its own tenant.
 */
interface TenantTPMModeResponse {
    tenant_id: string;
    /** "none", "shared" or "vtpm". */
    mode: string;
}
/**
 * Mirrors pkg/api/transport/types.go SetTenantTPMModeRequest. Refused while
 * the tenant's scope holds objects or policies, which cannot move between
 * TPMs.
 */
interface SetTenantTPMModeRequest {
    tenant_id: string;
    mode: string;
    owner_auth?: Base64;
}
/** Mirrors pkg/api/transport/types.go TenantVTPMStatusResponse. */
interface TenantVTPMStatusResponse {
    tenant_id: string;
    running: boolean;
    pid?: number;
    socket?: string;
    restarts?: number;
}

/** Tenant lifecycle, per-tenant barriers, entitlements, and quotas. */
declare class TenantsClient {
    private readonly http;
    constructor(http: HttpCore);
    /** POST /api/v1/tenants/ */
    create(req: CreateTenantRequest): Promise<WrappedTenantResponse>;
    /** GET /api/v1/tenants/ */
    list(page?: PageQuery): Promise<ListTenantsResponse>;
    /** GET /api/v1/tenants/{tenantID} */
    get(tenantId: string): Promise<WrappedTenantResponse>;
    /** DELETE /api/v1/tenants/{tenantID} (204). */
    delete(tenantId: string): Promise<void>;
    /** GET /api/v1/tenants/{tenantID}/barrier/status */
    barrierStatus(tenantId: string): Promise<TenantBarrierStatusResponse>;
    /** POST /api/v1/tenants/{tenantID}/barrier/init */
    barrierInit(tenantId: string, req: TenantBarrierInitRequest): Promise<TenantBarrierStatusResponse>;
    /** POST /api/v1/tenants/{tenantID}/barrier/unseal */
    barrierUnseal(tenantId: string, req: TenantBarrierUnsealRequest): Promise<TenantBarrierStatusResponse>;
    /** PUT /api/v1/tenants/{tenantID}/entitlements */
    updateEntitlements(tenantId: string, req: UpdateTenantEntitlementsRequest): Promise<UpdateTenantEntitlementsResponse>;
    /** PUT /api/v1/tenants/{tenantID}/quotas */
    updateQuotas(tenantId: string, req: UpdateTenantQuotasRequest): Promise<UpdateTenantQuotasResponse>;
    /**
     * GET /api/v1/tenants/{tenantID}/tpm — a tenant's TPM mode. System-scope
     * only.
     */
    getTPMMode(tenantId: string): Promise<TenantTPMModeResponse>;
    /**
     * PUT /api/v1/tenants/{tenantID}/tpm — changes a tenant's TPM mode.
     * Refused while the tenant's scope holds objects or policies.
     */
    setTPMMode(tenantId: string, req: SetTenantTPMModeRequest): Promise<TenantTPMModeResponse>;
    /** GET /api/v1/tenants/{tenantID}/tpm/vtpm — a vtpm-mode tenant's virtual TPM. */
    vtpmStatus(tenantId: string): Promise<TenantVTPMStatusResponse>;
    /** POST /api/v1/tenants/{tenantID}/tpm/vtpm/start */
    vtpmStart(tenantId: string): Promise<TenantVTPMStatusResponse>;
    /** POST /api/v1/tenants/{tenantID}/tpm/vtpm/stop */
    vtpmStop(tenantId: string): Promise<TenantVTPMStatusResponse>;
}

/**
 * TPM policy DTOs. Mirrors pkg/api/transport/types.go (the TPM policy
 * section) — served over REST at /api/v1/tpm/policies,
 * /api/v1/keys/{id}/tpm-policy, /api/v1/tpm/authority/rotate, and a
 * tenant's TPM mode/vTPM under /api/v1/tenants/{tenantID}/tpm. See
 * docs/tpm-policies/api.md.
 */

/** TPM policy condition types (pkg/api/transport TPMPolicyCondition*). */
type TPMPolicyConditionType = 'pcr' | 'auth_value' | 'locality';
/**
 * Mirrors pkg/api/transport/types.go TPMPolicyCondition: one condition of a
 * branch. Only the fields of its type are set.
 */
interface TPMPolicyCondition {
    type: TPMPolicyConditionType;
    /** A pcr condition's bank: sha1, sha256, sha384 or sha512. */
    bank?: string;
    /** A pcr condition's PCR indices, 0-23. */
    pcrs?: number[];
    /**
     * A pcr condition's hex-encoded values captured at create/update, keyed by
     * PCR index. Reported only; a create request carrying them is refused.
     */
    pcr_values?: Record<string, string>;
    /** Hex-encoded PolicyPCR digest over pcr_values. Reported only. */
    pcr_digest?: string;
    /** A locality condition's allowed localities, 0-4. */
    localities?: number[];
}
/**
 * Mirrors pkg/api/transport/types.go TPMPolicyBranch: the AND of its
 * conditions, at most one of each type.
 */
interface TPMPolicyBranch {
    conditions: TPMPolicyCondition[];
    /** Whether the branch holds an approval; reported on a policy only. */
    approved?: boolean;
}
/** Mirrors pkg/api/transport/types.go TPMPolicy: an OR of branches. */
interface TPMPolicy {
    name: string;
    /** Empty for the system scope. */
    tenant_id?: string;
    /** Free text, settable at creation and at any time after. */
    description?: string;
    /** The policy's branches, tried in order when an object is used. */
    branches: TPMPolicyBranch[];
    /** The policy's NV index; objects bound to it follow it. */
    index: number;
    /** False after a revoke until the next update. */
    approved: boolean;
    epoch?: number;
    authority_generation?: number;
    /** Marks the policy barrier auto-unseal uses. */
    auto_unseal?: boolean;
    created_at: RFC3339;
    updated_at?: RFC3339;
}
/**
 * Mirrors pkg/api/transport/types.go TPMPolicyCreateRequest. The values of
 * its pcr conditions are always captured live from the tenant's TPM; the
 * caller never supplies them. pcrBranch (clients/tpmPolicy.ts) builds the
 * common one-branch policy over a PCR selection.
 */
interface TPMPolicyCreateRequest {
    tenant_id?: string;
    name: string;
    description?: string;
    branches: TPMPolicyBranch[];
    auto_unseal?: boolean;
    /** The physical TPM's owner-hierarchy authorization; never logged. */
    owner_auth?: Base64;
}
/** Mirrors pkg/api/transport/types.go TPMPolicyListResponse. */
interface TPMPolicyListResponse {
    policies: TPMPolicy[];
}
/**
 * Mirrors pkg/api/transport/types.go TPMPolicyDeleteRequest. Deletion is
 * refused (409) while any object is assigned to the policy.
 */
interface TPMPolicyDeleteRequest {
    tenant_id?: string;
    owner_auth?: Base64;
}
/** Mirrors pkg/api/transport/types.go TPMPolicyBranchVerification. */
interface TPMPolicyBranchVerification {
    /** True when the branch's pcr condition, if any, still holds its values. */
    match: boolean;
    /** PCR indices that no longer match, ascending. */
    mismatched?: number[];
    /** Whether the branch's approval is current. */
    approved: boolean;
}
/**
 * Mirrors pkg/api/transport/types.go TPMPolicyVerifyResponse. Advisory: the
 * TPM itself enforces the policy on use.
 */
interface TPMPolicyVerifyResponse {
    name: string;
    /** True when every branch matches. */
    match: boolean;
    /** True when every branch's approval is current. */
    approved: boolean;
    /** Each branch, index-aligned with the policy's. */
    branches: TPMPolicyBranchVerification[];
}
/**
 * Mirrors pkg/api/transport/types.go TPMPolicyObjectsResponse. Objects are
 * "<kind>/<name>" IDs (kind is "key" or "sealed"), sorted.
 */
interface TPMPolicyObjectsResponse {
    name: string;
    objects: string[];
}
/** TPM object kinds a policy is assigned to (pkg/api/transport/types.go). */
type TPMObjectKind = 'key' | 'sealed';
/** Mirrors pkg/api/transport/types.go TPMObjectPolicyResponse. */
interface TPMObjectPolicyResponse {
    object_id: string;
    kind: string;
    policy: string;
    /** Hex-encoded authPolicy digest at creation. */
    auth_policy?: string;
    created_at: RFC3339;
}
/** Mirrors pkg/api/transport/types.go TPMAuthorityRotateResponse. */
interface TPMAuthorityRotateResponse {
    tenant_id?: string;
    /** Counts rotations. */
    generation: number;
    /** The new authority's hex-encoded TPM Name; every approval is now verified against it. */
    authority_name: string;
    /** The revocation counter's current value. */
    epoch: number;
}

/**
 * Returns a branch holding one pcr condition over pcrs of bank: the whole of
 * a policy that approves one PCR state. Mirrors
 * pkg/api/transport.TPMPolicyPCRBranch.
 */
declare function pcrBranch(bank: string, pcrs: number[]): TPMPolicyBranch;
/**
 * Named TPM policies: PCR-bank capture, approval lifecycle, auto-unseal, and
 * the objects (keys / sealed data) bound to them. Mirrors
 * pkg/api/rest/handlers_tpm_policy.go and pkg/api/rest/wire.TPMPolicyClient.
 * See docs/tpm-policies/api.md.
 */
declare class TpmPolicyClient {
    private readonly http;
    constructor(http: HttpCore);
    /** POST /api/v1/tpm/policies — captures the live values of its pcr conditions. */
    create(req: TPMPolicyCreateRequest): Promise<TPMPolicy>;
    /** GET /api/v1/tpm/policies?tenant_id= */
    list(tenantId?: string): Promise<TPMPolicyListResponse>;
    /** GET /api/v1/tpm/policies/{name}?tenant_id= */
    get(name: string, tenantId?: string): Promise<TPMPolicy>;
    /** POST /api/v1/tpm/policies/{name}/update — re-captures and re-approves. */
    update(name: string, tenantId?: string): Promise<TPMPolicy>;
    /** POST /api/v1/tpm/policies/{name}/revoke — withdraws the approval. */
    revoke(name: string, tenantId?: string): Promise<TPMPolicy>;
    /** POST /api/v1/tpm/policies/{name}/verify — compares captured vs. live PCR values. */
    verify(name: string, tenantId?: string): Promise<TPMPolicyVerifyResponse>;
    /**
     * DELETE /api/v1/tpm/policies/{name} (204). Refused with 409 while any
     * object is assigned to the policy.
     */
    delete(name: string, req?: TPMPolicyDeleteRequest): Promise<void>;
    /** GET /api/v1/tpm/policies/{name}/objects?tenant_id= — objects bound to the policy. */
    objects(name: string, tenantId?: string): Promise<TPMPolicyObjectsResponse>;
    /**
     * POST /api/v1/tpm/policies/{name}/auto-unseal — setting it clears the
     * mark from every other policy of the tenant.
     */
    setAutoUnseal(name: string, enabled: boolean, tenantId?: string): Promise<TPMPolicy>;
    /** POST /api/v1/tpm/policies/{name}/description — an empty description clears it. */
    setDescription(name: string, description: string, tenantId?: string): Promise<TPMPolicy>;
    /** GET /api/v1/keys/{id}/tpm-policy?tenant_id=&kind= — the policy an object was created under. */
    keyPolicy(keyId: string, opts?: {
        tenantId?: string;
        kind?: TPMObjectKind;
    }): Promise<TPMObjectPolicyResponse>;
    /** POST /api/v1/tpm/authority/rotate — rotates a tenant's policy authority. */
    rotateAuthority(tenantId?: string): Promise<TPMAuthorityRotateResponse>;
}

/**
 * User management DTOs. Mirrors pkg/api/rest/user_handlers.go and
 * pkg/api/transport/types.go UserInfo / ListUsersResponse.
 */

/** Mirrors pkg/api/transport/types.go UserInfo. */
interface UserInfo {
    /**
     * Numeric qrdb user id, carried as a STRING: the Go DTO tags it
     * `json:"id,string"` because a uint64 exceeds the range JSON numbers
     * represent exactly. Convert with Number() only when the id is known to be
     * within Number.MAX_SAFE_INTEGER — the N-factor endpoints key on it.
     */
    id: string;
    username: string;
    display_name?: string;
    role?: string;
    enabled: boolean;
    created_at: RFC3339;
    last_login?: RFC3339;
}
/** Mirrors pkg/api/rest/user_handlers.go createUserBody. */
interface CreateUserRequest {
    username: string;
    display_name: string;
    role: string;
    tenant_id: string;
}
/** Mirrors pkg/api/transport/types.go ListUsersResponse (PageResponse embedded flat). */
interface ListUsersResponse {
    users: UserInfo[];
    page: number;
    page_size: number;
    total: number;
    has_more: boolean;
}
/** Mirrors pkg/api/rest/user_handlers.go bindUserCertBody. */
interface BindUserCertRequest {
    thumbprint: string;
    not_after_unix: number;
}
/** Status response for delete / cert-bind ({username, status}). */
interface UserStatusResponse {
    username: string;
    status: string;
}
/** Mirrors pkg/api/rest/user_handlers.go userCredentialItem. */
interface UserCredentialItem {
    id: string;
    name: string;
}
/** Response envelope for GET /api/v1/users/{username}/credentials. */
interface ListUserCredentialsResponse {
    credentials: UserCredentialItem[];
}

/** User management (backed by the embedded qrdb node). */
declare class UsersClient {
    private readonly http;
    constructor(http: HttpCore);
    /** POST /api/v1/users/ */
    create(req: CreateUserRequest): Promise<UserInfo>;
    /** GET /api/v1/users/ */
    list(): Promise<ListUsersResponse>;
    /** GET /api/v1/users/{username} */
    get(username: string): Promise<UserInfo>;
    /** POST /api/v1/users/{username}/enable */
    enable(username: string): Promise<UserInfo>;
    /** POST /api/v1/users/{username}/disable */
    disable(username: string): Promise<UserInfo>;
    /** DELETE /api/v1/users/{username} */
    delete(username: string): Promise<UserStatusResponse>;
    /** POST /api/v1/users/{username}/cert-bindings */
    bindCert(username: string, req: BindUserCertRequest): Promise<UserStatusResponse>;
    /** GET /api/v1/users/{username}/credentials */
    credentials(username: string): Promise<ListUserCredentialsResponse>;
}

/**
 * XkmsClient is the full REST client facade for the xkms web UI: one shared
 * HTTP core (base URL, token provider, injectable fetch) composing every
 * domain client.
 */
declare class XkmsClient {
    readonly http: HttpCore;
    readonly authPaths: AuthPaths;
    readonly health: HealthClient;
    readonly capabilities: CapabilitiesClient;
    readonly auth: AuthClient;
    readonly backends: BackendsClient;
    readonly keys: KeysClient;
    readonly certs: CertsClient;
    readonly seal: SealClient;
    readonly frost: FrostClient;
    readonly barrier: BarrierClient;
    readonly pin: PinClient;
    readonly piv: PivClient;
    readonly ca: CaClient;
    readonly cluster: ClusterClient;
    readonly custodian: CustodianClient;
    readonly shares: SharesClient;
    readonly tenants: TenantsClient;
    readonly passwords: PasswordsClient;
    readonly oidcCredentials: OidcCredentialClient;
    readonly platform: PlatformClient;
    readonly tpmPolicies: TpmPolicyClient;
    readonly init: InitClient;
    readonly credentials: CredentialsClient;
    readonly users: UsersClient;
    readonly factors: FactorsClient;
    readonly ssh: SshClient;
    readonly audit: AuditClient;
    constructor(config: XkmsClientConfig);
}
/** createClient constructs an XkmsClient from a config. */
declare function createClient(config: XkmsClientConfig): XkmsClient;

/** The display name of a vault passkey's relying party (pkg/vaultpasskey). */
declare const VAULT_PASSKEY_RP_NAME = "xkms password vault";
/**
 * VaultPasskeyPrfUnsupportedError: the browser or the authenticator returned
 * no PRF result. The passkey cannot hold a vault factor; the message says
 * what would.
 */
declare class VaultPasskeyPrfUnsupportedError extends Error {
    constructor();
}
/**
 * VaultPasskeyUnavailableError: this page cannot use a vault passkey -- the
 * server offers none, the browser has no WebAuthn, or none of the vault's
 * passkeys belongs to this page's domain.
 */
declare class VaultPasskeyUnavailableError extends Error {
    constructor(message: string);
}
/** Where the module reaches WebAuthn and randomness; tests replace both. */
interface VaultPasskeyPlatform {
    credentials?: Pick<CredentialsContainer, 'create' | 'get'>;
    hostname: string;
    random(length: number): Uint8Array<ArrayBuffer>;
}
/** relyingPartyServes reports whether a page on hostname can use rpId. */
declare function relyingPartyServes(rpId: string, hostname: string): boolean;
/** bufferToBase64 encodes bytes as standard, padded base64 (Go's []byte JSON). */
declare function bufferToBase64(buffer: ArrayBuffer | ArrayBufferView): string;
/** Options for enrolling a vault passkey. */
interface EnrollVaultPasskeyOptions {
    /** The vault status: its `passkey_rp_id` is the relying party. */
    status: Pick<PasswordVaultStatusResponse, 'passkey_rp_id'>;
    /** Names the factor ("laptop key"). */
    label?: string;
    /** Names the credential's user on the authenticator. */
    userName?: string;
}
/**
 * enrollVaultPasskey creates a vault passkey and evaluates its PRF over a
 * fresh salt, returning the credential for `passwords.vaultEnroll` (or
 * `vaultRecover`). The authenticator is touched once when it evaluates PRF
 * at creation, twice otherwise.
 */
declare function enrollVaultPasskey(options: EnrollVaultPasskeyOptions, platform?: VaultPasskeyPlatform): Promise<PasswordVaultCredential>;
/**
 * unlockVaultPasskey evaluates the vault's passkeys that belong to this
 * page's domain in one WebAuthn ceremony, each over its own salt, and
 * returns the unlock credential of the one the user presented.
 */
declare function unlockVaultPasskey(factors: PasswordVaultFactor[], platform?: VaultPasskeyPlatform): Promise<PasswordVaultCredential>;

export { type AddCustodianMemberRequest, type AddCustodianMemberResponse, type AlgorithmInfo, type AlgorithmsResponse, type AllKeyVersionsResponse, type AssertionCredentialJSON, type AttestKeyRequest, type AttestKeyResponse, type AttestationCredentialJSON, AuditClient, type AuditEvent, type AuditFilter, type AuditPage, AuthClient, type AuthFactorAddRequest, type AuthFactorAddResponse, type AuthFactorGetResponse, type AuthFactorListResponse, type AuthFactorLoginRequest, type AuthFactorLoginResponse, type AuthFactorRecord, type AuthFactorRelabelRequest, type AuthFactorRelabelResponse, type AuthFactorRemoveResponse, type AuthFactorRotateRequest, type AuthFactorRotateResponse, type AuthFactorType, type AuthMeResponse, type AuthPaths, type AuthValidateResponse, type BackendCapabilities, type BackendInfo, BackendsClient, BarrierClient, type BarrierEnableEncryptionRequest, type BarrierEnableEncryptionResponse, type BarrierGenerateRecoveryKeysRequest, type BarrierGenerateRootTokenRequest, type BarrierInitializeRequest, type BarrierInitializeShamirRequest, type BarrierRecoverWithKeysRequest, type BarrierRekeyRequest, type BarrierStatusResponse, type BarrierUnsealRequest, type BarrierUnsealShareRequest, type BarrierUnsealSharesRequest, type Base64, type BindUserCertRequest, CaClient, type CanSealResponse, CapabilitiesClient, type CertificateInfo, CertsClient, type ChangeSOPINRequest, type ChangeUserPINRequest, type ClaimCertBeginRequest, type ClaimCertBeginResponse, type ClaimCertCompleteRequest, type ClaimCertCompleteResponse, type ClaimShareBeginRequest, type ClaimShareBeginResponse, type ClaimShareCompleteRequest, type ClaimShareCompleteResponse, ClusterClient, type ClusterMemberInfo, type ClusterStatusInfo, type ClusterStatusResponse, type CopyKeyRequest, type CopyKeyResponse, type CreateCustodianGroupRequest, type CreateCustodianGroupResponse, type CreateTenantRequest, type CreateUserRequest, type CredentialStrategyResponse, type CredentialSubmitRequest, type CredentialSubmitResponse, CredentialsClient, CustodianClient, type CustodianGroupInfo, type CustodianMemberInfo, DEFAULT_AUTH_PATHS, type DecryptRequest, type DecryptResponse, type DeleteKeyResponse, type DeriveKeyECDHRequest, type DeriveKeyECDHResponse, type DistributeSharesResponse, type EncryptAsymRequest, type EncryptAsymResponse, type EncryptRequest, type EncryptResponse, type EnrollDeviceRequest, type EnrollDeviceResponse, type EnrollVaultPasskeyOptions, type ErrorEnvelope, type ExportKeyMaterialResponse, type ExportKeyRequest, type ExportKeyResponse, FactorsClient, type FrostAggregateRequest, type FrostAggregateResponse, FrostClient, type FrostCommitment, type FrostDeleteKeyResponse, type FrostGenerateKeyRequest, type FrostGenerateKeyResponse, type FrostGenerateNoncesResponse, type FrostImportKeyRequest, type FrostImportKeyResponse, type FrostKeyInfo, type FrostKeyPackage, type FrostListKeysResponse, type FrostSignRoundRequest, type FrostSignRoundResponse, type FrostSignatureShare, type FrostVerifyRequest, type FrostVerifyResponse, type GenerateCRLRequest, type GenerateCRLResponse, type GenerateKeyRequest, type GenerateKeyResponse, type GeneratePIVCSRRequest, type GeneratePIVCSRResponse, type GeneratePIVKeyRequest, type GeneratePIVKeyResponse, type GetCABundleResponse, type GetCACertificateResponse, type GetCertChainResponse, type GetCertResponse, type GetCustodianGroupResponse, type GetImportParametersRequest, type GetImportParametersResponse, type GetKeyResponse, type GetPIVCertificateResponse, type GetTLSCertificateResponse, HEADER_SESSION_ID, type HealthCheckResponse, type HealthCheckResult, HealthClient, type HealthResponse, type HostKeyMode, HttpCore, type HttpMethod, type HttpResult, type ImportKeyRequest, type ImportKeyResponse, InitClient, type InitStatusResponse, type IsRevokedResponse, type IssueAKCertificateRequest, type IssueAKCertificateResponse, type IssueCertificateRequest, type IssueCertificateResponse, type IssueEKCertificateRequest, type IssueEKCertificateResponse, type KeyInfo, type KeyRotationResult, type KeyRotationState, type KeyVersionInfo, type KeyVersionState, type KeyVersionStateResponse, KeyVersionsClient, KeysClient, type ListBackendsResponse, type ListCertsResponse, type ListClusterMembersResponse, type ListCustodianGroupsResponse, type ListKeyVersionsResponse, type ListKeysResponse, type ListPIVSlotsResponse, type ListSharesResponse, type ListTenantsResponse, type ListUserCredentialsResponse, type ListUsersResponse, type LockoutStatusResponse, type OIDCAccessToken, type OIDCCredential, type OIDCCredentialConfig, type OIDCCredentialCreateRequest, type OIDCCredentialListResponse, type OIDCCredentialRef, type OIDCCredentialScope, type OIDCCredentialStatus, type OIDCCredentialTokens, type OIDCDeviceLogin, OIDCDeviceLoginError, type OIDCDeviceLoginFailure, OidcCredentialClient, type PIVSlotStatus, type PageQuery, type PageResponse, type PasswordAddRequest, type PasswordAddResponse, type PasswordDeleteResponse, type PasswordDetailResponse, type PasswordGenerateRequest, type PasswordGenerateResponse, type PasswordInfo, type PasswordListResponse, type PasswordStoreAccessModeRequest, type PasswordStoreAccessModeResponse, type PasswordStoreStatusResponse, type PasswordStoreUnlockRequest, type PasswordUpdateRequest, type PasswordUpdateResponse, type PasswordVaultCredential, type PasswordVaultEnrollRequest, type PasswordVaultEnrollResponse, type PasswordVaultFactor, type PasswordVaultFactorInfoType, type PasswordVaultFactorType, type PasswordVaultKeyFactorType, type PasswordVaultKeyRef, type PasswordVaultRecoverRequest, type PasswordVaultRotateRequest, type PasswordVaultStatusResponse, PasswordsClient, PinClient, PivClient, PlatformClient, type QueryParams, type QuorumProgress, type RFC3339, type RecoveryKeyResult, type RefreshRequest, type RequestOptions, type ResetLockoutRequest, type RevokeCertificateRequest, type RevokeCertificateResponse, type RootToken, type RotateKeyResponse, type RotateScopeKeysResponse, type SSHAddAuthorizedKeyRequest, type SSHAddKnownHostRequest, type SSHAuthorizedEntry, type SSHAuthorizedListResponse, type SSHEmitRequest, type SSHEmitResponse, type SSHGenerateKeyRequest, type SSHImportKeyRequest, type SSHKey, type SSHKeyListResponse, type SSHPin, type SSHPinListResponse, type SSHPublicKey, type SSHSignRequest, type SSHSignResponse, type SSHVerifyAuthorizedRequest, type SSHVerifyKnownHostRequest, type SaveCertChainRequest, type SaveCertRequest, SealClient, type SealRequest, type SealResponse, type SealStoreDeleteResponse, type SealStoreGetResponse, type SealStoreListResponse, type SealStorePutRequest, type SealStorePutResponse, type SealStoreResealResponse, type SealStoreStatusResponse, type ServerControl, type SetSOPINRequest, type SetTenantTPMModeRequest, type SetUserPINRequest, type ShamirInitParams, type ShamirInitResult, type ShareCollectionStatusResponse, type ShareStatusResponse, SharesClient, type SignCSRInitRequest, type SignCSRInitResponse, type SignCSRRequest, type SignCSRResponse, type SignRequest, type SignResponse, type SignTCGCSRRequest, type SignTCGCSRResponse, SshClient, type StorePIVCertificateRequest, type SubmitShareRequest, type SuccessResponse, type TPMAuthorityRotateResponse, type TPMObjectKind, type TPMObjectPolicyResponse, type TPMPolicy, type TPMPolicyBranch, type TPMPolicyBranchVerification, type TPMPolicyCondition, type TPMPolicyConditionType, type TPMPolicyCreateRequest, type TPMPolicyDeleteRequest, type TPMPolicyListResponse, type TPMPolicyObjectsResponse, type TPMPolicyVerifyResponse, type TenantBarrierInitRequest, type TenantBarrierStatusResponse, type TenantBarrierUnsealRequest, type TenantEntitlements, type TenantInfo, type TenantInfoResponse, type TenantQuotas, type TenantTPMModeResponse, type TenantVTPMStatusResponse, TenantsClient, type TokenProvider, type TokenResponse, TpmPolicyClient, type UnsealRequest, type UnsealResponse, type UnwrapKeyByIDRequest, type UnwrapKeyByIDResponse, type UnwrapKeyRequest, type UnwrapKeyResponse, type UpdateTenantEntitlementsRequest, type UpdateTenantEntitlementsResponse, type UpdateTenantQuotasRequest, type UpdateTenantQuotasResponse, type UserCredentialItem, type UserInfo, type UserStatusResponse, UsersClient, VAULT_PASSKEY_RP_NAME, type VaultPasskeyPlatform, VaultPasskeyPrfUnsupportedError, VaultPasskeyUnavailableError, type VerifyPINRequest, type VerifyRequest, type VerifyResponse, type WaitForDeviceLoginOptions, type WebAuthnAuthResponse, type WebAuthnBeginLoginRequest, type WebAuthnBeginRegistrationRequest, type WebAuthnCeremonyStart, WebAuthnEnvelopeError, type WrapKeyByIDRequest, type WrapKeyByIDResponse, type WrapKeyRequest, type WrapKeyResponse, type WrappedTenantResponse, XkmsApiError, XkmsClient, type XkmsClientConfig, XkmsNetworkError, base64urlToBuffer, bufferToBase64, bufferToBase64url, buildURL, createClient, encodeAssertionResponse, encodeAttestationResponse, encodeHostKeyResponse, encodePathSegment, encodeResize, enrollVaultPasskey, isWailsRuntime, parseControl, parseCreationOptions, parseErrorEnvelope, parseRequestOptions, pcrBranch, relyingPartyServes, resolveAuthPaths, unlockVaultPasskey };
