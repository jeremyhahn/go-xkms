"use strict";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __defNormalProp = (obj, key, value) => key in obj ? __defProp(obj, key, { enumerable: true, configurable: true, writable: true, value }) : obj[key] = value;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var __publicField = (obj, key, value) => __defNormalProp(obj, typeof key !== "symbol" ? key + "" : key, value);

// src/index.ts
var index_exports = {};
__export(index_exports, {
  AuthClient: () => AuthClient,
  BackendsClient: () => BackendsClient,
  CaClient: () => CaClient,
  CapabilitiesClient: () => CapabilitiesClient,
  CertsClient: () => CertsClient,
  CredentialsClient: () => CredentialsClient,
  DEFAULT_AUTH_PATHS: () => DEFAULT_AUTH_PATHS,
  FrostClient: () => FrostClient,
  HEADER_SESSION_ID: () => HEADER_SESSION_ID,
  HealthClient: () => HealthClient,
  HttpCore: () => HttpCore,
  KeyVersionsClient: () => KeyVersionsClient,
  KeysClient: () => KeysClient,
  OIDCDeviceLoginError: () => OIDCDeviceLoginError,
  OidcCredentialClient: () => OidcCredentialClient,
  PasswordsClient: () => PasswordsClient,
  PinClient: () => PinClient,
  PivClient: () => PivClient,
  PlatformClient: () => PlatformClient,
  SealClient: () => SealClient,
  SshClient: () => SshClient,
  TenantsClient: () => TenantsClient,
  TpmPolicyClient: () => TpmPolicyClient,
  UsersClient: () => UsersClient,
  VAULT_PASSKEY_RP_NAME: () => VAULT_PASSKEY_RP_NAME,
  VaultPasskeyPrfUnsupportedError: () => VaultPasskeyPrfUnsupportedError,
  VaultPasskeyUnavailableError: () => VaultPasskeyUnavailableError,
  WebAuthnEnvelopeError: () => WebAuthnEnvelopeError,
  XKEY_PING_TIMEOUT_MS: () => XKEY_PING_TIMEOUT_MS,
  XKEY_UNLOCK_TIMEOUT_MS: () => XKEY_UNLOCK_TIMEOUT_MS,
  XkeyBridgeError: () => XkeyBridgeError,
  XkeyExtensionUnavailableError: () => XkeyExtensionUnavailableError,
  XkmsApiError: () => XkmsApiError,
  XkmsClient: () => XkmsClient,
  XkmsNetworkError: () => XkmsNetworkError,
  base64urlToBuffer: () => base64urlToBuffer,
  bufferToBase64: () => bufferToBase64,
  bufferToBase64url: () => bufferToBase64url,
  buildURL: () => buildURL,
  createClient: () => createClient,
  detectXkeyExtension: () => detectXkeyExtension,
  encodeAssertionResponse: () => encodeAssertionResponse,
  encodeAttestationResponse: () => encodeAttestationResponse,
  encodeHostKeyResponse: () => encodeHostKeyResponse,
  encodePathSegment: () => encodePathSegment,
  encodeResize: () => encodeResize,
  enrollVaultPasskey: () => enrollVaultPasskey,
  isWailsRuntime: () => isWailsRuntime,
  keyFactorFingerprints: () => keyFactorFingerprints,
  parseControl: () => parseControl,
  parseCreationOptions: () => parseCreationOptions,
  parseErrorEnvelope: () => parseErrorEnvelope,
  parseRequestOptions: () => parseRequestOptions,
  pcrBranch: () => pcrBranch,
  relyingPartyServes: () => relyingPartyServes,
  resolveAuthPaths: () => resolveAuthPaths,
  unlockVaultPasskey: () => unlockVaultPasskey,
  unlockWithXkey: () => unlockWithXkey
});
module.exports = __toCommonJS(index_exports);

// src/protocol.ts
function parseControl(data) {
  let m;
  try {
    m = JSON.parse(data);
  } catch {
    return null;
  }
  if (!m || typeof m.type !== "string") {
    return null;
  }
  if (m.type === "error") {
    return { type: "error", message: typeof m.message === "string" ? m.message : void 0 };
  }
  if (m.type === "exit") {
    return { type: "exit" };
  }
  if (m.type === "hostkey") {
    if (typeof m.host !== "string" || typeof m.key_type !== "string" || typeof m.fingerprint !== "string" || typeof m.known !== "boolean") {
      return null;
    }
    const mode = m.mode === "confirm" || m.mode === "notify" ? m.mode : "confirm";
    return {
      type: "hostkey",
      host: m.host,
      key_type: m.key_type,
      fingerprint: m.fingerprint,
      known: m.known,
      mode
    };
  }
  return null;
}
function encodeResize(rows, cols) {
  return JSON.stringify({ type: "resize", rows, cols });
}
function encodeHostKeyResponse(accept) {
  return JSON.stringify({ type: "hostkey-response", accept });
}

// src/errors.ts
var XkmsApiError = class extends Error {
  constructor(status, code, message, correlationId, envelope) {
    super(message);
    __publicField(this, "status");
    __publicField(this, "code");
    __publicField(this, "correlationId");
    /** The parsed error envelope, when the body was JSON. */
    __publicField(this, "envelope");
    this.name = "XkmsApiError";
    this.status = status;
    this.code = code;
    this.correlationId = correlationId;
    this.envelope = envelope;
  }
};
var XkmsNetworkError = class extends Error {
  constructor(message, cause) {
    super(message);
    __publicField(this, "cause2");
    this.name = "XkmsNetworkError";
    this.cause2 = cause;
  }
};
function parseErrorEnvelope(status, statusText, bodyText, correlationId) {
  let envelope;
  if (bodyText) {
    try {
      const parsed = JSON.parse(bodyText);
      if (parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)) {
        envelope = parsed;
      }
    } catch {
    }
  }
  const code = envelope && typeof envelope.error === "string" && envelope.error !== "" ? envelope.error : `http_${status}`;
  const message = (envelope && typeof envelope.message === "string" && envelope.message !== "" ? envelope.message : void 0) ?? (envelope && typeof envelope.error === "string" && envelope.error !== "" ? envelope.error : void 0) ?? (statusText || `request failed with status ${status}`);
  return new XkmsApiError(status, code, message, correlationId, envelope);
}

// src/config.ts
var DEFAULT_AUTH_PATHS = {
  loginCert: "/api/v1/auth/login/piv",
  refresh: "/api/v1/auth/refresh",
  validate: "/api/v1/auth/validate",
  logout: "/api/v1/auth/logout",
  me: "/api/v1/auth/me",
  capabilities: "/api/v1/capabilities"
};
function resolveAuthPaths(overrides) {
  return { ...DEFAULT_AUTH_PATHS, ...overrides ?? {} };
}

// src/http.ts
function buildURL(baseURL, path, query) {
  const base = baseURL.replace(/\/+$/, "");
  let url = `${base}${path.startsWith("/") ? path : `/${path}`}`;
  if (query) {
    const parts = [];
    for (const [key, value] of Object.entries(query)) {
      if (value === void 0 || value === null || value === "") {
        continue;
      }
      parts.push(`${encodeURIComponent(key)}=${encodeURIComponent(String(value))}`);
    }
    if (parts.length > 0) {
      url += `?${parts.join("&")}`;
    }
  }
  return url;
}
function encodePathSegment(segment) {
  return encodeURIComponent(segment);
}
var HttpCore = class {
  constructor(config) {
    __publicField(this, "baseURL");
    __publicField(this, "token");
    __publicField(this, "fetchImpl");
    this.baseURL = config.baseURL;
    this.token = config.token;
    this.fetchImpl = config.fetch ?? globalThis.fetch.bind(globalThis);
  }
  /** request performs a call and returns the decoded body. */
  async request(method, path, opts = {}) {
    const { data } = await this.requestRaw(method, path, opts);
    return data;
  }
  /** requestRaw performs a call and returns the decoded body plus the Response. */
  async requestRaw(method, path, opts = {}) {
    const url = buildURL(this.baseURL, path, opts.query);
    const headers = { ...opts.headers ?? {} };
    const useAuth = opts.auth !== false;
    if (useAuth && this.token && headers["Authorization"] === void 0) {
      const token = await this.token();
      if (token) {
        headers["Authorization"] = `Bearer ${token}`;
      }
    }
    const init = { method, headers };
    if (opts.body !== void 0) {
      headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(opts.body);
    }
    if (opts.credentials !== void 0) {
      init.credentials = opts.credentials;
    }
    let response;
    try {
      response = await this.fetchImpl(url, init);
    } catch (err) {
      throw new XkmsNetworkError(`request to ${url} failed: ${String(err)}`, err);
    }
    const correlationId = response.headers.get("X-Correlation-ID") ?? void 0;
    if (!response.ok && !(opts.okOn ?? []).includes(response.status)) {
      let bodyText = "";
      try {
        bodyText = await response.text();
      } catch {
      }
      throw parseErrorEnvelope(response.status, response.statusText, bodyText, correlationId);
    }
    const parse = opts.parse ?? "json";
    if (parse === "void" || response.status === 204 || method === "HEAD") {
      return { data: void 0, response };
    }
    if (parse === "text") {
      return { data: await response.text(), response };
    }
    if (!response.ok) {
      return { data: void 0, response };
    }
    const text = await response.text();
    if (text === "") {
      return { data: void 0, response };
    }
    return { data: JSON.parse(text), response };
  }
};

// src/wails.ts
function isWailsRuntime() {
  if (typeof globalThis === "undefined") {
    return false;
  }
  const w = globalThis;
  return w["go"] !== void 0 || w["runtime"] !== void 0;
}

// src/clients/auth.ts
var HEADER_SESSION_ID = "X-Session-Id";
var WEBAUTHN_BASE = "/api/v1/webauthn";
var AuthClient = class {
  constructor(http, paths) {
    __publicField(this, "http", http);
    __publicField(this, "paths", paths);
  }
  // -------------------------------------------------------------------
  // Token-pair session endpoints (pkg/api/rest/handlers_auth.go)
  // -------------------------------------------------------------------
  /**
   * POST {authPaths.loginCert} — exchange the TLS-verified client
   * certificate (PIV / mTLS identity) for a bearer token pair.
   */
  loginCert() {
    return this.http.request("POST", this.paths.loginCert, {
      auth: false,
      credentials: "include"
    });
  }
  /** POST {authPaths.refresh} — rotate a refresh token into a new pair. */
  refresh(refreshToken) {
    return this.http.request("POST", this.paths.refresh, {
      auth: false,
      body: { refresh_token: refreshToken }
    });
  }
  /** GET {authPaths.me} — identity, effective UI permissions, capability flags. */
  me() {
    return this.http.request("GET", this.paths.me);
  }
  /** GET {authPaths.validate} — lightweight boot-time session probe. */
  validate() {
    return this.http.request("GET", this.paths.validate);
  }
  /** POST {authPaths.logout} — revoke the refresh-token family (204). */
  async logout(refreshToken) {
    await this.http.request("POST", this.paths.logout, {
      body: { refresh_token: refreshToken ?? "" },
      parse: "void"
    });
  }
  // -------------------------------------------------------------------
  // WebAuthn browser ceremonies (pkg/webauthn/http mounted at
  // /api/v1/webauthn; session correlation via X-Session-Id)
  // -------------------------------------------------------------------
  /**
   * POST /api/v1/webauthn/registration/begin — enrolls an account's FIRST
   * passkey without a session. Returns the raw go-webauthn creation options
   * envelope plus the session ID from the X-Session-Id response header.
   * Feed `options` to parseCreationOptions. An account that already has a
   * passkey is refused with 403 `registration_refused`; add further passkeys
   * with webAuthnAddCredentialBegin.
   */
  async webAuthnRegisterBegin(req) {
    const { data, response } = await this.http.requestRaw(
      "POST",
      `${WEBAUTHN_BASE}/registration/begin`,
      { auth: false, body: req }
    );
    return {
      options: data,
      sessionId: response.headers.get(HEADER_SESSION_ID) ?? ""
    };
  }
  /**
   * POST /api/v1/webauthn/credentials/begin — start adding a passkey to the
   * signed-in account. Rides the configured TokenProvider: the account is the
   * session's own, never one named in the request. Complete the ceremony with
   * webAuthnRegisterFinish under the returned session ID.
   */
  async webAuthnAddCredentialBegin() {
    const { data, response } = await this.http.requestRaw(
      "POST",
      `${WEBAUTHN_BASE}/credentials/begin`,
      {}
    );
    return {
      options: data,
      sessionId: response.headers.get(HEADER_SESSION_ID) ?? ""
    };
  }
  /**
   * POST /api/v1/webauthn/registration/finish — submit the encoded
   * attestation (encodeAttestationResponse) under the session's
   * X-Session-Id header.
   */
  webAuthnRegisterFinish(sessionId, credential) {
    return this.http.request("POST", `${WEBAUTHN_BASE}/registration/finish`, {
      auth: false,
      body: credential,
      headers: { [HEADER_SESSION_ID]: sessionId }
    });
  }
  /**
   * POST /api/v1/webauthn/login/begin — returns the raw go-webauthn
   * request options envelope plus X-Session-Id. Feed `options` to
   * parseRequestOptions. Omit the request body for the discoverable-credential
   * flow. The response never reveals whether the account exists; the user ID
   * arrives only with a successful webAuthnFinishLogin.
   */
  async webAuthnBeginLogin(req) {
    const { data, response } = await this.http.requestRaw(
      "POST",
      `${WEBAUTHN_BASE}/login/begin`,
      { auth: false, body: req ?? {} }
    );
    return {
      options: data,
      sessionId: response.headers.get(HEADER_SESSION_ID) ?? ""
    };
  }
  /**
   * POST /api/v1/webauthn/login/finish — submit the encoded assertion
   * (encodeAssertionResponse) under the session's X-Session-Id header.
   */
  webAuthnFinishLogin(sessionId, credential) {
    return this.http.request("POST", `${WEBAUTHN_BASE}/login/finish`, {
      auth: false,
      body: credential,
      headers: { [HEADER_SESSION_ID]: sessionId }
    });
  }
};

// src/clients/backends.ts
var BackendsClient = class {
  constructor(http) {
    __publicField(this, "http", http);
  }
  /** GET /api/v1/backends */
  list(page) {
    return this.http.request("GET", "/api/v1/backends", { query: { ...page } });
  }
  /** GET /api/v1/backends/{id} */
  get(id) {
    return this.http.request("GET", `/api/v1/backends/${encodeURIComponent(id)}`);
  }
};

// src/clients/ca.ts
var BASE = "/api/v1/ca";
var CaClient = class {
  constructor(http) {
    __publicField(this, "http", http);
  }
  /** GET /api/v1/ca/bundle?store_type=&algorithm= */
  bundle(storeType, algorithm) {
    return this.http.request("GET", `${BASE}/bundle`, {
      query: { store_type: storeType, algorithm }
    });
  }
  /** GET /api/v1/ca/certificate?identity= */
  certificate(identity) {
    return this.http.request("GET", `${BASE}/certificate`, { query: { identity } });
  }
  /** POST /api/v1/ca/sign-csr */
  signCSR(req) {
    return this.http.request("POST", `${BASE}/sign-csr`, { body: req });
  }
  /** POST /api/v1/ca/issue */
  issue(req) {
    return this.http.request("POST", `${BASE}/issue`, { body: req });
  }
  /** POST /api/v1/ca/revoke */
  revoke(req) {
    return this.http.request("POST", `${BASE}/revoke`, { body: req });
  }
  /** POST /api/v1/ca/crl */
  generateCRL(req) {
    return this.http.request("POST", `${BASE}/crl`, { body: req ?? {} });
  }
  /** GET /api/v1/ca/revoked/{serial} */
  isRevoked(serial) {
    return this.http.request("GET", `${BASE}/revoked/${encodeURIComponent(serial)}`);
  }
  /** POST /api/v1/ca/tcg/ek */
  issueEK(req) {
    return this.http.request("POST", `${BASE}/tcg/ek`, { body: req });
  }
  /** POST /api/v1/ca/tcg/ak */
  issueAK(req) {
    return this.http.request("POST", `${BASE}/tcg/ak`, { body: req });
  }
  /** POST /api/v1/ca/tcg/sign-csr */
  signTCGCSR(req) {
    return this.http.request("POST", `${BASE}/tcg/sign-csr`, { body: req });
  }
  /** POST /api/v1/ca/tcg/enroll */
  enrollDevice(req) {
    return this.http.request("POST", `${BASE}/tcg/enroll`, { body: req });
  }
  /**
   * GET /v1/ca/bootstrap — the unauthenticated go-truststrap bootstrap
   * endpoint; returns the raw PEM bundle text
   * (application/pem-certificate-chain), not JSON.
   */
  bootstrapBundle() {
    return this.http.request("GET", "/v1/ca/bootstrap", { auth: false, parse: "text" });
  }
};

// src/clients/capabilities.ts
var CapabilitiesClient = class {
  constructor(http, paths) {
    __publicField(this, "http", http);
    __publicField(this, "paths", paths);
  }
  /** GET {authPaths.capabilities} -> { "<capability>": boolean, ... } */
  get() {
    return this.http.request("GET", this.paths.capabilities);
  }
};

// src/clients/certs.ts
var BASE2 = "/api/v1/certs";
function certPath(id, suffix = "") {
  return `${BASE2}/${encodeURIComponent(id)}${suffix}`;
}
var CertsClient = class {
  constructor(http) {
    __publicField(this, "http", http);
  }
  /**
   * POST /api/v1/certs?key_id=&backend= — the handler reads key_id and
   * backend from the query string; the body carries the PEM.
   */
  save(keyId, backend, req) {
    return this.http.request("POST", BASE2, {
      body: req,
      query: { key_id: keyId, backend }
    });
  }
  /** GET /api/v1/certs?backend= */
  list(backend, page) {
    return this.http.request("GET", BASE2, { query: { backend, ...page } });
  }
  /** GET /api/v1/certs/{id}?backend= */
  get(id, backend) {
    return this.http.request("GET", certPath(id), { query: { backend } });
  }
  /** DELETE /api/v1/certs/{id}?backend= */
  delete(id, backend) {
    return this.http.request("DELETE", certPath(id), { query: { backend } });
  }
  /** HEAD /api/v1/certs/{id}?backend= — true when the certificate exists. */
  async exists(id, backend) {
    const { response } = await this.http.requestRaw("HEAD", certPath(id), {
      query: { backend },
      parse: "void",
      okOn: [404]
    });
    return response.ok;
  }
  /** POST /api/v1/certs/{id}/chain */
  saveChain(id, req) {
    return this.http.request("POST", certPath(id, "/chain"), {
      body: req,
      query: { backend: req.backend }
    });
  }
  /** GET /api/v1/certs/{id}/chain?backend= */
  getChain(id, backend) {
    return this.http.request("GET", certPath(id, "/chain"), { query: { backend } });
  }
  /** GET /api/v1/tls/{id}?backend= — private key + cert + chain bundle. */
  tlsBundle(id, backend) {
    return this.http.request("GET", `/api/v1/tls/${encodeURIComponent(id)}`, {
      query: { backend }
    });
  }
};

// src/clients/credentials.ts
var BASE3 = "/api/v1/credentials";
var CredentialsClient = class {
  constructor(http) {
    __publicField(this, "http", http);
  }
  /** POST /api/v1/credentials/submit */
  submit(req) {
    return this.http.request("POST", `${BASE3}/submit`, { body: req });
  }
  /** GET /api/v1/credentials/strategy */
  strategy() {
    return this.http.request("GET", `${BASE3}/strategy`);
  }
};

// src/clients/frost.ts
var BASE4 = "/api/v1/frost";
var FrostClient = class {
  constructor(http) {
    __publicField(this, "http", http);
  }
  /** POST /api/v1/frost/keys */
  generateKey(req) {
    return this.http.request("POST", `${BASE4}/keys`, { body: req });
  }
  /** POST /api/v1/frost/keys/import */
  importKey(req) {
    return this.http.request("POST", `${BASE4}/keys/import`, { body: req });
  }
  /** GET /api/v1/frost/keys */
  listKeys(page) {
    return this.http.request("GET", `${BASE4}/keys`, { query: { ...page } });
  }
  /** GET /api/v1/frost/keys/{id} */
  getKey(id) {
    return this.http.request("GET", `${BASE4}/keys/${encodeURIComponent(id)}`);
  }
  /** DELETE /api/v1/frost/keys/{id} */
  deleteKey(id) {
    return this.http.request("DELETE", `${BASE4}/keys/${encodeURIComponent(id)}`);
  }
  /** POST /api/v1/frost/keys/{id}/nonces */
  generateNonces(id) {
    return this.http.request("POST", `${BASE4}/keys/${encodeURIComponent(id)}/nonces`);
  }
  /** POST /api/v1/frost/keys/{id}/sign */
  signRound(id, req) {
    return this.http.request("POST", `${BASE4}/keys/${encodeURIComponent(id)}/sign`, {
      body: req
    });
  }
  /** POST /api/v1/frost/aggregate */
  aggregate(req) {
    return this.http.request("POST", `${BASE4}/aggregate`, { body: req });
  }
  /** POST /api/v1/frost/verify */
  verify(req) {
    return this.http.request("POST", `${BASE4}/verify`, { body: req });
  }
};

// src/clients/health.ts
var HealthClient = class {
  constructor(http) {
    __publicField(this, "http", http);
  }
  /** GET /health */
  health() {
    return this.http.request("GET", "/health", { auth: false });
  }
  /** GET /health/live */
  live() {
    return this.http.request("GET", "/health/live", { auth: false });
  }
  /** GET /health/ready */
  ready() {
    return this.http.request("GET", "/health/ready", { auth: false });
  }
  /** GET /health/startup */
  startup() {
    return this.http.request("GET", "/health/startup", { auth: false });
  }
  /** GET /api/v1/algorithms */
  algorithms() {
    return this.http.request("GET", "/api/v1/algorithms", { auth: false });
  }
};

// src/clients/keyVersions.ts
var BASE5 = "/api/v1/keys";
function versionsPath(id, suffix = "") {
  return `${BASE5}/${encodeURIComponent(id)}/versions${suffix}`;
}
var KeyVersionsClient = class {
  constructor(http) {
    __publicField(this, "http", http);
  }
  /** GET /api/v1/keys/{id}/versions?backend= */
  list(id, backend) {
    return this.http.request("GET", versionsPath(id), { query: { backend } });
  }
  /** POST /api/v1/keys/{id}/versions/{version}/enable?backend= */
  enable(id, version, backend) {
    return this.http.request("POST", versionsPath(id, `/${version}/enable`), { query: { backend } });
  }
  /** POST /api/v1/keys/{id}/versions/{version}/disable?backend= — the current version cannot be disabled. */
  disable(id, version, backend) {
    return this.http.request("POST", versionsPath(id, `/${version}/disable`), { query: { backend } });
  }
  /** POST /api/v1/keys/{id}/versions/{version}/retire?backend= — deletes the version's key material for good. */
  retire(id, version, backend) {
    return this.http.request("POST", versionsPath(id, `/${version}/retire`), { query: { backend } });
  }
  /** POST /api/v1/keys/{id}/versions/enable-all?backend= */
  enableAll(id, backend) {
    return this.http.request("POST", versionsPath(id, "/enable-all"), { query: { backend } });
  }
  /** POST /api/v1/keys/{id}/versions/disable-all?backend= — never reaches the current version. */
  disableAll(id, backend) {
    return this.http.request("POST", versionsPath(id, "/disable-all"), { query: { backend } });
  }
  /** POST /api/v1/keys/rotate-all — rotates every key of the caller's tenant, or of tenantId (system callers only). */
  rotateAll(tenantId) {
    return this.http.request("POST", `${BASE5}/rotate-all`, {
      body: tenantId ? { tenant_id: tenantId } : {}
    });
  }
};

// src/clients/keys.ts
var BASE6 = "/api/v1/keys";
function keyPath(id, suffix = "") {
  return `${BASE6}/${encodeURIComponent(id)}${suffix}`;
}
var KeysClient = class {
  constructor(http) {
    __publicField(this, "http", http);
    /** A key's versions: list, enable, disable, retire, and rotate a whole tenant. */
    __publicField(this, "versions");
    this.versions = new KeyVersionsClient(http);
  }
  /** POST /api/v1/keys */
  generate(req) {
    return this.http.request("POST", BASE6, { body: req });
  }
  /** GET /api/v1/keys?backend= */
  list(backend, page) {
    return this.http.request("GET", BASE6, { query: { backend, ...page } });
  }
  /** GET /api/v1/keys/{id}?backend= */
  get(id, backend) {
    return this.http.request("GET", keyPath(id), { query: { backend } });
  }
  /** DELETE /api/v1/keys/{id}?backend= */
  delete(id, backend) {
    return this.http.request("DELETE", keyPath(id), { query: { backend } });
  }
  /**
   * POST /api/v1/keys/{id}/sign — the backend rides both the body and the
   * `?backend=` query (the handler honors the query override; clustered
   * deployments require it).
   */
  sign(id, req) {
    return this.http.request("POST", keyPath(id, "/sign"), {
      body: req,
      query: { backend: req.backend }
    });
  }
  /** POST /api/v1/keys/{id}/verify */
  verify(id, req) {
    return this.http.request("POST", keyPath(id, "/verify"), {
      body: req,
      query: { backend: req.backend }
    });
  }
  /**
   * POST /api/v1/keys/{id}/rotate?backend= (backend query is required) —
   * creates the key's next version and makes it current; earlier versions
   * stay enabled.
   */
  rotate(id, backend) {
    return this.http.request("POST", keyPath(id, "/rotate"), { query: { backend } });
  }
  /** POST /api/v1/keys/{id}/encrypt */
  encrypt(id, req) {
    return this.http.request("POST", keyPath(id, "/encrypt"), { body: req });
  }
  /** POST /api/v1/keys/{id}/decrypt */
  decrypt(id, req) {
    return this.http.request("POST", keyPath(id, "/decrypt"), { body: req });
  }
  /** POST /api/v1/keys/{id}/encrypt-asym */
  encryptAsym(id, req) {
    return this.http.request("POST", keyPath(id, "/encrypt-asym"), { body: req });
  }
  /** POST /api/v1/keys/import-params */
  importParams(req) {
    return this.http.request("POST", `${BASE6}/import-params`, { body: req });
  }
  /** POST /api/v1/keys/wrap */
  wrap(req) {
    return this.http.request("POST", `${BASE6}/wrap`, { body: req });
  }
  /** POST /api/v1/keys/unwrap */
  unwrap(req) {
    return this.http.request("POST", `${BASE6}/unwrap`, { body: req });
  }
  /** POST /api/v1/keys/import */
  import(req) {
    return this.http.request("POST", `${BASE6}/import`, { body: req });
  }
  /** POST /api/v1/keys/{id}/export */
  export(id, req) {
    return this.http.request("POST", keyPath(id, "/export"), {
      body: req,
      query: { backend: req.backend }
    });
  }
  /** POST /api/v1/keys/copy */
  copy(req) {
    return this.http.request("POST", `${BASE6}/copy`, { body: req });
  }
  /** POST /api/v1/attest */
  attest(req) {
    return this.http.request("POST", "/api/v1/attest", { body: req });
  }
  /** POST /api/v1/keys/derive-ecdh */
  deriveECDH(req) {
    return this.http.request("POST", `${BASE6}/derive-ecdh`, { body: req });
  }
  /** POST /api/v1/keys/{id}/export-material?backend= */
  exportMaterial(id, backend) {
    return this.http.request("POST", keyPath(id, "/export-material"), {
      query: { backend }
    });
  }
  /** POST /api/v1/keys/wrap-by-id */
  wrapById(req) {
    return this.http.request("POST", `${BASE6}/wrap-by-id`, { body: req });
  }
  /** POST /api/v1/keys/unwrap-by-id */
  unwrapById(req) {
    return this.http.request("POST", `${BASE6}/unwrap-by-id`, { body: req });
  }
};

// src/clients/oidcCredential.ts
var BASE7 = "/api/v1/oidc/credentials";
var DEFAULT_DEVICE_INTERVAL_SECONDS = 5;
var OIDCDeviceLoginError = class extends Error {
  constructor(reason, name) {
    super(
      reason === "expired" ? `oidc credential "${name}": device login expired before it was approved` : `oidc credential "${name}": no device login in progress`
    );
    __publicField(this, "reason");
    this.name = "OIDCDeviceLoginError";
    this.reason = reason;
  }
};
function credentialPath(ref, action) {
  const path = `${BASE7}/${encodeURIComponent(ref.scope)}/${encodeURIComponent(ref.name)}`;
  return action ? `${path}/${action}` : path;
}
function refQuery(ref) {
  return { tenant_id: ref.tenant_id, owner: ref.owner };
}
function sleep(ms, signal) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(signal.reason);
      return;
    }
    const onAbort = () => {
      clearTimeout(timer);
      reject(signal?.reason);
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}
var OidcCredentialClient = class {
  constructor(http) {
    __publicField(this, "http", http);
  }
  /** GET /api/v1/oidc/credentials?tenant_id= — the shared credentials and the caller's personal ones. */
  list(tenantId) {
    return this.http.request("GET", BASE7, { query: { tenant_id: tenantId } });
  }
  /**
   * POST /api/v1/oidc/credentials (201). With tokens the credential is
   * active at once; without, it is pending a device login or an import.
   */
  create(req) {
    return this.http.request("POST", BASE7, { body: req });
  }
  /** GET /api/v1/oidc/credentials/{scope}/{name}?tenant_id=&owner= — the public view (no tokens). */
  get(ref) {
    return this.http.request("GET", credentialPath(ref), { query: refQuery(ref) });
  }
  /** DELETE /api/v1/oidc/credentials/{scope}/{name}?tenant_id=&owner= (204). */
  async delete(ref) {
    await this.http.request("DELETE", credentialPath(ref), {
      query: refQuery(ref),
      parse: "void"
    });
  }
  /**
   * POST /api/v1/oidc/credentials/{scope}/{name}/import — replaces the
   * credential's login with tokens obtained elsewhere and makes it active.
   */
  importTokens(ref, tokens) {
    return this.http.request("POST", credentialPath(ref, "import"), {
      query: refQuery(ref),
      body: { tokens }
    });
  }
  /** POST /api/v1/oidc/credentials/{scope}/{name}/refresh — refreshes now. */
  refresh(ref) {
    return this.http.request("POST", credentialPath(ref, "refresh"), { query: refQuery(ref) });
  }
  /**
   * POST /api/v1/oidc/credentials/{scope}/{name}/token — a current access
   * token, refreshed first when inside its refresh margin. The answer is a
   * bearer secret: hold it no longer than its use.
   */
  getAccessToken(ref) {
    return this.http.request("POST", credentialPath(ref, "token"), { query: refQuery(ref) });
  }
  /**
   * POST /api/v1/oidc/credentials/{scope}/{name}/device — starts a device
   * login; the returned credential's device_login carries the user code and
   * verification URI.
   */
  startDeviceLogin(ref) {
    return this.http.request("POST", credentialPath(ref, "device"), { query: refQuery(ref) });
  }
  /**
   * POST /api/v1/oidc/credentials/{scope}/{name}/device/poll — polls the
   * device login once; the credential stays pending until the user approves.
   */
  pollDeviceLogin(ref) {
    return this.http.request("POST", credentialPath(ref, "device/poll"), { query: refQuery(ref) });
  }
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
  async waitForDeviceLogin(credential, opts = {}) {
    let current = "status" in credential ? credential : void 0;
    for (; ; ) {
      if (current !== void 0 && current.status !== "pending") {
        return current;
      }
      const login = current?.device_login;
      if (current !== void 0 && login === void 0) {
        throw new OIDCDeviceLoginError("not_started", credential.name);
      }
      if (login !== void 0 && Date.now() >= Date.parse(login.expires_at)) {
        throw new OIDCDeviceLoginError("expired", credential.name);
      }
      const interval = login?.interval_seconds || DEFAULT_DEVICE_INTERVAL_SECONDS;
      await sleep(interval * 1e3, opts.signal);
      current = await this.pollDeviceLogin(credential);
      if (current.status === "pending") {
        opts.onPending?.(current);
      }
    }
  }
};

// src/clients/passwords.ts
var BASE8 = "/api/v1/passwords";
var VAULT = "/api/v1/password-vault";
var PasswordsClient = class {
  constructor(http) {
    __publicField(this, "http", http);
  }
  /** POST /api/v1/passwords/ */
  add(req) {
    return this.http.request("POST", `${BASE8}/`, { body: req });
  }
  /** GET /api/v1/passwords/?folder=&scope= */
  list(folder, scope) {
    return this.http.request("GET", `${BASE8}/`, { query: { folder, scope } });
  }
  /** GET /api/v1/passwords/{id} */
  get(id) {
    return this.http.request("GET", `${BASE8}/${encodeURIComponent(id)}`);
  }
  /** PUT /api/v1/passwords/{id} */
  update(id, req) {
    return this.http.request("PUT", `${BASE8}/${encodeURIComponent(id)}`, { body: req });
  }
  /** DELETE /api/v1/passwords/{id} */
  delete(id) {
    return this.http.request("DELETE", `${BASE8}/${encodeURIComponent(id)}`);
  }
  /** POST /api/v1/password-vault/unlock -- opens the caller's session with one of their vault factors. */
  unlock(req) {
    return this.http.request("POST", `${VAULT}/unlock`, { body: req });
  }
  /** GET /api/v1/password-vault */
  vaultStatus() {
    return this.http.request("GET", VAULT);
  }
  /**
   * POST /api/v1/password-vault/factors -- the first enrollment initializes
   * the vault, opens the session and returns the one-time recovery code.
   */
  vaultEnroll(req) {
    return this.http.request("POST", `${VAULT}/factors`, { body: req });
  }
  /** PUT /api/v1/password-vault/factors/{id} */
  vaultRotate(factorId, req) {
    return this.http.request("PUT", `${VAULT}/factors/${encodeURIComponent(factorId)}`, { body: req });
  }
  /** DELETE /api/v1/password-vault/factors/{id} (204 No Content) */
  async vaultRemoveFactor(factorId) {
    await this.http.request("DELETE", `${VAULT}/factors/${encodeURIComponent(factorId)}`);
  }
  /** POST /api/v1/password-vault/recover -- returns the replacement recovery code. */
  vaultRecover(req) {
    return this.http.request("POST", `${VAULT}/recover`, { body: req });
  }
  /** POST /api/v1/password-vault/lock */
  lock() {
    return this.http.request("POST", `${VAULT}/lock`);
  }
  /** GET /api/v1/password-vault/session -- the caller's session and the entries it can read now. */
  status() {
    return this.http.request("GET", `${VAULT}/session`);
  }
  /** POST /api/v1/passwords/access-mode */
  setAccessMode(req) {
    return this.http.request("POST", `${BASE8}/access-mode`, { body: req });
  }
  /** POST /api/v1/passwords/generate */
  generate(req) {
    return this.http.request("POST", `${BASE8}/generate`, { body: req });
  }
};

// src/clients/pin.ts
var BASE9 = "/api/v1/pin";
var PinClient = class {
  constructor(http) {
    __publicField(this, "http", http);
  }
  /** POST /api/v1/pin/so/set */
  setSO(req) {
    return this.http.request("POST", `${BASE9}/so/set`, { body: req });
  }
  /** POST /api/v1/pin/user/set */
  setUser(req) {
    return this.http.request("POST", `${BASE9}/user/set`, { body: req });
  }
  /** POST /api/v1/pin/so/change */
  changeSO(req) {
    return this.http.request("POST", `${BASE9}/so/change`, { body: req });
  }
  /** POST /api/v1/pin/user/change */
  changeUser(req) {
    return this.http.request("POST", `${BASE9}/user/change`, { body: req });
  }
  /** POST /api/v1/pin/so/verify */
  verifySO(req) {
    return this.http.request("POST", `${BASE9}/so/verify`, { body: req });
  }
  /** POST /api/v1/pin/user/verify */
  verifyUser(req) {
    return this.http.request("POST", `${BASE9}/user/verify`, { body: req });
  }
  /** GET /api/v1/pin/lockout */
  lockoutStatus() {
    return this.http.request("GET", `${BASE9}/lockout`);
  }
  /** POST /api/v1/pin/lockout/reset */
  resetLockout(req) {
    return this.http.request("POST", `${BASE9}/lockout/reset`, { body: req });
  }
};

// src/clients/piv.ts
var BASE10 = "/api/v1/piv";
function slotPath(slot, suffix) {
  return `${BASE10}/slots/${encodeURIComponent(slot)}${suffix}`;
}
var PivClient = class {
  constructor(http) {
    __publicField(this, "http", http);
  }
  /** GET /api/v1/piv/slots?backend= */
  listSlots(backend) {
    return this.http.request("GET", `${BASE10}/slots`, { query: { backend } });
  }
  /** GET /api/v1/piv/slots/{slot}/certificate?backend=&format= */
  getCertificate(slot, backend, format) {
    return this.http.request("GET", slotPath(slot, "/certificate"), {
      query: { backend, format }
    });
  }
  /** POST /api/v1/piv/slots/{slot}/certificate */
  storeCertificate(slot, req) {
    return this.http.request("POST", slotPath(slot, "/certificate"), { body: req });
  }
  /** DELETE /api/v1/piv/slots/{slot}/certificate?backend= */
  deleteCertificate(slot, backend) {
    return this.http.request("DELETE", slotPath(slot, "/certificate"), {
      query: { backend }
    });
  }
  /** POST /api/v1/piv/slots/{slot}/generate */
  generateKey(slot, req) {
    return this.http.request("POST", slotPath(slot, "/generate"), { body: req });
  }
  /** POST /api/v1/piv/slots/{slot}/import */
  importCertificate(slot, req) {
    return this.http.request("POST", slotPath(slot, "/import"), { body: req });
  }
  /** GET /api/v1/piv/slots/{slot}/export?backend=&format= */
  exportCertificate(slot, backend, format) {
    return this.http.request("GET", slotPath(slot, "/export"), {
      query: { backend, format }
    });
  }
  /** POST /api/v1/piv/slots/{slot}/csr */
  generateCSR(slot, req) {
    return this.http.request("POST", slotPath(slot, "/csr"), { body: req });
  }
};

// src/clients/platform.ts
var BASE11 = "/api/v1/platform";
var PlatformClient = class {
  constructor(http) {
    __publicField(this, "http", http);
  }
  /** PUT /api/v1/platform/secrets/{key} */
  putSecret(key, req) {
    return this.http.request("PUT", `${BASE11}/secrets/${encodeURIComponent(key)}`, {
      body: req
    });
  }
  /** GET /api/v1/platform/secrets/{key} */
  getSecret(key) {
    return this.http.request("GET", `${BASE11}/secrets/${encodeURIComponent(key)}`);
  }
  /** DELETE /api/v1/platform/secrets/{key} */
  deleteSecret(key) {
    return this.http.request("DELETE", `${BASE11}/secrets/${encodeURIComponent(key)}`);
  }
  /** GET /api/v1/platform/secrets */
  listSecrets() {
    return this.http.request("GET", `${BASE11}/secrets`);
  }
  /** POST /api/v1/platform/secrets/{key}/reseal */
  resealSecret(key) {
    return this.http.request("POST", `${BASE11}/secrets/${encodeURIComponent(key)}/reseal`);
  }
  /** GET /api/v1/platform/status */
  status() {
    return this.http.request("GET", `${BASE11}/status`);
  }
};

// src/clients/seal.ts
var SealClient = class {
  constructor(http) {
    __publicField(this, "http", http);
  }
  /** POST /api/v1/seal */
  seal(req) {
    return this.http.request("POST", "/api/v1/seal", { body: req });
  }
  /** POST /api/v1/unseal */
  unseal(req) {
    return this.http.request("POST", "/api/v1/unseal", { body: req });
  }
  /** GET /api/v1/seal/capability?backend= */
  capability(backend) {
    return this.http.request("GET", "/api/v1/seal/capability", { query: { backend } });
  }
};

// src/clients/ssh.ts
var BASE12 = "/xkms/v1/ssh";
function keyPath2(scope, owner, name, suffix = "") {
  return `${BASE12}/keys/${encodePathSegment(scope)}/${encodePathSegment(owner)}/${encodePathSegment(name)}${suffix}`;
}
function authorizedPath(scope, owner, name) {
  return `${BASE12}/authorized-keys/${encodePathSegment(scope)}/${encodePathSegment(owner)}/${encodePathSegment(name)}`;
}
var SshClient = class {
  constructor(http) {
    __publicField(this, "http", http);
  }
  // ------------------------------------------------------------------
  // Keys
  // ------------------------------------------------------------------
  /** POST /xkms/v1/ssh/keys */
  generateKey(req) {
    return this.http.request("POST", `${BASE12}/keys`, { body: req });
  }
  /** POST /xkms/v1/ssh/keys/import */
  importKey(req) {
    return this.http.request("POST", `${BASE12}/keys/import`, { body: req });
  }
  /** GET /xkms/v1/ssh/keys?scope=&owner= */
  listKeys(scope, owner) {
    return this.http.request("GET", `${BASE12}/keys`, { query: { scope, owner } });
  }
  /** GET /xkms/v1/ssh/keys/{scope}/{owner}/{name} */
  getKey(scope, owner, name) {
    return this.http.request("GET", keyPath2(scope, owner, name));
  }
  /** DELETE /xkms/v1/ssh/keys/{scope}/{owner}/{name} (204). */
  async deleteKey(scope, owner, name) {
    await this.http.request("DELETE", keyPath2(scope, owner, name), { parse: "void" });
  }
  /** GET /xkms/v1/ssh/keys/{scope}/{owner}/{name}/public */
  exportPublic(scope, owner, name) {
    return this.http.request("GET", keyPath2(scope, owner, name, "/public"));
  }
  /** POST /xkms/v1/ssh/keys/{scope}/{owner}/{name}/sign */
  sign(scope, owner, name, req) {
    return this.http.request("POST", keyPath2(scope, owner, name, "/sign"), { body: req });
  }
  // ------------------------------------------------------------------
  // Known hosts
  // ------------------------------------------------------------------
  /** POST /xkms/v1/ssh/known-hosts (201). */
  async addKnownHost(req) {
    await this.http.request("POST", `${BASE12}/known-hosts`, {
      body: req,
      parse: "void"
    });
  }
  /** GET /xkms/v1/ssh/known-hosts?scope=&owner= */
  listKnownHosts(scope, owner) {
    return this.http.request("GET", `${BASE12}/known-hosts`, { query: { scope, owner } });
  }
  /** DELETE /xkms/v1/ssh/known-hosts/{host}?scope=&owner= (204). */
  async removeKnownHost(host, scope, owner) {
    await this.http.request("DELETE", `${BASE12}/known-hosts/${encodePathSegment(host)}`, {
      query: { scope, owner },
      parse: "void"
    });
  }
  /**
   * POST /xkms/v1/ssh/known-hosts/{host}/verify — resolves on match (204);
   * a mismatch surfaces as an XkmsApiError with status 409 whose envelope
   * carries expected/received fingerprints.
   */
  async verifyKnownHost(host, req) {
    await this.http.request(
      "POST",
      `${BASE12}/known-hosts/${encodePathSegment(host)}/verify`,
      { body: req, parse: "void" }
    );
  }
  // ------------------------------------------------------------------
  // Authorized keys
  // ------------------------------------------------------------------
  /** POST /xkms/v1/ssh/authorized-keys (201). */
  async addAuthorizedKey(req) {
    await this.http.request("POST", `${BASE12}/authorized-keys`, {
      body: req,
      parse: "void"
    });
  }
  /** GET /xkms/v1/ssh/authorized-keys?scope=&owner= */
  listAuthorizedKeys(scope, owner) {
    return this.http.request("GET", `${BASE12}/authorized-keys`, { query: { scope, owner } });
  }
  /** GET /xkms/v1/ssh/authorized-keys/{scope}/{owner}/{name} */
  getAuthorizedKey(scope, owner, name) {
    return this.http.request("GET", authorizedPath(scope, owner, name));
  }
  /** DELETE /xkms/v1/ssh/authorized-keys/{scope}/{owner}/{name} (204). */
  async removeAuthorizedKey(scope, owner, name) {
    await this.http.request("DELETE", authorizedPath(scope, owner, name), {
      parse: "void"
    });
  }
  /** POST /xkms/v1/ssh/authorized-keys/emit */
  emitAuthorizedKey(req) {
    return this.http.request("POST", `${BASE12}/authorized-keys/emit`, { body: req });
  }
  /** POST /xkms/v1/ssh/authorized-keys/verify — returns the matching entry. */
  verifyAuthorizedKey(req) {
    return this.http.request("POST", `${BASE12}/authorized-keys/verify`, { body: req });
  }
};

// src/clients/tenants.ts
var BASE13 = "/api/v1/tenants";
function tenantPath(id, suffix = "") {
  return `${BASE13}/${encodeURIComponent(id)}${suffix}`;
}
var TenantsClient = class {
  constructor(http) {
    __publicField(this, "http", http);
  }
  /** POST /api/v1/tenants/ */
  create(req) {
    return this.http.request("POST", `${BASE13}/`, { body: req });
  }
  /** GET /api/v1/tenants/ */
  list(page) {
    return this.http.request("GET", `${BASE13}/`, { query: { ...page } });
  }
  /** GET /api/v1/tenants/{tenantID} */
  get(tenantId) {
    return this.http.request("GET", tenantPath(tenantId));
  }
  /** DELETE /api/v1/tenants/{tenantID} (204). */
  async delete(tenantId) {
    await this.http.request("DELETE", tenantPath(tenantId), { parse: "void" });
  }
  /** PUT /api/v1/tenants/{tenantID}/entitlements */
  updateEntitlements(tenantId, req) {
    return this.http.request("PUT", tenantPath(tenantId, "/entitlements"), { body: req });
  }
  /** PUT /api/v1/tenants/{tenantID}/quotas */
  updateQuotas(tenantId, req) {
    return this.http.request("PUT", tenantPath(tenantId, "/quotas"), { body: req });
  }
  /**
   * GET /api/v1/tenants/{tenantID}/tpm — a tenant's TPM mode. System-scope
   * only.
   */
  getTPMMode(tenantId) {
    return this.http.request("GET", tenantPath(tenantId, "/tpm"));
  }
  /**
   * PUT /api/v1/tenants/{tenantID}/tpm — changes a tenant's TPM mode.
   * Refused while the tenant's scope holds objects or policies.
   */
  setTPMMode(tenantId, req) {
    return this.http.request("PUT", tenantPath(tenantId, "/tpm"), { body: req });
  }
  /** GET /api/v1/tenants/{tenantID}/tpm/vtpm — a vtpm-mode tenant's virtual TPM. */
  vtpmStatus(tenantId) {
    return this.http.request("GET", tenantPath(tenantId, "/tpm/vtpm"));
  }
  /** POST /api/v1/tenants/{tenantID}/tpm/vtpm/start */
  vtpmStart(tenantId) {
    return this.http.request("POST", tenantPath(tenantId, "/tpm/vtpm/start"));
  }
  /** POST /api/v1/tenants/{tenantID}/tpm/vtpm/stop */
  vtpmStop(tenantId) {
    return this.http.request("POST", tenantPath(tenantId, "/tpm/vtpm/stop"));
  }
};

// src/clients/tpmPolicy.ts
var BASE14 = "/api/v1/tpm/policies";
function pcrBranch(bank, pcrs) {
  return { conditions: [{ type: "pcr", bank, pcrs }] };
}
function policyPath(name, action) {
  const path = `${BASE14}/${encodeURIComponent(name)}`;
  return action ? `${path}/${action}` : path;
}
var TpmPolicyClient = class {
  constructor(http) {
    __publicField(this, "http", http);
  }
  /** POST /api/v1/tpm/policies — captures the live values of its pcr conditions. */
  create(req) {
    return this.http.request("POST", BASE14, { body: req });
  }
  /** GET /api/v1/tpm/policies?tenant_id= */
  list(tenantId) {
    return this.http.request("GET", BASE14, { query: { tenant_id: tenantId } });
  }
  /** GET /api/v1/tpm/policies/{name}?tenant_id= */
  get(name, tenantId) {
    return this.http.request("GET", policyPath(name), { query: { tenant_id: tenantId } });
  }
  /** POST /api/v1/tpm/policies/{name}/update — re-captures and re-approves. */
  update(name, tenantId) {
    return this.http.request("POST", policyPath(name, "update"), {
      body: { tenant_id: tenantId, name }
    });
  }
  /** POST /api/v1/tpm/policies/{name}/revoke — withdraws the approval. */
  revoke(name, tenantId) {
    return this.http.request("POST", policyPath(name, "revoke"), {
      body: { tenant_id: tenantId, name }
    });
  }
  /** POST /api/v1/tpm/policies/{name}/verify — compares captured vs. live PCR values. */
  verify(name, tenantId) {
    return this.http.request("POST", policyPath(name, "verify"), {
      body: { tenant_id: tenantId, name }
    });
  }
  /**
   * DELETE /api/v1/tpm/policies/{name} (204). Refused with 409 while any
   * object is assigned to the policy.
   */
  async delete(name, req = {}) {
    await this.http.request("DELETE", policyPath(name), {
      body: { tenant_id: req.tenant_id, owner_auth: req.owner_auth },
      parse: "void"
    });
  }
  /** GET /api/v1/tpm/policies/{name}/objects?tenant_id= — objects bound to the policy. */
  objects(name, tenantId) {
    return this.http.request("GET", policyPath(name, "objects"), {
      query: { tenant_id: tenantId }
    });
  }
  /**
   * POST /api/v1/tpm/policies/{name}/auto-unseal — setting it clears the
   * mark from every other policy of the tenant.
   */
  setAutoUnseal(name, enabled, tenantId) {
    return this.http.request("POST", policyPath(name, "auto-unseal"), {
      body: { tenant_id: tenantId, name, enabled }
    });
  }
  /** POST /api/v1/tpm/policies/{name}/description — an empty description clears it. */
  setDescription(name, description, tenantId) {
    return this.http.request("POST", policyPath(name, "description"), {
      body: { tenant_id: tenantId, name, description }
    });
  }
  /** GET /api/v1/keys/{id}/tpm-policy?tenant_id=&kind= — the policy an object was created under. */
  keyPolicy(keyId, opts = {}) {
    return this.http.request("GET", `/api/v1/keys/${encodeURIComponent(keyId)}/tpm-policy`, {
      query: { tenant_id: opts.tenantId, kind: opts.kind }
    });
  }
  /** POST /api/v1/tpm/authority/rotate — rotates a tenant's policy authority. */
  rotateAuthority(tenantId) {
    return this.http.request("POST", "/api/v1/tpm/authority/rotate", {
      body: { tenant_id: tenantId }
    });
  }
};

// src/clients/users.ts
var BASE15 = "/api/v1/users";
function userPath(username, suffix = "") {
  return `${BASE15}/${encodeURIComponent(username)}${suffix}`;
}
var UsersClient = class {
  constructor(http) {
    __publicField(this, "http", http);
  }
  /** POST /api/v1/users/ */
  create(req) {
    return this.http.request("POST", `${BASE15}/`, { body: req });
  }
  /** GET /api/v1/users/ */
  list() {
    return this.http.request("GET", `${BASE15}/`);
  }
  /** GET /api/v1/users/{username} */
  get(username) {
    return this.http.request("GET", userPath(username));
  }
  /** POST /api/v1/users/{username}/enable */
  enable(username) {
    return this.http.request("POST", userPath(username, "/enable"));
  }
  /** POST /api/v1/users/{username}/disable */
  disable(username) {
    return this.http.request("POST", userPath(username, "/disable"));
  }
  /** DELETE /api/v1/users/{username} */
  delete(username) {
    return this.http.request("DELETE", userPath(username));
  }
  /** POST /api/v1/users/{username}/cert-bindings */
  bindCert(username, req) {
    return this.http.request("POST", userPath(username, "/cert-bindings"), { body: req });
  }
  /** GET /api/v1/users/{username}/credentials */
  credentials(username) {
    return this.http.request("GET", userPath(username, "/credentials"));
  }
};

// src/client.ts
var XkmsClient = class {
  constructor(config) {
    __publicField(this, "http");
    __publicField(this, "authPaths");
    __publicField(this, "health");
    __publicField(this, "capabilities");
    __publicField(this, "auth");
    __publicField(this, "backends");
    __publicField(this, "keys");
    __publicField(this, "certs");
    __publicField(this, "seal");
    __publicField(this, "frost");
    __publicField(this, "pin");
    __publicField(this, "piv");
    __publicField(this, "ca");
    __publicField(this, "tenants");
    __publicField(this, "passwords");
    __publicField(this, "oidcCredentials");
    __publicField(this, "platform");
    __publicField(this, "tpmPolicies");
    __publicField(this, "credentials");
    __publicField(this, "users");
    __publicField(this, "ssh");
    this.http = new HttpCore(config);
    this.authPaths = resolveAuthPaths(config.authPaths);
    this.health = new HealthClient(this.http);
    this.capabilities = new CapabilitiesClient(this.http, this.authPaths);
    this.auth = new AuthClient(this.http, this.authPaths);
    this.backends = new BackendsClient(this.http);
    this.keys = new KeysClient(this.http);
    this.certs = new CertsClient(this.http);
    this.seal = new SealClient(this.http);
    this.frost = new FrostClient(this.http);
    this.pin = new PinClient(this.http);
    this.piv = new PivClient(this.http);
    this.ca = new CaClient(this.http);
    this.tenants = new TenantsClient(this.http);
    this.passwords = new PasswordsClient(this.http);
    this.oidcCredentials = new OidcCredentialClient(this.http);
    this.platform = new PlatformClient(this.http);
    this.tpmPolicies = new TpmPolicyClient(this.http);
    this.credentials = new CredentialsClient(this.http);
    this.users = new UsersClient(this.http);
    this.ssh = new SshClient(this.http);
  }
};
function createClient(config) {
  return new XkmsClient(config);
}

// src/webauthn.ts
function base64urlToBuffer(value) {
  const normalised = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalised + "=".repeat((4 - normalised.length % 4) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}
function bufferToBase64url(buffer) {
  const bytes = buffer instanceof ArrayBuffer ? new Uint8Array(buffer) : new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
var WebAuthnEnvelopeError = class extends Error {
  constructor(message) {
    super(message);
    this.name = "WebAuthnEnvelopeError";
  }
};
function unwrapEnvelope(raw) {
  if (raw === null || typeof raw !== "object") {
    throw new WebAuthnEnvelopeError("WebAuthn options missing from server response");
  }
  const obj = raw;
  const inner = obj.publicKey !== void 0 && obj.publicKey !== null ? obj.publicKey : obj;
  if (typeof inner.challenge !== "string" || inner.challenge.length === 0) {
    throw new WebAuthnEnvelopeError(
      "WebAuthn challenge missing from server response (unexpected options shape)"
    );
  }
  return inner;
}
function parseCreationOptions(raw) {
  const json = unwrapEnvelope(raw);
  const options = {
    challenge: base64urlToBuffer(json.challenge),
    rp: json.rp,
    user: {
      id: base64urlToBuffer(json.user.id),
      name: json.user.name,
      displayName: json.user.displayName
    },
    pubKeyCredParams: json.pubKeyCredParams
  };
  if (json.timeout !== void 0) options.timeout = json.timeout;
  if (json.attestation !== void 0) options.attestation = json.attestation;
  if (json.authenticatorSelection !== void 0) {
    options.authenticatorSelection = json.authenticatorSelection;
  }
  if (json.extensions !== void 0) options.extensions = json.extensions;
  if (json.excludeCredentials !== void 0) {
    options.excludeCredentials = json.excludeCredentials.map((c) => ({
      id: base64urlToBuffer(c.id),
      type: c.type,
      ...c.transports !== void 0 ? { transports: c.transports } : {}
    }));
  }
  return options;
}
function parseRequestOptions(raw) {
  const json = unwrapEnvelope(raw);
  const options = {
    challenge: base64urlToBuffer(json.challenge)
  };
  if (json.timeout !== void 0) options.timeout = json.timeout;
  if (json.rpId !== void 0) options.rpId = json.rpId;
  if (json.userVerification !== void 0) options.userVerification = json.userVerification;
  if (json.extensions !== void 0) options.extensions = json.extensions;
  if (json.allowCredentials !== void 0) {
    options.allowCredentials = json.allowCredentials.map((c) => ({
      id: base64urlToBuffer(c.id),
      type: c.type,
      ...c.transports !== void 0 ? { transports: c.transports } : {}
    }));
  }
  return options;
}
function encodeAttestationResponse(credential) {
  const response = credential.response;
  const transports = typeof response.getTransports === "function" ? response.getTransports() : [];
  const out = {
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: bufferToBase64url(response.clientDataJSON),
      attestationObject: bufferToBase64url(response.attestationObject)
    },
    clientExtensionResults: credential.getClientExtensionResults()
  };
  if (credential.authenticatorAttachment) {
    out.authenticatorAttachment = credential.authenticatorAttachment;
  }
  if (transports.length > 0) {
    out.response.transports = transports;
  }
  return out;
}
function encodeAssertionResponse(credential) {
  const response = credential.response;
  const out = {
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: bufferToBase64url(response.clientDataJSON),
      authenticatorData: bufferToBase64url(response.authenticatorData),
      signature: bufferToBase64url(response.signature)
    },
    clientExtensionResults: credential.getClientExtensionResults()
  };
  if (credential.authenticatorAttachment) {
    out.authenticatorAttachment = credential.authenticatorAttachment;
  }
  if (response.userHandle && response.userHandle.byteLength > 0) {
    out.response.userHandle = bufferToBase64url(response.userHandle);
  }
  return out;
}

// src/vaultPasskey.ts
var PRF_LENGTH = 32;
var VAULT_PASSKEY_RP_NAME = "xkms password vault";
var VaultPasskeyPrfUnsupportedError = class extends Error {
  constructor() {
    super(
      "This browser or security key does not support the WebAuthn PRF extension (FIDO2 hmac-secret), which a vault passkey needs. Use a security key with hmac-secret and a PIN, in a current Chrome, Edge, Firefox or Safari, or use your passphrase."
    );
    this.name = "VaultPasskeyPrfUnsupportedError";
  }
};
var VaultPasskeyUnavailableError = class extends Error {
  constructor(message) {
    super(message);
    this.name = "VaultPasskeyUnavailableError";
  }
};
function defaultPlatform() {
  return {
    credentials: globalThis.navigator?.credentials,
    hostname: globalThis.location?.hostname ?? "",
    random: (n) => crypto.getRandomValues(new Uint8Array(new ArrayBuffer(n)))
  };
}
function relyingPartyServes(rpId, hostname) {
  return rpId !== "" && (hostname === rpId || hostname.endsWith("." + rpId));
}
function bufferToBase64(buffer) {
  const url = bufferToBase64url(buffer).replace(/-/g, "+").replace(/_/g, "/");
  return url + "=".repeat((4 - url.length % 4) % 4);
}
function prfFirst(credential) {
  const prf = credential.getClientExtensionResults().prf;
  const first = prf?.results?.first;
  if (first === void 0) return void 0;
  const bytes = first instanceof ArrayBuffer ? new Uint8Array(first) : new Uint8Array(first.buffer, first.byteOffset, first.byteLength);
  return bytes.length === PRF_LENGTH ? bytes : void 0;
}
function requireCredentials(platform) {
  if (!platform.credentials) {
    throw new VaultPasskeyUnavailableError("This browser has no WebAuthn support.");
  }
  return platform.credentials;
}
async function enrollVaultPasskey(options, platform = defaultPlatform()) {
  const rpId = options.status.passkey_rp_id ?? "";
  if (rpId === "") {
    throw new VaultPasskeyUnavailableError(
      "The server offers no passkeys: it has no WebAuthn relying party (webauthn.rp_id) configured."
    );
  }
  if (!relyingPartyServes(rpId, platform.hostname)) {
    throw new VaultPasskeyUnavailableError(
      `Vault passkeys belong to ${rpId}; open the console there to enroll one.`
    );
  }
  const credentials = requireCredentials(platform);
  const salt = platform.random(PRF_LENGTH);
  const userName = options.userName ?? VAULT_PASSKEY_RP_NAME;
  const created = await credentials.create({
    publicKey: {
      rp: { id: rpId, name: VAULT_PASSKEY_RP_NAME },
      user: { id: platform.random(16), name: userName, displayName: userName },
      challenge: platform.random(32),
      pubKeyCredParams: [
        { type: "public-key", alg: -7 },
        { type: "public-key", alg: -257 }
      ],
      authenticatorSelection: { userVerification: "required", residentKey: "discouraged" },
      extensions: { prf: { eval: { first: salt } } }
    }
  });
  if (!created) {
    throw new VaultPasskeyUnavailableError("No passkey was created.");
  }
  const prf = created.getClientExtensionResults().prf;
  if (prf?.enabled !== true) {
    throw new VaultPasskeyPrfUnsupportedError();
  }
  const secret = prfFirst(created) ?? (await evaluate(credentials, rpId, [{ id: created.rawId, salt }], platform)).secret;
  return {
    factor: "passkey",
    credential_id: bufferToBase64(created.rawId),
    prf_salt: bufferToBase64(salt),
    secret: bufferToBase64(secret),
    rp_id: rpId,
    ...options.label !== void 0 ? { label: options.label } : {}
  };
}
async function unlockVaultPasskey(factors, platform = defaultPlatform()) {
  const passkeys = factors.filter((f) => f.factor === "passkey" && f.credential_id && f.prf_salt && f.rp_id);
  if (passkeys.length === 0) {
    throw new VaultPasskeyUnavailableError("Your vault has no passkey.");
  }
  const usable = passkeys.filter((f) => relyingPartyServes(f.rp_id, platform.hostname));
  if (usable.length === 0) {
    throw new VaultPasskeyUnavailableError(
      `Your vault's passkeys belong to ${passkeys.map((f) => f.rp_id).join(", ")}; open the console there, or use xkey.`
    );
  }
  const rpId = usable.map((f) => f.rp_id).sort((a, b) => b.length - a.length)[0];
  const candidates = usable.filter((f) => f.rp_id === rpId).map((f) => ({ id: base64urlToBuffer(f.credential_id), salt: new Uint8Array(base64urlToBuffer(f.prf_salt)) }));
  const { id, secret } = await evaluate(requireCredentials(platform), rpId, candidates, platform);
  return { factor: "passkey", credential_id: bufferToBase64(id), secret: bufferToBase64(secret) };
}
async function evaluate(credentials, rpId, candidates, platform) {
  const evalByCredential = {};
  for (const c of candidates) evalByCredential[bufferToBase64url(c.id)] = { first: c.salt };
  const asserted = await credentials.get({
    publicKey: {
      rpId,
      challenge: platform.random(32),
      allowCredentials: candidates.map((c) => ({ type: "public-key", id: c.id })),
      userVerification: "required",
      extensions: { prf: { evalByCredential } }
    }
  });
  if (!asserted) {
    throw new VaultPasskeyUnavailableError("No passkey was presented.");
  }
  const secret = prfFirst(asserted);
  if (!secret) {
    throw new VaultPasskeyPrfUnsupportedError();
  }
  return { id: asserted.rawId, secret };
}

// src/vaultBridge.ts
var XkeyExtensionUnavailableError = class extends Error {
  constructor() {
    super(
      "Unlocking with a PIV card, certificate or TPM key needs the xKey browser extension and the xKey app. Install the extension, pair it with xKey, and connect xKey to this server."
    );
    this.name = "XkeyExtensionUnavailableError";
  }
};
var XkeyBridgeError = class extends Error {
  constructor(message) {
    super(message);
    this.name = "XkeyBridgeError";
  }
};
var XKEY_PING_TIMEOUT_MS = 800;
var XKEY_UNLOCK_TIMEOUT_MS = 135e3;
var KEY_FACTORS = /* @__PURE__ */ new Set(["piv", "certificate", "tpm"]);
function keyFactorFingerprints(factors) {
  return factors.filter((f) => KEY_FACTORS.has(f.factor) && f.key_fingerprint).map((f) => f.key_fingerprint);
}
function newRequestId() {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
function exchange(win, request, replyType, timeoutMs) {
  const requestId = newRequestId();
  return new Promise((resolve) => {
    const onMessage = (event) => {
      const data = event.data;
      if (event.origin !== win.location.origin || !data || data.source !== "xkey-extension") return;
      if (data.type !== replyType || data.requestId !== requestId) return;
      cleanup();
      resolve(data);
    };
    const timer = setTimeout(() => {
      cleanup();
      resolve(void 0);
    }, timeoutMs);
    const cleanup = () => {
      clearTimeout(timer);
      win.removeEventListener("message", onMessage);
    };
    win.addEventListener("message", onMessage);
    win.postMessage({ source: "xkms-console", requestId, ...request }, win.location.origin);
  });
}
async function detectXkeyExtension(win = window, timeoutMs = XKEY_PING_TIMEOUT_MS) {
  return await exchange(win, { type: "xkey-ping" }, "xkey-pong", timeoutMs) !== void 0;
}
async function unlockWithXkey(fingerprints, win = window, timeoutMs = XKEY_UNLOCK_TIMEOUT_MS) {
  if (fingerprints.length === 0) {
    throw new XkeyBridgeError("Your vault has no PIV, certificate or TPM factor.");
  }
  if (!await detectXkeyExtension(win)) {
    throw new XkeyExtensionUnavailableError();
  }
  const reply = await exchange(win, { type: "xkey-vault-unlock", fingerprints }, "xkey-vault-unlock-result", timeoutMs);
  if (!reply) {
    throw new XkeyBridgeError("xKey did not answer in time.");
  }
  if (reply.unlocked !== true) {
    throw new XkeyBridgeError(typeof reply.error === "string" && reply.error ? reply.error : "xKey did not unlock the vault.");
  }
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  AuthClient,
  BackendsClient,
  CaClient,
  CapabilitiesClient,
  CertsClient,
  CredentialsClient,
  DEFAULT_AUTH_PATHS,
  FrostClient,
  HEADER_SESSION_ID,
  HealthClient,
  HttpCore,
  KeyVersionsClient,
  KeysClient,
  OIDCDeviceLoginError,
  OidcCredentialClient,
  PasswordsClient,
  PinClient,
  PivClient,
  PlatformClient,
  SealClient,
  SshClient,
  TenantsClient,
  TpmPolicyClient,
  UsersClient,
  VAULT_PASSKEY_RP_NAME,
  VaultPasskeyPrfUnsupportedError,
  VaultPasskeyUnavailableError,
  WebAuthnEnvelopeError,
  XKEY_PING_TIMEOUT_MS,
  XKEY_UNLOCK_TIMEOUT_MS,
  XkeyBridgeError,
  XkeyExtensionUnavailableError,
  XkmsApiError,
  XkmsClient,
  XkmsNetworkError,
  base64urlToBuffer,
  bufferToBase64,
  bufferToBase64url,
  buildURL,
  createClient,
  detectXkeyExtension,
  encodeAssertionResponse,
  encodeAttestationResponse,
  encodeHostKeyResponse,
  encodePathSegment,
  encodeResize,
  enrollVaultPasskey,
  isWailsRuntime,
  keyFactorFingerprints,
  parseControl,
  parseCreationOptions,
  parseErrorEnvelope,
  parseRequestOptions,
  pcrBranch,
  relyingPartyServes,
  resolveAuthPaths,
  unlockVaultPasskey,
  unlockWithXkey
});
//# sourceMappingURL=index.cjs.map