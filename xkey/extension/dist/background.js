// xKey AutoFill Extension - Background Service Worker
//
// This service worker manages the native messaging connection to the xKey
// desktop application. All credential operations route through here.
//
// Lifecycle:
//   1. Content script or popup sends an ExtensionMessage.
//   2. Service worker connects to native host if not already connected.
//   3. Request is encrypted and sent over the native messaging port.
//   4. Encrypted response is decrypted and returned to the caller.
//   5. Session times out after inactivity (default 5 minutes).
//
// Phase 8 additions:
//   - Ed25519 identity binding in handshake (extension pairing protocol).
//   - Challenge-response authentication for credential fills.
//   - Pairing flow when native host requires extension registration.
import { SessionCrypto } from './crypto.js';
import { ExtensionIdentity } from './identity.js';
// ---------------------------------------------------------------------------
// Inline types (background runs as ES module, but we keep it self-contained
// to avoid bundling complexity)
// ---------------------------------------------------------------------------
const NATIVE_HOST_NAME = 'com.automatethethings.xkey';
// ---------------------------------------------------------------------------
// Base64 helpers (duplicated here to keep background self-contained)
// ---------------------------------------------------------------------------
function toBase64(bytes) {
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}
// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
let sessionCrypto = null;
let port = null;
let connected = false;
let sessionTimer = null;
let sessionTimeoutSec = 300; // 5 minutes, 0 = no timeout
/** Whether the native host requires pairing before the session can proceed. */
let pairingRequired = false;
/**
 * Set during pairing: the native host's public key for ECDH completion
 * after pairing succeeds.
 */
let pairingPeerPubKey = null;
// Pending request tracking: each sendRequest call registers a resolver
// that gets invoked when the next native message arrives.
let pendingResolve = null;
let pendingReject = null;
// ---------------------------------------------------------------------------
// Tab domain history for SSO/redirect handling
// ---------------------------------------------------------------------------
/** Track domain navigation history per tab (handles SSO redirects like Okta). */
const tabDomainHistory = new Map();
const MAX_TAB_HISTORY = 5;
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
    if (!changeInfo.url)
        return;
    try {
        const host = new URL(changeInfo.url).hostname;
        if (!host)
            return;
        const history = tabDomainHistory.get(tabId) || [];
        // Only add if different from the last entry (avoid duplicates for same-domain navigations).
        if (history[history.length - 1] !== host) {
            history.push(host);
            if (history.length > MAX_TAB_HISTORY)
                history.shift();
            tabDomainHistory.set(tabId, history);
        }
    }
    catch {
        // Ignore invalid URLs (chrome://, about:, etc.).
    }
});
chrome.tabs.onRemoved.addListener((tabId) => {
    tabDomainHistory.delete(tabId);
});
// ---------------------------------------------------------------------------
// Connection management
// ---------------------------------------------------------------------------
/**
 * Connect to the native messaging host and perform X25519 ECDH handshake
 * with Ed25519 identity binding.
 */
async function connect() {
    if (connected && port && sessionCrypto?.ready) {
        return;
    }
    // Clean up any prior state.
    disconnect();
    // 1. Open native messaging port.
    port = chrome.runtime.connectNative(NATIVE_HOST_NAME);
    // 2. Generate ephemeral X25519 keypair.
    sessionCrypto = await SessionCrypto.create();
    // 3. Get Ed25519 identity for binding.
    let identityKey;
    let identitySig;
    let origin;
    try {
        const identity = await ExtensionIdentity.getOrCreate();
        origin = chrome.runtime.getURL('');
        // Get the ephemeral public key as raw bytes for signing.
        const ephemeralPubKeyBase64 = sessionCrypto.getPublicKeyBase64();
        const ephemeralPubKeyBinary = atob(ephemeralPubKeyBase64);
        const ephemeralPubKeyBytes = new Uint8Array(ephemeralPubKeyBinary.length);
        for (let i = 0; i < ephemeralPubKeyBinary.length; i++) {
            ephemeralPubKeyBytes[i] = ephemeralPubKeyBinary.charCodeAt(i);
        }
        // Sign the handshake binding.
        const sig = await ExtensionIdentity.signHandshake(ephemeralPubKeyBytes, origin);
        identityKey = toBase64(identity.publicKey);
        identitySig = toBase64(sig);
    }
    catch (err) {
        // Ed25519 not supported or identity creation failed.
        // Proceed without identity binding (host may reject or require pairing).
        console.warn('[xKey] Ed25519 identity unavailable:', err);
    }
    // 4. Perform handshake with identity fields.
    const handshakeResult = await performHandshake(port, sessionCrypto, identityKey, identitySig, origin);
    if (handshakeResult === 'pairing_required') {
        // Pairing is needed. The session is not yet ready.
        // The popup will be notified and will collect the pairing code.
        // NOTE: Do NOT register onDisconnect here — submitPairingCode()
        // registers it after ECDH completes. Registering it here caused
        // double-handler issues where the first handler could fire during
        // async gaps in the pairing flow, corrupting session state.
        return;
    }
    if (!handshakeResult) {
        disconnect();
        throw new Error('Native host handshake failed');
    }
    // 5. Wire up disconnect handler.
    wireDisconnectHandler();
    connected = true;
    resetSessionTimer();
    // Fetch policy to update session timeout.
    try {
        const policyResp = await sendRequest({
            type: 'autofill',
            autofill: { action: 'policy' },
        });
        if (policyResp.autofill?.policy) {
            const timeout = policyResp.autofill.policy.session_timeout_sec;
            if (typeof timeout === 'number' && timeout >= 0) {
                sessionTimeoutSec = timeout;
                resetSessionTimer();
            }
        }
    }
    catch {
        // Policy fetch is best-effort; proceed with defaults.
    }
}
/**
 * Perform X25519 ECDH handshake with the native host, including
 * Ed25519 identity binding fields.
 *
 * Protocol:
 *   Extension -> Host: { type: "handshake", pubkey, identity_key?, identity_sig?, origin? }
 *   Host -> Extension: { type: "handshake_ok", pubkey }
 *                  OR: { type: "handshake_pair", pubkey, pairing_required: true }
 *
 * Returns true if handshake succeeded, 'pairing_required' if pairing is needed,
 * or false if handshake failed.
 */
function performHandshake(nativePort, cryptoSession, identityKey, identitySig, origin) {
    return new Promise((resolve) => {
        const timeout = setTimeout(() => {
            nativePort.onMessage.removeListener(handler);
            resolve(false);
        }, 5000);
        const handler = async (msg) => {
            clearTimeout(timeout);
            nativePort.onMessage.removeListener(handler);
            const response = msg;
            // Handle pairing_required response.
            if (response.type === 'handshake_pair' && response.pairing_required && response.pubkey) {
                pairingRequired = true;
                pairingPeerPubKey = response.pubkey;
                console.log('[xKey] Pairing required by native host');
                resolve('pairing_required');
                return;
            }
            // Handle normal handshake_ok response.
            if (response.type !== 'handshake_ok' || !response.pubkey) {
                resolve(false);
                return;
            }
            try {
                await cryptoSession.completeHandshake(response.pubkey);
                resolve(true);
            }
            catch (err) {
                console.error('[xKey] Handshake ECDH failed:', err);
                resolve(false);
            }
        };
        nativePort.onMessage.addListener(handler);
        // Send our public key with identity binding.
        const hsMsg = {
            type: 'handshake',
            pubkey: cryptoSession.getPublicKeyBase64(),
        };
        if (identityKey) {
            hsMsg.identity_key = identityKey;
        }
        if (identitySig) {
            hsMsg.identity_sig = identitySig;
        }
        if (origin) {
            hsMsg.origin = origin;
        }
        nativePort.postMessage(hsMsg);
    });
}
/**
 * Submit a pairing code to the native host. Called when the popup
 * sends a 'pairing_submit' message.
 *
 * On success, completes the ECDH handshake with the stored peer pubkey
 * and transitions to the connected state.
 */
async function submitPairingCode(code) {
    if (!pairingRequired || !port || !sessionCrypto || !pairingPeerPubKey) {
        return { success: false, error: 'No pairing session in progress' };
    }
    // Get identity key for the pairing confirmation.
    let identityKeyBase64;
    try {
        const identity = await ExtensionIdentity.getOrCreate();
        identityKeyBase64 = toBase64(identity.publicKey);
    }
    catch (err) {
        const errMsg = err instanceof Error ? err.message : String(err);
        return { success: false, error: `Identity unavailable: ${errMsg}` };
    }
    // Send pairing confirmation to native host.
    const confirmMsg = {
        type: 'pairing_confirm',
        code,
        identity_key: identityKeyBase64,
    };
    return new Promise((resolve) => {
        const timeout = setTimeout(() => {
            port?.onMessage.removeListener(handler);
            disconnect();
            resolve({ success: false, error: 'Pairing response timeout' });
        }, 10000);
        const handler = async (msg) => {
            clearTimeout(timeout);
            port?.onMessage.removeListener(handler);
            const result = msg;
            if (result.type === 'pairing_ok') {
                // Complete the ECDH handshake with the stored peer pubkey.
                try {
                    await sessionCrypto.completeHandshake(pairingPeerPubKey);
                    pairingRequired = false;
                    pairingPeerPubKey = null;
                    connected = true;
                    resetSessionTimer();
                    // Wire up disconnect handler now that we are connected.
                    wireDisconnectHandler();
                    // Fetch policy.
                    try {
                        const policyResp = await sendRequest({
                            type: 'autofill',
                            autofill: { action: 'policy' },
                        });
                        if (policyResp.autofill?.policy) {
                            const t = policyResp.autofill.policy.session_timeout_sec;
                            if (typeof t === 'number' && t >= 0) {
                                sessionTimeoutSec = t;
                                resetSessionTimer();
                            }
                        }
                    }
                    catch {
                        // Best-effort.
                    }
                    resolve({ success: true });
                }
                catch (err) {
                    disconnect();
                    const errMsg = err instanceof Error ? err.message : String(err);
                    resolve({ success: false, error: `ECDH failed after pairing: ${errMsg}` });
                }
            }
            else if (result.type === 'pairing_failed') {
                disconnect();
                resolve({ success: false, error: result.error || 'Pairing rejected' });
            }
            else {
                disconnect();
                resolve({ success: false, error: 'Unexpected pairing response' });
            }
        };
        port.onMessage.addListener(handler);
        port.postMessage(confirmMsg);
    });
}
/**
 * Generate a 32-byte random challenge, base64-encoded.
 * Used for CTAP2 challenge-response authentication on fill requests.
 */
function generateChallenge() {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}
/**
 * Send an encrypted request to the native host and wait for the
 * encrypted response.
 */
async function sendRequest(request) {
    if (!connected || !port || !sessionCrypto?.ready) {
        throw new Error('Not connected to xKey');
    }
    // Serialize and encrypt.
    const plaintext = JSON.stringify(request);
    const { nonce, ciphertext } = await sessionCrypto.encrypt(plaintext);
    const encMsg = {
        type: 'encrypted',
        nonce,
        ciphertext,
    };
    // Determine timeout based on request type.
    // Fill requests need longer timeout for PIN entry + touch.
    const isGetAction = request.autofill?.action === 'get';
    const timeoutMs = isGetAction ? 45000 : 10000;
    // Wait for the response.
    const responsePromise = new Promise((resolve, reject) => {
        // Only one request at a time (serial protocol).
        if (pendingResolve) {
            reject(new Error('A request is already in flight'));
            return;
        }
        pendingResolve = resolve;
        pendingReject = reject;
        // Timeout for response.
        const timeout = setTimeout(() => {
            pendingResolve = null;
            pendingReject = null;
            reject(new Error('Native host response timeout'));
        }, timeoutMs);
        const handler = (msg) => {
            clearTimeout(timeout);
            port?.onMessage.removeListener(handler);
            const savedResolve = pendingResolve;
            pendingResolve = null;
            pendingReject = null;
            savedResolve?.(msg);
        };
        port.onMessage.addListener(handler);
    });
    // Send the encrypted message.
    port.postMessage(encMsg);
    // Wait for and decrypt response.
    const rawResponse = await responsePromise;
    const encResp = rawResponse;
    if (encResp.type !== 'encrypted') {
        // Could be an error message from the host before encryption.
        const errResp = rawResponse;
        if (errResp.error) {
            throw new Error(errResp.error);
        }
        throw new Error('Unexpected response type from native host');
    }
    const decrypted = await sessionCrypto.decrypt(encResp.nonce, encResp.ciphertext);
    const response = JSON.parse(decrypted);
    if (response.status === 'error') {
        throw new Error(response.error || 'Unknown error from xKey');
    }
    return response;
}
/**
 * Register the onDisconnect handler on the current port.
 * Extracted to avoid duplicate handler registration.
 */
function wireDisconnectHandler() {
    if (!port)
        return;
    port.onDisconnect.addListener(() => {
        const lastError = chrome.runtime.lastError?.message || 'disconnected';
        console.warn('[xKey] Native host disconnected:', lastError);
        handleDisconnect();
    });
}
/**
 * Tear down the native messaging connection and session state.
 */
function disconnect() {
    if (sessionTimer) {
        clearTimeout(sessionTimer);
        sessionTimer = null;
    }
    if (port) {
        try {
            port.disconnect();
        }
        catch {
            // Ignore errors during cleanup.
        }
        port = null;
    }
    sessionCrypto = null;
    connected = false;
    pairingRequired = false;
    pairingPeerPubKey = null;
    pendingResolve = null;
    pendingReject = null;
}
/**
 * Handle native host disconnection.
 */
function handleDisconnect() {
    const savedReject = pendingReject;
    disconnect();
    savedReject?.(new Error('Native host disconnected'));
}
/**
 * Reset the session inactivity timer.
 */
function resetSessionTimer() {
    if (sessionTimer) {
        clearTimeout(sessionTimer);
        sessionTimer = null;
    }
    if (sessionTimeoutSec > 0) {
        sessionTimer = setTimeout(() => {
            console.log('[xKey] Session timeout, disconnecting');
            disconnect();
        }, sessionTimeoutSec * 1000);
    }
}
// ---------------------------------------------------------------------------
// Browser focus
// ---------------------------------------------------------------------------
/**
 * Bring the browser window that initiated the fill request back into focus.
 * Called after a successful credential or TOTP fill so the user doesn't
 * have to manually switch back from the xKey desktop app.
 */
async function focusSenderWindow(sender) {
    const windowId = sender.tab?.windowId;
    if (windowId != null) {
        try {
            await chrome.windows.update(windowId, { focused: true });
        }
        catch {
            // Best-effort — ignore if the window was closed or not focusable.
        }
    }
}
/**
 * Handle a message from the content script or popup.
 */
async function handleMessage(message, _sender) {
    try {
        // Handle pairing cancel — allows popup to force a fresh connection.
        if (message.type === 'pairing_cancel') {
            disconnect();
            return { type: 'pairing_cancelled' };
        }
        // Handle pairing status query without connecting.
        if (message.type === 'status' && pairingRequired) {
            // If the port died while waiting for pairing, reset and allow fresh connect.
            if (!port) {
                disconnect();
            }
            else {
                return { type: 'pairing_status', required: true };
            }
        }
        // Handle pairing code submission.
        if (message.type === 'pairing_submit') {
            const result = await submitPairingCode(message.code);
            if (result.success) {
                return { type: 'pairing_ok' };
            }
            return { type: 'pairing_failed', error: result.error };
        }
        // If pairing is required, don't proceed with other requests.
        if (pairingRequired) {
            // Stale pairing state with dead port — reset.
            if (!port) {
                disconnect();
            }
            else {
                return { type: 'pairing_status', required: true };
            }
        }
        if (!connected) {
            await connect();
        }
        // If connect triggered pairing, report it.
        if (pairingRequired) {
            return { type: 'pairing_status', required: true };
        }
        resetSessionTimer();
        switch (message.type) {
            case 'search': {
                // Collect domains to search: current domain + tab navigation history.
                // This handles SSO redirects (e.g. site.com → okta.com) by also
                // searching for credentials stored against previously visited domains.
                const domains = new Set([message.domain]);
                const tabId = _sender.tab?.id;
                if (tabId != null) {
                    const history = tabDomainHistory.get(tabId);
                    if (history) {
                        for (const d of history) {
                            domains.add(d);
                        }
                    }
                }
                // Search all related domains and merge results (deduplicated by ID).
                const allCreds = [];
                const seenIds = new Set();
                for (const domain of domains) {
                    const resp = await sendRequest({
                        type: 'autofill',
                        autofill: { action: 'search', domain },
                    });
                    for (const cred of resp.autofill?.credentials ?? []) {
                        if (!seenIds.has(cred.id)) {
                            seenIds.add(cred.id);
                            allCreds.push(cred);
                        }
                    }
                }
                return { type: 'credentials', data: allCreds };
            }
            case 'fill': {
                // Generate a 32-byte random challenge for CTAP2 authentication.
                const challenge = generateChallenge();
                const resp = await sendRequest({
                    type: 'autofill',
                    autofill: { action: 'get', id: message.id, challenge },
                });
                // Bring the browser back into focus after PIN + touch in xKey app.
                if (resp.autofill?.fill) {
                    await focusSenderWindow(_sender);
                }
                return { type: 'fill_result', data: resp.autofill?.fill };
            }
            case 'totp': {
                const resp = await sendRequest({
                    type: 'autofill',
                    autofill: { action: 'totp', domain: message.domain },
                });
                if (resp.autofill?.totp) {
                    await focusSenderWindow(_sender);
                }
                return { type: 'totp_result', data: resp.autofill?.totp };
            }
            case 'totp_by_id': {
                const resp = await sendRequest({
                    type: 'autofill',
                    autofill: { action: 'totp_by_id', id: message.id },
                });
                if (resp.autofill?.totp) {
                    await focusSenderWindow(_sender);
                }
                return { type: 'totp_result', data: resp.autofill?.totp };
            }
            case 'status': {
                const resp = await sendRequest({
                    type: 'autofill',
                    autofill: { action: 'status' },
                });
                return { type: 'status_result', data: resp.autofill?.status };
            }
            case 'check_credential': {
                // Search for any credential matching this domain + username.
                // Returns exists:true when at least one match is found so the
                // content script knows not to offer a duplicate save prompt.
                const resp = await sendRequest({
                    type: 'autofill',
                    autofill: { action: 'search', domain: message.domain },
                });
                const creds = resp.autofill?.credentials ?? [];
                const exists = creds.some((c) => c.username === message.username);
                return { type: 'check_result', exists };
            }
            case 'save_credential': {
                // Forward the save request to the native host.
                // Extra fields (username, password, title) are sent as top-level
                // properties on the autofill envelope; the native host reads them
                // alongside the standard action/domain fields.
                const saveReq = {
                    type: 'autofill',
                    autofill: {
                        action: 'save',
                        domain: message.domain,
                        username: message.username,
                        password: message.password,
                        title: message.title,
                    },
                };
                const resp = await sendRequest(saveReq);
                const success = resp.status === 'ok';
                return { type: 'save_result', success };
            }
            case 'ignore_domain': {
                // Ask the native host to suppress save prompts for this domain.
                const resp = await sendRequest({
                    type: 'autofill',
                    autofill: { action: 'ignore_domain', domain: message.domain },
                });
                const success = resp.status === 'ok';
                return { type: 'save_result', success };
            }
            case 'unlock': {
                const unlockMsg = message;
                const resp = await sendRequest({
                    type: 'unlock',
                    unlock: { pin: unlockMsg.pin },
                });
                const unlockResult = resp.unlock;
                if (unlockResult?.success) {
                    return { type: 'unlock_result', success: true };
                }
                return { type: 'unlock_result', success: false, error: unlockResult?.error || resp.error || 'Unlock failed' };
            }
            case 'reconnect': {
                // connect() was already called above when !connected.
                const status = await sendRequest({ type: 'autofill', autofill: { action: 'status' } });
                const locked = status.autofill?.status?.app_locked ?? false;
                if (locked) {
                    try {
                        await sendRequest({ type: 'autofill', autofill: { action: 'focus' } });
                    }
                    catch {
                        // Best-effort: bring xKey to foreground so the user can unlock.
                    }
                }
                return { type: 'reconnect_result', connected: true, locked };
            }
            default: {
                return { type: 'error', message: 'Unknown message type' };
            }
        }
    }
    catch (err) {
        const errMsg = err instanceof Error ? err.message : String(err);
        return { type: 'error', message: errMsg };
    }
}
// Register message listener.
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    handleMessage(message, sender).then(sendResponse);
    return true; // Keep the message channel open for async response.
});
//# sourceMappingURL=background.js.map