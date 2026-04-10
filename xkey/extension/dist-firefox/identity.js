// xKey AutoFill Extension - Extension Identity (Ed25519 Keypair)
//
// Manages a long-lived Ed25519 keypair stored in chrome.storage.local.
// This key is the browser binding -- scoped per extension and per browser
// profile by Chrome's storage sandbox. It is used to bind ephemeral
// session keys to a persistent identity for the pairing protocol.
//
// Requirements: Chrome 113+ (Ed25519 support in Web Crypto API).
const encoder = new TextEncoder();
/** Storage key for the persisted Ed25519 JWK private key. */
const STORAGE_KEY = 'xkey_identity';
/** Context string mixed into the handshake binding hash. */
const SIGN_CONTEXT = 'xkey-ext-v1';
/** Encode bytes to base64 string. */
function toBase64(bytes) {
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}
/** Decode base64 string to bytes. */
function fromBase64(b64) {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}
/**
 * Check whether the browser supports Ed25519 via Web Crypto.
 * Returns false on Chrome < 113 or environments that lack it.
 */
async function isEd25519Supported() {
    try {
        const testKey = await crypto.subtle.generateKey('Ed25519', false, ['sign', 'verify']);
        // If we got here, Ed25519 is supported. Discard the key.
        void testKey;
        return true;
    }
    catch {
        return false;
    }
}
/**
 * ExtensionIdentity manages a long-lived Ed25519 keypair stored in
 * chrome.storage.local. This key is the browser binding -- scoped per
 * extension and per browser profile by Chrome's storage sandbox.
 */
export class ExtensionIdentity {
    /**
     * Get or create the Ed25519 identity keypair.
     * Returns the public key bytes and a sign function.
     *
     * Throws if Ed25519 is not supported by the browser.
     */
    static async getOrCreate() {
        const supported = await isEd25519Supported();
        if (!supported) {
            throw new Error('Ed25519 not supported by this browser (requires Chrome 113+)');
        }
        // Try to load existing keypair from storage.
        const stored = await ExtensionIdentity.loadFromStorage();
        if (stored) {
            return stored;
        }
        // Generate a new Ed25519 keypair.
        const keyPair = await crypto.subtle.generateKey('Ed25519', true, // extractable so we can export to JWK for storage
        ['sign', 'verify']);
        // Export private key as JWK for persistent storage.
        const privateJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
        // Export public key as raw bytes.
        const publicRaw = await crypto.subtle.exportKey('raw', keyPair.publicKey);
        const publicKeyBytes = new Uint8Array(publicRaw);
        // Store the JWK in chrome.storage.local.
        await chrome.storage.local.set({
            [STORAGE_KEY]: {
                privateJwk,
                publicKeyBase64: toBase64(publicKeyBytes),
            },
        });
        // Import back as non-extractable for signing (defense in depth).
        const signingKey = await crypto.subtle.importKey('jwk', privateJwk, 'Ed25519', false, ['sign']);
        return {
            publicKey: publicKeyBytes,
            sign: async (data) => {
                const sig = await crypto.subtle.sign('Ed25519', signingKey, data.buffer);
                return new Uint8Array(sig);
            },
        };
    }
    /**
     * Sign a handshake binding: SHA256(ephemeralPubKey || origin || SIGN_CONTEXT).
     * This binds the identity to the ephemeral session key, preventing replay.
     *
     * @param ephemeralPubKey - The ephemeral X25519 public key bytes.
     * @param origin - The extension origin (chrome-extension://ID/).
     * @returns The Ed25519 signature bytes.
     */
    static async signHandshake(ephemeralPubKey, origin) {
        const identity = await ExtensionIdentity.getOrCreate();
        // Build the binding message: ephemeralPubKey || UTF-8(origin) || UTF-8(SIGN_CONTEXT)
        const originBytes = encoder.encode(origin);
        const contextBytes = encoder.encode(SIGN_CONTEXT);
        const bindingMessage = new Uint8Array(ephemeralPubKey.length + originBytes.length + contextBytes.length);
        bindingMessage.set(ephemeralPubKey, 0);
        bindingMessage.set(originBytes, ephemeralPubKey.length);
        bindingMessage.set(contextBytes, ephemeralPubKey.length + originBytes.length);
        // Hash the binding message with SHA-256.
        const hashBuf = await crypto.subtle.digest('SHA-256', bindingMessage);
        const hashBytes = new Uint8Array(hashBuf);
        // Sign the hash with the Ed25519 identity key.
        return identity.sign(hashBytes);
    }
    /**
     * Get the raw public key bytes (for display/status).
     * Returns null if not yet created.
     */
    static async getPublicKey() {
        const result = await chrome.storage.local.get(STORAGE_KEY);
        const data = result[STORAGE_KEY];
        if (!data || !data.publicKeyBase64) {
            return null;
        }
        return fromBase64(data.publicKeyBase64);
    }
    /**
     * Reset the identity (for re-pairing). Deletes the stored keypair.
     */
    static async reset() {
        await chrome.storage.local.remove(STORAGE_KEY);
    }
    /**
     * Load the keypair from chrome.storage.local and return the public key
     * and a signing function. Returns null if no keypair is stored.
     */
    static async loadFromStorage() {
        const result = await chrome.storage.local.get(STORAGE_KEY);
        const data = result[STORAGE_KEY];
        if (!data || !data.privateJwk || !data.publicKeyBase64) {
            return null;
        }
        try {
            // Import the private key as non-extractable for signing.
            const signingKey = await crypto.subtle.importKey('jwk', data.privateJwk, 'Ed25519', false, ['sign']);
            const publicKeyBytes = fromBase64(data.publicKeyBase64);
            return {
                publicKey: publicKeyBytes,
                sign: async (rawData) => {
                    const sig = await crypto.subtle.sign('Ed25519', signingKey, rawData.buffer);
                    return new Uint8Array(sig);
                },
            };
        }
        catch (err) {
            // Stored key is corrupted or algorithm no longer supported.
            // Remove it and let getOrCreate generate a new one.
            console.warn('[xKey] Failed to load identity key, resetting:', err);
            await ExtensionIdentity.reset();
            return null;
        }
    }
}
//# sourceMappingURL=identity.js.map