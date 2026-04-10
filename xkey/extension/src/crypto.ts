// xKey AutoFill Extension - Session Encryption
//
// Implements X25519 ECDH key agreement + HKDF-SHA256 key derivation +
// AES-256-GCM authenticated encryption using the Web Crypto API.
//
// Protocol:
//   1. Both sides generate ephemeral X25519 keypairs.
//   2. Public keys are exchanged in the handshake.
//   3. ECDH shared secret is derived.
//   4. HKDF-SHA256 derives two directional AES-256-GCM keys:
//      - info="xkey-nativemsg-v1-send"
//      - info="xkey-nativemsg-v1-recv"
//   5. Direction is determined by lexicographic comparison of public keys.
//      The party with the lower public key uses "send" as their send key.
//   6. Nonces are monotonic 64-bit counters, encoded as 12-byte IVs
//      (8 bytes LE uint64 + 4 zero bytes).

const HKDF_SEND_INFO = 'xkey-nativemsg-v1-send';
const HKDF_RECV_INFO = 'xkey-nativemsg-v1-recv';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/**
 * Compare two Uint8Arrays lexicographically.
 * Returns negative if a < b, zero if equal, positive if a > b.
 */
function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    if (a[i] !== b[i]) {
      return a[i] - b[i];
    }
  }
  return a.length - b.length;
}

/** Encode bytes to base64 string. */
function toBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/** Decode base64 string to bytes. */
function fromBase64(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Build a 12-byte AES-GCM nonce from a uint64 counter.
 * Layout: [counter as 8-byte LE uint64] [4 zero bytes]
 */
function buildNonce(counter: number): Uint8Array {
  const buf = new ArrayBuffer(12);
  const view = new DataView(buf);
  // Write counter as little-endian uint64.
  // JavaScript numbers are safe up to 2^53-1, which is more than sufficient
  // for a session nonce counter.
  const lo = counter & 0xFFFFFFFF;
  const hi = Math.floor(counter / 0x100000000) & 0xFFFFFFFF;
  view.setUint32(0, lo, true);
  view.setUint32(4, hi, true);
  // Bytes 8-11 remain zero.
  return new Uint8Array(buf);
}

/**
 * Derive an AES-256-GCM key using HKDF-SHA256 from a shared secret.
 */
async function deriveKey(sharedSecret: ArrayBuffer, info: string): Promise<CryptoKey> {
  const hkdfKey = await crypto.subtle.importKey(
    'raw',
    sharedSecret,
    'HKDF',
    false,
    ['deriveKey'],
  );

  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(32), // 32 zero bytes
      info: encoder.encode(info),
    },
    hkdfKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

/**
 * SessionCrypto manages X25519 ECDH key exchange and AES-256-GCM
 * session encryption for the native messaging channel.
 *
 * Usage:
 *   const session = await SessionCrypto.create();
 *   // Send session.getPublicKeyBase64() to peer in handshake
 *   // Receive peer's public key
 *   await session.completeHandshake(peerPubKeyBase64);
 *   // Now encrypt/decrypt:
 *   const { nonce, ciphertext } = await session.encrypt('hello');
 *   const plaintext = await session.decrypt(nonce, ciphertext);
 */
export class SessionCrypto {
  private sendKey: CryptoKey | null = null;
  private recvKey: CryptoKey | null = null;
  // Nonces start at 1 to match the Go native host convention.
  // Go uses atomic.Uint64.Add(1) which pre-increments (first nonce = 1),
  // and its Decrypt rejects nonce <= last (last starts at 0, so nonce 0
  // is always rejected).
  private sendNonce: number = 1;
  private recvNonce: number = 1;
  private publicKeyBytes: Uint8Array;
  private privateKey: CryptoKey;
  private _ready: boolean = false;

  private constructor(privateKey: CryptoKey, publicKeyBytes: Uint8Array) {
    this.privateKey = privateKey;
    this.publicKeyBytes = publicKeyBytes;
  }

  /**
   * Factory method: generate an ephemeral X25519 keypair and return
   * a new SessionCrypto instance ready for handshake.
   */
  static async create(): Promise<SessionCrypto> {
    const keyPair = await crypto.subtle.generateKey(
      'X25519' as unknown as EcKeyGenParams,
      false,
      ['deriveBits'],
    ) as CryptoKeyPair;

    // Export the public key so we can send it and compare it.
    const pubRaw = await crypto.subtle.exportKey('raw', keyPair.publicKey);
    const pubBytes = new Uint8Array(pubRaw);

    return new SessionCrypto(keyPair.privateKey, pubBytes);
  }

  /**
   * Complete the handshake by performing ECDH with the peer's public key
   * and deriving directional session keys.
   *
   * After this call, encrypt() and decrypt() are available.
   */
  async completeHandshake(peerPubKeyBase64: string): Promise<void> {
    const peerPubBytes = fromBase64(peerPubKeyBase64);

    // Import peer's public key for ECDH.
    const peerPubKey = await crypto.subtle.importKey(
      'raw',
      peerPubBytes.buffer as ArrayBuffer,
      'X25519' as unknown as EcKeyImportParams,
      false,
      [],
    );

    // Derive the shared secret via ECDH.
    const sharedSecret = await crypto.subtle.deriveBits(
      { name: 'X25519', public: peerPubKey } as unknown as EcdhKeyDeriveParams,
      this.privateKey,
      256,
    );

    // Derive two directional keys.
    const keySend = await deriveKey(sharedSecret, HKDF_SEND_INFO);
    const keyRecv = await deriveKey(sharedSecret, HKDF_RECV_INFO);

    // Determine direction by lexicographic comparison of public keys.
    // The party with the lower public key uses the "send"-labeled key
    // as their send key. The party with the higher public key swaps.
    const cmp = compareBytes(this.publicKeyBytes, peerPubBytes);
    if (cmp < 0) {
      // Our key is lower: send = SEND label, recv = RECV label
      this.sendKey = keySend;
      this.recvKey = keyRecv;
    } else {
      // Our key is higher (or equal, which should not happen): swap
      this.sendKey = keyRecv;
      this.recvKey = keySend;
    }

    this.sendNonce = 1;
    this.recvNonce = 1;
    this._ready = true;
  }

  /**
   * Encrypt a plaintext string using AES-256-GCM with the next send nonce.
   * Returns the nonce value and the base64-encoded ciphertext.
   */
  async encrypt(plaintext: string): Promise<{ nonce: number; ciphertext: string }> {
    if (!this.sendKey) {
      throw new Error('SessionCrypto: handshake not completed');
    }

    const nonce = this.sendNonce;
    this.sendNonce++;

    const iv = buildNonce(nonce);
    const plaintextBytes = encoder.encode(plaintext);

    const ciphertextBuf = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv.buffer as ArrayBuffer },
      this.sendKey,
      plaintextBytes,
    );

    return {
      nonce,
      ciphertext: toBase64(new Uint8Array(ciphertextBuf)),
    };
  }

  /**
   * Decrypt a ciphertext received from the peer.
   *
   * Enforces monotonic nonce ordering for replay protection:
   * the received nonce must equal the expected receive counter.
   */
  async decrypt(nonce: number, ciphertextBase64: string): Promise<string> {
    if (!this.recvKey) {
      throw new Error('SessionCrypto: handshake not completed');
    }

    // Replay protection: nonces must arrive in strict order.
    if (nonce !== this.recvNonce) {
      throw new Error(
        `SessionCrypto: unexpected nonce ${nonce}, expected ${this.recvNonce}`,
      );
    }
    this.recvNonce++;

    const iv = buildNonce(nonce);
    const ciphertextBytes = fromBase64(ciphertextBase64);

    const plaintextBuf = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv.buffer as ArrayBuffer },
      this.recvKey,
      ciphertextBytes.buffer as ArrayBuffer,
    );

    return decoder.decode(plaintextBuf);
  }

  /** Get our public key as a base64 string (for the handshake message). */
  getPublicKeyBase64(): string {
    return toBase64(this.publicKeyBytes);
  }

  /** Whether the handshake is complete and encryption is available. */
  get ready(): boolean {
    return this._ready;
  }
}
