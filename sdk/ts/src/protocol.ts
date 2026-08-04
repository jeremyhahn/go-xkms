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
export type HostKeyMode = 'confirm' | 'notify';

/** A server→client control frame. */
export type ServerControl =
  | { type: 'error'; message?: string | undefined }
  | { type: 'exit' }
  | {
      type: 'hostkey';
      host: string;
      key_type: string;
      fingerprint: string;
      known: boolean;
      mode: HostKeyMode;
    };

/** parseControl parses a TEXT control frame; returns null if not a known control. */
export function parseControl(data: string): ServerControl | null {
  let m: {
    type?: unknown;
    message?: unknown;
    host?: unknown;
    key_type?: unknown;
    fingerprint?: unknown;
    known?: unknown;
    mode?: unknown;
  };
  try {
    m = JSON.parse(data) as typeof m;
  } catch {
    return null;
  }
  if (!m || typeof m.type !== 'string') {
    return null;
  }
  if (m.type === 'error') {
    return { type: 'error', message: typeof m.message === 'string' ? m.message : undefined };
  }
  if (m.type === 'exit') {
    return { type: 'exit' };
  }
  if (m.type === 'hostkey') {
    if (
      typeof m.host !== 'string' ||
      typeof m.key_type !== 'string' ||
      typeof m.fingerprint !== 'string' ||
      typeof m.known !== 'boolean'
    ) {
      return null;
    }
    // Fail-closed: an unrecognized or missing mode must never be treated as
    // merely informational — default to "confirm" so the caller always gets
    // a chance to reject an unverified host key.
    const mode: HostKeyMode = m.mode === 'confirm' || m.mode === 'notify' ? m.mode : 'confirm';
    return {
      type: 'hostkey',
      host: m.host,
      key_type: m.key_type,
      fingerprint: m.fingerprint,
      known: m.known,
      mode,
    };
  }
  return null;
}

/** encodeResize renders a client→server resize control frame. */
export function encodeResize(rows: number, cols: number): string {
  return JSON.stringify({ type: 'resize', rows, cols });
}

/** encodeHostKeyResponse renders a client→server hostkey-response control frame. */
export function encodeHostKeyResponse(accept: boolean): string {
  return JSON.stringify({ type: 'hostkey-response', accept });
}
