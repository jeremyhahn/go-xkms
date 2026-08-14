// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

/**
 * Desktop (Wails) bootstrap. When the SPA runs inside the Wails shell, the
 * shell binds a `bridge` object exposing GetConnection(), which reports the
 * engine's base URL and — in standalone mode — the per-launch loopback token.
 *
 * This module reads that connection before the app mounts and:
 *   - points the SDK client at the engine (window.__XKMS_API_BASE_URL__), and
 *   - in standalone mode, installs the loopback token as a static bearer and
 *     flips the auth store to authenticated, so the desktop owner lands
 *     directly on the console without a login ceremony.
 *
 * In a plain browser (no Wails runtime) it is a no-op.
 */

import { isWailsRuntime } from "@go-xkms/sdk";
import { setAuthenticated } from "@go-xkms/svelte-auth";

interface DesktopConnection {
  mode: "remote" | "standalone";
  base_url: string;
  token?: string;
}

// window globals the SPA consults for the engine URL and loopback token.
declare global {
  interface Window {
    __XKMS_API_BASE_URL__?: string;
    __XKMS_LOOPBACK_TOKEN__?: string;
    go?: {
      main?: {
        bridge?: { GetConnection: () => Promise<string> | string };
      };
    };
  }
}

/**
 * bootstrapDesktop resolves the Wails connection and configures the SPA. It
 * returns true when a standalone loopback session was established (the app
 * can skip the login screen), false otherwise.
 */
export async function bootstrapDesktop(): Promise<boolean> {
  if (!isWailsRuntime()) {
    return false;
  }
  const bridge = window.go?.main?.bridge;
  if (!bridge) {
    return false;
  }

  let conn: DesktopConnection;
  try {
    const raw = await bridge.GetConnection();
    conn = JSON.parse(raw) as DesktopConnection;
  } catch {
    return false;
  }

  if (conn.base_url) {
    window.__XKMS_API_BASE_URL__ = conn.base_url;
  }

  if (conn.mode === "standalone" && conn.token) {
    // The loopback token is a static bearer accepted only over 127.0.0.1;
    // stash it for the SDK token factory and mark the session authenticated.
    window.__XKMS_LOOPBACK_TOKEN__ = conn.token;
    setAuthenticated({ access_token: conn.token });
    return true;
  }

  return false;
}
