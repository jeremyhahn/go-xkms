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
 * SDK client singleton.
 *
 * The client is created once, up front — before login, because the login
 * views need it to run the passkey/PIV handshake. A static bearer token
 * therefore cannot be baked in at construction; instead a token *factory*
 * (`() => getValidAccessToken()`) is passed, which the SDK invokes lazily on
 * every request. After a successful login persists the access token, every
 * subsequent call automatically attaches `Authorization: Bearer <token>`,
 * pre-emptively refreshing within the skew window. Public endpoints run
 * before a token exists; the factory returns '' and the header is omitted.
 *
 * This is the single auth choke point for the SPA.
 */

import { XkmsClient, isWailsRuntime } from "@go-xkms/sdk";
import { getValidAccessToken } from "@go-xkms/svelte-auth";

let _client: XkmsClient | null = null;

// resolveBaseURL picks the API origin. In a browser the SPA is same-origin
// with the daemon. The Wails desktop shell (a later phase) will inject a
// remote URL or the standalone loopback URL before the app boots; until then
// it falls back to the page origin.
function resolveBaseURL(): string {
  if (typeof window === "undefined") {
    return "";
  }
  const injected = (window as unknown as { __XKMS_API_BASE_URL__?: string })
    .__XKMS_API_BASE_URL__;
  if (injected !== undefined && injected !== "") {
    return injected;
  }
  return window.location.origin;
}

/**
 * loopbackToken returns the desktop standalone per-launch token when the Wails
 * shell installed one, else "". A static loopback bearer is used directly
 * (never refreshed) — the engine accepts it only over 127.0.0.1.
 */
function loopbackToken(): string {
  if (typeof window === "undefined") {
    return "";
  }
  return (window as unknown as { __XKMS_LOOPBACK_TOKEN__?: string }).__XKMS_LOOPBACK_TOKEN__ ?? "";
}

/** getSDKClient returns the singleton XkmsClient, creating it on first use. */
export function getSDKClient(): XkmsClient {
  if (_client === null) {
    _client = new XkmsClient({
      baseURL: resolveBaseURL(),
      token: async (): Promise<string> => {
        // Desktop standalone: the loopback token wins and is sent verbatim.
        const lb = loopbackToken();
        if (lb !== "") {
          return lb;
        }
        return getValidAccessToken();
      },
    });
    // isWailsRuntime is referenced so the desktop bootstrap seam is documented
    // and the import is not flagged as unused.
    void isWailsRuntime();
  }
  return _client;
}

/** resetSDKClient clears the singleton (test isolation only). */
export function resetSDKClient(): void {
  _client = null;
}
