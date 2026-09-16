/**
 * Transport layer for detecting Wails desktop mode vs browser mode.
 *
 * In Wails mode the REST API is mounted in-process as the AssetServer handler
 * of the desktop app, same-origin with the frontend it serves. The Go backend
 * exposes a GetApiBaseUrl() binding that returns the base to prefix, which is
 * the empty string: there is no port to discover, no listener to reach and
 * therefore no credential to carry.
 *
 * In browser/web mode, relative URLs (/api/v1) are used so the browser
 * proxies through the same origin.
 *
 * Both modes end up calling fetch('/api/v1/...') against the window's own
 * origin.
 */

/** Returns true when running inside a Wails desktop window. */
export function isWailsAvailable(): boolean {
  return (
    typeof window !== 'undefined' &&
    (!!(window as any).runtime || !!(window as any).go)
  );
}

/** Returns the base URL for all API calls. */
export function getApiBaseUrl(): string {
  if (typeof window !== 'undefined' && (window as any).__API_BASE_URL__) {
    return (window as any).__API_BASE_URL__;
  }
  // Empty so admin-api.ts can use full paths. The admin server has routes at
  // both /admin/* and /api/v1/tenants/*. A server-hosted deployment may set
  // __API_BASE_URL__ to a prefix; the desktop app reports the empty string,
  // because the API shares the webview's origin.
  return '';
}

/**
 * Initialise the transport layer.
 *
 * When running inside Wails this calls the Go-side GetApiBaseUrl() binding and
 * stores the base every subsequent request is prefixed with.
 *
 * In browser mode this is a no-op.
 */
export async function initTransport(): Promise<void> {
  if (!isWailsAvailable()) {
    return;
  }

  try {
    const runtime = (window as any).runtime;
    if (runtime && typeof runtime.Call === 'function') {
      const baseUrl: string = await runtime.Call('main.App', 'GetApiBaseUrl');
      (window as any).__API_BASE_URL__ = baseUrl;
    }
  } catch (_e) {
    console.warn('Failed to get API base URL from Wails, using default');
  }
}
