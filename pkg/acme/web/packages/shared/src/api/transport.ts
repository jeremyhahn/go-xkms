/**
 * Transport layer for detecting Wails desktop mode vs browser mode.
 *
 * In Wails mode, an embedded HTTP server runs on a dynamic port and the
 * Go backend exposes a GetApiBaseUrl() binding so the frontend can discover it.
 *
 * In browser/web mode, relative URLs (/api/v1) are used so the browser
 * proxies through the same origin.
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
  // In browser mode, return empty string so admin-api.ts can use full paths.
  // The admin server has routes at both /admin/* and /api/v1/tenants/*.
  // Wails desktop mode sets __API_BASE_URL__ via the Go binding.
  return '';
}

/**
 * Initialise the transport layer.
 *
 * When running inside Wails this calls the Go-side GetApiBaseUrl() binding
 * and stores the result so that every subsequent fetch uses the correct
 * embedded server port.
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
