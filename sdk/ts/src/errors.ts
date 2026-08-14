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
export interface ErrorEnvelope {
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
export class XkmsApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly correlationId: string | undefined;
  /** The parsed error envelope, when the body was JSON. */
  readonly envelope: ErrorEnvelope | undefined;

  constructor(
    status: number,
    code: string,
    message: string,
    correlationId?: string,
    envelope?: ErrorEnvelope,
  ) {
    super(message);
    this.name = 'XkmsApiError';
    this.status = status;
    this.code = code;
    this.correlationId = correlationId;
    this.envelope = envelope;
  }
}

/**
 * XkmsNetworkError is thrown when the request never produced an HTTP
 * response (DNS failure, refused connection, aborted fetch, CORS block).
 */
export class XkmsNetworkError extends Error {
  readonly cause2: unknown;

  constructor(message: string, cause?: unknown) {
    super(message);
    this.name = 'XkmsNetworkError';
    this.cause2 = cause;
  }
}

/**
 * parseErrorEnvelope maps a failed HTTP response body to an XkmsApiError.
 * Tolerates non-JSON bodies (proxies, HTML error pages).
 */
export function parseErrorEnvelope(
  status: number,
  statusText: string,
  bodyText: string,
  correlationId?: string,
): XkmsApiError {
  let envelope: ErrorEnvelope | undefined;
  if (bodyText) {
    try {
      const parsed = JSON.parse(bodyText) as unknown;
      if (parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)) {
        envelope = parsed as ErrorEnvelope;
      }
    } catch {
      // Non-JSON body; fall through to the status-only error.
    }
  }
  const code =
    envelope && typeof envelope.error === 'string' && envelope.error !== ''
      ? envelope.error
      : `http_${status}`;
  const message =
    (envelope && typeof envelope.message === 'string' && envelope.message !== ''
      ? envelope.message
      : undefined) ??
    (envelope && typeof envelope.error === 'string' && envelope.error !== ''
      ? envelope.error
      : undefined) ??
    (statusText || `request failed with status ${status}`);
  return new XkmsApiError(status, code, message, correlationId, envelope);
}
