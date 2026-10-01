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
 * Helpers for server-side OIDC credentials in the console: the provider
 * templates the create dialog offers, a credential's status badge, and the
 * client-side parse of a codex CLI auth.json into importable tokens.
 */

import type {
  OIDCCredential,
  OIDCCredentialRef,
  OIDCCredentialStatus,
  OIDCCredentialTokens,
} from "@go-xkms/sdk";

/** How a credential's login is obtained. */
export type LoginMethod = "device" | "import";

/** A provider template the create dialog offers (pkg/oidc BuiltinTemplates). */
export interface ProviderTemplate {
  /** The config.template value; "" is a custom OIDC provider. */
  id: string;
  label: string;
  /** Login methods the provider supports, preferred first. */
  methods: LoginMethod[];
  /** The provider has no fixed issuer: the dialog asks for one. */
  needsIssuer: boolean;
  /** The provider has no public client: the dialog asks for a client ID. */
  needsClientId: boolean;
  /** The provider's login is a codex CLI auth.json that can be pasted. */
  codexAuthJson: boolean;
  /** One line of guidance shown under the picker. */
  hint: string;
}

/**
 * PROVIDER_TEMPLATES are the templates a console user can create a credential
 * from. aws is absent: it is an xkey-local login, not a server credential.
 */
export const PROVIDER_TEMPLATES: ProviderTemplate[] = [
  {
    id: "openai",
    label: "OpenAI (ChatGPT / codex)",
    methods: ["device", "import"],
    needsIssuer: false,
    needsClientId: false,
    codexAuthJson: true,
    hint: "Log in with a device code, or import the tokens of a codex auth.json. Refresh tokens rotate on use.",
  },
  {
    id: "anthropic",
    label: "Anthropic (Claude Code token)",
    methods: ["import"],
    needsIssuer: false,
    needsClientId: false,
    codexAuthJson: false,
    hint: "Import the one-year token `claude setup-token` prints. It is never refreshed: replace it before it expires.",
  },
  {
    id: "google",
    label: "Google",
    methods: ["device", "import"],
    needsIssuer: false,
    needsClientId: true,
    codexAuthJson: false,
    hint: "Needs an OAuth client of your Google Cloud project.",
  },
  {
    id: "microsoft",
    label: "Microsoft Entra ID",
    methods: ["device", "import"],
    needsIssuer: false,
    needsClientId: true,
    codexAuthJson: false,
    hint: "Needs an app registration's client ID.",
  },
  {
    id: "okta",
    label: "Okta",
    methods: ["device", "import"],
    needsIssuer: true,
    needsClientId: true,
    codexAuthJson: false,
    hint: "Needs your Okta issuer URL and an app's client ID.",
  },
  {
    id: "auth0",
    label: "Auth0",
    methods: ["device", "import"],
    needsIssuer: true,
    needsClientId: true,
    codexAuthJson: false,
    hint: "Needs your Auth0 tenant's issuer URL and an application's client ID.",
  },
  {
    id: "keycloak",
    label: "Keycloak",
    methods: ["device", "import"],
    needsIssuer: true,
    needsClientId: true,
    codexAuthJson: false,
    hint: "Needs the realm's issuer URL and a client ID.",
  },
  {
    id: "",
    label: "Custom OIDC provider",
    methods: ["device", "import"],
    needsIssuer: true,
    needsClientId: true,
    codexAuthJson: false,
    hint: "Endpoints are discovered from the issuer.",
  },
];

/** templateFor returns the template of a config.template value (custom when unknown). */
export function templateFor(id: string | undefined): ProviderTemplate {
  return (
    PROVIDER_TEMPLATES.find((t) => t.id === (id ?? "")) ??
    PROVIDER_TEMPLATES[PROVIDER_TEMPLATES.length - 1]!
  );
}

/** providerLabel names a credential's provider for the list. */
export function providerLabel(c: OIDCCredential): string {
  const template = c.config.template ?? "";
  if (template !== "") return templateFor(template).label;
  return c.config.issuer ?? "Custom";
}

/** A status badge: its label and StatusBadge kind. */
export interface StatusView {
  label: string;
  kind: "success" | "warning" | "error" | "info";
}

const STATUS_VIEWS: Record<OIDCCredentialStatus, StatusView> = {
  active: { label: "active", kind: "success" },
  pending: { label: "pending login", kind: "info" },
  relogin_required: { label: "re-login required", kind: "error" },
  expired: { label: "expired", kind: "error" },
};

/** statusView returns the badge of a credential status. */
export function statusView(status: OIDCCredentialStatus): StatusView {
  return STATUS_VIEWS[status] ?? { label: status, kind: "warning" };
}

/** needsAttention reports a status a person must act on: a fresh login or tokens. */
export function needsAttention(status: OIDCCredentialStatus): boolean {
  return status === "relogin_required" || status === "expired";
}

/** refOf returns the reference naming a listed credential. */
export function refOf(c: OIDCCredentialRef): OIDCCredentialRef {
  return { tenant_id: c.tenant_id, scope: c.scope, owner: c.owner, name: c.name };
}

/** refKey is a stable key for a credential in a keyed each block. */
export function refKey(c: OIDCCredentialRef): string {
  return `${c.tenant_id ?? ""}/${c.scope}/${c.owner ?? ""}/${c.name}`;
}

/** CodexAuthParseError is thrown when pasted text is not a usable codex auth.json. */
export class CodexAuthParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CodexAuthParseError";
  }
}

function stringField(obj: Record<string, unknown>, key: string): string | undefined {
  const value = obj[key];
  return typeof value === "string" && value !== "" ? value : undefined;
}

/**
 * parseCodexAuthJson reads the tokens of a codex CLI auth.json
 * ({"tokens": {"access_token", "refresh_token", "id_token", ...}}). It runs
 * in the browser only: the file's text is never sent or logged as a whole,
 * and the error messages never echo it.
 */
export function parseCodexAuthJson(text: string): OIDCCredentialTokens {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new CodexAuthParseError("Not valid JSON: paste the whole auth.json file.");
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new CodexAuthParseError("Not a codex auth.json: expected a JSON object.");
  }
  const tokens = (parsed as Record<string, unknown>).tokens;
  if (tokens === null || typeof tokens !== "object" || Array.isArray(tokens)) {
    throw new CodexAuthParseError(
      "No ChatGPT login in this auth.json: it has no tokens (an API-key login cannot be imported).",
    );
  }
  const fields = tokens as Record<string, unknown>;
  const accessToken = stringField(fields, "access_token");
  if (accessToken === undefined) {
    throw new CodexAuthParseError("This auth.json has no access_token.");
  }
  const result: OIDCCredentialTokens = { access_token: accessToken };
  const refreshToken = stringField(fields, "refresh_token");
  if (refreshToken !== undefined) result.refresh_token = refreshToken;
  const idToken = stringField(fields, "id_token");
  if (idToken !== undefined) result.id_token = idToken;
  return result;
}

/** parseScopes splits a space- or comma-separated scope list. */
export function parseScopes(text: string): string[] {
  return text.split(/[\s,]+/).filter((s) => s !== "");
}

/** fmtTime renders an RFC 3339 timestamp for the list ("—" when absent). */
export function fmtTime(ts: string | undefined): string {
  return ts === undefined || ts === "" ? "—" : new Date(ts).toLocaleString();
}
