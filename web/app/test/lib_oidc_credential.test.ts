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

import { describe, it, expect } from "vitest";
import type { OIDCCredential } from "@go-xkms/sdk";
import {
  CodexAuthParseError,
  PROVIDER_TEMPLATES,
  fmtTime,
  needsAttention,
  parseCodexAuthJson,
  parseScopes,
  providerLabel,
  refKey,
  refOf,
  statusView,
  templateFor,
} from "../src/lib/oidcCredential.ts";

function credential(over: Partial<OIDCCredential> = {}): OIDCCredential {
  return {
    scope: "tenant",
    name: "codex",
    config: { template: "openai" },
    status: "active",
    refreshable: true,
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
    ...over,
  };
}

describe("parseCodexAuthJson", () => {
  it("reads the access, refresh and ID tokens of a codex auth.json and ignores the rest", () => {
    const text = JSON.stringify({
      OPENAI_API_KEY: null,
      tokens: { id_token: "it", access_token: "at", refresh_token: "rt", account_id: "acct" },
      last_refresh: "2026-01-01T00:00:00Z",
    });
    expect(parseCodexAuthJson(text)).toEqual({ access_token: "at", refresh_token: "rt", id_token: "it" });
  });

  it("omits optional tokens the file does not carry", () => {
    expect(parseCodexAuthJson('{"tokens":{"access_token":"at","refresh_token":""}}')).toEqual({ access_token: "at" });
  });

  it.each([
    ["not JSON", "{tokens:", /Not valid JSON/],
    ["a JSON array", "[]", /expected a JSON object/],
    ["an API-key login", '{"OPENAI_API_KEY":"sk-x","tokens":null}', /no tokens/],
    ["tokens without an access token", '{"tokens":{"refresh_token":"secret-refresh"}}', /no access_token/],
  ])("rejects %s with a message that never echoes the input", (_, text, pattern) => {
    let err: unknown;
    try {
      parseCodexAuthJson(text);
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(CodexAuthParseError);
    expect((err as Error).message).toMatch(pattern);
    expect((err as Error).message).not.toContain("sk-x");
    expect((err as Error).message).not.toContain("secret-refresh");
  });
});

describe("templates", () => {
  it("offers device login for openai, import only for anthropic, and never aws", () => {
    expect(templateFor("openai").methods).toEqual(["device", "import"]);
    expect(templateFor("anthropic").methods).toEqual(["import"]);
    expect(PROVIDER_TEMPLATES.some((t) => t.id === "aws")).toBe(false);
  });

  it("asks issuer-less providers only for a client ID, and falls back to custom for unknown ids", () => {
    expect(templateFor("google")).toMatchObject({ needsIssuer: false, needsClientId: true });
    expect(templateFor("keycloak")).toMatchObject({ needsIssuer: true, needsClientId: true });
    expect(templateFor("nope").id).toBe("");
    expect(templateFor(undefined).id).toBe("");
  });

  it("labels a credential by its template, else by its issuer", () => {
    expect(providerLabel(credential())).toBe("OpenAI (ChatGPT / codex)");
    expect(providerLabel(credential({ config: { issuer: "https://idp.example.com" } }))).toBe("https://idp.example.com");
    expect(providerLabel(credential({ config: {} }))).toBe("Custom");
  });
});

describe("status", () => {
  it("flags relogin_required and expired as errors needing attention", () => {
    expect(statusView("relogin_required")).toEqual({ label: "re-login required", kind: "error" });
    expect(statusView("expired")).toEqual({ label: "expired", kind: "error" });
    expect(statusView("active").kind).toBe("success");
    expect(statusView("pending").kind).toBe("info");
    expect(needsAttention("relogin_required")).toBe(true);
    expect(needsAttention("pending")).toBe(false);
  });

  it("renders an unknown status as a warning rather than crashing", () => {
    expect(statusView("revoked" as never)).toEqual({ label: "revoked", kind: "warning" });
  });
});

describe("references and formatting", () => {
  it("strips a credential down to its reference and keys personal ones by owner", () => {
    const c = credential({ tenant_id: "t1", scope: "user", owner: "alice", name: "mine" });
    expect(refOf(c)).toEqual({ tenant_id: "t1", scope: "user", owner: "alice", name: "mine" });
    expect(refKey(c)).not.toBe(refKey({ ...c, owner: "bob" }));
  });

  it("splits scopes on spaces and commas and formats absent times as a dash", () => {
    expect(parseScopes(" openid, profile  email ")).toEqual(["openid", "profile", "email"]);
    expect(parseScopes("")).toEqual([]);
    expect(fmtTime(undefined)).toBe("—");
    expect(fmtTime("2026-01-01T00:00:00Z")).not.toBe("—");
  });
});
