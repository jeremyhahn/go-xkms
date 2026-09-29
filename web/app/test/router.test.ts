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
import { parseHash } from "../src/stores/router.svelte.ts";

describe("parseHash", () => {
  it("maps the root and empty hash to the dashboard", () => {
    expect(parseHash("").name).toBe("dashboard");
    expect(parseHash("#").name).toBe("dashboard");
    expect(parseHash("#/").name).toBe("dashboard");
    expect(parseHash("#/dashboard").name).toBe("dashboard");
  });

  it("maps every known static route", () => {
    const cases: Array<[string, string]> = [
      ["#/login", "login"],
      ["#/backends", "backends"],
      ["#/keys", "keys"],
      ["#/certs", "certificates"],
      ["#/certificates", "certificates"],
      ["#/ca", "ca"],
      ["#/barrier", "barrier"],
      ["#/tenants", "tenants"],
      ["#/custodians", "custodians"],
      ["#/shares", "shares"],
      ["#/pin", "pin"],
      ["#/piv", "piv"],
      ["#/ssh", "ssh"],
      ["#/passwords", "passwords"],
      ["#/platform", "platform"],
      ["#/tpm/policies", "tpmPolicies"],
      ["#/users", "users"],
      ["#/cluster", "cluster"],
      ["#/ceremony", "ceremony"],
      ["#/settings", "settings"],
    ];
    for (const [hash, name] of cases) {
      expect(parseHash(hash).name, hash).toBe(name);
    }
  });

  it("returns not-found for unknown paths", () => {
    expect(parseHash("#/does-not-exist").name).toBe("not-found");
    expect(parseHash("#/keys/extra/segments").name).toBe("not-found");
  });

  it("preserves the original hash on the route", () => {
    expect(parseHash("#/backends").hash).toBe("#/backends");
  });
});
