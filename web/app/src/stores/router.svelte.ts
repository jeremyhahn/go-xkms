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
 * Minimal hash-based SPA router. Parses window.location.hash into a reactive
 * route object with no external dependency, so one bundle works identically
 * when served at /ui/ (daemon) or / (Wails desktop).
 */

export type RouteName =
  | "dashboard"
  | "login"
  | "register"
  | "backends"
  | "keys"
  | "certificates"
  | "ca"
  | "tenants"
  | "pin"
  | "piv"
  | "ssh"
  | "passwords"
  | "oidcCredentials"
  | "platform"
  | "tpmPolicies"
  | "users"
  | "frost"
  | "tenantDetail"
  | "settings"
  | "not-found";

export interface Route {
  name: RouteName;
  params: Record<string, string>;
  hash: string;
}

// staticRoutes maps an exact hash path to a route name. Parameterised routes
// (none yet in this phase) would be matched separately below.
const staticRoutes: Record<string, RouteName> = {
  "/": "dashboard",
  "/dashboard": "dashboard",
  "/login": "login",
  "/register": "register",
  "/backends": "backends",
  "/keys": "keys",
  "/certs": "certificates",
  "/certificates": "certificates",
  "/ca": "ca",
  "/tenants": "tenants",
  "/pin": "pin",
  "/piv": "piv",
  "/ssh": "ssh",
  "/passwords": "passwords",
  "/oidc/credentials": "oidcCredentials",
  "/platform": "platform",
  "/tpm/policies": "tpmPolicies",
  "/users": "users",
  "/frost": "frost",
  "/tenants/detail": "tenantDetail",
  "/settings": "settings",
};

export function parseHash(hash: string): Route {
  const path = hash.replace(/^#/, "") || "/";
  const name = staticRoutes[path];
  if (name !== undefined) {
    return { name, params: {}, hash };
  }
  return { name: "not-found", params: {}, hash };
}

// Reactive routerStore uses the module-scope `let x = $state(...)` + getter
// pattern. This is the cross-module reactivity shape that reliably propagates
// template updates in Svelte 5.55 — exporting a `$state` proxy directly does
// not re-render consumers in other modules.
const initial = parseHash(
  typeof window !== "undefined" ? window.location.hash : "#/dashboard",
);
let _name = $state<RouteName>(initial.name);
let _params = $state<Record<string, string>>(initial.params);
let _hash = $state<string>(initial.hash);

export const routerStore = {
  get name(): RouteName {
    return _name;
  },
  get params(): Record<string, string> {
    return _params;
  },
  get hash(): string {
    return _hash;
  },
};

if (typeof window !== "undefined") {
  window.addEventListener("hashchange", () => {
    const next = parseHash(window.location.hash);
    _name = next.name;
    _params = next.params;
    _hash = next.hash;
  });
}

/** Navigate to a hash path, e.g. navigateTo('/backends'). */
export function navigateTo(path: string): void {
  const hash = path.startsWith("#") ? path : `#${path}`;
  if (typeof window !== "undefined") {
    window.location.hash = hash;
  }
}
