/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
 *
 * This file is part of go-xkms.
 *
 * go-xkms is dual-licensed:
 *
 * 1. GNU Affero General Public License v3.0 (AGPL-3.0)
 *    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
 *
 * 2. Commercial License
 *    Contact licensing@automatethethings.com for commercial licensing options.
 */

// Ruling 972 (1): no console view may lead to a 501 / "not configured"
// state, so each view whose routes a subsystem serves is gated on that
// subsystem's flag (ROUTE_CAPABILITY) and shows SUBSYSTEM_OFF instead.
// The flags are the session's /auth/me capabilities map, which the server
// computes from the same guards its route table uses (capabilityFlags in
// pkg/api/rest/handlers_auth.go). The public /api/v1/capabilities carries
// only login-page flags, so an anonymous caller cannot fingerprint which
// subsystems the deployment wired.

import { sessionStore } from "./session.svelte.ts";

export type CapabilityFlag = "ca" | "ssh" | "tenants" | "passwords" | "webauthn" | "frost";

/** Disabled state of each gated subsystem: what is off and how to turn it on. */
export const SUBSYSTEM_OFF: Readonly<Record<CapabilityFlag, { title: string; setting: string }>> = {
  ca: {
    title: "The certificate authority is off on this server.",
    setting: "Add a ca: section to xkmsd.yaml and restart xkmsd.",
  },
  ssh: {
    title: "SSH key management is off on this server.",
    setting: "xkmsd composes the SSH store from its storage (DAO factory); configure storage in xkmsd.yaml.",
  },
  tenants: {
    title: "Tenant management is off on this server.",
    setting: "xkmsd needs the embedded node's barrier registry (node: in xkmsd.yaml).",
  },
  passwords: {
    title: "The password store is off on this server.",
    setting: "xkmsd composes the password store from its storage (DAO factory); configure storage in xkmsd.yaml.",
  },
  webauthn: {
    title: "Passkeys are off on this server.",
    setting: "Set webauthn.enabled: true in xkmsd.yaml.",
  },
  frost: {
    title: "FROST threshold signing is not in this xkmsd build.",
    setting: "Rebuild xkmsd with -tags frost (the default build serves no FROST routes).",
  },
};

/** Router name -> the capability flag its view's routes need. */
export const ROUTE_CAPABILITY: Readonly<Record<string, CapabilityFlag>> = {
  ca: "ca",
  caTcg: "ca",
  ssh: "ssh",
  sshTrust: "ssh",
  sshSign: "ssh",
  sshKeyImport: "ssh",
  tenants: "tenants",
  tenantDetail: "tenants",
  tenantQuotas: "tenants",
  tenantEntitlements: "tenants",
  // Lists tenants to pick one (GET /api/v1/tenants/).
  tenantTpm: "tenants",
  passwords: "passwords",
  passwordAccessMode: "passwords",
  // POST /api/v1/webauthn/credentials/begin.
  addPasskey: "webauthn",
  // The !frost build answers the FROST routes with 501 (handlers_frost_stub.go).
  frost: "frost",
  frostKeyImport: "frost",
};

/** The flag that gates a route, when the session reports it explicitly false. */
export function routeOffFlag(route: string): CapabilityFlag | null {
  const flag = ROUTE_CAPABILITY[route];
  if (!flag) return null;
  const me = sessionStore.me;
  return me !== null && me.capabilities?.[flag] === false ? flag : null;
}

export function routeOff(route: string): boolean {
  return routeOffFlag(route) !== null;
}

/**
 * True when a gated route must wait for the session. A failed session load
 * holds nothing: it must not lock the operator out of every view.
 */
export function routePending(route: string): boolean {
  return ROUTE_CAPABILITY[route] !== undefined && sessionStore.me === null && sessionStore.error === null;
}
