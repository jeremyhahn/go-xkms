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

// Deployment capabilities (GET /api/v1/capabilities), read once per page
// load. Ruling 972 (1): no console view may lead to a 501 / "not configured"
// state, so each view whose routes a subsystem serves is gated on that
// subsystem's flag (ROUTE_CAPABILITY) and shows SUBSYSTEM_OFF instead.
// The server computes each flag from the same predicate its route table
// gates the routes with (pkg/api/rest/handlers_capabilities.go).

import { getSDKClient } from "./sdkClient.ts";

export type CapabilityFlag =
  | "ca_enabled"
  | "ssh_enabled"
  | "tenants_enabled"
  | "passwords_enabled"
  | "webauthn_enabled";

/** Disabled state of each gated subsystem: what is off and how to turn it on. */
export const SUBSYSTEM_OFF: Readonly<Record<CapabilityFlag, { title: string; setting: string }>> = {
  ca_enabled: {
    title: "The certificate authority is off on this server.",
    setting: "Add a ca: section to xkmsd.yaml and restart xkmsd.",
  },
  ssh_enabled: {
    title: "SSH key management is off on this server.",
    setting: "xkmsd composes the SSH store from its storage (DAO factory); configure storage in xkmsd.yaml.",
  },
  tenants_enabled: {
    title: "Tenant management is off on this server.",
    setting: "xkmsd needs the embedded node's barrier registry (node: in xkmsd.yaml).",
  },
  passwords_enabled: {
    title: "The password store is off on this server.",
    setting: "xkmsd composes the password store from its storage (DAO factory); configure storage in xkmsd.yaml.",
  },
  webauthn_enabled: {
    title: "Passkeys are off on this server.",
    setting: "Set webauthn.enabled: true in xkmsd.yaml.",
  },
};

/** Router name -> the capability flag its view's routes need. */
export const ROUTE_CAPABILITY: Readonly<Record<string, CapabilityFlag>> = {
  ca: "ca_enabled",
  caTcg: "ca_enabled",
  ssh: "ssh_enabled",
  sshTrust: "ssh_enabled",
  sshSign: "ssh_enabled",
  sshKeyImport: "ssh_enabled",
  tenants: "tenants_enabled",
  tenantDetail: "tenants_enabled",
  tenantQuotas: "tenants_enabled",
  tenantEntitlements: "tenants_enabled",
  // Lists tenants to pick one (GET /api/v1/tenants/).
  tenantTpm: "tenants_enabled",
  passwords: "passwords_enabled",
  passwordAccessMode: "passwords_enabled",
  // POST /api/v1/webauthn/credentials/begin.
  addPasskey: "webauthn_enabled",
};

export const capabilitiesStore = $state<{ caps: Record<string, unknown> | null; loaded: boolean }>({
  caps: null,
  loaded: false,
});

let inflight: Promise<void> | null = null;

/**
 * Reads the capabilities once; later calls share the first read. A failed
 * probe disables nothing (caps stays null): it must not lock the operator
 * out of every view.
 */
export function loadCapabilities(): Promise<void> {
  if (inflight) return inflight;
  inflight = (async () => {
    try {
      capabilitiesStore.caps = (await getSDKClient().capabilities.get()) as Record<string, unknown>;
    } catch {
      capabilitiesStore.caps = null;
    }
    capabilitiesStore.loaded = true;
  })();
  return inflight;
}

/** Test hook: forget the read so the next load probes again. */
export function resetCapabilities(): void {
  inflight = null;
  capabilitiesStore.caps = null;
  capabilitiesStore.loaded = false;
}

/** The flag that gates a route, when the server reports it explicitly false. */
export function routeOffFlag(route: string): CapabilityFlag | null {
  const flag = ROUTE_CAPABILITY[route];
  if (!flag) return null;
  const caps = capabilitiesStore.caps;
  return caps !== null && caps[flag] === false ? flag : null;
}

export function routeOff(route: string): boolean {
  return routeOffFlag(route) !== null;
}

/** True when a gated route must wait for the capabilities read. */
export function routePending(route: string): boolean {
  return ROUTE_CAPABILITY[route] !== undefined && !capabilitiesStore.loaded;
}
