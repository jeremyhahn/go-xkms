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

import type { RouteName } from "$stores/router.svelte.ts";

/** A single sidebar entry. */
export interface NavItem {
  route: RouteName;
  path: string;
  label: string;
  icon: string;
  /** RBAC gate: hidden unless the session holds resource:action. */
  requires?: { resource: string; action: string };
  /** Capability gate: hidden unless the server wired this subsystem. */
  capability?: string;
}

/** A labeled group of nav items. */
export interface NavSection {
  heading: string;
  items: NavItem[];
}

// navSections is the full navigation model. Icon names are lucide-svelte
// component keys resolved in Sidebar.svelte. requires/capability drive
// hiding; the server remains the enforcement authority.
export const navSections: NavSection[] = [
  {
    heading: "Overview",
    items: [
      { route: "dashboard", path: "/dashboard", label: "Dashboard", icon: "LayoutDashboard" },
      { route: "backends", path: "/backends", label: "Backends", icon: "Server", requires: { resource: "backends", action: "list" } },
    ],
  },
  {
    heading: "Keys & Crypto",
    items: [
      { route: "keys", path: "/keys", label: "Keys", icon: "Key", requires: { resource: "keys", action: "list" } },
      { route: "frost", path: "/frost", label: "FROST", icon: "Snowflake", capability: "frost", requires: { resource: "keys", action: "list" } },
      { route: "tpmPolicies", path: "/tpm/policies", label: "TPM Policies", icon: "ShieldCheck", capability: "tpm_policies" },
    ],
  },
  {
    heading: "Certificates & CA",
    items: [
      { route: "certificates", path: "/certs", label: "Certificates", icon: "FileBadge", requires: { resource: "certs", action: "list" } },
      { route: "ca", path: "/ca", label: "Certificate Authority", icon: "Landmark", capability: "ca" },
      { route: "caTcg", path: "/ca/tcg", label: "TCG Certificates", icon: "Fingerprint", capability: "ca", requires: { resource: "certs", action: "issue" } },
    ],
  },
  {
    heading: "Security",
    items: [
      { route: "pin", path: "/pin", label: "PIN", icon: "KeyRound", requires: { resource: "pin", action: "read" } },
      { route: "piv", path: "/piv", label: "PIV", icon: "CreditCard", requires: { resource: "piv", action: "read" } },
      { route: "ssh", path: "/ssh", label: "SSH", icon: "TerminalSquare", capability: "ssh", requires: { resource: "ssh", action: "read" } },
      { route: "passwords", path: "/passwords", label: "Passwords", icon: "Vault", capability: "passwords", requires: { resource: "passwords", action: "read" } },
      { route: "oidcCredentials", path: "/oidc/credentials", label: "OIDC Credentials", icon: "LogIn", capability: "oidc_credentials", requires: { resource: "oidc_credentials", action: "list" } },
      { route: "platform", path: "/platform", label: "Platform Secrets", icon: "FolderLock", capability: "platform" },
    ],
  },
  {
    heading: "Identity & Access",
    items: [
      { route: "users", path: "/users", label: "Users", icon: "Users", requires: { resource: "users", action: "list" } },
      { route: "tenants", path: "/tenants", label: "Tenants", icon: "Building2", capability: "tenants", requires: { resource: "tenants", action: "list" } },
    ],
  },
  {
    heading: "Settings",
    items: [
      { route: "settings", path: "/settings", label: "Settings", icon: "Settings" },
    ],
  },
];
