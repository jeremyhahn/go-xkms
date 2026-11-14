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
      { route: "frostSigning", path: "/frost/sign", label: "FROST Signing", icon: "Snowflake", capability: "frost", requires: { resource: "keys", action: "sign" } },
      { route: "dashboard", path: "/dashboard", label: "Dashboard", icon: "LayoutDashboard" },
      { route: "trustBundle", path: "/trust/bundle", label: "Trust Bundle", icon: "ShieldCheck" },
      { route: "backends", path: "/backends", label: "Backends", icon: "Server", requires: { resource: "backends", action: "list" } },
      { route: "systemHealth", path: "/system/health", label: "System Health", icon: "Network" },
    ],
  },
  {
    heading: "Keys & Crypto",
    items: [
      { route: "frostKeyImport", path: "/frost/import", label: "FROST Key Import", icon: "Snowflake", capability: "frost", requires: { resource: "keys", action: "import" } },
      { route: "keys", path: "/keys", label: "Keys", icon: "Key", requires: { resource: "keys", action: "list" } },
      { route: "keyVersions", path: "/keys/versions", label: "Key Versions", icon: "Split", requires: { resource: "keys", action: "list" } },
      { route: "frost", path: "/frost", label: "FROST", icon: "Snowflake", capability: "frost", requires: { resource: "keys", action: "list" } },
      { route: "tpmKeyPolicy", path: "/tpm/key-policy", label: "TPM Key Policy", icon: "ScrollText", capability: "tpm_policies", requires: { resource: "tpm_policy", action: "get" } },
      { route: "tpmPolicies", path: "/tpm/policies", label: "TPM Policies", icon: "ShieldCheck", capability: "tpm_policies" },
      { route: "seal", path: "/seal", label: "Seal", icon: "Lock", requires: { resource: "keys", action: "encrypt" } },
    ],
  },
  {
    heading: "Certificates & CA",
    items: [
      { route: "userCertBinding", path: "/users/cert-bindings", label: "Certificate Binding", icon: "FileBadge", requires: { resource: "users", action: "update" } },
      { route: "certificates", path: "/certs", label: "Certificates", icon: "FileBadge", requires: { resource: "certs", action: "list" } },
      { route: "certImport", path: "/certs/import", label: "Import Certificate", icon: "FileBadge", requires: { resource: "certs", action: "enroll" } },
      { route: "ca", path: "/ca", label: "Certificate Authority", icon: "Landmark", capability: "ca" },
      { route: "caTcg", path: "/ca/tcg", label: "TCG Certificates", icon: "Fingerprint", capability: "ca", requires: { resource: "certs", action: "issue" } },
    ],
  },
  {
    heading: "Security",
    items: [
      { route: "sshKeyImport", path: "/ssh/import", label: "SSH Key Import", icon: "TerminalSquare", capability: "ssh", requires: { resource: "ssh", action: "write" } },
      { route: "pin", path: "/pin", label: "PIN", icon: "KeyRound", requires: { resource: "pin", action: "read" } },
      { route: "pinSetup", path: "/pin/setup", label: "PIN Setup", icon: "KeyRound", requires: { resource: "pin", action: "write" } },
      { route: "piv", path: "/piv", label: "PIV", icon: "CreditCard", requires: { resource: "piv", action: "read" } },
      { route: "pivSlots", path: "/piv/slots", label: "PIV Slots", icon: "FileBadge", requires: { resource: "piv", action: "read" } },
      { route: "ssh", path: "/ssh", label: "SSH", icon: "TerminalSquare", capability: "ssh", requires: { resource: "ssh", action: "read" } },
      { route: "sshTrust", path: "/ssh/trust", label: "SSH Trust", icon: "Fingerprint", capability: "ssh", requires: { resource: "ssh", action: "read" } },
      { route: "passwords", path: "/passwords", label: "Passwords", icon: "Vault", capability: "passwords", requires: { resource: "passwords", action: "read" } },
      { route: "passwordAccessMode", path: "/passwords/access-mode", label: "Password Access Mode", icon: "Lock", capability: "passwords", requires: { resource: "passwords", action: "write" } },
      { route: "oidcCredentials", path: "/oidc/credentials", label: "OIDC Credentials", icon: "LogIn", capability: "oidc_credentials", requires: { resource: "oidc_credentials", action: "list" } },
      { route: "platform", path: "/platform", label: "Platform Secrets", icon: "FolderLock", capability: "platform" },
      { route: "bootCredentials", path: "/credentials/boot", label: "Boot Credentials", icon: "KeyRound", requires: { resource: "credentials", action: "strategy" } },
    ],
  },
  {
    heading: "Identity & Access",
    items: [
      { route: "tenantQuotas", path: "/tenants/quotas", label: "Tenant Quotas", icon: "Building2", capability: "tenants", requires: { resource: "tenants", action: "set_quotas" } },
      { route: "users", path: "/users", label: "Users", icon: "Users", requires: { resource: "users", action: "list" } },
      { route: "addPasskey", path: "/account/passkeys", label: "Add Passkey", icon: "Fingerprint", capability: "webauthn" },
      { route: "tenants", path: "/tenants", label: "Tenants", icon: "Building2", capability: "tenants", requires: { resource: "tenants", action: "list" } },
      { route: "tenantTpm", path: "/tenants/tpm", label: "Tenant TPM", icon: "Server", capability: "tpm_policies", requires: { resource: "tenants", action: "read" } },
    ],
  },
  {
    heading: "Settings",
    items: [
      { route: "platformSecretNames", path: "/platform/secrets", label: "Secret Names", icon: "FolderLock", capability: "platform", requires: { resource: "keys", action: "list" } },
      { route: "settings", path: "/settings", label: "Settings", icon: "Settings" },
      { route: "tenantEntitlements", path: "/tenants/entitlements", label: "Tenant Entitlements", icon: "Building2", capability: "tenants", requires: { resource: "tenants", action: "set_entitlements" } },
    ],
  },
];
