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

// The lead is concurrently adding routes to nav.ts/router.svelte.ts, so
// these assertions are deliberately structural (a specific item exists and
// is shaped correctly) rather than exact-count based, per the file
// ownership note for this task.

import { describe, it, expect } from "vitest";
import { navSections, type NavItem } from "../src/lib/nav.ts";

function findItem(route: string): NavItem | undefined {
  for (const section of navSections) {
    const found = section.items.find((i) => i.route === route);
    if (found) return found;
  }
  return undefined;
}

describe("navSections", () => {
  it("is a non-empty list of sections, each with a heading and at least one item", () => {
    expect(navSections.length).toBeGreaterThan(0);
    for (const section of navSections) {
      expect(typeof section.heading).toBe("string");
      expect(section.heading.length).toBeGreaterThan(0);
      expect(section.items.length).toBeGreaterThan(0);
    }
  });

  it("maps the keys route to /keys and gates it on keys:list", () => {
    const item = findItem("keys");
    expect(item).toBeDefined();
    expect(item!.path).toBe("/keys");
    expect(item!.requires).toEqual({ resource: "keys", action: "list" });
  });

  it("maps the dashboard route to /dashboard with no RBAC or capability gate", () => {
    const item = findItem("dashboard");
    expect(item).toBeDefined();
    expect(item!.path).toBe("/dashboard");
    expect(item!.requires).toBeUndefined();
    expect(item!.capability).toBeUndefined();
  });

  it("gates the certificate authority route on the 'ca' capability", () => {
    const item = findItem("ca");
    expect(item).toBeDefined();
    expect(item!.path).toBe("/ca");
    expect(item!.capability).toBe("ca");
  });

  it("gates ssh on both a capability and a permission", () => {
    const item = findItem("ssh");
    expect(item).toBeDefined();
    expect(item!.capability).toBe("ssh");
    expect(item!.requires).toEqual({ resource: "ssh", action: "use" });
  });

  it("gives every item a non-empty label and icon key", () => {
    for (const section of navSections) {
      for (const item of section.items) {
        expect(item.label.length).toBeGreaterThan(0);
        expect(item.icon.length).toBeGreaterThan(0);
        expect(item.path.startsWith("/")).toBe(true);
      }
    }
  });

  it("has no duplicate route entries across all sections", () => {
    const routes = navSections.flatMap((s) => s.items.map((i) => i.route));
    expect(new Set(routes).size).toBe(routes.length);
  });
});
