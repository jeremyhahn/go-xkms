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

// docs/web-console/engineering.md: Seal shows for keys:encrypt or
// keys:decrypt; OTA Image Keys for keys:create, keys:sign or keys:rotate.

import { describe, it, expect } from "vitest";
import { itemVisible, navSections, type NavItem } from "../src/lib/nav.ts";

function item(route: string): NavItem {
  for (const s of navSections) {
    const found = s.items.find((i) => i.route === route);
    if (found) return found;
  }
  throw new Error(`no nav item ${route}`);
}

function visibleWith(route: string, action: string): boolean {
  return itemVisible(item(route), (r, a) => r === "keys" && a === action, () => true);
}

describe("nav alternative-permission gates", () => {
  it.each(["encrypt", "decrypt"])("shows Seal for keys:%s alone", (a) => {
    expect(visibleWith("seal", a)).toBe(true);
  });

  it.each(["create", "sign", "rotate"])("shows OTA Image Keys for keys:%s alone", (a) => {
    expect(visibleWith("otaImageKeys", a)).toBe(true);
  });

  it("hides both without any of their permissions", () => {
    expect(visibleWith("seal", "list")).toBe(false);
    expect(visibleWith("otaImageKeys", "list")).toBe(false);
  });
});
