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

import { describe, it, expect, beforeEach } from "vitest";
import { themeStore, setTheme, toggleTheme } from "../src/stores/theme.svelte.ts";

describe("theme store", () => {
  beforeEach(() => {
    setTheme("xkms-dark");
  });

  it("applies the theme to the document root", () => {
    setTheme("xkms-light");
    expect(document.documentElement.getAttribute("data-theme")).toBe("xkms-light");
    expect(themeStore.theme).toBe("xkms-light");
  });

  it("persists the theme to localStorage", () => {
    setTheme("xkms-light");
    expect(localStorage.getItem("xkms_theme")).toBe("xkms-light");
  });

  it("toggles between dark and light", () => {
    setTheme("xkms-dark");
    toggleTheme();
    expect(themeStore.theme).toBe("xkms-light");
    toggleTheme();
    expect(themeStore.theme).toBe("xkms-dark");
  });
});
