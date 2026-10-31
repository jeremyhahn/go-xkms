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

// test/theme.test.ts (owned by another agent) covers setTheme/toggleTheme
// against a live module instance. readStored() and the one-time `apply()`
// at module load only run once, at import time, so exercising them requires
// a fresh module instance per case.
//
// vi.resetModules() would give one, but it also discards the Svelte runtime
// the store imports, so every case re-evaluated that runtime and the first
// paid its cold compile under v8 coverage (0.6-0.9 s on an idle host, past
// 5 s on a loaded CI runner). Instead the store is imported once, statically,
// so the cold compile happens at collection like any component test's
// imports, and each case imports its own instance of the store alone through
// a unique query string (about 20 ms); the runtime stays shared.

import { describe, it, expect, beforeEach } from "vitest";
import "../src/stores/theme.svelte.ts";

type ThemeModule = typeof import("../src/stores/theme.svelte.ts");

let instance = 0;

// freshThemeStore evaluates a new instance of the theme store module, so its
// load-time readStored() and apply() run against the current localStorage.
function freshThemeStore(): Promise<ThemeModule> {
  instance += 1;
  return import(/* @vite-ignore */ `../src/stores/theme.svelte.ts?instance=${instance}`);
}

describe("theme store initial load", () => {
  beforeEach(() => {
    localStorage.clear();
    document.documentElement.removeAttribute("data-theme");
  });

  it("defaults to xkms-dark when localStorage holds no value", async () => {
    const { themeStore } = await freshThemeStore();
    expect(themeStore.theme).toBe("xkms-dark");
  });

  it("defaults to xkms-dark when localStorage holds a value that is not a known theme", async () => {
    localStorage.setItem("xkms_theme", "not-a-real-theme");
    const { themeStore } = await freshThemeStore();
    expect(themeStore.theme).toBe("xkms-dark");
  });

  it("restores a persisted xkms-light theme on load", async () => {
    localStorage.setItem("xkms_theme", "xkms-light");
    const { themeStore } = await freshThemeStore();
    expect(themeStore.theme).toBe("xkms-light");
  });

  it("applies the restored theme to the document root immediately at module load", async () => {
    localStorage.setItem("xkms_theme", "xkms-light");
    await freshThemeStore();
    expect(document.documentElement.getAttribute("data-theme")).toBe("xkms-light");
  });
});
