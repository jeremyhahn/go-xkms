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
// a fresh module graph per case via vi.resetModules() + dynamic import.

import { describe, it, expect, beforeEach, vi } from "vitest";

describe("theme store initial load", () => {
  beforeEach(() => {
    vi.resetModules();
    localStorage.clear();
    document.documentElement.removeAttribute("data-theme");
  });

  it("defaults to xkms-dark when localStorage holds no value", async () => {
    const { themeStore } = await import("../src/stores/theme.svelte.ts");
    expect(themeStore.theme).toBe("xkms-dark");
  });

  it("defaults to xkms-dark when localStorage holds a value that is not a known theme", async () => {
    localStorage.setItem("xkms_theme", "not-a-real-theme");
    const { themeStore } = await import("../src/stores/theme.svelte.ts");
    expect(themeStore.theme).toBe("xkms-dark");
  });

  it("restores a persisted xkms-light theme on load", async () => {
    localStorage.setItem("xkms_theme", "xkms-light");
    const { themeStore } = await import("../src/stores/theme.svelte.ts");
    expect(themeStore.theme).toBe("xkms-light");
  });

  it("applies the restored theme to the document root immediately at module load", async () => {
    localStorage.setItem("xkms_theme", "xkms-light");
    await import("../src/stores/theme.svelte.ts");
    expect(document.documentElement.getAttribute("data-theme")).toBe("xkms-light");
  });
});
