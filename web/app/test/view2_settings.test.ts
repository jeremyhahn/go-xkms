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

import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/svelte";
import type { AuthMeResponse } from "@go-xkms/sdk";

// SettingsView reads sessionStore and themeStore directly (no SDK calls of
// its own), so drive the real session store through loadSession with a
// mocked /auth/me, and use the real theme store as-is.
const authMe = vi.fn<() => Promise<AuthMeResponse>>();
vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({ auth: { me: authMe } }),
  resetSDKClient: () => {},
}));

import { clearSession, loadSession } from "../src/stores/session.svelte.ts";
import { setTheme } from "../src/stores/theme.svelte.ts";
import SettingsView from "../src/views/SettingsView.svelte";

beforeEach(() => {
  vi.clearAllMocks();
  clearSession();
  setTheme("xkms-dark");
});

describe("SettingsView", () => {
  it("renders the real identity fields from the session store", async () => {
    authMe.mockResolvedValue({
      subject: "user-7",
      username: "carol",
      display_name: "Carol Custodian",
      roles: ["admin", "operator"],
      permissions: {},
      capabilities: {},
    });
    await loadSession();

    render(SettingsView);

    expect(screen.getByText("carol")).toBeInTheDocument();
    expect(screen.getByText("Carol Custodian")).toBeInTheDocument();
    expect(screen.getByText("admin, operator")).toBeInTheDocument();
  });

  it("falls back to an em dash when there are no roles", async () => {
    authMe.mockResolvedValue({
      subject: "user-8",
      username: "dave",
      roles: [],
      permissions: {},
      capabilities: {},
    });
    await loadSession();

    render(SettingsView);

    expect(screen.getByText("—")).toBeInTheDocument();
  });

  it("switches the theme when Light is clicked", async () => {
    authMe.mockResolvedValue({ subject: "u", username: "u", roles: [], permissions: {}, capabilities: {} });
    await loadSession();

    render(SettingsView);

    await fireEvent.click(screen.getByRole("button", { name: "Light" }));

    expect(document.documentElement.getAttribute("data-theme")).toBe("xkms-light");
  });

  it("renders a status badge per server capability, keyed by wired state", async () => {
    authMe.mockResolvedValue({
      subject: "u",
      username: "u",
      roles: [],
      permissions: {},
      capabilities: { ca: true, cluster: false },
    });
    await loadSession();

    render(SettingsView);

    expect(screen.getByText("ca")).toBeInTheDocument();
    expect(screen.getByText("cluster")).toBeInTheDocument();
  });

  it("shows a placeholder when the server reported no capabilities", async () => {
    authMe.mockResolvedValue({ subject: "u", username: "u", roles: [], permissions: {}, capabilities: {} });
    await loadSession();

    render(SettingsView);

    expect(screen.getByText("No capability information.")).toBeInTheDocument();
  });
});
