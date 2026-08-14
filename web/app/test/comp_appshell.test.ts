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
import { render, screen, fireEvent, waitFor } from "@testing-library/svelte";
import { createRawSnippet } from "svelte";
import type { AuthMeResponse } from "@go-xkms/sdk";

// vi.mock factories are hoisted above the rest of the module, so the mocks
// they reference must be created through vi.hoisted() rather than plain
// top-level const declarations.
const { meMock, logoutMock, endSessionMock, readRefreshTokenMock } = vi.hoisted(() => ({
  meMock: vi.fn<() => Promise<AuthMeResponse>>(),
  logoutMock: vi.fn<() => Promise<void>>(),
  endSessionMock: vi.fn(),
  readRefreshTokenMock: vi.fn<() => string | undefined>(),
}));

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({ auth: { me: meMock, logout: logoutMock } }),
  resetSDKClient: () => {},
}));

vi.mock("@go-xkms/svelte-auth", () => ({
  authStore: { get status() { return "authenticated"; } },
  endSession: endSessionMock,
  readRefreshToken: readRefreshTokenMock,
}));

import AppShell from "../src/components/AppShell.svelte";
import { loadSession, clearSession } from "../src/stores/session.svelte.ts";
import { setTheme } from "../src/stores/theme.svelte.ts";
import { toastStore, dismissToast } from "../src/stores/toast.svelte.ts";

const childrenSnippet = createRawSnippet(() => ({
  render: () => `<div data-testid="child">Child content</div>`,
}));

describe("AppShell", () => {
  beforeEach(async () => {
    vi.clearAllMocks();
    for (const t of [...toastStore.toasts]) dismissToast(t.id);
    clearSession();
    setTheme("xkms-dark");
    window.location.hash = "";
    meMock.mockResolvedValue({
      subject: "u1",
      username: "alice",
      display_name: "Alice Admin",
      permissions: {},
      capabilities: {},
    });
    await loadSession();
  });

  it("renders the signed-in operator's display name and the routed content", () => {
    render(AppShell, { props: { children: childrenSnippet } });
    expect(screen.getByText("Alice Admin")).toBeInTheDocument();
    expect(screen.getByTestId("child")).toBeInTheDocument();
  });

  it("toggles the theme icon when the theme button is clicked", async () => {
    setTheme("xkms-dark");
    render(AppShell, { props: { children: childrenSnippet } });

    await fireEvent.click(screen.getByRole("button", { name: "Toggle theme" }));

    expect(document.documentElement.getAttribute("data-theme")).toBe("xkms-light");
  });

  it("signs out: calls the SDK logout, clears local session state and navigates to /login", async () => {
    logoutMock.mockResolvedValue(undefined);
    readRefreshTokenMock.mockReturnValue("refresh-abc");
    render(AppShell, { props: { children: childrenSnippet } });

    await fireEvent.click(screen.getByRole("button", { name: /Sign out/ }));

    await waitFor(() => expect(logoutMock).toHaveBeenCalledWith("refresh-abc"));
    expect(endSessionMock).toHaveBeenCalledOnce();
    expect(window.location.hash).toBe("#/login");
    // AppShell does not render ToastContainer itself; assert against the
    // shared store the way a sibling page-level shell would observe it.
    await waitFor(() =>
      expect(toastStore.toasts.some((t) => t.message === "Signed out.")).toBe(true),
    );
  });

  it("tears down local session state even when the server logout call fails", async () => {
    logoutMock.mockRejectedValue(new Error("network unreachable"));
    readRefreshTokenMock.mockReturnValue(undefined);
    render(AppShell, { props: { children: childrenSnippet } });

    await fireEvent.click(screen.getByRole("button", { name: /Sign out/ }));

    // Logout is best-effort: a failed server call must not block local teardown.
    await waitFor(() => expect(endSessionMock).toHaveBeenCalledOnce());
    expect(window.location.hash).toBe("#/login");
  });
});
