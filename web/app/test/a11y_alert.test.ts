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

// Regression coverage for the Alert.svelte fix: every error/status banner
// and toast in the app used to be a bare `<div class="alert ...">` with no
// announcement semantics, so a failure message that appeared while a screen
// reader user's focus was elsewhere was silently missed. Alert.svelte now
// gives error/warning banners `role="alert"` (an implicit assertive live
// region) and success/info banners `role="status"` (polite), and
// ToastContainer routes every toast kind through it.

import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/svelte";
import ToastContainer from "../src/components/ToastContainer.svelte";
import { toastStore, showToast, dismissToast } from "../src/stores/toast.svelte.ts";

const backendsList = vi.fn();
vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({ backends: { list: backendsList } }),
  resetSDKClient: () => {},
}));

import BackendsView from "../src/views/BackendsView.svelte";

describe("Alert a11y", () => {
  beforeEach(() => {
    for (const t of [...toastStore.toasts]) dismissToast(t.id);
    backendsList.mockReset();
  });

  it("gives an error toast an assertive alert role", async () => {
    render(ToastContainer);
    showToast("error", "Backend unreachable.", 0);

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Backend unreachable.");
    expect(alert).toHaveAttribute("aria-live", "assertive");
  });

  it("gives a warning toast the same assertive alert role", async () => {
    render(ToastContainer);
    showToast("warning", "Clipboard unavailable.", 0);

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Clipboard unavailable.");
  });

  it("gives a success toast a polite status role, not alert", async () => {
    render(ToastContainer);
    showToast("success", "Key rotated.", 0);

    const status = await screen.findByRole("status");
    expect(status).toHaveTextContent("Key rotated.");
    expect(status).toHaveAttribute("aria-live", "polite");
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("gives an info toast a polite status role", async () => {
    render(ToastContainer);
    showToast("info", "Signed out.", 0);

    const status = await screen.findByRole("status");
    expect(status).toHaveTextContent("Signed out.");
  });

  it("announces a real view's load error via role=alert", async () => {
    backendsList.mockRejectedValue(new Error("backend service unreachable"));
    render(BackendsView);

    const alert = await screen.findByRole("alert");
    await waitFor(() => expect(alert).toHaveTextContent("backend service unreachable"));
  });
});
