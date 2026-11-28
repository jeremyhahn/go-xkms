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
import type {
  PasswordStoreStatusResponse,
  PasswordStoreAccessModeRequest,
  PasswordStoreAccessModeResponse,
} from "@go-xkms/sdk";

const status = vi.fn<() => Promise<PasswordStoreStatusResponse>>();
const setAccessMode = vi.fn<(req: PasswordStoreAccessModeRequest) => Promise<PasswordStoreAccessModeResponse>>();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({ passwords: { status, setAccessMode } }),
  resetSDKClient: () => {},
}));

const toasts: Array<{ kind: string; message: string }> = [];
vi.mock("../src/stores/toast.svelte.ts", () => ({
  showToast: (kind: string, message: string) => {
    toasts.push({ kind, message });
  },
}));

import PasswordAccessModeView from "../src/views/PasswordAccessModeView.svelte";

const available: PasswordStoreStatusResponse = {
  available: true,
  is_locked: false,
  barrier_sealed: false,
  password_count: 3,
  message: "",
  access_mode: "session_based",
};

const notImplemented = "The wired password store cannot enforce the requested access mode";

beforeEach(() => {
  vi.clearAllMocks();
  toasts.length = 0;
});

function applyButton(): HTMLButtonElement {
  return screen.getByRole("button", { name: "Apply" }) as HTMLButtonElement;
}

async function mountAvailable(): Promise<void> {
  status.mockResolvedValue(available);
  render(PasswordAccessModeView);
  await waitFor(() => expect(applyButton()).toBeTruthy());
}

async function chooseAndApply(label: RegExp): Promise<void> {
  await fireEvent.click(screen.getByLabelText(label));
  await waitFor(() => expect(applyButton().disabled).toBe(false));
  await fireEvent.click(applyButton());
}

describe("PasswordAccessModeView", () => {
  it("mount: calls status once and shows the store state", async () => {
    await mountAvailable();
    expect(status).toHaveBeenCalledTimes(1);
    expect(screen.getByTestId("current-mode").textContent).toContain("session_based");
  });

  it("mount: an unavailable store shows an info alert and disables Apply", async () => {
    status.mockResolvedValue({ ...available, available: false, message: "no password store configured" });
    render(PasswordAccessModeView);
    await waitFor(() => expect(screen.getByText(/no password store configured/i)).toBeTruthy());
    expect(applyButton().disabled).toBe(true);
    await fireEvent.click(screen.getByLabelText(/session based/i));
    expect(applyButton().disabled).toBe(true);
  });

  it("validation: Apply stays disabled until a mode is chosen", async () => {
    await mountAvailable();
    expect(applyButton().disabled).toBe(true);
    await fireEvent.click(screen.getByLabelText(/session based/i));
    await waitFor(() => expect(applyButton().disabled).toBe(false));
  });

  it("apply: session_based asks for a confirm, then sets the mode and toasts the message", async () => {
    setAccessMode.mockResolvedValue({ mode: "session_based", message: "access mode set to session_based" });
    await mountAvailable();
    await chooseAndApply(/session based/i);
    const confirm = await screen.findByRole("button", { name: "Confirm" });
    expect(screen.getByTestId("confirm-mode").textContent).toContain("session_based");
    expect(setAccessMode).not.toHaveBeenCalled();
    await fireEvent.click(confirm);
    await waitFor(() => expect(setAccessMode).toHaveBeenCalledTimes(1));
    expect(setAccessMode).toHaveBeenCalledWith({ mode: "session_based" });
    await waitFor(() =>
      expect(toasts).toContainEqual({ kind: "success", message: "access mode set to session_based" }),
    );
    await waitFor(() => expect(screen.getByTestId("current-mode").textContent).toContain("session_based"));
  });

  it("apply: Cancel on the confirm step calls nothing", async () => {
    await mountAvailable();
    await chooseAndApply(/session based/i);
    await fireEvent.click(await screen.findByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByRole("button", { name: "Confirm" })).toBeNull());
    expect(setAccessMode).not.toHaveBeenCalled();
    expect(toasts).toHaveLength(0);
  });

  // PasswordStoreSetAccessMode fixes the mode at composition time: a tenant
  // store is session_based and any other mode can only answer 501, so the
  // view never offers it (docs/web-console/engineering.md no-501 invariant).
  it("session_based store: PIN per operation is disabled, explained, and never requested", async () => {
    await mountAvailable();
    const pin = screen.getByLabelText(/pin per operation/i) as HTMLInputElement;
    expect(pin.disabled).toBe(true);
    expect((screen.getByLabelText(/session based/i) as HTMLInputElement).disabled).toBe(false);
    expect(screen.getByTestId("mode-fixed").textContent).toMatch(/session_based/);
    await fireEvent.click(pin);
    expect(applyButton().disabled).toBe(true);
    expect(setAccessMode).not.toHaveBeenCalled();
  });

  it("pin_per_operation store: session based is disabled instead", async () => {
    status.mockResolvedValue({ ...available, access_mode: "pin_per_operation" });
    render(PasswordAccessModeView);
    await waitFor(() => expect(applyButton()).toBeTruthy());
    expect((screen.getByLabelText(/session based/i) as HTMLInputElement).disabled).toBe(true);
    expect((screen.getByLabelText(/pin per operation/i) as HTMLInputElement).disabled).toBe(false);
  });

  it("a server that reports no mode offers no choice", async () => {
    status.mockResolvedValue({ ...available, access_mode: undefined });
    render(PasswordAccessModeView);
    await waitFor(() => expect(applyButton()).toBeTruthy());
    expect((screen.getByLabelText(/session based/i) as HTMLInputElement).disabled).toBe(true);
    expect((screen.getByLabelText(/pin per operation/i) as HTMLInputElement).disabled).toBe(true);
    expect(screen.getByText(/not known/i)).toBeTruthy();
    expect(applyButton().disabled).toBe(true);
  });

  it("errors: a rejected call shows the message and keeps the effective mode", async () => {
    setAccessMode.mockRejectedValueOnce(new Error(notImplemented));
    await mountAvailable();
    await chooseAndApply(/session based/i);
    await fireEvent.click(await screen.findByRole("button", { name: "Confirm" }));
    await waitFor(() => expect(screen.getByText(notImplemented)).toBeTruthy());
    expect(screen.getByTestId("current-mode").textContent).toContain("session_based");
    expect(toasts.filter((t) => t.kind === "success")).toHaveLength(0);
  });
});
