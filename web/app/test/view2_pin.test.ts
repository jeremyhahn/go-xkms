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
import type { LockoutStatusResponse } from "@go-xkms/sdk";

const lockoutStatus = vi.fn<() => Promise<LockoutStatusResponse>>();
const changeSO = vi.fn();
const changeUser = vi.fn();
const resetLockout = vi.fn();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({ pin: { lockoutStatus, changeSO, changeUser, resetLockout } }),
  resetSDKClient: () => {},
}));

const toasts: Array<{ kind: string; message: string }> = [];
vi.mock("../src/stores/toast.svelte.ts", () => ({
  showToast: (kind: string, message: string) => {
    toasts.push({ kind, message });
  },
}));

import PinView from "../src/views/PinView.svelte";

beforeEach(() => {
  vi.clearAllMocks();
  toasts.length = 0;
});

describe("PinView", () => {
  it("renders the real lockout counters once loaded", async () => {
    lockoutStatus.mockResolvedValue({ failed_attempts: 2, max_attempts: 5, is_locked: false, recovery_seconds: 0 });

    render(PinView);

    expect(await screen.findByText("2")).toBeInTheDocument();
    expect(screen.getByText("5")).toBeInTheDocument();
    expect(screen.getByText("no")).toBeInTheDocument();
  });

  it("shows locked as yes when the lockout is active", async () => {
    lockoutStatus.mockResolvedValue({ failed_attempts: 5, max_attempts: 5, is_locked: true, recovery_seconds: 30 });

    render(PinView);

    expect(await screen.findByText("yes")).toBeInTheDocument();
  });

  it("surfaces a lockout-status error", async () => {
    lockoutStatus.mockRejectedValue(new Error("pin subsystem unavailable"));

    render(PinView);

    expect(await screen.findByText("pin subsystem unavailable")).toBeInTheDocument();
  });

  it("changes the SO PIN with the current/new pair and nothing else", async () => {
    lockoutStatus.mockResolvedValue({ failed_attempts: 0, max_attempts: 5, is_locked: false, recovery_seconds: 0 });
    changeSO.mockResolvedValue({ message: "changed" });

    render(PinView);
    await screen.findByText("Change SO PIN");

    await fireEvent.input(screen.getByPlaceholderText("Current SO PIN"), { target: { value: "old-so" } });
    await fireEvent.input(screen.getByPlaceholderText("New SO PIN"), { target: { value: "new-so" } });
    await fireEvent.click(screen.getAllByRole("button", { name: "Change" })[0]!);

    await waitFor(() => expect(changeSO).toHaveBeenCalledOnce());
    expect(changeSO.mock.calls[0]![0]).toEqual({ current_so_pin: "old-so", new_so_pin: "new-so" });
    expect(toasts).toContainEqual({ kind: "success", message: "SO PIN changed." });
    expect(changeUser).not.toHaveBeenCalled();
  });

  it("changes the user PIN independently of the SO PIN form", async () => {
    lockoutStatus.mockResolvedValue({ failed_attempts: 0, max_attempts: 5, is_locked: false, recovery_seconds: 0 });
    changeUser.mockResolvedValue({ message: "changed" });

    render(PinView);
    await screen.findByText("Change User PIN");

    await fireEvent.input(screen.getByPlaceholderText("Current user PIN"), { target: { value: "old-user" } });
    await fireEvent.input(screen.getByPlaceholderText("New user PIN"), { target: { value: "new-user" } });
    await fireEvent.click(screen.getAllByRole("button", { name: "Change" })[1]!);

    await waitFor(() => expect(changeUser).toHaveBeenCalledOnce());
    expect(changeUser.mock.calls[0]![0]).toEqual({ current_user_pin: "old-user", new_user_pin: "new-user" });
    expect(changeSO).not.toHaveBeenCalled();
  });

  it("surfaces a PIN-change failure via toast", async () => {
    lockoutStatus.mockResolvedValue({ failed_attempts: 0, max_attempts: 5, is_locked: false, recovery_seconds: 0 });
    changeSO.mockRejectedValue(new Error("current PIN incorrect"));

    render(PinView);
    await screen.findByText("Change SO PIN");

    await fireEvent.input(screen.getByPlaceholderText("New SO PIN"), { target: { value: "new-so" } });
    await fireEvent.click(screen.getAllByRole("button", { name: "Change" })[0]!);

    await waitFor(() => expect(toasts).toContainEqual({ kind: "error", message: "current PIN incorrect" }));
  });

  it("resets the lockout counter with the SO PIN and reloads status", async () => {
    lockoutStatus.mockResolvedValueOnce({ failed_attempts: 5, max_attempts: 5, is_locked: true, recovery_seconds: 30 });
    resetLockout.mockResolvedValue({ message: "reset" });
    lockoutStatus.mockResolvedValueOnce({ failed_attempts: 0, max_attempts: 5, is_locked: false, recovery_seconds: 0 });

    render(PinView);
    await screen.findByText("Reset lockout");

    await fireEvent.input(screen.getByPlaceholderText("SO PIN"), { target: { value: "so-pin-1" } });
    await fireEvent.click(screen.getByRole("button", { name: "Reset counter" }));

    await waitFor(() => expect(resetLockout).toHaveBeenCalledOnce());
    expect(resetLockout.mock.calls[0]![0]).toEqual({ so_pin: "so-pin-1" });
    await waitFor(() => expect(lockoutStatus).toHaveBeenCalledTimes(2));
  });
});
