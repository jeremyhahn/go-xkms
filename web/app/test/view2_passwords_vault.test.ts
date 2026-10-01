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

// The vault-factor side of the Passwords view: listing, adding, changing and
// removing the caller's own factors while the session is open, and
// recovering a locked vault with the one-time recovery code.

import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, fireEvent, waitFor, within } from "@testing-library/svelte";
import type {
  PasswordStoreStatusResponse,
  PasswordVaultEnrollRequest,
  PasswordVaultEnrollResponse,
  PasswordVaultRecoverRequest,
  PasswordVaultRotateRequest,
  PasswordVaultStatusResponse,
} from "@go-xkms/sdk";

const status = vi.fn<() => Promise<PasswordStoreStatusResponse>>();
const list = vi.fn();
const unlock = vi.fn();
const lock = vi.fn();
const vaultStatus = vi.fn<() => Promise<PasswordVaultStatusResponse>>();
const vaultEnroll = vi.fn<(req: PasswordVaultEnrollRequest) => Promise<PasswordVaultEnrollResponse>>();
const vaultRotate = vi.fn<(id: string, req: PasswordVaultRotateRequest) => Promise<PasswordVaultEnrollResponse>>();
const vaultRemoveFactor = vi.fn<(id: string) => Promise<void>>();
const vaultRecover = vi.fn<(req: PasswordVaultRecoverRequest) => Promise<PasswordVaultEnrollResponse>>();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({
    passwords: { status, list, unlock, lock, vaultStatus, vaultEnroll, vaultRotate, vaultRemoveFactor, vaultRecover },
  }),
  resetSDKClient: () => {},
}));

const toasts: Array<{ kind: string; message: string }> = [];
vi.mock("../src/stores/toast.svelte.ts", () => ({
  showToast: (kind: string, message: string) => {
    toasts.push({ kind, message });
  },
}));

import PasswordsView from "../src/views/PasswordsView.svelte";

const unlockedStatus: PasswordStoreStatusResponse = { available: true, is_locked: false, barrier_sealed: false, password_count: 0, message: "" };
const lockedStatus: PasswordStoreStatusResponse = { available: true, is_locked: true, barrier_sealed: false, password_count: 0, message: "" };

const factors: PasswordVaultStatusResponse = {
  initialized: true,
  unlocked: true,
  factors: [
    { id: "f1", factor: "passphrase", label: "web console", created_at: "2026-09-30T00:00:00Z" },
    { id: "f2", factor: "passphrase", label: "laptop", created_at: "2026-09-30T00:00:00Z" },
    { id: "rc", factor: "recovery", created_at: "2026-09-30T00:00:00Z" },
  ],
};

async function openFactors(): Promise<HTMLElement> {
  render(PasswordsView);
  await fireEvent.click(await screen.findByRole("button", { name: "Vault factors" }));
  const dialog = await screen.findByRole("dialog", { hidden: true });
  await within(dialog).findByText("laptop");
  return dialog;
}

beforeEach(() => {
  vi.clearAllMocks();
  toasts.length = 0;
  list.mockResolvedValue({ passwords: [], total: 0 });
  vaultStatus.mockResolvedValue(factors);
});

describe("PasswordsView vault factors", () => {
  it("lists the caller's factors and never offers to remove the recovery code", async () => {
    status.mockResolvedValue(unlockedStatus);
    const dialog = await openFactors();

    const rows = within(dialog).getAllByRole("row").slice(1);
    expect(rows).toHaveLength(3);
    expect(within(rows[0]!).getByText("web console")).toBeInTheDocument();
    expect(within(rows[2]!).getByText("recovery code")).toBeInTheDocument();
    expect(within(rows[2]!).queryByRole("button", { name: /Remove/, hidden: true })).toBeNull();
  });

  it("adds a passphrase factor", async () => {
    status.mockResolvedValue(unlockedStatus);
    vaultEnroll.mockResolvedValue({ factor: { id: "f3", factor: "passphrase", created_at: "2026-09-30T00:00:00Z" } });
    const dialog = await openFactors();

    const add = within(dialog).getByRole("button", { name: "Add passphrase", hidden: true });
    expect(add).toBeDisabled();
    await fireEvent.input(within(dialog).getByLabelText("New passphrase"), { target: { value: "second passphrase" } });
    await fireEvent.input(within(dialog).getByLabelText("Confirm new passphrase"), { target: { value: "second passphrase" } });
    await fireEvent.input(within(dialog).getByLabelText("Label"), { target: { value: "phone" } });
    await fireEvent.click(add);

    await waitFor(() => expect(vaultEnroll).toHaveBeenCalledOnce());
    expect(vaultEnroll.mock.calls[0]![0]).toEqual({ factor: "passphrase", passphrase: "second passphrase", label: "phone" });
    expect(toasts).toContainEqual({ kind: "success", message: "Passphrase added." });
    await waitFor(() => expect(vaultStatus).toHaveBeenCalledTimes(2));
  });

  it("refuses a short or mismatched new passphrase before calling the server", async () => {
    status.mockResolvedValue(unlockedStatus);
    const dialog = await openFactors();

    const add = within(dialog).getByRole("button", { name: "Add passphrase", hidden: true });
    await fireEvent.input(within(dialog).getByLabelText("New passphrase"), { target: { value: "short" } });
    await fireEvent.input(within(dialog).getByLabelText("Confirm new passphrase"), { target: { value: "short" } });
    expect(add).toBeDisabled();
    await fireEvent.input(within(dialog).getByLabelText("New passphrase"), { target: { value: "long enough one" } });
    await fireEvent.input(within(dialog).getByLabelText("Confirm new passphrase"), { target: { value: "long enough two" } });
    expect(add).toBeDisabled();
    expect(vaultEnroll).not.toHaveBeenCalled();
  });

  it("changes a passphrase factor in place", async () => {
    status.mockResolvedValue(unlockedStatus);
    vaultRotate.mockResolvedValue({ factor: { id: "f4", factor: "passphrase", created_at: "2026-09-30T00:00:00Z" } });
    const dialog = await openFactors();

    const rows = within(dialog).getAllByRole("row").slice(1);
    await fireEvent.click(within(rows[1]!).getByRole("button", { name: "Change laptop", hidden: true }));
    await fireEvent.input(within(dialog).getByLabelText("New passphrase"), { target: { value: "rotated passphrase" } });
    await fireEvent.input(within(dialog).getByLabelText("Confirm new passphrase"), { target: { value: "rotated passphrase" } });
    await fireEvent.click(within(dialog).getByRole("button", { name: "Change passphrase", hidden: true }));

    await waitFor(() => expect(vaultRotate).toHaveBeenCalledOnce());
    expect(vaultRotate.mock.calls[0]).toEqual(["f2", { factor: "passphrase", passphrase: "rotated passphrase", label: "laptop" }]);
    expect(toasts).toContainEqual({ kind: "success", message: "Passphrase changed." });
  });

  it("removes a factor", async () => {
    status.mockResolvedValue(unlockedStatus);
    vaultRemoveFactor.mockResolvedValue(undefined);
    const dialog = await openFactors();

    const rows = within(dialog).getAllByRole("row").slice(1);
    await fireEvent.click(within(rows[1]!).getByRole("button", { name: "Remove laptop", hidden: true }));

    await waitFor(() => expect(vaultRemoveFactor).toHaveBeenCalledWith("f2"));
    expect(toasts).toContainEqual({ kind: "success", message: "Factor removed." });
  });

  it("shows the server's refusal to remove the last factor inside the dialog", async () => {
    status.mockResolvedValue(unlockedStatus);
    vaultRemoveFactor.mockRejectedValue(new Error("cannot remove the last passphrase or passkey"));
    const dialog = await openFactors();

    const rows = within(dialog).getAllByRole("row").slice(1);
    await fireEvent.click(within(rows[0]!).getByRole("button", { name: "Remove web console", hidden: true }));

    expect(await within(dialog).findByText("cannot remove the last passphrase or passkey")).toBeInTheDocument();
  });
});

describe("PasswordsView recovery", () => {
  it("recovers a locked vault with the recovery code and a new passphrase, then shows the new code", async () => {
    status.mockResolvedValueOnce(lockedStatus);
    vaultStatus.mockResolvedValue({ initialized: true, unlocked: false, factors: [] });
    vaultRecover.mockResolvedValue({
      factor: { id: "f9", factor: "passphrase", created_at: "2026-09-30T00:00:00Z" },
      recovery_code: "WXYZ-2345-ABCD-EFGH-IJKL-MNOP-QRST-UVWX",
    });
    status.mockResolvedValue(unlockedStatus);

    render(PasswordsView);
    await fireEvent.click(await screen.findByRole("button", { name: "Use recovery code" }));

    const recover = screen.getByRole("button", { name: "Recover vault" });
    expect(recover).toBeDisabled();
    await fireEvent.input(screen.getByLabelText("Recovery code"), { target: { value: "abcd-efgh-ijkl-mnop-qrst-uvwx-yz23-4567" } });
    await fireEvent.input(screen.getByLabelText("New passphrase"), { target: { value: "fresh passphrase" } });
    await fireEvent.input(screen.getByLabelText("Confirm new passphrase"), { target: { value: "fresh passphrase" } });
    await fireEvent.click(recover);

    await waitFor(() => expect(vaultRecover).toHaveBeenCalledOnce());
    expect(vaultRecover.mock.calls[0]![0]).toEqual({
      recovery_code: "abcd-efgh-ijkl-mnop-qrst-uvwx-yz23-4567",
      factor: "passphrase",
      passphrase: "fresh passphrase",
      label: "web console",
    });
    expect(await screen.findByText("WXYZ-2345-ABCD-EFGH-IJKL-MNOP-QRST-UVWX")).toBeInTheDocument();
  });

  it("keeps the recovery form open and shows the refusal on a wrong code", async () => {
    status.mockResolvedValue(lockedStatus);
    vaultStatus.mockResolvedValue({ initialized: true, unlocked: false, factors: [] });
    vaultRecover.mockRejectedValue(new Error("vault credential rejected"));

    render(PasswordsView);
    await fireEvent.click(await screen.findByRole("button", { name: "Use recovery code" }));
    await fireEvent.input(screen.getByLabelText("Recovery code"), { target: { value: "WRONG" } });
    await fireEvent.input(screen.getByLabelText("New passphrase"), { target: { value: "fresh passphrase" } });
    await fireEvent.input(screen.getByLabelText("Confirm new passphrase"), { target: { value: "fresh passphrase" } });
    await fireEvent.click(screen.getByRole("button", { name: "Recover vault" }));

    expect(await screen.findByText("vault credential rejected")).toBeInTheDocument();
    expect(screen.getByLabelText("Recovery code")).toBeInTheDocument();
  });
});
