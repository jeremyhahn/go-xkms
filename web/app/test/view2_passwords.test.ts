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
  PasswordInfo,
  PasswordStoreStatusResponse,
  PasswordStoreUnlockRequest,
  PasswordVaultEnrollRequest,
  PasswordVaultEnrollResponse,
  PasswordVaultStatusResponse,
} from "@go-xkms/sdk";

const status = vi.fn<() => Promise<PasswordStoreStatusResponse>>();
const list = vi.fn<() => Promise<{ passwords: PasswordInfo[]; total: number }>>();
const unlock = vi.fn<(req: PasswordStoreUnlockRequest) => Promise<PasswordStoreStatusResponse>>();
const lock = vi.fn<() => Promise<PasswordStoreStatusResponse>>();
const add = vi.fn();
const del = vi.fn();
const vaultStatus = vi.fn<() => Promise<PasswordVaultStatusResponse>>();
const vaultEnroll = vi.fn<(req: PasswordVaultEnrollRequest) => Promise<PasswordVaultEnrollResponse>>();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({ passwords: { status, list, unlock, lock, add, delete: del, vaultStatus, vaultEnroll } }),
  resetSDKClient: () => {},
}));

const toasts: Array<{ kind: string; message: string }> = [];
vi.mock("../src/stores/toast.svelte.ts", () => ({
  showToast: (kind: string, message: string) => {
    toasts.push({ kind, message });
  },
}));

import PasswordsView from "../src/views/PasswordsView.svelte";

function entry(over: Partial<PasswordInfo> = {}): PasswordInfo {
  return {
    id: "pw-1",
    name: "github",
    username: "alice",
    url: "https://github.com",
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
    ...over,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  toasts.length = 0;
  vaultStatus.mockResolvedValue({ initialized: true, unlocked: false, factors: [] });
});

describe("PasswordsView", () => {
  it("loads an unlocked vault and renders the real entry fields", async () => {
    status.mockResolvedValue({ available: true, is_locked: false, barrier_sealed: false, password_count: 1, message: "" });
    list.mockResolvedValue({ passwords: [entry()], total: 1 });

    render(PasswordsView);

    expect(await screen.findByText("github")).toBeInTheDocument();
    expect(screen.getByText("alice")).toBeInTheDocument();
    expect(screen.getByText("https://github.com")).toBeInTheDocument();
    expect(screen.getByText("unlocked")).toBeInTheDocument();
    expect(screen.getByText("1 entries")).toBeInTheDocument();
  });

  it("shows the unlock form instead of the table while the vault is locked", async () => {
    status.mockResolvedValue({ available: true, is_locked: true, barrier_sealed: false, password_count: 0, message: "" });

    render(PasswordsView);

    expect(await screen.findByPlaceholderText("Passphrase")).toBeInTheDocument();
    expect(screen.getByText("locked")).toBeInTheDocument();
    expect(list).not.toHaveBeenCalled();
    expect(screen.queryByText("github")).not.toBeInTheDocument();
  });

  it("shows the empty state when the vault has no entries", async () => {
    status.mockResolvedValue({ available: true, is_locked: false, barrier_sealed: false, password_count: 0, message: "" });
    list.mockResolvedValue({ passwords: [], total: 0 });

    render(PasswordsView);

    expect(await screen.findByText("No entries.")).toBeInTheDocument();
  });

  it("surfaces a status error instead of a blank page", async () => {
    status.mockRejectedValue(new Error("vault backend unreachable"));

    render(PasswordsView);

    expect(await screen.findByText("vault backend unreachable")).toBeInTheDocument();
  });

  it("unlocks with the entered passphrase and reloads the entry list", async () => {
    status.mockResolvedValueOnce({ available: true, is_locked: true, barrier_sealed: false, password_count: 0, message: "" });
    unlock.mockResolvedValue({ available: true, is_locked: false, barrier_sealed: false, password_count: 1, message: "" });
    status.mockResolvedValueOnce({ available: true, is_locked: false, barrier_sealed: false, password_count: 1, message: "" });
    list.mockResolvedValue({ passwords: [entry()], total: 1 });

    render(PasswordsView);

    const input = await screen.findByPlaceholderText("Passphrase");
    await fireEvent.input(input, { target: { value: "my vault passphrase" } });
    await fireEvent.click(screen.getByRole("button", { name: "Unlock" }));

    await waitFor(() => expect(unlock).toHaveBeenCalledOnce());
    // The session opens with the user's own passphrase, never a PIN.
    expect(unlock.mock.calls[0]![0]).toEqual({ factor: "passphrase", passphrase: "my vault passphrase" });
    expect(await screen.findByText("github")).toBeInTheDocument();
  });

  it("locks the vault via the header action", async () => {
    status.mockResolvedValue({ available: true, is_locked: false, barrier_sealed: false, password_count: 1, message: "" });
    list.mockResolvedValue({ passwords: [entry()], total: 1 });
    lock.mockResolvedValue({ available: true, is_locked: true, barrier_sealed: false, password_count: 0, message: "" });

    render(PasswordsView);
    await screen.findByText("github");

    await fireEvent.click(screen.getByRole("button", { name: "Lock" }));

    await waitFor(() => expect(lock).toHaveBeenCalledOnce());
    expect(toasts).toContainEqual({ kind: "success", message: "Vault locked." });
  });

  it("adds a new entry with the fields from the form", async () => {
    status.mockResolvedValue({ available: true, is_locked: false, barrier_sealed: false, password_count: 0, message: "" });
    list.mockResolvedValue({ passwords: [], total: 0 });
    add.mockResolvedValue({ id: "pw-2", name: "gitlab", message: "" });

    render(PasswordsView);
    await screen.findByText("No entries.");

    await fireEvent.click(screen.getByRole("button", { name: "+ Add" }));
    await fireEvent.input(screen.getByPlaceholderText("Name"), { target: { value: "gitlab" } });
    await fireEvent.input(screen.getByPlaceholderText("Username"), { target: { value: "bob" } });
    await fireEvent.input(screen.getByPlaceholderText("Password"), { target: { value: "s3cret" } });
    await fireEvent.click(screen.getByRole("button", { name: "Add", hidden: true }));

    await waitFor(() => expect(add).toHaveBeenCalledOnce());
    expect(add.mock.calls[0]![0]).toEqual({ name: "gitlab", username: "bob", password: "s3cret" });
  });

  it("surfaces an add failure inside the dialog instead of closing it", async () => {
    status.mockResolvedValue({ available: true, is_locked: false, barrier_sealed: false, password_count: 0, message: "" });
    list.mockResolvedValue({ passwords: [], total: 0 });
    add.mockRejectedValue(new Error("name already exists"));

    render(PasswordsView);
    await screen.findByText("No entries.");

    await fireEvent.click(screen.getByRole("button", { name: "+ Add" }));
    await fireEvent.input(screen.getByPlaceholderText("Name"), { target: { value: "dup" } });
    await fireEvent.input(screen.getByPlaceholderText("Password"), { target: { value: "pw" } });
    await fireEvent.click(screen.getByRole("button", { name: "Add", hidden: true }));

    expect(await screen.findByText("name already exists")).toBeInTheDocument();
    // The dialog stays open on failure.
    expect(screen.getByPlaceholderText("Name")).toBeInTheDocument();
  });

  it("deletes an entry by id", async () => {
    status.mockResolvedValue({ available: true, is_locked: false, barrier_sealed: false, password_count: 1, message: "" });
    list.mockResolvedValue({ passwords: [entry({ id: "pw-9" })], total: 1 });
    del.mockResolvedValue({ message: "" });

    render(PasswordsView);
    await screen.findByText("github");

    await fireEvent.click(screen.getByRole("button", { name: "Delete" }));

    await waitFor(() => expect(del).toHaveBeenCalledWith("pw-9"));
  });

  it("creates the vault on first use and shows the recovery code once", async () => {
    vaultStatus.mockResolvedValue({ initialized: false, unlocked: false, factors: [] });
    status.mockResolvedValueOnce({ available: true, is_locked: true, barrier_sealed: false, password_count: 0, message: "" });
    vaultEnroll.mockResolvedValue({
      factor: { id: "f1", factor: "passphrase", created_at: "2026-09-30T00:00:00Z" },
      recovery_code: "ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ23-4567",
    });
    status.mockResolvedValueOnce({ available: true, is_locked: false, barrier_sealed: false, password_count: 0, message: "" });
    list.mockResolvedValue({ passwords: [], total: 0 });

    render(PasswordsView);

    const create = await screen.findByRole("button", { name: "Create vault" });
    expect(create).toBeDisabled();
    await fireEvent.input(screen.getByPlaceholderText("Passphrase (8+ characters)"), { target: { value: "first passphrase" } });
    await fireEvent.input(screen.getByPlaceholderText("Confirm passphrase"), { target: { value: "first passphrase" } });
    await fireEvent.click(create);

    await waitFor(() => expect(vaultEnroll).toHaveBeenCalledOnce());
    expect(vaultEnroll.mock.calls[0]![0]).toEqual({ factor: "passphrase", passphrase: "first passphrase", label: "web console" });
    expect(await screen.findByText("ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ23-4567")).toBeInTheDocument();
    await fireEvent.click(screen.getByRole("button", { name: "I have stored it" }));
    await waitFor(() => expect(screen.queryByText("ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ23-4567")).not.toBeInTheDocument());
  });

  it("refuses to create a vault with mismatched passphrases", async () => {
    vaultStatus.mockResolvedValue({ initialized: false, unlocked: false, factors: [] });
    status.mockResolvedValue({ available: true, is_locked: true, barrier_sealed: false, password_count: 0, message: "" });

    render(PasswordsView);

    const create = await screen.findByRole("button", { name: "Create vault" });
    await fireEvent.input(screen.getByPlaceholderText("Passphrase (8+ characters)"), { target: { value: "first passphrase" } });
    await fireEvent.input(screen.getByPlaceholderText("Confirm passphrase"), { target: { value: "other passphrase" } });
    expect(create).toBeDisabled();
    expect(vaultEnroll).not.toHaveBeenCalled();
  });
});
