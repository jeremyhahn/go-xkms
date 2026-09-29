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
import type { AuthMeResponse, UserInfo, CreateUserRequest } from "@go-xkms/sdk";

const authMe = vi.fn<() => Promise<AuthMeResponse>>();
const list = vi.fn<() => Promise<{ users: UserInfo[]; page: number; page_size: number; total: number; has_more: boolean }>>();
const create = vi.fn<(req: CreateUserRequest) => Promise<UserInfo>>();
const enableUser = vi.fn<(username: string) => Promise<UserInfo>>();
const disableUser = vi.fn<(username: string) => Promise<UserInfo>>();
const del = vi.fn();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({
    auth: { me: authMe },
    users: { list, create, enable: enableUser, disable: disableUser, delete: del },
  }),
  resetSDKClient: () => {},
}));

const toasts: Array<{ kind: string; message: string }> = [];
vi.mock("../src/stores/toast.svelte.ts", () => ({
  showToast: (kind: string, message: string) => {
    toasts.push({ kind, message });
  },
}));

// UsersView gates its create/update/delete controls on the real session
// store's can(); drive it with loadSession against a mocked /auth/me rather
// than re-implementing the permission map here.
import { clearSession, loadSession } from "../src/stores/session.svelte.ts";
import UsersView from "../src/views/UsersView.svelte";

function user(over: Partial<UserInfo> = {}): UserInfo {
  return {
    id: "1",
    username: "alice",
    display_name: "Alice Admin",
    role: "admin",
    enabled: true,
    created_at: "2026-01-01T00:00:00Z",
    ...over,
  };
}

async function withPermissions(perms: Record<string, boolean>): Promise<void> {
  authMe.mockResolvedValue({
    subject: "op-1",
    username: "operator",
    roles: ["admin"],
    permissions: perms,
    capabilities: {},
  });
  await loadSession();
}

beforeEach(() => {
  vi.clearAllMocks();
  toasts.length = 0;
  clearSession();
});

describe("UsersView", () => {
  it("renders username, display name, role and enabled state", async () => {
    await withPermissions({ "users:create": true, "users:update": true, "users:delete": true });
    list.mockResolvedValue({ users: [user()], page: 1, page_size: 50, total: 1, has_more: false });

    render(UsersView);

    expect(await screen.findByText("alice")).toBeInTheDocument();
    expect(screen.getByText("Alice Admin")).toBeInTheDocument();
    expect(screen.getByText("admin")).toBeInTheDocument();
    expect(screen.getByText("yes")).toBeInTheDocument();
  });

  it("shows the empty state with no users", async () => {
    await withPermissions({});
    list.mockResolvedValue({ users: [], page: 1, page_size: 50, total: 0, has_more: false });

    render(UsersView);

    expect(await screen.findByText("No users.")).toBeInTheDocument();
  });

  it("surfaces a load error instead of a blank page", async () => {
    await withPermissions({});
    list.mockRejectedValue(new Error("user directory unavailable"));

    render(UsersView);

    expect(await screen.findByText("user directory unavailable")).toBeInTheDocument();
  });

  it("hides create/disable/delete controls without the matching permission", async () => {
    await withPermissions({ "users:create": false, "users:disable": false, "users:delete": false });
    list.mockResolvedValue({ users: [user()], page: 1, page_size: 50, total: 1, has_more: false });

    render(UsersView);
    await screen.findByText("alice");

    expect(screen.queryByRole("button", { name: "+ Create" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Disable" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Delete" })).not.toBeInTheDocument();
  });

  it("shows create/disable/delete controls with the matching permission", async () => {
    await withPermissions({ "users:create": true, "users:disable": true, "users:delete": true });
    list.mockResolvedValue({ users: [user()], page: 1, page_size: 50, total: 1, has_more: false });

    render(UsersView);
    await screen.findByText("alice");

    expect(screen.getByRole("button", { name: "+ Create" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Disable" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Delete" })).toBeInTheDocument();
  });

  it("creates a user with the form fields and defaults", async () => {
    await withPermissions({ "users:create": true });
    list.mockResolvedValue({ users: [], page: 1, page_size: 50, total: 0, has_more: false });
    create.mockResolvedValue(user({ username: "newbie" }));

    render(UsersView);
    await screen.findByText("No users.");

    await fireEvent.click(screen.getByRole("button", { name: "+ Create" }));
    await fireEvent.input(screen.getByPlaceholderText("Username"), { target: { value: "newbie" } });
    await fireEvent.input(screen.getByPlaceholderText("Display name"), { target: { value: "New Bee" } });
    await fireEvent.click(screen.getByRole("button", { name: "Create", hidden: true }));

    await waitFor(() => expect(create).toHaveBeenCalledOnce());
    expect(create.mock.calls[0]![0]).toEqual({
      username: "newbie",
      display_name: "New Bee",
      role: "user",
      tenant_id: "system",
    });
  });

  it("surfaces a create failure inside the dialog", async () => {
    await withPermissions({ "users:create": true });
    list.mockResolvedValue({ users: [], page: 1, page_size: 50, total: 0, has_more: false });
    create.mockRejectedValue(new Error("username already taken"));

    render(UsersView);
    await screen.findByText("No users.");

    await fireEvent.click(screen.getByRole("button", { name: "+ Create" }));
    await fireEvent.input(screen.getByPlaceholderText("Username"), { target: { value: "dup" } });
    await fireEvent.click(screen.getByRole("button", { name: "Create", hidden: true }));

    expect(await screen.findByText("username already taken")).toBeInTheDocument();
  });

  it("disables an enabled user through POST .../disable", async () => {
    await withPermissions({ "users:disable": true });
    list.mockResolvedValue({ users: [user({ enabled: true })], page: 1, page_size: 50, total: 1, has_more: false });
    disableUser.mockResolvedValue(user({ enabled: false }));

    render(UsersView);
    await screen.findByText("alice");

    await fireEvent.click(screen.getByRole("button", { name: "Disable" }));

    await waitFor(() => expect(disableUser).toHaveBeenCalledOnce());
    expect(disableUser.mock.calls[0]![0]).toBe("alice");
    expect(enableUser).not.toHaveBeenCalled();
  });

  it("enables a disabled user through POST .../enable", async () => {
    await withPermissions({ "users:enable": true });
    list.mockResolvedValue({ users: [user({ enabled: false })], page: 1, page_size: 50, total: 1, has_more: false });
    enableUser.mockResolvedValue(user({ enabled: true }));

    render(UsersView);
    await screen.findByText("alice");

    await fireEvent.click(screen.getByRole("button", { name: "Enable" }));

    await waitFor(() => expect(enableUser).toHaveBeenCalledOnce());
    expect(enableUser.mock.calls[0]![0]).toBe("alice");
    expect(disableUser).not.toHaveBeenCalled();
  });

  it("surfaces a toggle failure via toast", async () => {
    await withPermissions({ "users:disable": true });
    list.mockResolvedValue({ users: [user({ enabled: true })], page: 1, page_size: 50, total: 1, has_more: false });
    disableUser.mockRejectedValue(new Error("cannot disable the last admin"));

    render(UsersView);
    await screen.findByText("alice");

    await fireEvent.click(screen.getByRole("button", { name: "Disable" }));

    await waitFor(() =>
      expect(toasts).toContainEqual({ kind: "error", message: "cannot disable the last admin" }),
    );
  });

  it("deletes a user by username", async () => {
    await withPermissions({ "users:delete": true });
    list.mockResolvedValueOnce({ users: [user()], page: 1, page_size: 50, total: 1, has_more: false });
    del.mockResolvedValue({ username: "alice", status: "deleted" });
    list.mockResolvedValueOnce({ users: [], page: 1, page_size: 50, total: 0, has_more: false });

    render(UsersView);
    await screen.findByText("alice");

    await fireEvent.click(screen.getByRole("button", { name: "Delete" }));

    await waitFor(() => expect(del).toHaveBeenCalledWith("alice"));
    expect(await screen.findByText("No users.")).toBeInTheDocument();
  });
});
