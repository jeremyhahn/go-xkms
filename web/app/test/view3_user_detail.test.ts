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
import type { UserInfo } from "@go-xkms/sdk";

const get = vi.fn<(username: string) => Promise<UserInfo>>();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({ users: { get } }),
  resetSDKClient: () => {},
}));

vi.mock("../src/stores/toast.svelte.ts", () => ({
  showToast: () => {},
}));

import UserDetailView from "../src/views/UserDetailView.svelte";

const alice: UserInfo = {
  id: "18446744073709551615",
  username: "alice",
  display_name: "Alice",
  roles: ["admin", "operator"],
  enabled: true,
  created_at: "2026-11-12T00:00:00Z",
  last_login: "2026-11-12T01:00:00Z",
};

async function lookUp(name: string): Promise<void> {
  await fireEvent.input(screen.getByLabelText("Username"), { target: { value: name } });
  await fireEvent.click(screen.getByRole("button", { name: "Look up" }));
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe("UserDetailView", () => {
  it("never calls the API for an empty or blank name", async () => {
    render(UserDetailView);

    await fireEvent.click(screen.getByRole("button", { name: "Look up" }));
    await lookUp("   ");

    expect(get).not.toHaveBeenCalled();
  });

  it("looks the trimmed name up and renders the full record", async () => {
    get.mockResolvedValue(alice);
    render(UserDetailView);

    await lookUp(" alice ");

    await waitFor(() => expect(get).toHaveBeenCalledOnce());
    expect(get).toHaveBeenCalledWith("alice");
    expect(await screen.findByText("18446744073709551615")).toBeInTheDocument();
    expect(screen.getByText("Alice")).toBeInTheDocument();
    expect(screen.getByText("admin")).toBeInTheDocument();
    expect(screen.getByText("operator")).toBeInTheDocument();
    expect(screen.getByText("enabled")).toBeInTheDocument();
    expect(screen.getByText("2026-11-12T00:00:00Z")).toBeInTheDocument();
    expect(screen.getByText("2026-11-12T01:00:00Z")).toBeInTheDocument();
  });

  it("looks up on Enter in the input", async () => {
    get.mockResolvedValue(alice);
    render(UserDetailView);

    const input = screen.getByLabelText("Username");
    await fireEvent.input(input, { target: { value: "alice" } });
    await fireEvent.keyDown(input, { key: "Enter" });

    await waitFor(() => expect(get).toHaveBeenCalledWith("alice"));
  });

  it("shows Never for a user who never logged in", async () => {
    const { last_login: _unused, ...never } = alice;
    get.mockResolvedValue(never);
    render(UserDetailView);

    await lookUp("alice");

    expect(await screen.findByText("Never")).toBeInTheDocument();
  });

  it("shows disabled for a disabled user", async () => {
    get.mockResolvedValue({ ...alice, enabled: false });
    render(UserDetailView);

    await lookUp("alice");

    expect(await screen.findByText("disabled")).toBeInTheDocument();
  });

  it("shows User not found on a 404", async () => {
    get.mockRejectedValue(Object.assign(new Error("nope"), { status: 404 }));
    render(UserDetailView);

    await lookUp("ghost");

    expect(await screen.findByText("User not found")).toBeInTheDocument();
    expect(screen.queryByText("nope")).not.toBeInTheDocument();
  });

  it("shows the message of any other failure", async () => {
    get.mockRejectedValue(new Error("backend down"));
    render(UserDetailView);

    await lookUp("alice");

    expect(await screen.findByText("backend down")).toBeInTheDocument();
  });
});
