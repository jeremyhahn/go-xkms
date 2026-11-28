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

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/svelte";
import type { SealStoreListResponse } from "@go-xkms/sdk";

const listSecrets = vi.fn<() => Promise<SealStoreListResponse>>();
const getSecret = vi.fn();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({ platform: { listSecrets, getSecret } }),
  resetSDKClient: () => {},
}));

const toasts: Array<{ kind: string; message: string }> = [];
vi.mock("../src/stores/toast.svelte.ts", () => ({
  showToast: (kind: string, message: string) => {
    toasts.push({ kind, message });
  },
}));

import PlatformSecretNamesView from "../src/views/PlatformSecretNamesView.svelte";

function renderedNames(): string[] {
  return screen.getAllByRole("listitem").map((li) => li.textContent?.trim() ?? "");
}

beforeEach(() => {
  vi.clearAllMocks();
  toasts.length = 0;
});

afterEach(() => {
  // A secret value is never fetched: the view shows names only.
  expect(getSecret).not.toHaveBeenCalled();
});

describe("PlatformSecretNamesView", () => {
  it("lists every secret name, sorted, with the total", async () => {
    listSecrets.mockResolvedValue({ names: ["tls-key", "api-token", "db-cred"], total: 3 });

    render(PlatformSecretNamesView);

    expect(await screen.findByText("db-cred")).toBeInTheDocument();
    expect(listSecrets).toHaveBeenCalledOnce();
    expect(renderedNames()).toEqual(["api-token", "db-cred", "tls-key"]);
    expect(screen.getByText("3 secrets")).toBeInTheDocument();
  });

  it("narrows the names by a case-insensitive filter without another call", async () => {
    listSecrets.mockResolvedValue({ names: ["DB-Cred", "tls-key", "db-backup"], total: 3 });

    render(PlatformSecretNamesView);
    await screen.findByText("tls-key");

    await fireEvent.input(screen.getByLabelText("Filter secret names"), { target: { value: "db" } });

    expect(renderedNames()).toEqual(["db-backup", "DB-Cred"]);
    expect(screen.queryByText("tls-key")).not.toBeInTheDocument();
    expect(listSecrets).toHaveBeenCalledOnce();
  });

  it("shows the empty state with no secrets stored", async () => {
    listSecrets.mockResolvedValue({ names: [], total: 0 });

    render(PlatformSecretNamesView);

    expect(await screen.findByText("No secrets stored")).toBeInTheDocument();
  });

  it("reloads the names on Refresh", async () => {
    listSecrets.mockResolvedValueOnce({ names: ["db-cred"], total: 1 });
    listSecrets.mockResolvedValueOnce({ names: ["db-cred", "new-key"], total: 2 });

    render(PlatformSecretNamesView);
    await screen.findByText("db-cred");

    await fireEvent.click(screen.getByRole("button", { name: "Refresh" }));

    expect(await screen.findByText("new-key")).toBeInTheDocument();
    expect(listSecrets).toHaveBeenCalledTimes(2);
    expect(screen.getByText("2 secrets")).toBeInTheDocument();
  });

  it("surfaces a list error in an alert", async () => {
    listSecrets.mockRejectedValue(new Error("seal store sealed"));

    render(PlatformSecretNamesView);

    expect(await screen.findByText("seal store sealed")).toBeInTheDocument();
    await waitFor(() => expect(screen.queryByRole("listitem")).not.toBeInTheDocument());
  });
});
