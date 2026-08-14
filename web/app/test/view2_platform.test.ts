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
import type { SealStoreStatusResponse, SealStorePutRequest } from "@go-xkms/sdk";

const status = vi.fn<() => Promise<SealStoreStatusResponse>>();
const putSecret = vi.fn<(key: string, req: SealStorePutRequest) => Promise<{ name: string; message: string }>>();
const resealSecret = vi.fn();
const deleteSecret = vi.fn();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({ platform: { status, putSecret, resealSecret, deleteSecret } }),
  resetSDKClient: () => {},
}));

const toasts: Array<{ kind: string; message: string }> = [];
vi.mock("../src/stores/toast.svelte.ts", () => ({
  showToast: (kind: string, message: string) => {
    toasts.push({ kind, message });
  },
}));

import PlatformView from "../src/views/PlatformView.svelte";

beforeEach(() => {
  vi.clearAllMocks();
  toasts.length = 0;
});

describe("PlatformView", () => {
  it("renders the real secret names once loaded", async () => {
    status.mockResolvedValue({ available: true, names: ["db-cred", "tls-key"], total: 2 });

    render(PlatformView);

    expect(await screen.findByText("db-cred")).toBeInTheDocument();
    expect(screen.getByText("tls-key")).toBeInTheDocument();
    expect(screen.getByText("available")).toBeInTheDocument();
    expect(screen.getByText("2 secrets")).toBeInTheDocument();
  });

  it("shows the empty state with no secrets stored", async () => {
    status.mockResolvedValue({ available: true, names: [], total: 0 });

    render(PlatformView);

    expect(await screen.findByText("No secrets stored.")).toBeInTheDocument();
  });

  it("surfaces a status error instead of a blank page", async () => {
    status.mockRejectedValue(new Error("seal store sealed"));

    render(PlatformView);

    expect(await screen.findByText("seal store sealed")).toBeInTheDocument();
  });

  it("stores a secret with both name and a base64-encoded secret", async () => {
    status.mockResolvedValue({ available: true, names: [], total: 0 });
    putSecret.mockResolvedValue({ name: "api-key", message: "" });

    render(PlatformView);
    await screen.findByText("No secrets stored.");

    await fireEvent.click(screen.getByRole("button", { name: "+ Store" }));
    await fireEvent.input(screen.getByPlaceholderText("Name"), { target: { value: "api-key" } });
    await fireEvent.input(screen.getByPlaceholderText("Secret value"), { target: { value: "hunter2" } });
    await fireEvent.click(screen.getByRole("button", { name: "Store", hidden: true }));

    await waitFor(() => expect(putSecret).toHaveBeenCalledOnce());
    const [key, req] = putSecret.mock.calls[0]!;
    expect(key).toBe("api-key");
    // SealStorePutRequest needs BOTH name and secret; secret is base64 of the UTF-8 bytes.
    expect(req).toEqual({ name: "api-key", secret: "aHVudGVyMg==" });
  });

  it("surfaces a store failure inside the dialog", async () => {
    status.mockResolvedValue({ available: true, names: [], total: 0 });
    putSecret.mockRejectedValue(new Error("platform store is sealed"));

    render(PlatformView);
    await screen.findByText("No secrets stored.");

    await fireEvent.click(screen.getByRole("button", { name: "+ Store" }));
    await fireEvent.input(screen.getByPlaceholderText("Name"), { target: { value: "api-key" } });
    await fireEvent.input(screen.getByPlaceholderText("Secret value"), { target: { value: "hunter2" } });
    await fireEvent.click(screen.getByRole("button", { name: "Store", hidden: true }));

    expect(await screen.findByText("platform store is sealed")).toBeInTheDocument();
  });

  it("reseals a named secret", async () => {
    status.mockResolvedValue({ available: true, names: ["db-cred"], total: 1 });
    resealSecret.mockResolvedValue({ name: "db-cred", message: "" });

    render(PlatformView);
    await screen.findByText("db-cred");

    await fireEvent.click(screen.getByRole("button", { name: "Reseal" }));

    await waitFor(() => expect(resealSecret).toHaveBeenCalledWith("db-cred"));
    expect(toasts).toContainEqual({ kind: "success", message: 'Secret "db-cred" resealed.' });
  });

  it("deletes a named secret and reloads", async () => {
    status.mockResolvedValueOnce({ available: true, names: ["db-cred"], total: 1 });
    deleteSecret.mockResolvedValue({ message: "" });
    status.mockResolvedValueOnce({ available: true, names: [], total: 0 });

    render(PlatformView);
    await screen.findByText("db-cred");

    await fireEvent.click(screen.getByRole("button", { name: "Delete" }));

    await waitFor(() => expect(deleteSecret).toHaveBeenCalledWith("db-cred"));
    expect(await screen.findByText("No secrets stored.")).toBeInTheDocument();
  });
});
