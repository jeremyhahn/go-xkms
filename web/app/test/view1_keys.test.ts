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
import type { ListKeysResponse } from "@go-xkms/sdk";

const list = vi.fn<() => Promise<ListKeysResponse>>();
const generate = vi.fn();
const rotate = vi.fn();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({ keys: { list, generate, rotate } }),
  resetSDKClient: () => {},
}));

const canMock = vi.fn<(resource: string, action: string) => boolean>();
vi.mock("../src/stores/session.svelte.ts", () => ({
  can: (resource: string, action: string) => canMock(resource, action),
  hasCapability: () => false,
}));

const toasts: Array<{ kind: string; message: string }> = [];
vi.mock("../src/stores/toast.svelte.ts", () => ({
  showToast: (kind: string, message: string) => {
    toasts.push({ kind, message });
  },
}));

import KeysView from "../src/views/KeysView.svelte";

const ecKey = { key_id: "ec-1", key_type: "ecdsa", algorithm: "ecdsa-p256", backend: "tpm2" };
const rsaKey = { key_id: "rsa-1", key_type: "rsa", algorithm: "rsa-2048", backend: "software" };

beforeEach(() => {
  vi.clearAllMocks();
  toasts.length = 0;
  // Default: every action permitted, matching the "signed-in admin" case.
  canMock.mockReturnValue(true);
});

describe("KeysView", () => {
  it("shows a loading spinner then the resolved keys", async () => {
    list.mockResolvedValue({ keys: [ecKey, rsaKey], pagination: { page: 1, page_size: 50, total: 2, has_more: false } });

    render(KeysView);
    expect(document.querySelector(".loading-spinner")).not.toBeNull();

    await waitFor(() => expect(screen.getByText("ec-1")).toBeInTheDocument());
    expect(screen.getByText("rsa-2048")).toBeInTheDocument();
    expect(screen.getByText("tpm2")).toBeInTheDocument();
  });

  it("shows the empty-state message when there are no keys", async () => {
    list.mockResolvedValue({ keys: [], pagination: { page: 1, page_size: 50, total: 0, has_more: false } });
    render(KeysView);

    expect(await screen.findByText("No keys yet. Generate one to get started.")).toBeInTheDocument();
  });

  it("surfaces a list error", async () => {
    list.mockRejectedValue(new Error("key store unavailable"));
    render(KeysView);

    expect(await screen.findByText("key store unavailable")).toBeInTheDocument();
  });

  it("hides Generate and Import when the operator lacks keys:create / keys:import", async () => {
    canMock.mockReturnValue(false);
    list.mockResolvedValue({ keys: [], pagination: { page: 1, page_size: 50, total: 0, has_more: false } });

    render(KeysView);
    await screen.findByText("No keys yet. Generate one to get started.");

    expect(screen.queryByRole("button", { name: "+ Generate" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Import" })).toBeNull();
  });

  it("generates an ECDSA key with key_type as the algorithm and curve as the conditional extra", async () => {
    list.mockResolvedValue({ keys: [], pagination: { page: 1, page_size: 50, total: 0, has_more: false } });
    generate.mockResolvedValue({ key_id: "new-ec", key_type: "ecdsa" });

    render(KeysView);
    await screen.findByText("No keys yet. Generate one to get started.");
    await fireEvent.click(screen.getByRole("button", { name: "+ Generate" }));

    const keyIdInput = screen.getByPlaceholderText("my-key");
    await fireEvent.input(keyIdInput, { target: { value: "my-ec-key" } });
    // ecdsa is the default selection; curve defaults to P-256.
    list.mockResolvedValue({ keys: [{ ...ecKey, key_id: "my-ec-key" }], pagination: { page: 1, page_size: 50, total: 1, has_more: false } });
    await fireEvent.click(screen.getByRole("button", { name: "Generate", hidden: true }));

    await waitFor(() => expect(generate).toHaveBeenCalledOnce());
    // GenerateKeyRequest.key_type IS the algorithm; key_size/algorithm must
    // be absent for an ecdsa request, and curve must be present.
    expect(generate.mock.calls[0]![0]).toEqual({
      key_id: "my-ec-key",
      key_type: "ecdsa",
      exportable: false,
      curve: "P-256",
    });
    expect(toasts.some((t) => t.kind === "success" && t.message.includes("my-ec-key"))).toBe(true);
  });

  it("generates an RSA key with key_size instead of curve", async () => {
    list.mockResolvedValue({ keys: [], pagination: { page: 1, page_size: 50, total: 0, has_more: false } });
    generate.mockResolvedValue({ key_id: "new-rsa", key_type: "rsa" });

    render(KeysView);
    await screen.findByText("No keys yet. Generate one to get started.");
    await fireEvent.click(screen.getByRole("button", { name: "+ Generate" }));

    await fireEvent.input(screen.getByPlaceholderText("my-key"), { target: { value: "my-rsa-key" } });
    const typeSelect = screen.getByDisplayValue("ecdsa");
    await fireEvent.change(typeSelect, { target: { value: "rsa" } });
    await fireEvent.click(screen.getByRole("button", { name: "Generate", hidden: true }));

    await waitFor(() => expect(generate).toHaveBeenCalledOnce());
    const req = generate.mock.calls[0]![0];
    expect(req).toEqual({
      key_id: "my-rsa-key",
      key_type: "rsa",
      exportable: false,
      key_size: 2048,
    });
    expect(req).not.toHaveProperty("curve");
  });

  it("generates a symmetric key with algorithm instead of curve/key_size", async () => {
    list.mockResolvedValue({ keys: [], pagination: { page: 1, page_size: 50, total: 0, has_more: false } });
    generate.mockResolvedValue({ key_id: "new-sym", key_type: "symmetric" });

    render(KeysView);
    await screen.findByText("No keys yet. Generate one to get started.");
    await fireEvent.click(screen.getByRole("button", { name: "+ Generate" }));

    await fireEvent.input(screen.getByPlaceholderText("my-key"), { target: { value: "my-sym-key" } });
    const typeSelect = screen.getByDisplayValue("ecdsa");
    await fireEvent.change(typeSelect, { target: { value: "symmetric" } });
    await fireEvent.click(screen.getByRole("button", { name: "Generate", hidden: true }));

    await waitFor(() => expect(generate).toHaveBeenCalledOnce());
    const req = generate.mock.calls[0]![0];
    expect(req).toEqual({
      key_id: "my-sym-key",
      key_type: "symmetric",
      exportable: false,
      algorithm: "aes-256-gcm",
    });
  });

  it("keeps the dialog open and shows the error when generation fails", async () => {
    list.mockResolvedValue({ keys: [], pagination: { page: 1, page_size: 50, total: 0, has_more: false } });
    generate.mockRejectedValue(new Error("key_id already exists"));

    render(KeysView);
    await screen.findByText("No keys yet. Generate one to get started.");
    await fireEvent.click(screen.getByRole("button", { name: "+ Generate" }));
    await fireEvent.input(screen.getByPlaceholderText("my-key"), { target: { value: "dup-key" } });
    await fireEvent.click(screen.getByRole("button", { name: "Generate", hidden: true }));

    expect(await screen.findByText("key_id already exists")).toBeInTheDocument();
    // Dialog stays open (Cancel button is still present) so the operator can
    // correct the key id.
    expect(screen.getByRole("button", { name: "Cancel", hidden: true })).toBeInTheDocument();
  });

  it("opens the key detail drawer showing the clicked key's id", async () => {
    list.mockResolvedValue({ keys: [ecKey, rsaKey], pagination: { page: 1, page_size: 50, total: 2, has_more: false } });

    render(KeysView);
    await screen.findByText("ec-1");
    await fireEvent.click(screen.getByText("ec-1"));

    // KeyDetail renders the key id as a drawer heading and its
    // type/algorithm/backend summary line.
    expect(await screen.findByText("ecdsa · ecdsa-p256 · tpm2")).toBeInTheDocument();
  });

  it("closes the drawer and reloads the list when a KeyDetail mutation reports onChanged", async () => {
    list.mockResolvedValue({ keys: [ecKey], pagination: { page: 1, page_size: 50, total: 1, has_more: false } });
    rotate.mockResolvedValue({ success: true, key_id: "ec-1", key_type: "ecdsa" });

    render(KeysView);
    await screen.findByText("ec-1");
    await fireEvent.click(screen.getByText("ec-1"));
    await screen.findByText("ecdsa · ecdsa-p256 · tpm2");

    await fireEvent.click(screen.getByRole("button", { name: "Rotate" }));

    await waitFor(() => expect(rotate).toHaveBeenCalledWith("ec-1", "tpm2"));
    // onChanged clears `selected` (drawer closes) and reloads the key list.
    await waitFor(() => expect(screen.queryByText("ecdsa · ecdsa-p256 · tpm2")).toBeNull());
    await waitFor(() => expect(list).toHaveBeenCalledTimes(2));
  });
});
