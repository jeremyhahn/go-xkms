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
import type { BackendInfo, KeyInfo } from "@go-xkms/sdk";

const backendsList = vi.fn();
const exportKey = vi.fn();
const copyKey = vi.fn();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({
    backends: { list: backendsList },
    keys: { export: exportKey, copy: copyKey },
  }),
  resetSDKClient: () => {},
}));

const toasts: Array<{ kind: string; message: string }> = [];
vi.mock("../src/stores/toast.svelte.ts", () => ({
  showToast: (kind: string, message: string) => {
    toasts.push({ kind, message });
  },
}));

import TransferPanel from "../src/components/keys/TransferPanel.svelte";

const sourceKey: KeyInfo = {
  key_id: "vault-aes",
  key_type: "symmetric",
  algorithm: "aes-256-gcm",
  backend: "software",
};

const backends: BackendInfo[] = [
  { id: "software", type: "software", hardware_backed: false, capabilities: {} as never },
  { id: "tpm2", type: "tpm2", hardware_backed: true, capabilities: {} as never },
];

beforeEach(() => {
  vi.clearAllMocks();
  toasts.length = 0;
  backendsList.mockResolvedValue({ backends, pagination: {} });
  Object.defineProperty(navigator, "clipboard", {
    value: { writeText: vi.fn().mockResolvedValue(undefined) },
    configurable: true,
  });
});

describe("TransferPanel", () => {
  it("exports the key wrapped and displays the wrapped blob and import token", async () => {
    exportKey.mockResolvedValue({
      wrapped_key: "d3JhcHBlZA==",
      algorithm: "RSAES_OAEP_SHA_256",
      import_token: "tok-1",
    });
    render(TransferPanel, { props: { keyInfo: sourceKey, onChanged: () => {} } });
    await waitFor(() => expect(backendsList).toHaveBeenCalledOnce());

    await fireEvent.click(screen.getByRole("button", { name: /Export wrapped/ }));

    await waitFor(() => expect(exportKey).toHaveBeenCalledOnce());
    expect(exportKey.mock.calls[0]![0]).toBe("vault-aes");
    expect(exportKey.mock.calls[0]![1]).toMatchObject({ backend: "software" });
    // The material must never be requested from the key itself — only the
    // wrapped export request is sent.
    expect(exportKey.mock.calls[0]![1]).not.toHaveProperty("key_material");
    expect(await screen.findByText("d3JhcHBlZA==")).toBeInTheDocument();
    expect(screen.getByText("tok-1")).toBeInTheDocument();
  });

  it("surfaces a server error from export instead of a stale result", async () => {
    exportKey.mockRejectedValue(new Error("backend cannot export this key type"));
    render(TransferPanel, { props: { keyInfo: sourceKey, onChanged: () => {} } });
    await waitFor(() => expect(backendsList).toHaveBeenCalledOnce());

    await fireEvent.click(screen.getByRole("button", { name: /Export wrapped/ }));

    expect(await screen.findByText("backend cannot export this key type")).toBeInTheDocument();
  });

  it("refuses to copy the key onto itself in the same backend", async () => {
    render(TransferPanel, { props: { keyInfo: sourceKey, onChanged: () => {} } });
    await waitFor(() => expect(backendsList).toHaveBeenCalledOnce());

    await fireEvent.change(screen.getByLabelText("Destination backend"), { target: { value: "software" } });
    await fireEvent.input(screen.getByLabelText("Destination key ID"), { target: { value: "vault-aes" } });
    await fireEvent.click(screen.getByRole("button", { name: /Copy key/ }));

    expect(await screen.findByText("Destination must differ from the source key.")).toBeInTheDocument();
    expect(copyKey).not.toHaveBeenCalled();
  });

  it("requires a destination backend and key ID before copying", async () => {
    render(TransferPanel, { props: { keyInfo: sourceKey, onChanged: () => {} } });
    await waitFor(() => expect(backendsList).toHaveBeenCalledOnce());

    await fireEvent.click(screen.getByRole("button", { name: /Copy key/ }));

    expect(await screen.findByText("Destination backend and key ID are required.")).toBeInTheDocument();
    expect(copyKey).not.toHaveBeenCalled();
  });

  it("copies a key to a different backend and notifies the caller", async () => {
    copyKey.mockResolvedValue({ key_id: "vault-aes-copy", backend: "tpm2" });
    const onChanged = vi.fn();
    render(TransferPanel, { props: { keyInfo: sourceKey, onChanged } });
    await waitFor(() => expect(backendsList).toHaveBeenCalledOnce());

    await fireEvent.change(screen.getByLabelText("Destination backend"), { target: { value: "tpm2" } });
    await fireEvent.click(screen.getByRole("button", { name: /Copy key/ }));

    await waitFor(() => expect(copyKey).toHaveBeenCalledOnce());
    expect(copyKey.mock.calls[0]![0]).toMatchObject({
      source_backend: "software",
      source_key_id: "vault-aes",
      dest_backend: "tpm2",
      dest_key_id: "vault-aes-copy",
      algorithm: "RSAES_OAEP_SHA_256",
    });
    // Copy takes the key's attributes from the source (go-xkms#1223).
    expect(copyKey.mock.calls[0]![0]).not.toHaveProperty("key_type");
    expect(copyKey.mock.calls[0]![0]).not.toHaveProperty("key_size");
    expect(copyKey.mock.calls[0]![0]).not.toHaveProperty("curve");
    expect(onChanged).toHaveBeenCalledOnce();
    expect(toasts.some((t) => t.kind === "success")).toBe(true);
  });

  it("surfaces a server error from copy without calling onChanged", async () => {
    copyKey.mockRejectedValue(new Error("destination backend is full"));
    const onChanged = vi.fn();
    render(TransferPanel, { props: { keyInfo: sourceKey, onChanged } });
    await waitFor(() => expect(backendsList).toHaveBeenCalledOnce());

    await fireEvent.change(screen.getByLabelText("Destination backend"), { target: { value: "tpm2" } });
    await fireEvent.click(screen.getByRole("button", { name: /Copy key/ }));

    expect(await screen.findByText("destination backend is full")).toBeInTheDocument();
    expect(onChanged).not.toHaveBeenCalled();
  });

  it("shows a warning banner (but does not crash) when the backend list fails to load", async () => {
    backendsList.mockRejectedValue(new Error("unreachable"));
    render(TransferPanel, { props: { keyInfo: sourceKey, onChanged: () => {} } });

    expect(await screen.findByText(/Could not list backends: unreachable/)).toBeInTheDocument();
  });

  it("copies the wrapped export result to the clipboard", async () => {
    exportKey.mockResolvedValue({ wrapped_key: "d3JhcHBlZA==", algorithm: "AES_KEY_WRAP" });
    render(TransferPanel, { props: { keyInfo: sourceKey, onChanged: () => {} } });
    await waitFor(() => expect(backendsList).toHaveBeenCalledOnce());

    await fireEvent.click(screen.getByRole("button", { name: /Export wrapped/ }));
    await screen.findByText("d3JhcHBlZA==");
    await fireEvent.click(screen.getByRole("button", { name: "Copy" }));

    await waitFor(() => expect(navigator.clipboard.writeText).toHaveBeenCalledWith("d3JhcHBlZA=="));
    expect(toasts.some((t) => t.kind === "success" && t.message.includes("copied"))).toBe(true);
  });
});
