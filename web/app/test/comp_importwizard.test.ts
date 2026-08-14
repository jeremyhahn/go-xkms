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
import type { BackendInfo } from "@go-xkms/sdk";

const backendsList = vi.fn();
const importParams = vi.fn();
const wrap = vi.fn();
const importKey = vi.fn();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({
    backends: { list: backendsList },
    keys: { importParams, wrap, import: importKey },
  }),
  resetSDKClient: () => {},
}));

const toasts: Array<{ kind: string; message: string }> = [];
vi.mock("../src/stores/toast.svelte.ts", () => ({
  showToast: (kind: string, message: string) => {
    toasts.push({ kind, message });
  },
}));

import ImportWizard from "../src/components/keys/ImportWizard.svelte";

const backends: BackendInfo[] = [
  { id: "software", type: "software", hardware_backed: false, capabilities: {} as never },
  { id: "tpm2", type: "tpm2", hardware_backed: true, capabilities: {} as never },
];

beforeEach(() => {
  vi.clearAllMocks();
  toasts.length = 0;
  backendsList.mockResolvedValue({ backends, pagination: {} });
  importParams.mockResolvedValue({
    wrapping_public_key_pem: "-----BEGIN PUBLIC KEY-----\nAA==\n-----END PUBLIC KEY-----",
    algorithm: "RSAES_OAEP_SHA_256",
  });
  Object.defineProperty(navigator, "clipboard", {
    value: { writeText: vi.fn().mockResolvedValue(undefined) },
    configurable: true,
  });
});

/** Renders the wizard and advances it to step 2 (wrapping parameters shown). */
async function toStep2(props?: { onClose?: () => void; onImported?: () => void }): Promise<void> {
  render(ImportWizard, { props: { onClose: props?.onClose ?? (() => {}), onImported: props?.onImported ?? (() => {}) } });
  await waitFor(() => expect(backendsList).toHaveBeenCalledOnce());
  await fireEvent.input(screen.getByLabelText("Key ID"), { target: { value: "new-key" } });
  await fireEvent.click(screen.getByRole("button", { name: "Get wrapping parameters", hidden: true }));
  await screen.findByText(/BEGIN PUBLIC KEY/);
}

/** Advances from step 2 to step 3 (wrapped-key entry). */
async function toStep3(props?: { onClose?: () => void; onImported?: () => void }): Promise<void> {
  await toStep2(props);
  await fireEvent.click(screen.getByRole("button", { name: "Continue", hidden: true }));
  await screen.findByLabelText("Wrapped key (base64)");
}

describe("ImportWizard", () => {
  it("preselects the first backend once the backend list loads", async () => {
    render(ImportWizard, { props: { onClose: () => {}, onImported: () => {} } });
    await waitFor(() => expect(backendsList).toHaveBeenCalledOnce());

    const select = (await screen.findByLabelText("Backend")) as HTMLSelectElement;
    await waitFor(() => expect(select.value).toBe("software"));
  });

  it("refuses to request wrapping parameters without a key ID", async () => {
    render(ImportWizard, { props: { onClose: () => {}, onImported: () => {} } });
    await waitFor(() => expect(backendsList).toHaveBeenCalledOnce());

    await fireEvent.click(screen.getByRole("button", { name: "Get wrapping parameters", hidden: true }));

    expect(await screen.findByText("Backend and key ID are required.")).toBeInTheDocument();
    expect(importParams).not.toHaveBeenCalled();
  });

  it("advances to step 2 and shows the wrapping key and import token once parameters are issued", async () => {
    importParams.mockResolvedValue({
      wrapping_public_key_pem: "-----BEGIN PUBLIC KEY-----\nAA==\n-----END PUBLIC KEY-----",
      algorithm: "RSAES_OAEP_SHA_256",
      import_token: "tok-1",
    });
    await toStep2();

    expect(importParams.mock.calls[0]![0]).toMatchObject({ backend: "software", key_id: "new-key" });
    expect(screen.getByText(/single-use import token issued/)).toBeInTheDocument();
  });

  it("surfaces a server error from fetchParams and stays on step 1", async () => {
    importParams.mockRejectedValue(new Error("backend does not support import"));
    render(ImportWizard, { props: { onClose: () => {}, onImported: () => {} } });
    await waitFor(() => expect(backendsList).toHaveBeenCalledOnce());

    await fireEvent.input(screen.getByLabelText("Key ID"), { target: { value: "new-key" } });
    await fireEvent.click(screen.getByRole("button", { name: "Get wrapping parameters", hidden: true }));

    expect(await screen.findByText("backend does not support import")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Get wrapping parameters", hidden: true })).toBeInTheDocument();
  });

  it("copies the wrapping public key to the clipboard from step 2", async () => {
    await toStep2();
    await fireEvent.click(screen.getByRole("button", { name: "Copy", hidden: true }));

    await waitFor(() => expect(navigator.clipboard.writeText).toHaveBeenCalledOnce());
    expect(toasts.some((t) => t.kind === "success" && t.message.includes("copied"))).toBe(true);
  });

  it("refuses to import a wrapped key that is not base64", async () => {
    await toStep3();
    await fireEvent.input(screen.getByLabelText("Wrapped key (base64)"), { target: { value: "not base64!!" } });
    await fireEvent.click(screen.getByRole("button", { name: "Import key", hidden: true }));

    expect(await screen.findByText("Wrapped key must be base64.")).toBeInTheDocument();
    expect(importKey).not.toHaveBeenCalled();
  });

  it("imports a valid wrapped key and notifies + closes the wizard", async () => {
    importKey.mockResolvedValue({ key_id: "new-key", backend: "software", success: true });
    const onImported = vi.fn();
    const onClose = vi.fn();

    await toStep3({ onClose, onImported });

    await fireEvent.input(screen.getByLabelText("Wrapped key (base64)"), { target: { value: "d3JhcHBlZA==" } });
    await fireEvent.click(screen.getByRole("button", { name: "Import key", hidden: true }));

    await waitFor(() => expect(importKey).toHaveBeenCalledOnce());
    expect(importKey.mock.calls[0]![0]).toMatchObject({ backend: "software", key_id: "new-key" });
    expect(onImported).toHaveBeenCalledOnce();
    expect(onClose).toHaveBeenCalledOnce();
    expect(toasts.some((t) => t.kind === "success")).toBe(true);
  });

  it("surfaces a server error from doImport and does not close the wizard", async () => {
    importKey.mockRejectedValue(new Error("import token expired"));
    const onClose = vi.fn();
    await toStep3({ onClose });

    await fireEvent.input(screen.getByLabelText("Wrapped key (base64)"), { target: { value: "d3JhcHBlZA==" } });
    await fireEvent.click(screen.getByRole("button", { name: "Import key", hidden: true }));

    expect(await screen.findByText("import token expired")).toBeInTheDocument();
    expect(onClose).not.toHaveBeenCalled();
  });

  it("refuses to wrap plaintext material that is not base64, without calling the SDK", async () => {
    await toStep3();
    await fireEvent.click(screen.getByText("Wrap plaintext material here instead"));
    const plainInput = screen.getByPlaceholderText("Key material (base64)");
    await fireEvent.input(plainInput, { target: { value: "not base64!!" } });
    await fireEvent.click(screen.getByRole("button", { name: "Wrap material", hidden: true }));

    expect(await screen.findByText("Key material must be base64.")).toBeInTheDocument();
    expect(wrap).not.toHaveBeenCalled();
  });

  it("wraps valid plaintext material server-side and populates the wrapped-key field", async () => {
    wrap.mockResolvedValue({ wrapped_key: "d3JhcHBlZA==", algorithm: "RSAES_OAEP_SHA_256" });
    await toStep3();
    await fireEvent.click(screen.getByText("Wrap plaintext material here instead"));
    await fireEvent.input(screen.getByPlaceholderText("Key material (base64)"), {
      target: { value: "cGxhaW50ZXh0" },
    });
    await fireEvent.click(screen.getByRole("button", { name: "Wrap material", hidden: true }));

    await waitFor(() => expect(wrap).toHaveBeenCalledOnce());
    // Once populated, the label also shows a byte-count hint, so match loosely.
    expect((screen.getByLabelText(/Wrapped key \(base64\)/) as HTMLTextAreaElement).value).toBe(
      "d3JhcHBlZA==",
    );
    expect(toasts.some((t) => t.kind === "success")).toBe(true);
  });

  it("calls onClose when the wizard is cancelled on step 1", async () => {
    const onClose = vi.fn();
    render(ImportWizard, { props: { onClose, onImported: () => {} } });
    await waitFor(() => expect(backendsList).toHaveBeenCalledOnce());

    await fireEvent.click(screen.getByRole("button", { name: "Cancel", hidden: true }));
    expect(onClose).toHaveBeenCalledOnce();
  });
});
