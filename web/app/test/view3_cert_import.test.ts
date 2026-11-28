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
import type { ListBackendsResponse, SaveCertRequest, SaveCertChainRequest, SuccessResponse } from "@go-xkms/sdk";

const list = vi.fn<() => Promise<ListBackendsResponse>>();
const save = vi.fn<(keyId: string, backend: string, req: SaveCertRequest) => Promise<SuccessResponse>>();
const exists = vi.fn<(id: string, backend: string) => Promise<boolean>>();
const saveChain = vi.fn<(id: string, req: SaveCertChainRequest) => Promise<SuccessResponse>>();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({ backends: { list }, certs: { save, exists, saveChain } }),
  resetSDKClient: () => {},
}));

const toasts: Array<{ kind: string; message: string }> = [];
vi.mock("../src/stores/toast.svelte.ts", () => ({
  showToast: (kind: string, message: string) => {
    toasts.push({ kind, message });
  },
}));

import CertImportView from "../src/views/CertImportView.svelte";

const LEAF = "-----BEGIN CERTIFICATE-----\nTEVBRg==\n-----END CERTIFICATE-----";
const INT1 = "-----BEGIN CERTIFICATE-----\nSU5UMQ==\n-----END CERTIFICATE-----";
const INT2 = "-----BEGIN CERTIFICATE-----\nSU5UMg==\n-----END CERTIFICATE-----";

function backendsResponse(): ListBackendsResponse {
  return {
    backends: [
      { id: "pkcs8", type: "pkcs8", hardware_backed: false },
      { id: "tpm2", type: "tpm2", hardware_backed: true },
    ],
    pagination: { page: 1, page_size: 50, total: 2 },
  } as unknown as ListBackendsResponse;
}

async function mountReady(): Promise<void> {
  render(CertImportView);
  await screen.findByRole("option", { name: "tpm2" });
}

async function fill(keyId: string, backend: string, pem: string, chain = ""): Promise<void> {
  await fireEvent.input(screen.getByLabelText("Key ID"), { target: { value: keyId } });
  await fireEvent.change(screen.getByLabelText("Backend"), { target: { value: backend } });
  await fireEvent.input(screen.getByLabelText("Certificate PEM"), { target: { value: pem } });
  if (chain !== "") {
    await fireEvent.input(screen.getByLabelText("Chain PEM"), { target: { value: chain } });
  }
}

function importButton(): HTMLButtonElement {
  return screen.getByRole("button", { name: "Import" }) as HTMLButtonElement;
}

beforeEach(() => {
  vi.clearAllMocks();
  toasts.length = 0;
  list.mockResolvedValue(backendsResponse());
});

describe("CertImportView", () => {
  it("loads the backends once and lists each id in the select", async () => {
    await mountReady();

    expect(list).toHaveBeenCalledOnce();
    expect(screen.getByRole("option", { name: "pkcs8" })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: "tpm2" })).toBeInTheDocument();
  });

  it("keeps Import disabled until key id, backend and a PEM certificate are set", async () => {
    await mountReady();
    expect(importButton().disabled).toBe(true);

    await fireEvent.input(screen.getByLabelText("Key ID"), { target: { value: "k1" } });
    expect(importButton().disabled).toBe(true);
    await fireEvent.change(screen.getByLabelText("Backend"), { target: { value: "pkcs8" } });
    expect(importButton().disabled).toBe(true);
    await fireEvent.input(screen.getByLabelText("Certificate PEM"), { target: { value: LEAF } });
    expect(importButton().disabled).toBe(false);
  });

  it("shows an inline error for a non-PEM paste and sends nothing", async () => {
    await mountReady();
    await fill("k1", "pkcs8", "not a certificate");

    expect(screen.getByText(/-----BEGIN CERTIFICATE-----/)).toBeInTheDocument();
    expect(importButton().disabled).toBe(true);
    await fireEvent.click(importButton());
    expect(exists).not.toHaveBeenCalled();
    expect(save).not.toHaveBeenCalled();
    expect(saveChain).not.toHaveBeenCalled();
  });

  it("stores a new certificate and toasts success", async () => {
    exists.mockResolvedValue(false);
    save.mockResolvedValue({ success: true });
    await mountReady();
    await fill("k1", "pkcs8", LEAF);

    await fireEvent.click(importButton());

    await waitFor(() => expect(save).toHaveBeenCalledOnce());
    expect(exists).toHaveBeenCalledWith("k1", "pkcs8");
    expect(save).toHaveBeenCalledWith("k1", "pkcs8", { backend: "pkcs8", certificate_pem: LEAF });
    expect(saveChain).not.toHaveBeenCalled();
    await waitFor(() => expect(toasts.some((t) => t.kind === "success")).toBe(true));
  });

  it("stores the chain blocks after the certificate", async () => {
    exists.mockResolvedValue(false);
    save.mockResolvedValue({ success: true });
    saveChain.mockResolvedValue({ success: true });
    await mountReady();
    await fill("k1", "tpm2", LEAF, `${INT1}\n${INT2}\n`);

    await fireEvent.click(importButton());

    await waitFor(() => expect(saveChain).toHaveBeenCalledOnce());
    expect(saveChain).toHaveBeenCalledWith("k1", { backend: "tpm2", cert_chain_pem: [INT1, INT2] });
    expect(save.mock.invocationCallOrder[0]!).toBeLessThan(saveChain.mock.invocationCallOrder[0]!);
  });

  it("asks before overwriting an existing certificate and saves after Confirm", async () => {
    exists.mockResolvedValue(true);
    save.mockResolvedValue({ success: true });
    await mountReady();
    await fill("k1", "pkcs8", LEAF);

    await fireEvent.click(importButton());

    expect(await screen.findByText(/already exists for key "k1"/)).toBeInTheDocument();
    expect(save).not.toHaveBeenCalled();
    await fireEvent.click(screen.getByRole("button", { name: "Confirm" }));
    await waitFor(() => expect(save).toHaveBeenCalledOnce());
  });

  it("sends nothing when the overwrite is cancelled", async () => {
    exists.mockResolvedValue(true);
    await mountReady();
    await fill("k1", "pkcs8", LEAF, INT1);

    await fireEvent.click(importButton());
    await screen.findByText(/already exists for key "k1"/);
    await fireEvent.click(screen.getByRole("button", { name: "Cancel" }));

    expect(screen.queryByText(/already exists for key "k1"/)).not.toBeInTheDocument();
    expect(save).not.toHaveBeenCalled();
    expect(saveChain).not.toHaveBeenCalled();
  });

  it("shows a save failure and does not store the chain", async () => {
    exists.mockResolvedValue(false);
    save.mockRejectedValue(new Error("key not found"));
    await mountReady();
    await fill("k1", "pkcs8", LEAF, INT1);

    await fireEvent.click(importButton());

    expect(await screen.findByText(/key not found/)).toBeInTheDocument();
    expect(saveChain).not.toHaveBeenCalled();
  });

  it("says the certificate was stored when only the chain fails", async () => {
    exists.mockResolvedValue(false);
    save.mockResolvedValue({ success: true });
    saveChain.mockRejectedValue(new Error("chain rejected"));
    await mountReady();
    await fill("k1", "pkcs8", LEAF, INT1);

    await fireEvent.click(importButton());

    expect(await screen.findByText(/certificate was stored but the chain was not: chain rejected/)).toBeInTheDocument();
  });

  // A caller with certs:enroll and certs:read but not backends:list types
  // the backend, as SealView does, and can still import.
  it("takes a typed backend and imports when backends.list() is refused", async () => {
    list.mockReset();
    list.mockRejectedValue(new Error("403 Forbidden: backends:list"));
    exists.mockResolvedValue(false);
    save.mockResolvedValue({ success: true });
    render(CertImportView);
    expect(await screen.findByText(/backends:list/)).toBeInTheDocument();

    const field = screen.getByLabelText("Backend");
    expect(field.tagName).toBe("INPUT");
    await fireEvent.input(screen.getByLabelText("Key ID"), { target: { value: "k1" } });
    await fireEvent.input(field, { target: { value: " tpm2 " } });
    await fireEvent.input(screen.getByLabelText("Certificate PEM"), { target: { value: LEAF } });
    expect(importButton().disabled).toBe(false);

    await fireEvent.click(importButton());

    await waitFor(() => expect(save).toHaveBeenCalledOnce());
    expect(exists).toHaveBeenCalledWith("k1", "tpm2");
    expect(save).toHaveBeenCalledWith("k1", "tpm2", { backend: "tpm2", certificate_pem: LEAF });
  });

  // POST /certs needs only certs:enroll, but HEAD /certs/{id} needs
  // certs:read: a refused overwrite check asks before it may overwrite.
  it("asks for confirmation and imports after Confirm when the overwrite check is refused", async () => {
    exists.mockRejectedValue(Object.assign(new Error("403 Forbidden: certs:read"), { status: 403 }));
    save.mockResolvedValue({ success: true });
    await mountReady();
    await fill("k1", "pkcs8", LEAF);

    await fireEvent.click(importButton());

    expect(await screen.findByText(/could not check whether a certificate exists for key "k1"/i)).toBeInTheDocument();
    expect(screen.queryByText(/403 Forbidden/)).not.toBeInTheDocument();
    expect(save).not.toHaveBeenCalled();
    await fireEvent.click(screen.getByRole("button", { name: "Confirm" }));
    await waitFor(() => expect(save).toHaveBeenCalledOnce());
    expect(save).toHaveBeenCalledWith("k1", "pkcs8", { backend: "pkcs8", certificate_pem: LEAF });
    await waitFor(() => expect(toasts.some((t) => t.kind === "success")).toBe(true));
  });

  it("sends nothing and re-enables the inputs when the refused-check confirm is cancelled", async () => {
    exists.mockRejectedValue(Object.assign(new Error("403 Forbidden: certs:read"), { status: 403 }));
    await mountReady();
    await fill("k1", "pkcs8", LEAF, INT1);

    await fireEvent.click(importButton());
    await screen.findByText(/could not check/i);
    await fireEvent.click(screen.getByRole("button", { name: "Cancel" }));

    expect(screen.queryByText(/could not check/i)).not.toBeInTheDocument();
    expect(save).not.toHaveBeenCalled();
    expect(saveChain).not.toHaveBeenCalled();
    expect(screen.getByLabelText("Key ID")).not.toBeDisabled();
    expect(screen.getByLabelText("Backend")).not.toBeDisabled();
    expect(screen.getByLabelText("Certificate PEM")).not.toBeDisabled();
    expect(screen.getByLabelText("Chain PEM")).not.toBeDisabled();
  });

  it("shows any other overwrite-check failure and never saves", async () => {
    exists.mockRejectedValue(Object.assign(new Error("boom"), { status: 500 }));
    await mountReady();
    await fill("k1", "pkcs8", LEAF);

    await fireEvent.click(importButton());

    expect(await screen.findByText(/boom/)).toBeInTheDocument();
    expect(screen.queryByText(/could not check/i)).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Confirm" })).not.toBeInTheDocument();
    expect(save).not.toHaveBeenCalled();
  });
});

describe("CertImportView frozen target", () => {
  it("stores to the key and backend the overwrite check was made for", async () => {
    exists.mockResolvedValue(true);
    save.mockResolvedValue({ success: true });
    await mountReady();
    await fill("k1", "pkcs8", LEAF, INT1);
    await fireEvent.click(importButton());
    await screen.findByRole("button", { name: "Confirm" });

    await fireEvent.input(screen.getByLabelText("Key ID"), { target: { value: "k2" } });
    await fireEvent.change(screen.getByLabelText("Backend"), { target: { value: "tpm2" } });
    await fireEvent.input(screen.getByLabelText("Certificate PEM"), { target: { value: INT2 } });
    await fireEvent.input(screen.getByLabelText("Chain PEM"), { target: { value: "" } });
    await fireEvent.click(screen.getByRole("button", { name: "Confirm" }));

    await waitFor(() => expect(save).toHaveBeenCalledOnce());
    expect(save).toHaveBeenCalledWith("k1", "pkcs8", { backend: "pkcs8", certificate_pem: LEAF });
    await waitFor(() => expect(saveChain).toHaveBeenCalledWith("k1", { backend: "pkcs8", cert_chain_pem: [INT1] }));
  });

  it("freezes the inputs while the overwrite confirm is open", async () => {
    exists.mockResolvedValue(true);
    await mountReady();
    await fill("k1", "pkcs8", LEAF);
    await fireEvent.click(importButton());
    await screen.findByRole("button", { name: "Confirm" });

    expect(screen.getByLabelText("Key ID")).toBeDisabled();
    expect(screen.getByLabelText("Backend")).toBeDisabled();
    expect(screen.getByLabelText("Certificate PEM")).toBeDisabled();
    expect(screen.getByLabelText("Chain PEM")).toBeDisabled();

    await fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(screen.getByLabelText("Key ID")).not.toBeDisabled();
  });

  it("freezes the inputs while the overwrite check is pending", async () => {
    let resolveExists: (v: boolean) => void = () => {};
    exists.mockImplementation(() => new Promise<boolean>((r) => (resolveExists = r)));
    save.mockResolvedValue({ success: true });
    await mountReady();
    await fill("k1", "pkcs8", LEAF);
    await fireEvent.click(importButton());
    await waitFor(() => expect(exists).toHaveBeenCalledOnce());

    expect(screen.getByLabelText("Key ID")).toBeDisabled();
    expect(screen.getByLabelText("Backend")).toBeDisabled();
    resolveExists(false);
    await waitFor(() => expect(save).toHaveBeenCalledWith("k1", "pkcs8", { backend: "pkcs8", certificate_pem: LEAF }));
  });
});
