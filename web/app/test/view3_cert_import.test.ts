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
});
