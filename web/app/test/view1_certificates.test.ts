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
import type { ListCertsResponse, GetCertResponse, GetCertChainResponse } from "@go-xkms/sdk";

const list = vi.fn<() => Promise<ListCertsResponse>>();
const get = vi.fn<(id: string, backend: string) => Promise<GetCertResponse>>();
const getChain = vi.fn<(id: string) => Promise<GetCertChainResponse>>();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({ certs: { list, get, getChain } }),
  resetSDKClient: () => {},
}));

const toasts: Array<{ kind: string; message: string }> = [];
vi.mock("../src/stores/toast.svelte.ts", () => ({
  showToast: (kind: string, message: string) => {
    toasts.push({ kind, message });
  },
}));

import CertificatesView from "../src/views/CertificatesView.svelte";

const certOne = {
  key_id: "cert-1",
  subject: "CN=server.example.com",
  issuer: "CN=xKMS CA",
  not_before: "2026-01-01",
  not_after: "2027-01-01",
  serial_number: "0a",
};

beforeEach(() => {
  vi.clearAllMocks();
  toasts.length = 0;
});

describe("CertificatesView", () => {
  it("shows a loading spinner then the resolved certificates", async () => {
    list.mockResolvedValue({ certificates: [certOne], pagination: { page: 1, page_size: 50, total: 1, has_more: false } });

    render(CertificatesView);
    expect(document.querySelector(".loading-spinner")).not.toBeNull();

    await waitFor(() => expect(screen.getByText("cert-1")).toBeInTheDocument());
    expect(screen.getByText("CN=server.example.com")).toBeInTheDocument();
    expect(screen.getByText("2027-01-01")).toBeInTheDocument();
  });

  it("shows the empty message when no certificates are stored", async () => {
    list.mockResolvedValue({ certificates: [], pagination: { page: 1, page_size: 50, total: 0, has_more: false } });
    render(CertificatesView);

    expect(await screen.findByText("No certificates stored.")).toBeInTheDocument();
  });

  it("surfaces a list error", async () => {
    list.mockRejectedValue(new Error("cert store unavailable"));
    render(CertificatesView);

    expect(await screen.findByText("cert store unavailable")).toBeInTheDocument();
  });

  it("opens the detail drawer on row click and renders the PEM and chain", async () => {
    list.mockResolvedValue({ certificates: [certOne], pagination: { page: 1, page_size: 50, total: 1, has_more: false } });
    get.mockResolvedValue({ key_id: "cert-1", certificate_pem: "-----BEGIN CERTIFICATE-----\nA\n-----END CERTIFICATE-----" });
    getChain.mockResolvedValue({
      key_id: "cert-1",
      cert_chain_pem: ["-----BEGIN CERTIFICATE-----\nB\n-----END CERTIFICATE-----"],
    });

    render(CertificatesView);
    await screen.findByText("cert-1");
    await fireEvent.click(screen.getByText("cert-1"));

    await waitFor(() => expect(get).toHaveBeenCalledWith("cert-1", ""));
    expect(getChain).toHaveBeenCalledWith("cert-1");
    await screen.findByText("Chain (1)");
    // pre blocks collapse whitespace under the default text-matcher
    // normalizer, so compare raw textContent for the exact PEM bodies.
    const preBlocks = Array.from(document.querySelectorAll("pre")).map((p) => p.textContent ?? "");
    expect(preBlocks.some((t) => t.includes("BEGIN CERTIFICATE") && t.includes("A"))).toBe(true);
    expect(preBlocks.some((t) => t.includes("BEGIN CERTIFICATE") && t.includes("B"))).toBe(true);
  });

  it("surfaces a detail error inside the drawer without crashing the list", async () => {
    list.mockResolvedValue({ certificates: [certOne], pagination: { page: 1, page_size: 50, total: 1, has_more: false } });
    get.mockRejectedValue(new Error("certificate not found"));
    getChain.mockResolvedValue({ key_id: "cert-1", cert_chain_pem: [] });

    render(CertificatesView);
    await screen.findByText("cert-1");
    await fireEvent.click(screen.getByText("cert-1"));

    expect(await screen.findByText("certificate not found")).toBeInTheDocument();
  });

  it("shows the certificate alone (no chain section) when getChain fails", async () => {
    list.mockResolvedValue({ certificates: [certOne], pagination: { page: 1, page_size: 50, total: 1, has_more: false } });
    get.mockResolvedValue({ key_id: "cert-1", certificate_pem: "-----BEGIN CERTIFICATE-----\nA\n-----END CERTIFICATE-----" });
    getChain.mockRejectedValue(new Error("chain store unavailable"));

    render(CertificatesView);
    await screen.findByText("cert-1");
    await fireEvent.click(screen.getByText("cert-1"));

    await waitFor(() => expect(getChain).toHaveBeenCalledOnce());
    // The chain fetch is best-effort: a failure clears it silently rather
    // than surfacing an error alongside the certificate that DID load.
    expect(screen.queryByText(/^Chain \(/)).toBeNull();
    expect(screen.queryByText("chain store unavailable")).toBeNull();
  });

  it("warns instead of toasting success when the clipboard write fails", async () => {
    list.mockResolvedValue({ certificates: [certOne], pagination: { page: 1, page_size: 50, total: 1, has_more: false } });
    get.mockResolvedValue({ key_id: "cert-1", certificate_pem: "-----BEGIN CERTIFICATE-----\nA\n-----END CERTIFICATE-----" });
    getChain.mockResolvedValue({ key_id: "cert-1", cert_chain_pem: [] });
    const writeText = vi.fn().mockRejectedValue(new Error("denied"));
    Object.assign(navigator, { clipboard: { writeText } });

    render(CertificatesView);
    await screen.findByText("cert-1");
    await fireEvent.click(screen.getByText("cert-1"));
    await screen.findByText("Copy");
    await fireEvent.click(screen.getByText("Copy"));

    await waitFor(() =>
      expect(toasts).toContainEqual({ kind: "warning", message: "Clipboard unavailable." }),
    );
  });

  it("copies the certificate PEM to the clipboard", async () => {
    list.mockResolvedValue({ certificates: [certOne], pagination: { page: 1, page_size: 50, total: 1, has_more: false } });
    get.mockResolvedValue({ key_id: "cert-1", certificate_pem: "-----BEGIN CERTIFICATE-----\nA\n-----END CERTIFICATE-----" });
    getChain.mockResolvedValue({ key_id: "cert-1", cert_chain_pem: [] });
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.assign(navigator, { clipboard: { writeText } });

    render(CertificatesView);
    await screen.findByText("cert-1");
    await fireEvent.click(screen.getByText("cert-1"));
    await screen.findByText("Copy");
    await fireEvent.click(screen.getByText("Copy"));

    await waitFor(() =>
      expect(writeText).toHaveBeenCalledWith("-----BEGIN CERTIFICATE-----\nA\n-----END CERTIFICATE-----"),
    );
    expect(toasts).toContainEqual({ kind: "success", message: "Copied to clipboard." });
  });
});
