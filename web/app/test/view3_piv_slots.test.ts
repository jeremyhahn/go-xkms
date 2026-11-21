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
import type {
  ListPIVSlotsResponse,
  PIVSlotStatus,
  GetPIVCertificateResponse,
  GeneratePIVCSRResponse,
} from "@go-xkms/sdk";

const listSlots = vi.fn<(backend?: string) => Promise<ListPIVSlotsResponse>>();
const getCertificate = vi.fn<(slot: string, backend?: string, format?: string) => Promise<GetPIVCertificateResponse>>();
const storeCertificate = vi.fn();
const deleteCertificate = vi.fn();
const exportCertificate = vi.fn<(slot: string, backend?: string, format?: string) => Promise<GetPIVCertificateResponse>>();
const generateCSR = vi.fn<(slot: string, req: unknown) => Promise<GeneratePIVCSRResponse>>();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({
    piv: { listSlots, getCertificate, storeCertificate, deleteCertificate, exportCertificate, generateCSR },
  }),
  resetSDKClient: () => {},
}));

const toasts: Array<{ kind: string; message: string }> = [];
vi.mock("../src/stores/toast.svelte.ts", () => ({
  showToast: (kind: string, message: string) => {
    toasts.push({ kind, message });
  },
}));

import PivSlotsView from "../src/views/PivSlotsView.svelte";

const CERT_PEM = "-----BEGIN CERTIFICATE-----\nMIIBalice\n-----END CERTIFICATE-----\n";
const CSR_PEM = "-----BEGIN CERTIFICATE REQUEST-----\nMIIBcsr\n-----END CERTIFICATE REQUEST-----\n";

const full: PIVSlotStatus = {
  slot: "9a",
  name: "Authentication",
  description: "PIV authentication",
  has_cert: true,
  has_key: true,
  subject: "CN=alice",
  issuer: "CN=xkms CA",
  algorithm: "RSA",
  key_size: 2048,
  not_after: "2027-01-01T00:00:00Z",
  backend: "yubikey",
};

const empty: PIVSlotStatus = {
  slot: "9c",
  name: "Digital Signature",
  description: "PIV signature",
  has_cert: false,
  has_key: false,
  backend: "yubikey",
};

const keyOnly: PIVSlotStatus = { ...empty, slot: "9d", name: "Key Management", has_key: true };

function slots(...s: PIVSlotStatus[]): ListPIVSlotsResponse {
  return { slots: s, page: 1, page_size: s.length, total: s.length, has_more: false };
}

function pemText(): string | null | undefined {
  return screen.getByTestId("pem").textContent;
}

beforeEach(() => {
  vi.clearAllMocks();
  toasts.length = 0;
});

describe("PivSlotsView", () => {
  it("lists one row per slot with key, certificate, subject, algorithm and expiry", async () => {
    listSlots.mockResolvedValue(slots(full, empty));

    render(PivSlotsView);

    expect(await screen.findByText("9a")).toBeInTheDocument();
    expect(listSlots).toHaveBeenCalledOnce();
    expect(screen.getByText("9c")).toBeInTheDocument();
    expect(screen.getByText("Authentication")).toBeInTheDocument();
    expect(screen.getByText("Digital Signature")).toBeInTheDocument();
    expect(screen.getByText("CN=alice")).toBeInTheDocument();
    expect(screen.getByText("RSA 2048")).toBeInTheDocument();
    expect(screen.getByText("2027-01-01T00:00:00Z")).toBeInTheDocument();
    expect(screen.getByText("key")).toBeInTheDocument();
    expect(screen.getByText("certificate")).toBeInTheDocument();
    expect(screen.getByText("no key")).toBeInTheDocument();
    expect(screen.getByText("no certificate")).toBeInTheDocument();
  });

  it("views and exports the decoded certificate of a slot that has one", async () => {
    listSlots.mockResolvedValue(slots(full, empty));
    getCertificate.mockResolvedValue({ slot: "9a", certificate: btoa(CERT_PEM), format: "pem" });
    exportCertificate.mockResolvedValue({ slot: "9a", certificate: btoa(CERT_PEM), format: "pem" });

    render(PivSlotsView);
    await screen.findByText("9a");

    expect(screen.queryByRole("button", { name: "View 9c" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Export 9c" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Delete 9c" })).toBeNull();

    await fireEvent.click(screen.getByRole("button", { name: "View 9a" }));

    await waitFor(() => expect(getCertificate).toHaveBeenCalledWith("9a", "yubikey", "pem"));
    await waitFor(() => expect(pemText()).toBe(CERT_PEM));

    await fireEvent.click(screen.getByRole("button", { name: "Export", hidden: true }));
    await waitFor(() => expect(exportCertificate).toHaveBeenCalledWith("9a", "yubikey", "pem"));
    const link = await screen.findByText("Download 9a.pem");
    expect(link.getAttribute("download")).toBe("9a.pem");
    expect(link.getAttribute("href")).toBe(`data:application/x-pem-file;base64,${btoa(CERT_PEM)}`);
  });

  it("installs a pasted PEM certificate and reloads the list", async () => {
    listSlots.mockResolvedValueOnce(slots(empty)).mockResolvedValueOnce(slots({ ...empty, has_cert: true }));
    storeCertificate.mockResolvedValue({ message: "" });

    render(PivSlotsView);
    await screen.findByText("9c");

    await fireEvent.click(screen.getByRole("button", { name: "Install 9c" }));
    const install = screen.getByRole("button", { name: "Install", hidden: true });
    expect(install).toBeDisabled();

    await fireEvent.input(screen.getByPlaceholderText("-----BEGIN CERTIFICATE-----"), { target: { value: CERT_PEM } });
    expect(install).not.toBeDisabled();
    await fireEvent.click(install);

    await waitFor(() =>
      expect(storeCertificate).toHaveBeenCalledWith("9c", { backend: "yubikey", certificate: btoa(CERT_PEM), format: "pem" }),
    );
    await waitFor(() => expect(listSlots).toHaveBeenCalledTimes(2));
    expect(toasts).toContainEqual({ kind: "success", message: "Certificate installed in slot 9c." });
  });

  it("deletes a certificate only after the confirm", async () => {
    listSlots.mockResolvedValue(slots(full));
    deleteCertificate.mockResolvedValue({ message: "" });

    render(PivSlotsView);
    await screen.findByText("9a");

    await fireEvent.click(screen.getByRole("button", { name: "Delete 9a" }));
    expect(screen.getByText("Delete the certificate in slot 9a?")).toBeInTheDocument();
    await fireEvent.click(screen.getByRole("button", { name: "Cancel", hidden: true }));
    expect(deleteCertificate).not.toHaveBeenCalled();
    expect(screen.queryByText("Delete the certificate in slot 9a?")).toBeNull();

    await fireEvent.click(screen.getByRole("button", { name: "Delete 9a" }));
    await fireEvent.click(screen.getByRole("button", { name: "Delete certificate", hidden: true }));

    await waitFor(() => expect(deleteCertificate).toHaveBeenCalledWith("9a", "yubikey"));
    await waitFor(() => expect(listSlots).toHaveBeenCalledTimes(2));
  });

  it("makes a CSR from a slot key and shows the decoded PEM", async () => {
    listSlots.mockResolvedValue(slots(keyOnly, empty));
    generateCSR.mockResolvedValue({ slot: "9d", csr: btoa(CSR_PEM) });

    render(PivSlotsView);
    await screen.findByText("9d");

    expect(screen.queryByRole("button", { name: "CSR 9c" })).toBeNull();
    await fireEvent.click(screen.getByRole("button", { name: "CSR 9d" }));

    const make = screen.getByRole("button", { name: "Generate CSR", hidden: true });
    expect(make).toBeDisabled();
    await fireEvent.input(screen.getByPlaceholderText("Common name"), { target: { value: "alice" } });
    await fireEvent.input(screen.getByPlaceholderText("Organization"), { target: { value: "Example" } });
    await fireEvent.click(make);

    await waitFor(() =>
      expect(generateCSR).toHaveBeenCalledWith("9d", { backend: "yubikey", subject: "alice", organization: "Example" }),
    );
    const req = generateCSR.mock.calls[0]![1] as Record<string, unknown>;
    expect(Object.keys(req).sort()).toEqual(["backend", "organization", "subject"]);
    await waitFor(() => expect(pemText()).toBe(CSR_PEM));
  });

  it("shows an alert when the slot list fails", async () => {
    listSlots.mockRejectedValue(new Error("no PIV card"));

    render(PivSlotsView);

    expect(await screen.findByText("no PIV card")).toBeInTheDocument();
  });

  it("toasts a failed install and keeps the pasted text", async () => {
    listSlots.mockResolvedValue(slots(empty));
    storeCertificate.mockRejectedValue(new Error("bad certificate"));

    render(PivSlotsView);
    await screen.findByText("9c");

    await fireEvent.click(screen.getByRole("button", { name: "Install 9c" }));
    const area = screen.getByPlaceholderText("-----BEGIN CERTIFICATE-----") as HTMLTextAreaElement;
    await fireEvent.input(area, { target: { value: CERT_PEM } });
    await fireEvent.click(screen.getByRole("button", { name: "Install", hidden: true }));

    await waitFor(() => expect(toasts).toContainEqual({ kind: "error", message: "bad certificate" }));
    expect((screen.getByPlaceholderText("-----BEGIN CERTIFICATE-----") as HTMLTextAreaElement).value).toBe(CERT_PEM);
    expect(listSlots).toHaveBeenCalledOnce();
  });
});
