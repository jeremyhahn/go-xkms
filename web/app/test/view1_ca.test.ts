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
  GetCACertificateResponse,
  IssueCertificateResponse,
  SignCSRResponse,
  IsRevokedResponse,
} from "@go-xkms/sdk";
import { textToB64 } from "../src/lib/b64.ts";

const certificate = vi.fn<() => Promise<GetCACertificateResponse>>();
const issue = vi.fn();
const signCSR = vi.fn();
const revoke = vi.fn();
const isRevoked = vi.fn<(serial: string) => Promise<IsRevokedResponse>>();
const bundle = vi.fn();
const generateCRL = vi.fn();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({
    ca: { certificate, issue, signCSR, revoke, isRevoked, bundle, generateCRL },
  }),
  resetSDKClient: () => {},
}));

const toasts: Array<{ kind: string; message: string }> = [];
vi.mock("../src/stores/toast.svelte.ts", () => ({
  showToast: (kind: string, message: string) => {
    toasts.push({ kind, message });
  },
}));

import CaView from "../src/views/CaView.svelte";

const caCert: GetCACertificateResponse = {
  certificate_pem: textToB64("-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----"),
  subject: "CN=xKMS Root CA",
  issuer: "CN=xKMS Issuing CA",
  serial_number: "01",
  not_before: "2026-01-01",
  not_after: "2036-01-01",
  is_ca: true,
};

const issuedResp: IssueCertificateResponse = {
  certificate_pem: textToB64("-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----"),
  chain_pem: textToB64(""),
  serial_number: "0a",
};

const signedResp: SignCSRResponse = {
  certificate_pem: textToB64("-----BEGIN CERTIFICATE-----\nsigned\n-----END CERTIFICATE-----"),
  chain_pem: "",
  serial_number: "0b",
};

beforeEach(() => {
  vi.clearAllMocks();
  toasts.length = 0;
  // URL.createObjectURL is not implemented in jsdom; the download helpers
  // used by bundle/CRL downloads need a stub. HTMLAnchorElement.click is
  // stubbed too — jsdom otherwise logs an unimplemented-navigation error
  // when downloadText() clicks the synthetic <a href="blob:...">.
  URL.createObjectURL = vi.fn(() => "blob:fake") as unknown as typeof URL.createObjectURL;
  URL.revokeObjectURL = vi.fn();
  HTMLAnchorElement.prototype.click = vi.fn();
});

describe("CaView", () => {
  it("shows a loading spinner then the CA certificate summary", async () => {
    certificate.mockResolvedValue(caCert);
    render(CaView);

    expect(document.querySelector(".loading-spinner")).not.toBeNull();

    await waitFor(() => expect(screen.getByText("CN=xKMS Root CA")).toBeInTheDocument());
    expect(screen.getByText("01")).toBeInTheDocument();
  });

  it("surfaces a CA-certificate load error but still renders the issue/sign/revoke tabs", async () => {
    certificate.mockRejectedValue(new Error("CA not initialized"));
    render(CaView);

    expect(await screen.findByText("CA not initialized")).toBeInTheDocument();
    // The tabs are not gated on caCert being present.
    expect(screen.getByRole("tab", { name: "Issue" })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "Sign CSR" })).toBeInTheDocument();
  });

  it("issues a certificate with the exact IssueCertificateRequest shape", async () => {
    certificate.mockResolvedValue(caCert);
    issue.mockResolvedValue(issuedResp);
    render(CaView);
    await screen.findByText("CN=xKMS Root CA");

    const [cnInput, orgInput] = screen.getAllByRole("textbox");
    await fireEvent.input(cnInput!, { target: { value: "host.example.com" } });
    await fireEvent.input(orgInput!, { target: { value: "Example Corp" } });
    const sansInput = screen.getByPlaceholderText("host.example.com, 10.0.0.5");
    await fireEvent.input(sansInput, { target: { value: "a.example.com, b.example.com" } });

    await fireEvent.click(screen.getByRole("button", { name: "Issue certificate" }));

    await waitFor(() => expect(issue).toHaveBeenCalledOnce());
    expect(issue.mock.calls[0]![0]).toEqual({
      profile: "server",
      common_name: "host.example.com",
      organization: "Example Corp",
      sans: ["a.example.com", "b.example.com"],
      validity_days: 365,
    });
    expect(toasts.some((t) => t.kind === "success" && t.message.includes("0a"))).toBe(true);
  });

  it("omits organization and sans when left blank", async () => {
    certificate.mockResolvedValue(caCert);
    issue.mockResolvedValue(issuedResp);
    render(CaView);
    await screen.findByText("CN=xKMS Root CA");

    const [cnInput] = screen.getAllByRole("textbox");
    await fireEvent.input(cnInput!, { target: { value: "host.example.com" } });
    await fireEvent.click(screen.getByRole("button", { name: "Issue certificate" }));

    await waitFor(() => expect(issue).toHaveBeenCalledOnce());
    const req = issue.mock.calls[0]![0];
    expect(req.organization).toBeUndefined();
    expect(req.sans).toBeUndefined();
  });

  it("surfaces an issue error inline without clearing the form", async () => {
    certificate.mockResolvedValue(caCert);
    issue.mockRejectedValue(new Error("profile not permitted"));
    render(CaView);
    await screen.findByText("CN=xKMS Root CA");

    const [cnInput] = screen.getAllByRole("textbox");
    await fireEvent.input(cnInput!, { target: { value: "host.example.com" } });
    await fireEvent.click(screen.getByRole("button", { name: "Issue certificate" }));

    expect(await screen.findByText("profile not permitted")).toBeInTheDocument();
  });

  it("refuses to sign text that is not a PEM CSR", async () => {
    certificate.mockResolvedValue(caCert);
    render(CaView);
    await screen.findByText("CN=xKMS Root CA");

    await fireEvent.click(screen.getByRole("tab", { name: "Sign CSR" }));
    const csrBox = screen.getByPlaceholderText("-----BEGIN CERTIFICATE REQUEST-----");
    await fireEvent.input(csrBox, { target: { value: "not a csr" } });
    await fireEvent.click(screen.getByRole("button", { name: "Sign CSR" }));

    expect(
      await screen.findByText(
        "Paste a PEM certificate signing request (-----BEGIN CERTIFICATE REQUEST-----).",
      ),
    ).toBeInTheDocument();
    expect(signCSR).not.toHaveBeenCalled();
  });

  it("signs a valid CSR and base64-encodes csr_pem for the wire", async () => {
    certificate.mockResolvedValue(caCert);
    signCSR.mockResolvedValue(signedResp);
    render(CaView);
    await screen.findByText("CN=xKMS Root CA");

    const pem = "-----BEGIN CERTIFICATE REQUEST-----\nMIIC\n-----END CERTIFICATE REQUEST-----";
    await fireEvent.click(screen.getByRole("tab", { name: "Sign CSR" }));
    const csrBox = screen.getByPlaceholderText("-----BEGIN CERTIFICATE REQUEST-----");
    await fireEvent.input(csrBox, { target: { value: pem } });
    await fireEvent.click(screen.getByRole("button", { name: "Sign CSR" }));

    await waitFor(() => expect(signCSR).toHaveBeenCalledOnce());
    expect(signCSR.mock.calls[0]![0]).toEqual({
      csr_pem: textToB64(pem),
      profile: "server",
      validity_days: 365,
    });
  });

  it("revokes a serial with the exact RevokeCertificateRequest shape and rechecks status", async () => {
    certificate.mockResolvedValue(caCert);
    revoke.mockResolvedValue({ success: true });
    isRevoked.mockResolvedValue({ revoked: true, reason: 1 });
    render(CaView);
    await screen.findByText("CN=xKMS Root CA");

    await fireEvent.click(screen.getByRole("tab", { name: /Revoke/ }));
    const serialInput = screen.getByRole("textbox");
    await fireEvent.input(serialInput, { target: { value: " 0a " } });

    // Reason select defaults to keyCompromise (value 1).
    await fireEvent.click(screen.getByRole("button", { name: "Revoke" }));

    await waitFor(() => expect(revoke).toHaveBeenCalledOnce());
    expect(revoke.mock.calls[0]![0]).toEqual({ serial_number: "0a", reason: 1 });
    await waitFor(() => expect(isRevoked).toHaveBeenCalledWith("0a"));
    expect(await screen.findByText("revoked")).toBeInTheDocument();
    const statusAlert = document.querySelector(".alert-error");
    expect(statusAlert?.textContent).toContain("0a");
    expect(statusAlert?.textContent).toContain("keyCompromise");
  });

  it("generates and downloads a CRL", async () => {
    certificate.mockResolvedValue(caCert);
    generateCRL.mockResolvedValue({ crl_pem: textToB64("crl-bytes") });
    render(CaView);
    await screen.findByText("CN=xKMS Root CA");

    await fireEvent.click(screen.getByRole("tab", { name: /Revoke/ }));
    await fireEvent.click(screen.getByRole("button", { name: /Generate.*CRL/ }));

    await waitFor(() => expect(generateCRL).toHaveBeenCalledOnce());
    expect(toasts).toContainEqual({ kind: "success", message: "CRL generated and downloaded." });
  });

  it("toasts an error when CRL generation fails", async () => {
    certificate.mockResolvedValue(caCert);
    generateCRL.mockRejectedValue(new Error("CA is sealed"));
    render(CaView);
    await screen.findByText("CN=xKMS Root CA");

    await fireEvent.click(screen.getByRole("tab", { name: /Revoke/ }));
    await fireEvent.click(screen.getByRole("button", { name: /Generate.*CRL/ }));

    await waitFor(() => expect(toasts).toContainEqual({ kind: "error", message: "CA is sealed" }));
  });

  it("downloads the trust bundle from the header action", async () => {
    certificate.mockResolvedValue(caCert);
    bundle.mockResolvedValue({
      bundle_pem: textToB64("-----BEGIN CERTIFICATE-----\nbundle\n-----END CERTIFICATE-----"),
      certificates: [textToB64("cert-a"), textToB64("cert-b")],
      content_type: "application/x-pem-file",
    });
    render(CaView);
    await screen.findByText("CN=xKMS Root CA");

    await fireEvent.click(screen.getByRole("button", { name: "Download trust bundle" }));

    await waitFor(() => expect(bundle).toHaveBeenCalledOnce());
    expect(toasts).toContainEqual({
      kind: "success",
      message: "Trust bundle downloaded (2 certificates).",
    });
  });

  it("toasts an error when the trust bundle download fails", async () => {
    certificate.mockResolvedValue(caCert);
    bundle.mockRejectedValue(new Error("bundle unavailable"));
    render(CaView);
    await screen.findByText("CN=xKMS Root CA");

    await fireEvent.click(screen.getByRole("button", { name: "Download trust bundle" }));

    await waitFor(() =>
      expect(toasts).toContainEqual({ kind: "error", message: "bundle unavailable" }),
    );
  });

  it("downloads the CA certificate from the certificate card", async () => {
    certificate.mockResolvedValue(caCert);
    render(CaView);
    await screen.findByText("CN=xKMS Root CA");

    // HTMLAnchorElement.click is stubbed to a vi.fn() in beforeEach.
    await fireEvent.click(screen.getByRole("button", { name: "Download" }));

    await waitFor(() => expect(HTMLAnchorElement.prototype.click).toHaveBeenCalled());
  });
});
