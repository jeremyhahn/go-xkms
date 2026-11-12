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
  IssueEKCertificateRequest,
  IssueEKCertificateResponse,
  IssueAKCertificateRequest,
  IssueAKCertificateResponse,
  SignTCGCSRRequest,
  SignTCGCSRResponse,
} from "@go-xkms/sdk";

const issueEK = vi.fn<(req: IssueEKCertificateRequest) => Promise<IssueEKCertificateResponse>>();
const issueAK = vi.fn<(req: IssueAKCertificateRequest) => Promise<IssueAKCertificateResponse>>();
const signTCGCSR = vi.fn<(req: SignTCGCSRRequest) => Promise<SignTCGCSRResponse>>();
const enrollDevice = vi.fn();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({ ca: { issueEK, issueAK, signTCGCSR, enrollDevice } }),
  resetSDKClient: () => {},
}));

const toasts: Array<{ kind: string; message: string }> = [];
vi.mock("../src/stores/toast.svelte.ts", () => ({
  showToast: (kind: string, message: string) => {
    toasts.push({ kind, message });
  },
}));

const { downloadText } = vi.hoisted(() => ({ downloadText: vi.fn() }));
vi.mock("../src/lib/pem.ts", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/lib/pem.ts")>();
  return { ...actual, downloadText };
});

import { encodePEM } from "../src/lib/pem.ts";
import TcgCertsView from "../src/views/TcgCertsView.svelte";

const keyPEM = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n-----END PUBLIC KEY-----";
const certPEM = "-----BEGIN CERTIFICATE-----\nMIIBcert\n-----END CERTIFICATE-----";

function certResponse(serial: string): IssueEKCertificateResponse {
  return { certificate_der: "MIIBcert", certificate_pem: encodePEM(certPEM), serial_number: serial };
}

async function fill(label: string, value: string): Promise<void> {
  await fireEvent.input(screen.getByLabelText(label), { target: { value } });
}

beforeEach(() => {
  vi.clearAllMocks();
  toasts.length = 0;
});

describe("TcgCertsView", () => {
  it("shows the EK, AK and TCG CSR tabs and calls nothing on mount", () => {
    render(TcgCertsView);

    expect(screen.getByRole("heading", { name: "TCG Certificates" })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "EK" })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "AK" })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "TCG CSR" })).toBeInTheDocument();
    expect(issueEK).not.toHaveBeenCalled();
    expect(issueAK).not.toHaveBeenCalled();
    expect(signTCGCSR).not.toHaveBeenCalled();
    expect(enrollDevice).not.toHaveBeenCalled();
  });

  it("issues an EK certificate from a PEM key and renders the result", async () => {
    issueEK.mockResolvedValue(certResponse("0a1b2c"));
    render(TcgCertsView);

    await fill("Common name", "device-ek");
    await fill("Organization", "Acme");
    await fill("EK public key", keyPEM);
    await fireEvent.click(screen.getByRole("button", { name: "Issue" }));

    await waitFor(() => expect(issueEK).toHaveBeenCalledTimes(1));
    expect(issueEK).toHaveBeenCalledWith({
      common_name: "device-ek",
      organization: "Acme",
      ek_public_key: encodePEM(keyPEM),
      tenant_id: undefined,
    });
    expect(await screen.findByText("0a1b2c")).toBeInTheDocument();
    expect(screen.getByTestId("tcg-result-pem").textContent).toContain("-----BEGIN CERTIFICATE-----");
    expect(enrollDevice).not.toHaveBeenCalled();
  });

  it("sends a Base64 EK key as is", async () => {
    issueEK.mockResolvedValue(certResponse("01"));
    render(TcgCertsView);

    await fill("Common name", "device-ek");
    await fill("Tenant ID", "t1");
    await fill("EK public key", "MFkwEwYHKoZIzj0CAQ==");
    await fireEvent.click(screen.getByRole("button", { name: "Issue" }));

    await waitFor(() => expect(issueEK).toHaveBeenCalledTimes(1));
    expect(issueEK).toHaveBeenCalledWith({
      common_name: "device-ek",
      organization: undefined,
      ek_public_key: "MFkwEwYHKoZIzj0CAQ==",
      tenant_id: "t1",
    });
  });

  it("issues an AK certificate with public_key", async () => {
    issueAK.mockResolvedValue(certResponse("ak-serial-7"));
    render(TcgCertsView);

    await fireEvent.click(screen.getByRole("tab", { name: "AK" }));
    await fill("Common name", "device-ak");
    await fill("AK public key", keyPEM);
    await fireEvent.click(screen.getByRole("button", { name: "Issue" }));

    await waitFor(() => expect(issueAK).toHaveBeenCalledTimes(1));
    expect(issueAK).toHaveBeenCalledWith({
      common_name: "device-ak",
      organization: undefined,
      public_key: encodePEM(keyPEM),
      tenant_id: undefined,
    });
    expect(issueEK).not.toHaveBeenCalled();
    expect(await screen.findByText("ak-serial-7")).toBeInTheDocument();
    await fireEvent.click(screen.getByRole("button", { name: "Download PEM" }));
    expect(downloadText).toHaveBeenCalledTimes(1);
    expect(downloadText.mock.calls[0][1]).toContain("-----BEGIN CERTIFICATE-----");
  });

  it("signs a Base64 TCG CSR and offers both certificates for download", async () => {
    signTCGCSR.mockResolvedValue({ iak_cert_der: "SUFLZGVy", idevid_cert_der: "SURldklEZGVy" });
    render(TcgCertsView);

    await fireEvent.click(screen.getByRole("tab", { name: "TCG CSR" }));
    await fill("Common name", "device-idevid");
    await fill("TCG CSR", "AQIDBA==");
    await fireEvent.click(screen.getByRole("button", { name: "Sign" }));

    await waitFor(() => expect(signTCGCSR).toHaveBeenCalledTimes(1));
    expect(signTCGCSR).toHaveBeenCalledWith({
      common_name: "device-idevid",
      organization: undefined,
      tcg_csr: "AQIDBA==",
      tenant_id: undefined,
    });
    expect(await screen.findByText("SUFLZGVy")).toBeInTheDocument();
    expect(screen.getByText("SURldklEZGVy")).toBeInTheDocument();
    await fireEvent.click(screen.getByRole("button", { name: "Download IAK" }));
    await fireEvent.click(screen.getByRole("button", { name: "Download IDevID" }));
    expect(downloadText).toHaveBeenCalledTimes(2);
    expect(downloadText.mock.calls[0][1]).toBe("SUFLZGVy");
    expect(downloadText.mock.calls[1][1]).toBe("SURldklEZGVy");
  });

  it("rejects a CSR that is neither PEM nor Base64 without a call", async () => {
    render(TcgCertsView);

    await fireEvent.click(screen.getByRole("tab", { name: "TCG CSR" }));
    await fill("Common name", "device-idevid");
    await fill("TCG CSR", "not base64 !!");
    await fireEvent.click(screen.getByRole("button", { name: "Sign" }));

    expect(await screen.findByText("Input is neither PEM nor Base64.")).toBeInTheDocument();
    expect(signTCGCSR).not.toHaveBeenCalled();
  });

  it("keeps Issue disabled until a common name and a key are set", async () => {
    render(TcgCertsView);

    const issue = screen.getByRole("button", { name: "Issue" });
    expect(issue).toBeDisabled();
    await fill("Common name", "device-ek");
    expect(issue).toBeDisabled();
    await fill("EK public key", keyPEM);
    expect(issue).toBeEnabled();
  });

  it("shows an error Alert and no result when the call is rejected", async () => {
    issueEK.mockRejectedValue(new Error("CA not configured"));
    render(TcgCertsView);

    await fill("Common name", "device-ek");
    await fill("EK public key", keyPEM);
    await fireEvent.click(screen.getByRole("button", { name: "Issue" }));

    expect(await screen.findByText("CA not configured")).toBeInTheDocument();
    expect(screen.queryByTestId("tcg-result-pem")).not.toBeInTheDocument();
  });
});
