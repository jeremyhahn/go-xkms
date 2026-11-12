// SPDX-License-Identifier: Apache-2.0
//
// TrustBundleView: shows and downloads the CA bootstrap bundle
// (GET /v1/ca/bootstrap via ca.bootstrapBundle) a new client pins on first
// contact.

import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/svelte";

const bootstrapBundle = vi.fn<() => Promise<string>>();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({ ca: { bootstrapBundle } }),
  resetSDKClient: () => {},
}));

const toasts: Array<{ kind: string; message: string }> = [];
vi.mock("../src/stores/toast.svelte.ts", () => ({
  showToast: (kind: string, message: string) => {
    toasts.push({ kind, message });
  },
}));

const downloadText = vi.fn<(filename: string, text: string, mime?: string) => void>();
vi.mock("../src/lib/pem.ts", () => ({ downloadText }));

import TrustBundleView from "../src/views/TrustBundleView.svelte";

const certA = "-----BEGIN CERTIFICATE-----\nQUFBQQ==\n-----END CERTIFICATE-----\n";
const certB = "-----BEGIN CERTIFICATE-----\nQkJCQg==\n-----END CERTIFICATE-----\n";
const bundle = certA + certB;

beforeEach(() => {
  vi.clearAllMocks();
  toasts.length = 0;
});

describe("TrustBundleView", () => {
  it("loads the bundle once on mount and shows the PEM with its certificate count", async () => {
    bootstrapBundle.mockResolvedValue(bundle);
    render(TrustBundleView);
    await waitFor(() => expect(screen.getByText("2 certificates")).toBeTruthy());
    expect(bootstrapBundle).toHaveBeenCalledTimes(1);
    const block = screen.getByLabelText("Bootstrap bundle PEM") as HTMLTextAreaElement;
    expect(block.value).toBe(bundle);
    expect(block.readOnly).toBe(true);
  });

  it("downloads the bundle as a PEM certificate chain", async () => {
    bootstrapBundle.mockResolvedValue(bundle);
    render(TrustBundleView);
    const btn = await screen.findByRole("button", { name: "Download" });
    await fireEvent.click(btn);
    expect(downloadText).toHaveBeenCalledWith("xkms-ca-bundle.pem", bundle, "application/pem-certificate-chain");
  });

  it("refresh fetches the bundle again and replaces the text", async () => {
    bootstrapBundle.mockResolvedValueOnce(certA).mockResolvedValueOnce(bundle);
    render(TrustBundleView);
    await waitFor(() => expect(screen.getByText("1 certificate")).toBeTruthy());
    await fireEvent.click(screen.getByRole("button", { name: "Refresh" }));
    await waitFor(() => expect(screen.getByText("2 certificates")).toBeTruthy());
    expect(bootstrapBundle).toHaveBeenCalledTimes(2);
    const block = screen.getByLabelText("Bootstrap bundle PEM") as HTMLTextAreaElement;
    expect(block.value).toBe(bundle);
  });

  it("an empty bundle says none is configured and hides Download", async () => {
    bootstrapBundle.mockResolvedValue("");
    render(TrustBundleView);
    await waitFor(() => expect(screen.getByText(/No bootstrap bundle is configured/)).toBeTruthy());
    expect(screen.queryByRole("button", { name: "Download" })).toBeNull();
  });

  it("a failed call shows an error alert with the message", async () => {
    bootstrapBundle.mockRejectedValue(new Error("bundler unavailable"));
    render(TrustBundleView);
    await waitFor(() => expect(screen.getByText("bundler unavailable")).toBeTruthy());
    expect(screen.queryByRole("button", { name: "Download" })).toBeNull();
  });
});
