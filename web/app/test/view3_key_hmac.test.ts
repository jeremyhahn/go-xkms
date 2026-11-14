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

const request = vi.fn();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({ http: { request } }),
  resetSDKClient: () => {},
}));

const toasts: Array<{ kind: string; message: string }> = [];
vi.mock("../src/stores/toast.svelte.ts", () => ({
  showToast: (kind: string, message: string) => {
    toasts.push({ kind, message });
  },
}));

import KeyHmacView from "../src/views/KeyHmacView.svelte";

beforeEach(() => {
  vi.clearAllMocks();
  toasts.length = 0;
});

async function fill(opts: { id?: string; backend?: string; data?: string } = {}): Promise<void> {
  await fireEvent.input(screen.getByLabelText("Key ID"), { target: { value: opts.id ?? "mac1" } });
  await fireEvent.input(screen.getByLabelText("Backend"), { target: { value: opts.backend ?? "software" } });
  await fireEvent.input(screen.getByLabelText("Data"), { target: { value: opts.data ?? "abc" } });
}

function computeBtn(): HTMLButtonElement {
  return screen.getByRole("button", { name: "Compute" }) as HTMLButtonElement;
}

function verifyBtn(): HTMLButtonElement {
  return screen.getByRole("button", { name: "Verify" }) as HTMLButtonElement;
}

describe("KeyHmacView compute", () => {
  it("posts the key, backend, base64 data and hash and renders the MAC", async () => {
    request.mockResolvedValue({ mac: "3q2+7w==", hash: "sha256", key_version: 2 });
    render(KeyHmacView);
    await fill();
    await fireEvent.change(screen.getByLabelText("Hash"), { target: { value: "sha256" } });
    await fireEvent.click(computeBtn());

    await waitFor(() => expect(request).toHaveBeenCalledOnce());
    expect(request).toHaveBeenCalledWith("POST", "/api/v1/keys/mac1/hmac", {
      body: { backend: "software", key_id: "mac1", data: "YWJj", hash: "sha256" },
    });
    expect(await screen.findByText("deadbeef")).toBeInTheDocument();
    expect(screen.getByText("3q2+7w==")).toBeInTheDocument();
    expect(screen.getByTestId("hmac-hash")).toHaveTextContent("sha256");
    expect(screen.getByTestId("hmac-version")).toHaveTextContent("2");
  });

  it("omits the hash field with the server default", async () => {
    request.mockResolvedValue({ mac: "3q2+7w==", hash: "sha256" });
    render(KeyHmacView);
    await fill();
    await fireEvent.click(computeBtn());

    await waitFor(() => expect(request).toHaveBeenCalledOnce());
    const [, , opts] = request.mock.calls[0]!;
    expect(opts.body).toEqual({ backend: "software", key_id: "mac1", data: "YWJj" });
    expect("hash" in opts.body).toBe(false);
  });

  it("sends base64 data as is in base64 mode", async () => {
    request.mockResolvedValue({ mac: "3q2+7w==", hash: "sha256" });
    render(KeyHmacView);
    await fireEvent.click(screen.getByLabelText("Data is base64"));
    await fill({ data: "AAEC" });
    await fireEvent.click(computeBtn());

    await waitFor(() => expect(request).toHaveBeenCalledOnce());
    expect(request.mock.calls[0]![2].body.data).toBe("AAEC");
  });
});

describe("KeyHmacView verify", () => {
  it("converts a hex MAC to base64 and shows a valid badge", async () => {
    request.mockResolvedValue({ valid: true });
    render(KeyHmacView);
    await fill();
    await fireEvent.input(screen.getByLabelText("MAC"), { target: { value: "deadbeef" } });
    await fireEvent.click(verifyBtn());

    await waitFor(() => expect(request).toHaveBeenCalledOnce());
    expect(request).toHaveBeenCalledWith("POST", "/api/v1/keys/mac1/hmac/verify", {
      body: { backend: "software", key_id: "mac1", data: "YWJj", mac: "3q2+7w==" },
    });
    expect(await screen.findByText("valid")).toBeInTheDocument();
  });

  it("shows an invalid badge and sends a base64 MAC as is", async () => {
    request.mockResolvedValue({ valid: false });
    render(KeyHmacView);
    await fill();
    await fireEvent.input(screen.getByLabelText("MAC"), { target: { value: "3q2+7w==" } });
    await fireEvent.click(verifyBtn());

    await waitFor(() => expect(request).toHaveBeenCalledOnce());
    expect(request.mock.calls[0]![2].body.mac).toBe("3q2+7w==");
    expect(await screen.findByText("invalid")).toBeInTheDocument();
  });
});

describe("KeyHmacView validation", () => {
  it("keeps Compute and Verify disabled until key ID, backend and data are set", async () => {
    render(KeyHmacView);
    expect(computeBtn()).toBeDisabled();
    expect(verifyBtn()).toBeDisabled();
    await fireEvent.input(screen.getByLabelText("Key ID"), { target: { value: "mac1" } });
    expect(computeBtn()).toBeDisabled();
    await fireEvent.input(screen.getByLabelText("Backend"), { target: { value: "software" } });
    expect(computeBtn()).toBeDisabled();
    await fireEvent.input(screen.getByLabelText("Data"), { target: { value: "abc" } });
    expect(computeBtn()).toBeEnabled();
    await fireEvent.input(screen.getByLabelText("MAC"), { target: { value: "deadbeef" } });
    expect(verifyBtn()).toBeEnabled();
  });

  it("rejects invalid base64 data in base64 mode without a request", async () => {
    render(KeyHmacView);
    await fireEvent.click(screen.getByLabelText("Data is base64"));
    await fill({ data: "not base64!" });
    await fireEvent.click(computeBtn());

    expect(await screen.findByText("Data is not valid base64.")).toBeInTheDocument();
    expect(request).not.toHaveBeenCalled();
  });

  it("rejects a MAC that is neither hex nor base64 without a request", async () => {
    render(KeyHmacView);
    await fill();
    await fireEvent.input(screen.getByLabelText("MAC"), { target: { value: "not a mac!" } });
    await fireEvent.click(verifyBtn());

    expect(await screen.findByText("MAC must be hex or base64.")).toBeInTheDocument();
    expect(request).not.toHaveBeenCalled();
  });
});

describe("KeyHmacView errors", () => {
  it("shows a rejected compute in an error alert", async () => {
    request.mockRejectedValue(new Error("key mac1 not found"));
    render(KeyHmacView);
    await fill();
    await fireEvent.click(computeBtn());

    expect(await screen.findByText("key mac1 not found")).toBeInTheDocument();
  });

  it("shows a rejected verify in an error alert", async () => {
    request.mockRejectedValue(new Error("permission denied"));
    render(KeyHmacView);
    await fill();
    await fireEvent.input(screen.getByLabelText("MAC"), { target: { value: "deadbeef" } });
    await fireEvent.click(verifyBtn());

    expect(await screen.findByText("permission denied")).toBeInTheDocument();
  });
});
