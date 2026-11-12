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
import type { TPMObjectPolicyResponse } from "@go-xkms/sdk";

const keyPolicy =
  vi.fn<(keyId: string, opts?: { tenantId?: string; kind?: "key" | "sealed" }) => Promise<TPMObjectPolicyResponse>>();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({ tpmPolicies: { keyPolicy } }),
  resetSDKClient: () => {},
}));

const toasts: Array<{ kind: string; message: string }> = [];
vi.mock("../src/stores/toast.svelte.ts", () => ({
  showToast: (kind: string, message: string) => {
    toasts.push({ kind, message });
  },
}));

import TpmKeyPolicyView from "../src/views/TpmKeyPolicyView.svelte";

const keyResp: TPMObjectPolicyResponse = {
  object_id: "key-123",
  kind: "key",
  policy: "pcr-boot",
  auth_policy: "a1b2c3d4e5f6",
  created_at: "2026-11-01T10:00:00Z",
};

function lookUp(): HTMLElement {
  return screen.getByRole("button", { name: "Look up" });
}

beforeEach(() => {
  vi.clearAllMocks();
  toasts.length = 0;
});

describe("TpmKeyPolicyView", () => {
  it("keeps Look up disabled until an object id is entered and calls nothing on mount", async () => {
    render(TpmKeyPolicyView);

    expect(lookUp()).toBeDisabled();
    expect(keyPolicy).not.toHaveBeenCalled();

    await fireEvent.input(screen.getByLabelText("Object ID"), { target: { value: "key-123" } });
    expect(lookUp()).not.toBeDisabled();
    expect(keyPolicy).not.toHaveBeenCalled();
  });

  it("looks up a key with the default kind and renders the five fields", async () => {
    keyPolicy.mockResolvedValue(keyResp);

    render(TpmKeyPolicyView);
    await fireEvent.input(screen.getByLabelText("Object ID"), { target: { value: "key-123" } });
    await fireEvent.click(lookUp());

    await waitFor(() => expect(keyPolicy).toHaveBeenCalledOnce());
    const [id, opts] = keyPolicy.mock.calls[0]!;
    expect(id).toBe("key-123");
    expect(opts?.kind).toBe("key");
    expect(opts?.tenantId).toBeUndefined();

    expect(await screen.findByText("pcr-boot")).toBeInTheDocument();
    expect(screen.getByText("key-123")).toBeInTheDocument();
    expect(screen.getByTestId("tpm-key-policy-kind")).toHaveTextContent("key");
    expect(screen.getByText("a1b2c3d4e5f6")).toBeInTheDocument();
    expect(screen.getByText("2026-11-01T10:00:00Z")).toBeInTheDocument();
  });

  it("passes the sealed kind and the tenant id", async () => {
    keyPolicy.mockResolvedValue({ ...keyResp, object_id: "blob-9", kind: "sealed" });

    render(TpmKeyPolicyView);
    await fireEvent.input(screen.getByLabelText("Object ID"), { target: { value: "blob-9" } });
    await fireEvent.change(screen.getByLabelText("Kind"), { target: { value: "sealed" } });
    await fireEvent.input(screen.getByLabelText("Tenant ID"), { target: { value: "tenant-a" } });
    await fireEvent.click(lookUp());

    await waitFor(() => expect(keyPolicy).toHaveBeenCalledOnce());
    expect(keyPolicy).toHaveBeenCalledWith("blob-9", { tenantId: "tenant-a", kind: "sealed" });
    expect(await screen.findByText("blob-9")).toBeInTheDocument();
  });

  it("renders a dash when the response has no auth policy", async () => {
    const { auth_policy: _omit, ...rest } = keyResp;
    keyPolicy.mockResolvedValue(rest);

    render(TpmKeyPolicyView);
    await fireEvent.input(screen.getByLabelText("Object ID"), { target: { value: "key-123" } });
    await fireEvent.click(lookUp());

    await screen.findByText("pcr-boot");
    expect(screen.getByTestId("tpm-key-policy-auth")).toHaveTextContent("—");
    expect(screen.queryByText(/undefined/)).not.toBeInTheDocument();
  });

  it("shows an error alert and clears an earlier result", async () => {
    keyPolicy.mockResolvedValueOnce(keyResp);
    keyPolicy.mockRejectedValueOnce(new Error("object not found"));

    render(TpmKeyPolicyView);
    await fireEvent.input(screen.getByLabelText("Object ID"), { target: { value: "key-123" } });
    await fireEvent.click(lookUp());
    expect(await screen.findByText("pcr-boot")).toBeInTheDocument();

    await fireEvent.input(screen.getByLabelText("Object ID"), { target: { value: "missing" } });
    await fireEvent.click(lookUp());

    expect(await screen.findByText("object not found")).toBeInTheDocument();
    expect(screen.queryByText("pcr-boot")).not.toBeInTheDocument();
  });
});
