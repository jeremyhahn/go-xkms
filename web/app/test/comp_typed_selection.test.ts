// Copyright (c) 2026 go-xkms authors. All rights reserved.
//
// A caller allowed to read a TPM policy or a tenant's TPM mode, but not to
// list policies or tenants, can still select the one it knows by name or ID.

import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/svelte";

const tenantsList = vi.fn();
const getTPMMode = vi.fn();
const vtpmStatus = vi.fn();
const list = vi.fn();
const get = vi.fn();
const objects = vi.fn();
const verify = vi.fn();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({
    tenants: { list: tenantsList, getTPMMode, vtpmStatus },
    tpmPolicies: { list, get, objects, verify },
  }),
  resetSDKClient: () => {},
}));

vi.mock("../src/stores/toast.svelte.ts", () => ({
  showToast: () => {},
}));

import TpmPolicyDetailView from "../src/views/TpmPolicyDetailView.svelte";
import TenantTpmView from "../src/views/TenantTpmView.svelte";

function forbidden(): Error {
  return Object.assign(new Error("403 Forbidden"), { status: 403 });
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe("TpmPolicyDetailView without tpm_policy:list", () => {
  it("Load, Objects and Verify use a typed policy name", async () => {
    tenantsList.mockRejectedValue(forbidden());
    list.mockRejectedValue(forbidden());
    get.mockResolvedValue({ name: "boot", branches: [], index: 1, approved: true, created_at: "2026-11-12T00:00:00Z" });
    objects.mockResolvedValue({ name: "boot", objects: [] });
    verify.mockResolvedValue({ name: "boot", match: true, approved: true, branches: [] });

    render(TpmPolicyDetailView);
    const input = await screen.findByLabelText("Policy name");
    await fireEvent.change(input, { target: { value: "boot" } });

    await fireEvent.click(screen.getByRole("button", { name: "Load" }));
    await waitFor(() => expect(get).toHaveBeenCalledWith("boot", undefined));
    await fireEvent.click(screen.getByRole("button", { name: "Objects" }));
    await waitFor(() => expect(objects).toHaveBeenCalledWith("boot", undefined));
    await fireEvent.click(screen.getByRole("button", { name: "Verify" }));
    await waitFor(() => expect(verify).toHaveBeenCalledWith("boot", undefined));
    expect(list).toHaveBeenCalledTimes(1);
  });
});

describe("TenantTpmView without tenants:list", () => {
  it("reads the mode of a typed tenant ID", async () => {
    tenantsList.mockRejectedValue(forbidden());
    getTPMMode.mockResolvedValue({ tenant_id: "t1", mode: "shared" });

    render(TenantTpmView);
    expect(await screen.findByText("403 Forbidden")).toBeInTheDocument();
    const input = await screen.findByLabelText("Tenant ID");
    await fireEvent.change(input, { target: { value: "t1" } });

    await waitFor(() => expect(getTPMMode).toHaveBeenCalledWith("t1"));
    expect((await screen.findByTestId("current-mode")).textContent).toBe("shared");
    expect(tenantsList).toHaveBeenCalledTimes(1);
  });
});
