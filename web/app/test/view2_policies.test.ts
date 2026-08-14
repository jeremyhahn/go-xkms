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
import type { PolicyInfo, PolicyCreateRequest } from "@go-xkms/sdk";

const list = vi.fn<() => Promise<{ policies: PolicyInfo[]; total: number }>>();
const create = vi.fn<(req: PolicyCreateRequest) => Promise<{ name: string; bank: string; pcr_indices: number[]; created_at: string; message: string }>>();
const verify = vi.fn<(name: string) => Promise<{ name: string; valid: boolean; message: string }>>();
const del = vi.fn();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({ policies: { list, create, verify, delete: del } }),
  resetSDKClient: () => {},
}));

const toasts: Array<{ kind: string; message: string }> = [];
vi.mock("../src/stores/toast.svelte.ts", () => ({
  showToast: (kind: string, message: string) => {
    toasts.push({ kind, message });
  },
}));

import PoliciesView from "../src/views/PoliciesView.svelte";

function policy(over: Partial<PolicyInfo> = {}): PolicyInfo {
  return {
    name: "boot-verified",
    bank: "sha256",
    pcr_indices: [0, 7],
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
    ...over,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  toasts.length = 0;
});

describe("PoliciesView", () => {
  it("renders the policy name, bank and joined PCR indices once loaded", async () => {
    list.mockResolvedValue({ policies: [policy()], total: 1 });

    render(PoliciesView);

    expect(await screen.findByText("boot-verified")).toBeInTheDocument();
    expect(screen.getByText("sha256")).toBeInTheDocument();
    expect(screen.getByText("0, 7")).toBeInTheDocument();
  });

  it("shows the empty state with no policies", async () => {
    list.mockResolvedValue({ policies: [], total: 0 });

    render(PoliciesView);

    expect(await screen.findByText("No policies.")).toBeInTheDocument();
  });

  it("surfaces a load error instead of a blank page", async () => {
    list.mockRejectedValue(new Error("TPM not present"));

    render(PoliciesView);

    expect(await screen.findByText("TPM not present")).toBeInTheDocument();
  });

  it("creates a policy with pcr_indices parsed from the comma-separated field", async () => {
    list.mockResolvedValue({ policies: [], total: 0 });
    create.mockResolvedValue({ name: "custom", bank: "sha256", pcr_indices: [0, 2, 4, 7], created_at: "", message: "" });

    render(PoliciesView);
    await screen.findByText("No policies.");

    await fireEvent.click(screen.getByRole("button", { name: "+ Create" }));
    await fireEvent.input(screen.getByPlaceholderText("Name"), { target: { value: "custom" } });
    await fireEvent.input(screen.getByPlaceholderText("PCR indices (e.g. 0,2,4,7)"), { target: { value: "0, 2, 4,7" } });
    await fireEvent.click(screen.getByRole("button", { name: "Create", hidden: true }));

    await waitFor(() => expect(create).toHaveBeenCalledOnce());
    // The wire-format field is pcr_indices (numbers), parsed from the text field.
    expect(create.mock.calls[0]![0]).toEqual({ name: "custom", bank: "sha256", pcr_indices: [0, 2, 4, 7] });
  });

  it("surfaces a create failure inside the dialog", async () => {
    list.mockResolvedValue({ policies: [], total: 0 });
    create.mockRejectedValue(new Error("policy name already exists"));

    render(PoliciesView);
    await screen.findByText("No policies.");

    await fireEvent.click(screen.getByRole("button", { name: "+ Create" }));
    await fireEvent.input(screen.getByPlaceholderText("Name"), { target: { value: "dup" } });
    await fireEvent.click(screen.getByRole("button", { name: "Create", hidden: true }));

    expect(await screen.findByText("policy name already exists")).toBeInTheDocument();
  });

  it("verifies a policy and surfaces the server message via toast", async () => {
    list.mockResolvedValue({ policies: [policy()], total: 1 });
    verify.mockResolvedValue({ name: "boot-verified", valid: false, message: "PCR 7 mismatch" });

    render(PoliciesView);
    await screen.findByText("boot-verified");

    await fireEvent.click(screen.getByRole("button", { name: "Verify" }));

    await waitFor(() => expect(verify).toHaveBeenCalledWith("boot-verified"));
    expect(toasts).toContainEqual({ kind: "warning", message: "boot-verified: INVALID — PCR 7 mismatch" });
  });

  it("deletes a policy by name and reloads", async () => {
    list.mockResolvedValueOnce({ policies: [policy()], total: 1 });
    del.mockResolvedValue({ message: "" });
    list.mockResolvedValueOnce({ policies: [], total: 0 });

    render(PoliciesView);
    await screen.findByText("boot-verified");

    await fireEvent.click(screen.getByRole("button", { name: "Delete" }));

    await waitFor(() => expect(del).toHaveBeenCalledWith("boot-verified"));
    expect(await screen.findByText("No policies.")).toBeInTheDocument();
  });
});
