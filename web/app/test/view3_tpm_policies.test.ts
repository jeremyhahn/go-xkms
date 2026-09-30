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
  TPMPolicy,
  TPMPolicyCreateRequest,
  TPMPolicyListResponse,
  TPMPolicyObjectsResponse,
  TPMPolicyVerifyResponse,
  TPMAuthorityRotateResponse,
} from "@go-xkms/sdk";

const list = vi.fn<() => Promise<TPMPolicyListResponse>>();
const create = vi.fn<(req: TPMPolicyCreateRequest) => Promise<TPMPolicy>>();
const verify = vi.fn<(name: string) => Promise<TPMPolicyVerifyResponse>>();
const update = vi.fn<(name: string) => Promise<TPMPolicy>>();
const revoke = vi.fn<(name: string) => Promise<TPMPolicy>>();
const setAutoUnseal = vi.fn<(name: string, enabled: boolean) => Promise<TPMPolicy>>();
const objects = vi.fn<(name: string) => Promise<TPMPolicyObjectsResponse>>();
const del = vi.fn<(name: string) => Promise<void>>();
const rotateAuthority = vi.fn<() => Promise<TPMAuthorityRotateResponse>>();
const setDescription = vi.fn<(name: string, description: string) => Promise<TPMPolicy>>();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({
    tpmPolicies: {
      list,
      create,
      verify,
      update,
      revoke,
      setAutoUnseal,
      setDescription,
      objects,
      delete: del,
      rotateAuthority,
    },
  }),
  resetSDKClient: () => {},
}));

const toasts: Array<{ kind: string; message: string }> = [];
vi.mock("../src/stores/toast.svelte.ts", () => ({
  showToast: (kind: string, message: string) => {
    toasts.push({ kind, message });
  },
}));

import TpmPoliciesView from "../src/views/TpmPoliciesView.svelte";

function policy(over: Partial<TPMPolicy> = {}): TPMPolicy {
  return {
    name: "boot",
    branches: [{ conditions: [{ type: "pcr", bank: "sha256", pcrs: [0, 7] }], approved: true }],
    index: 1,
    approved: true,
    created_at: "2026-01-01T00:00:00Z",
    ...over,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  toasts.length = 0;
  // The list column count is fetched per policy via objects(); default to
  // empty so tests that don't care about counts don't need to stub it.
  objects.mockResolvedValue({ name: "", objects: [] });
});

describe("TpmPoliciesView", () => {
  it("renders name, description, branches, approval status, auto-unseal and object count once loaded", async () => {
    list.mockResolvedValue({
      policies: [
        policy({
          auto_unseal: true,
          description: "firmware or PIN",
          branches: [
            { conditions: [{ type: "pcr", bank: "sha256", pcrs: [0, 7] }, { type: "locality", localities: [0] }] },
            { conditions: [{ type: "auth_value" }] },
          ],
        }),
      ],
    });
    objects.mockResolvedValue({ name: "boot", objects: ["key/db-key", "sealed/backup"] });

    render(TpmPoliciesView);

    expect(await screen.findByText("boot")).toBeInTheDocument();
    expect(screen.getByText("firmware or PIN")).toBeInTheDocument();
    expect(screen.getByText("PCR sha256 [0, 7] + locality 0")).toBeInTheDocument();
    expect(screen.getByText("password")).toBeInTheDocument();
    expect(screen.getByText("approved")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Toggle auto-unseal for boot" })).toHaveTextContent("On");
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Objects bound to boot" })).toHaveTextContent("2"),
    );
  });

  it("shows the empty state with no policies", async () => {
    list.mockResolvedValue({ policies: [] });

    render(TpmPoliciesView);

    expect(await screen.findByText("No TPM policies.")).toBeInTheDocument();
  });

  it("surfaces a load error instead of a blank page", async () => {
    list.mockRejectedValue(new Error("TPM not present"));

    render(TpmPoliciesView);

    expect(await screen.findByText("TPM not present")).toBeInTheDocument();
  });

  it("creates a policy of one pcr branch with the default bank and PCR selection", async () => {
    list.mockResolvedValue({ policies: [] });
    create.mockResolvedValue(policy());

    render(TpmPoliciesView);
    await screen.findByText("No TPM policies.");

    await fireEvent.click(screen.getByRole("button", { name: "+ Create" }));
    await fireEvent.input(screen.getByPlaceholderText("Name"), { target: { value: "boot" } });
    await fireEvent.click(screen.getByRole("button", { name: "Create", hidden: true }));

    await waitFor(() => expect(create).toHaveBeenCalledOnce());
    expect(create.mock.calls[0]![0]).toEqual({
      name: "boot",
      description: "",
      branches: [{ conditions: [{ type: "pcr", bank: "sha256", pcrs: [0, 7] }] }],
      auto_unseal: false,
    });
  });

  it("adjusts the PCR selection and bank before creating a policy", async () => {
    list.mockResolvedValue({ policies: [] });
    create.mockResolvedValue(policy());

    render(TpmPoliciesView);
    await screen.findByText("No TPM policies.");

    await fireEvent.click(screen.getByRole("button", { name: "+ Create" }));
    await fireEvent.input(screen.getByPlaceholderText("Name"), { target: { value: "extended" } });
    await fireEvent.input(screen.getByPlaceholderText("Description"), { target: { value: "kernel" } });
    await fireEvent.change(screen.getByRole("combobox"), { target: { value: "sha384" } });
    // Deselect the default PCR 0, select PCR 14, leave PCR 7 checked.
    await fireEvent.click(screen.getByRole("checkbox", { name: "PCR 0" }));
    await fireEvent.click(screen.getByRole("checkbox", { name: "PCR 14" }));
    await fireEvent.click(screen.getByRole("checkbox", { name: "Auto-unseal", hidden: true }));
    await fireEvent.click(screen.getByRole("button", { name: "Create", hidden: true }));

    await waitFor(() => expect(create).toHaveBeenCalledOnce());
    expect(create.mock.calls[0]![0]).toEqual({
      name: "extended",
      description: "kernel",
      branches: [{ conditions: [{ type: "pcr", bank: "sha384", pcrs: [7, 14] }] }],
      auto_unseal: true,
    });
  });

  it("creates a composite policy in advanced mode: PCRs and locality, or the password", async () => {
    list.mockResolvedValue({ policies: [] });
    create.mockResolvedValue(policy());

    render(TpmPoliciesView);
    await screen.findByText("No TPM policies.");

    await fireEvent.click(screen.getByRole("button", { name: "+ Create" }));
    await fireEvent.input(screen.getByPlaceholderText("Name"), { target: { value: "strict" } });
    await fireEvent.click(screen.getByRole("tab", { name: "Advanced", hidden: true }));
    await fireEvent.click(screen.getByRole("checkbox", { name: "Branch 1 locality condition", hidden: true }));
    await fireEvent.click(screen.getByRole("button", { name: "+ Add branch", hidden: true }));
    // The second branch: the password alone.
    await fireEvent.click(screen.getByRole("checkbox", { name: "Branch 2 PCR condition", hidden: true }));
    await fireEvent.click(screen.getByRole("checkbox", { name: "Branch 2 password condition", hidden: true }));
    await fireEvent.click(screen.getByRole("button", { name: "Create", hidden: true }));

    await waitFor(() => expect(create).toHaveBeenCalledOnce());
    expect(create.mock.calls[0]![0].branches).toEqual([
      { conditions: [{ type: "pcr", bank: "sha256", pcrs: [0, 7] }, { type: "locality", localities: [0] }] },
      { conditions: [{ type: "auth_value" }] },
    ]);
  });

  it("refuses to create an advanced branch without conditions, and removes a branch", async () => {
    list.mockResolvedValue({ policies: [] });

    render(TpmPoliciesView);
    await screen.findByText("No TPM policies.");

    await fireEvent.click(screen.getByRole("button", { name: "+ Create" }));
    await fireEvent.input(screen.getByPlaceholderText("Name"), { target: { value: "empty" } });
    await fireEvent.click(screen.getByRole("tab", { name: "Advanced", hidden: true }));
    await fireEvent.click(screen.getByRole("button", { name: "+ Add branch", hidden: true }));
    await fireEvent.click(screen.getByRole("checkbox", { name: "Branch 2 PCR condition", hidden: true }));

    expect(screen.getByText("Choose at least one condition")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Create", hidden: true })).toBeDisabled();

    await fireEvent.click(screen.getByRole("button", { name: "Remove branch 2", hidden: true }));
    expect(screen.queryByText("Choose at least one condition")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Create", hidden: true })).toBeEnabled();
  });

  it("edits a policy's description", async () => {
    list.mockResolvedValue({ policies: [policy({ description: "old" })] });
    setDescription.mockResolvedValue(policy({ description: "firmware" }));

    render(TpmPoliciesView);
    await screen.findByText("boot");

    await fireEvent.click(screen.getByRole("button", { name: "Edit description of boot" }));
    const text = screen.getByRole("textbox", { name: "Policy description", hidden: true });
    expect(text).toHaveValue("old");
    await fireEvent.input(text, { target: { value: "firmware" } });
    await fireEvent.click(screen.getByRole("button", { name: "Save", hidden: true }));

    await waitFor(() => expect(setDescription).toHaveBeenCalledWith("boot", "firmware"));
    await waitFor(() => expect(list).toHaveBeenCalledTimes(2));
  });

  it("surfaces a refused description inside its dialog", async () => {
    list.mockResolvedValue({ policies: [policy()] });
    setDescription.mockRejectedValue(new Error("description too long"));

    render(TpmPoliciesView);
    await screen.findByText("boot");

    await fireEvent.click(screen.getByRole("button", { name: "Edit description of boot" }));
    await fireEvent.click(screen.getByRole("button", { name: "Save", hidden: true }));

    expect(await screen.findByText("description too long")).toBeInTheDocument();
  });

  it("surfaces a create failure inside the dialog", async () => {
    list.mockResolvedValue({ policies: [] });
    create.mockRejectedValue(new Error("policy name already exists"));

    render(TpmPoliciesView);
    await screen.findByText("No TPM policies.");

    await fireEvent.click(screen.getByRole("button", { name: "+ Create" }));
    await fireEvent.input(screen.getByPlaceholderText("Name"), { target: { value: "dup" } });
    await fireEvent.click(screen.getByRole("button", { name: "Create", hidden: true }));

    expect(await screen.findByText("policy name already exists")).toBeInTheDocument();
  });

  it("verifies a policy and shows each branch's result in a dialog", async () => {
    list.mockResolvedValue({ policies: [policy()] });
    verify.mockResolvedValue({
      name: "boot",
      match: false,
      approved: true,
      branches: [
        { match: false, mismatched: [7], approved: true },
        { match: true, approved: true },
      ],
    });

    render(TpmPoliciesView);
    await screen.findByText("boot");

    await fireEvent.click(screen.getByRole("button", { name: "Verify" }));

    await waitFor(() => expect(verify).toHaveBeenCalledWith("boot"));
    expect(await screen.findByText('Verify "boot"')).toBeInTheDocument();
    expect(screen.getByText("PCRs mismatched")).toBeInTheDocument();
    expect(screen.getByText(/Branch 1:\s*PCRs 7 changed,\s*approved/)).toBeInTheDocument();
    expect(screen.getByText(/Branch 2:\s*PCRs match,\s*approved/)).toBeInTheDocument();
  });

  it("re-captures and re-approves a policy via Update, then reloads the list", async () => {
    list.mockResolvedValue({ policies: [policy()] });
    update.mockResolvedValue(policy());

    render(TpmPoliciesView);
    await screen.findByText("boot");

    await fireEvent.click(screen.getByRole("button", { name: "Update" }));

    await waitFor(() => expect(update).toHaveBeenCalledWith("boot"));
    await waitFor(() => expect(list).toHaveBeenCalledTimes(2));
  });

  it("revokes a policy's approval and reloads the list", async () => {
    list.mockResolvedValue({ policies: [policy()] });
    revoke.mockResolvedValue(policy({ approved: false }));

    render(TpmPoliciesView);
    await screen.findByText("boot");

    await fireEvent.click(screen.getByRole("button", { name: "Revoke" }));

    await waitFor(() => expect(revoke).toHaveBeenCalledWith("boot"));
    await waitFor(() => expect(list).toHaveBeenCalledTimes(2));
  });

  it("toggles auto-unseal on for a policy that has it off", async () => {
    list.mockResolvedValue({ policies: [policy({ auto_unseal: false })] });
    setAutoUnseal.mockResolvedValue(policy({ auto_unseal: true }));

    render(TpmPoliciesView);
    await screen.findByText("boot");

    await fireEvent.click(screen.getByRole("button", { name: "Toggle auto-unseal for boot" }));

    await waitFor(() => expect(setAutoUnseal).toHaveBeenCalledWith("boot", true));
  });

  it("opens the objects drawer and lists the objects bound to the policy", async () => {
    list.mockResolvedValue({ policies: [policy()] });
    objects.mockResolvedValue({ name: "boot", objects: ["key/db-key", "sealed/backup"] });

    render(TpmPoliciesView);
    await screen.findByText("boot");

    await fireEvent.click(await screen.findByRole("button", { name: "Objects bound to boot" }));

    expect(await screen.findByText('Objects bound to "boot"')).toBeInTheDocument();
    expect(screen.getByText("key/db-key")).toBeInTheDocument();
    expect(screen.getByText("sealed/backup")).toBeInTheDocument();
  });

  it("deletes a policy by name and reloads", async () => {
    list.mockResolvedValueOnce({ policies: [policy()] });
    del.mockResolvedValue(undefined);
    list.mockResolvedValueOnce({ policies: [] });

    render(TpmPoliciesView);
    await screen.findByText("boot");

    await fireEvent.click(screen.getByRole("button", { name: "Delete" }));

    await waitFor(() => expect(del).toHaveBeenCalledWith("boot"));
    expect(await screen.findByText("No TPM policies.")).toBeInTheDocument();
  });

  it("surfaces the 409 conflict message listing the policy's assigned objects on delete", async () => {
    list.mockResolvedValue({ policies: [policy()] });
    del.mockRejectedValue(new Error('policy "boot" is assigned to key/db-key, sealed/backup'));

    render(TpmPoliciesView);
    await screen.findByText("boot");

    await fireEvent.click(screen.getByRole("button", { name: "Delete" }));

    await waitFor(() =>
      expect(toasts).toContainEqual({
        kind: "error",
        message: 'policy "boot" is assigned to key/db-key, sealed/backup',
      }),
    );
  });

  it("rotates the policy authority after confirmation", async () => {
    list.mockResolvedValue({ policies: [] });
    rotateAuthority.mockResolvedValue({ generation: 2, authority_name: "ab12cd", epoch: 1 });

    render(TpmPoliciesView);
    await screen.findByText("No TPM policies.");

    await fireEvent.click(screen.getByRole("button", { name: "Rotate authority" }));
    expect(screen.getByText("Rotate policy authority?")).toBeInTheDocument();
    await fireEvent.click(screen.getByRole("button", { name: "Rotate", hidden: true }));

    await waitFor(() => expect(rotateAuthority).toHaveBeenCalledOnce());
    expect(toasts.some((t) => t.kind === "success" && t.message.includes("generation 2"))).toBe(true);
  });

  it("cancels the rotate-authority confirmation without calling the API", async () => {
    list.mockResolvedValue({ policies: [] });

    render(TpmPoliciesView);
    await screen.findByText("No TPM policies.");

    await fireEvent.click(screen.getByRole("button", { name: "Rotate authority" }));
    await fireEvent.click(screen.getByRole("button", { name: "Cancel", hidden: true }));

    expect(rotateAuthority).not.toHaveBeenCalled();
    expect(screen.queryByText("Rotate policy authority?")).not.toBeInTheDocument();
  });
});
