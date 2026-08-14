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
import { render, screen, waitFor } from "@testing-library/svelte";
import userEvent from "@testing-library/user-event";
import type {
  AuthFactorAddResponse,
  AuthFactorListResponse,
  AuthFactorRelabelResponse,
  AuthFactorRemoveResponse,
  AuthMeResponse,
  ListUsersResponse,
} from "@go-xkms/sdk";

const listUsers = vi.fn<() => Promise<ListUsersResponse>>();
const listFactors = vi.fn<() => Promise<AuthFactorListResponse>>();
const addFactor = vi.fn<() => Promise<AuthFactorAddResponse>>();
const removeFactor = vi.fn<() => Promise<AuthFactorRemoveResponse>>();
const relabelFactor = vi.fn<() => Promise<AuthFactorRelabelResponse>>();
const authMe = vi.fn<() => Promise<AuthMeResponse>>();

const toasts: { kind: string; message: string }[] = [];

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({
    users: { list: listUsers },
    factors: {
      list: listFactors,
      add: addFactor,
      remove: removeFactor,
      relabel: relabelFactor,
    },
    auth: { me: authMe },
  }),
  resetSDKClient: () => {},
}));

vi.mock("../src/stores/toast.svelte.ts", () => ({
  showToast: (kind: string, message: string) => {
    toasts.push({ kind, message });
  },
}));

import { clearSession, loadSession } from "../src/stores/session.svelte.ts";
import FactorsView from "../src/views/FactorsView.svelte";

function factor(over: Record<string, unknown> = {}) {
  return {
    id: "f-1",
    user_id: 42,
    type: "fido2",
    label: "YubiKey 5",
    credential: "Y3JlZA==",
    registered_at: "2026-01-01T00:00:00Z",
    ...over,
  };
}

async function withPermissions(perms: Record<string, boolean>): Promise<void> {
  authMe.mockResolvedValue({
    subject: "op-1",
    username: "operator",
    roles: ["admin"],
    permissions: perms,
    capabilities: { factors: true },
  } as AuthMeResponse);
  await loadSession();
}

const ALL = { "users:read": true, "users:update": true, "users:list": true };

beforeEach(async () => {
  vi.clearAllMocks();
  toasts.length = 0;
  clearSession();
  listUsers.mockResolvedValue({
    users: [
      {
        id: "42",
        username: "alice",
        display_name: "Alice",
        role: "admin",
        enabled: true,
        created_at: "2026-01-01T00:00:00Z",
      },
      {
        id: "43",
        username: "bob",
        display_name: "Bob",
        role: "operator",
        enabled: true,
        created_at: "2026-01-01T00:00:00Z",
      },
    ],
  } as ListUsersResponse);
  listFactors.mockResolvedValue({ factors: [], total: 0 });
});

describe("FactorsView loading", () => {
  it("selects the first user and lists that user's factors by numeric id", async () => {
    await withPermissions(ALL);
    listFactors.mockResolvedValue({ factors: [factor()], total: 1 });

    render(FactorsView);

    await waitFor(() => expect(screen.getByText("YubiKey 5")).toBeInTheDocument());
    // UserInfo.id arrives as a string (Go tags it `json:"id,string"`), but the
    // factors endpoint is keyed by a NUMBER — a regression here would send
    // "42" and the server would reject it as an invalid user_id.
    expect(listFactors).toHaveBeenCalledWith(42);
    expect(screen.getByText("fido2")).toBeInTheDocument();
  });

  it("reloads factors when a different user is selected", async () => {
    await withPermissions(ALL);

    render(FactorsView);
    await waitFor(() => expect(listFactors).toHaveBeenCalledWith(42));

    const select = document.querySelector("select") as HTMLSelectElement;
    await userEvent.selectOptions(select, "43");

    await waitFor(() => expect(listFactors).toHaveBeenCalledWith(43));
  });

  it("shows the empty message when the user has no factors", async () => {
    await withPermissions(ALL);

    render(FactorsView);

    expect(await screen.findByText("No factors enrolled.")).toBeInTheDocument();
  });

  it("surfaces a user-list failure", async () => {
    await withPermissions(ALL);
    listUsers.mockRejectedValue(new Error("user store unavailable"));

    render(FactorsView);

    expect(await screen.findByText("user store unavailable")).toBeInTheDocument();
  });

  it("surfaces a factor-list failure", async () => {
    await withPermissions(ALL);
    listFactors.mockRejectedValue(new Error("qrdb node unreachable"));

    render(FactorsView);

    expect(await screen.findByText("qrdb node unreachable")).toBeInTheDocument();
  });
});

describe("FactorsView status rendering", () => {
  it("distinguishes an active factor from a revoked one", async () => {
    await withPermissions(ALL);
    listFactors.mockResolvedValue({
      factors: [
        factor(),
        factor({ id: "f-2", label: "old card", revoked_at: "2026-02-01T00:00:00Z" }),
      ],
      total: 2,
    });

    render(FactorsView);

    await waitFor(() => expect(screen.getByText("active")).toBeInTheDocument());
    expect(screen.getByText("revoked")).toBeInTheDocument();
    // A revoked factor must not offer mutation controls — it is already gone.
    expect(screen.getAllByRole("button", { name: "Revoke" })).toHaveLength(1);
  });

  it("renders an em dash for a factor that has never been used", async () => {
    await withPermissions(ALL);
    listFactors.mockResolvedValue({ factors: [factor()], total: 1 });

    render(FactorsView);

    await waitFor(() => expect(screen.getByText("YubiKey 5")).toBeInTheDocument());
    expect(screen.getByText("—")).toBeInTheDocument();
  });

  it("falls back to the factor id when it carries no label", async () => {
    await withPermissions(ALL);
    listFactors.mockResolvedValue({ factors: [factor({ label: undefined })], total: 1 });

    render(FactorsView);

    await waitFor(() => expect(screen.getByText("f-1")).toBeInTheDocument());
  });
});

describe("FactorsView enrolment", () => {
  it("sends the selected user, type, and base64 credential", async () => {
    await withPermissions(ALL);
    addFactor.mockResolvedValue({ factor: factor() });

    render(FactorsView);
    await waitFor(() => expect(screen.getByText("No factors enrolled.")).toBeInTheDocument());

    await userEvent.click(screen.getByRole("button", { name: "+ Enroll factor" }));
    const dialog = screen.getByText("Enroll auth factor").closest(".modal-box") as HTMLElement;
    await userEvent.type(dialog.querySelector('input[placeholder="Label"]') as HTMLElement, "YubiKey 5");
    await userEvent.type(dialog.querySelector("input.font-mono") as HTMLElement, "Y3JlZA==");
    await userEvent.click(screen.getByRole("button", { name: "Enroll", hidden: true }));

    await waitFor(() => expect(addFactor).toHaveBeenCalled());
    expect(addFactor).toHaveBeenCalledWith({
      user_id: 42,
      type: "fido2",
      label: "YubiKey 5",
      credential: "Y3JlZA==",
      // fido2 factors have no renewal-stable SPKI key, so it must be omitted
      // rather than sent as an empty string.
      spki_credential: undefined,
      created_by: "admin",
    });
    expect(toasts.at(-1)?.kind).toBe("success");
  });

  it("offers the SPKI field for certificate factors but not for fido2", async () => {
    await withPermissions(ALL);

    render(FactorsView);
    await waitFor(() => expect(screen.getByText("No factors enrolled.")).toBeInTheDocument());

    await userEvent.click(screen.getByRole("button", { name: "+ Enroll factor" }));
    expect(screen.queryByText(/SPKI credential/)).toBeNull();

    const dialog = screen.getByText("Enroll auth factor").closest(".modal-box") as HTMLElement;
    await userEvent.selectOptions(dialog.querySelector("select") as HTMLSelectElement, "mtls");

    expect(await screen.findByText(/SPKI credential/)).toBeInTheDocument();
  });

  it("keeps the dialog open and shows the reason when enrolment fails", async () => {
    await withPermissions(ALL);
    addFactor.mockRejectedValue(new Error("credential already enrolled"));

    render(FactorsView);
    await waitFor(() => expect(screen.getByText("No factors enrolled.")).toBeInTheDocument());

    await userEvent.click(screen.getByRole("button", { name: "+ Enroll factor" }));
    const dialog = screen.getByText("Enroll auth factor").closest(".modal-box") as HTMLElement;
    await userEvent.type(dialog.querySelector('input[placeholder="Label"]') as HTMLElement, "dupe");
    await userEvent.type(dialog.querySelector("input.font-mono") as HTMLElement, "Y3JlZA==");
    await userEvent.click(screen.getByRole("button", { name: "Enroll", hidden: true }));

    expect(await screen.findByText("credential already enrolled")).toBeInTheDocument();
    expect(screen.getByText("Enroll auth factor")).toBeInTheDocument();
  });

  it("will not submit without both a label and a credential", async () => {
    await withPermissions(ALL);

    render(FactorsView);
    await waitFor(() => expect(screen.getByText("No factors enrolled.")).toBeInTheDocument());

    await userEvent.click(screen.getByRole("button", { name: "+ Enroll factor" }));
    expect(screen.getByRole("button", { name: "Enroll", hidden: true })).toBeDisabled();
    expect(addFactor).not.toHaveBeenCalled();
  });
});

describe("FactorsView revocation", () => {
  it("revokes without force by default and with force on the explicit control", async () => {
    await withPermissions(ALL);
    listFactors.mockResolvedValue({ factors: [factor()], total: 1 });
    removeFactor.mockResolvedValue({ status: "revoked" });

    render(FactorsView);
    await waitFor(() => expect(screen.getByText("YubiKey 5")).toBeInTheDocument());

    await userEvent.click(screen.getByRole("button", { name: "Revoke" }));
    await waitFor(() => expect(removeFactor).toHaveBeenCalledWith("f-1", false));

    await userEvent.click(screen.getByRole("button", { name: "Force revoke" }));
    await waitFor(() => expect(removeFactor).toHaveBeenCalledWith("f-1", true));
  });

  it("toasts the last-active-factor refusal instead of swallowing it", async () => {
    await withPermissions(ALL);
    listFactors.mockResolvedValue({ factors: [factor()], total: 1 });
    removeFactor.mockRejectedValue(new Error("cannot revoke last active factor"));

    render(FactorsView);
    await waitFor(() => expect(screen.getByText("YubiKey 5")).toBeInTheDocument());

    await userEvent.click(screen.getByRole("button", { name: "Revoke" }));

    await waitFor(() =>
      expect(toasts.at(-1)).toEqual({
        kind: "error",
        message: "cannot revoke last active factor",
      }),
    );
  });
});

describe("FactorsView relabel", () => {
  it("sends only the new label, keyed by factor id", async () => {
    await withPermissions(ALL);
    listFactors.mockResolvedValue({ factors: [factor()], total: 1 });
    relabelFactor.mockResolvedValue({ factor: factor({ label: "spare key" }) });

    render(FactorsView);
    await waitFor(() => expect(screen.getByText("YubiKey 5")).toBeInTheDocument());

    await userEvent.click(screen.getByRole("button", { name: "Relabel" }));
    const dialog = screen.getByText("Relabel factor").closest(".modal-box") as HTMLElement;
    const input = dialog.querySelector("input") as HTMLInputElement;
    await userEvent.clear(input);
    await userEvent.type(input, "spare key");
    await userEvent.click(screen.getByRole("button", { name: "Save", hidden: true }));

    await waitFor(() => expect(relabelFactor).toHaveBeenCalledWith("f-1", { label: "spare key" }));
    expect(toasts.at(-1)?.kind).toBe("success");
  });

  it("keeps the dialog open and shows the reason when the relabel fails", async () => {
    await withPermissions(ALL);
    listFactors.mockResolvedValue({ factors: [factor()], total: 1 });
    relabelFactor.mockRejectedValue(new Error("factor not found"));

    render(FactorsView);
    await waitFor(() => expect(screen.getByText("YubiKey 5")).toBeInTheDocument());

    await userEvent.click(screen.getByRole("button", { name: "Relabel" }));
    await userEvent.click(screen.getByRole("button", { name: "Save", hidden: true }));

    expect(await screen.findByText("factor not found")).toBeInTheDocument();
    expect(screen.getByText("Relabel factor")).toBeInTheDocument();
  });
});

describe("FactorsView RBAC gating", () => {
  it("hides every mutation control without users:update", async () => {
    await withPermissions({ "users:read": true, "users:list": true });
    listFactors.mockResolvedValue({ factors: [factor()], total: 1 });

    render(FactorsView);
    await waitFor(() => expect(screen.getByText("YubiKey 5")).toBeInTheDocument());

    expect(screen.queryByRole("button", { name: "+ Enroll factor" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Relabel" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Revoke" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Force revoke" })).toBeNull();
  });
});
