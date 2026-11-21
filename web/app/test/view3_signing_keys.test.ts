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

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/svelte";
import type {
  ListSigningKeyBindingsResponse,
  SetSigningKeyBindingRequest,
  SigningKeyBinding,
  SigningKeyResolution,
} from "@go-xkms/sdk";

const list = vi.fn<() => Promise<ListSigningKeyBindingsResponse>>();
const set = vi.fn<(req: SetSigningKeyBindingRequest) => Promise<SigningKeyBinding>>();
const del = vi.fn<(repository: string) => Promise<void>>();
const resolve = vi.fn<(repository: string) => Promise<SigningKeyResolution>>();
const get = vi.fn<(repository: string) => Promise<SigningKeyBinding>>();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({ signingKeys: { list, set, delete: del, resolve, get } }),
  resetSDKClient: () => {},
}));

const toasts: Array<{ kind: string; message: string }> = [];
vi.mock("../src/stores/toast.svelte.ts", () => ({
  showToast: (kind: string, message: string) => {
    toasts.push({ kind, message });
  },
}));

import SigningKeysView from "../src/views/SigningKeysView.svelte";

function binding(over: Partial<SigningKeyBinding> = {}): SigningKeyBinding {
  return {
    repository: "acme/fw",
    key_id: "fw-key",
    backend: "software",
    updated_at: "2026-01-01T00:00:00Z",
    ...over,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  toasts.length = 0;
});

afterEach(() => {
  vi.restoreAllMocks();
});

async function openSetForm(): Promise<void> {
  await fireEvent.click(await screen.findByRole("button", { name: "Set binding" }));
  await screen.findByRole("heading", { name: "Set signing key binding" });
}

async function fill(repository: string, keyId: string, backend: string): Promise<void> {
  await fireEvent.input(screen.getByLabelText("Repository"), { target: { value: repository } });
  await fireEvent.input(screen.getByLabelText("Key ID"), { target: { value: keyId } });
  await fireEvent.input(screen.getByLabelText("Backend"), { target: { value: backend } });
}

describe("SigningKeysView list", () => {
  it("renders one row per binding", async () => {
    list.mockResolvedValue({
      bindings: [
        binding(),
        binding({ repository: "acme/app", key_id: "app-key", backend: "pkcs11", updated_at: "2026-02-02T00:00:00Z" }),
      ],
    });
    const { container } = render(SigningKeysView);
    await screen.findByText("acme/fw");
    expect(screen.getByText("acme/app")).toBeTruthy();
    expect(screen.getByText("fw-key")).toBeTruthy();
    expect(screen.getByText("app-key")).toBeTruthy();
    expect(screen.getByText("software")).toBeTruthy();
    expect(screen.getByText("pkcs11")).toBeTruthy();
    expect(container.querySelector('time[datetime="2026-01-01T00:00:00Z"]')).not.toBeNull();
    expect(container.querySelector('time[datetime="2026-02-02T00:00:00Z"]')).not.toBeNull();
    expect(container.querySelectorAll("tbody tr").length).toBe(2);
  });

  it("says the release key signs every repository when there are no bindings", async () => {
    list.mockResolvedValue({ bindings: [] });
    render(SigningKeysView);
    await screen.findByText(/release key signs every repository/i);
  });

  it("shows an error alert when list fails", async () => {
    list.mockRejectedValue(new Error("list boom"));
    render(SigningKeysView);
    await screen.findByText("list boom");
  });
});

describe("SigningKeysView set", () => {
  it("sets a binding, toasts and reloads", async () => {
    list.mockResolvedValue({ bindings: [] });
    set.mockResolvedValue(binding());
    render(SigningKeysView);
    await openSetForm();
    await fill("acme/fw", "fw-key", "software");
    await fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(set).toHaveBeenCalledTimes(1));
    expect(set).toHaveBeenCalledWith({ repository: "acme/fw", key_id: "fw-key", backend: "software" });
    await waitFor(() => expect(list).toHaveBeenCalledTimes(2));
    expect(toasts.some((t) => t.kind === "success")).toBe(true);
  });

  it("sends no backend field when backend is empty", async () => {
    list.mockResolvedValue({ bindings: [] });
    set.mockResolvedValue(binding({ backend: undefined }));
    render(SigningKeysView);
    await openSetForm();
    await fill("acme/fw", "fw-key", "");
    await fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(set).toHaveBeenCalledTimes(1));
    const req = set.mock.calls[0]![0];
    expect(req).toEqual({ repository: "acme/fw", key_id: "fw-key" });
    expect("backend" in req).toBe(false);
  });

  it("disables submit while repository or key id is empty", async () => {
    list.mockResolvedValue({ bindings: [] });
    render(SigningKeysView);
    await openSetForm();
    const save = screen.getByRole("button", { name: "Save" }) as HTMLButtonElement;
    expect(save.disabled).toBe(true);
    await fill("acme/fw", "", "");
    expect(save.disabled).toBe(true);
    await fill("", "fw-key", "");
    expect(save.disabled).toBe(true);
    await fill("acme/fw", "fw-key", "");
    expect(save.disabled).toBe(false);
  });

  it("toasts an error and keeps the form values when set fails", async () => {
    list.mockResolvedValue({ bindings: [] });
    set.mockRejectedValue(new Error("set boom"));
    render(SigningKeysView);
    await openSetForm();
    await fill("acme/fw", "fw-key", "software");
    await fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(toasts.some((t) => t.kind === "error" && t.message.includes("set boom"))).toBe(true));
    expect((screen.getByLabelText("Repository") as HTMLInputElement).value).toBe("acme/fw");
    expect((screen.getByLabelText("Key ID") as HTMLInputElement).value).toBe("fw-key");
    expect((screen.getByLabelText("Backend") as HTMLInputElement).value).toBe("software");
  });
});

describe("SigningKeysView delete", () => {
  it("deletes after confirm and reloads", async () => {
    list.mockResolvedValue({ bindings: [binding()] });
    del.mockResolvedValue(undefined);
    render(SigningKeysView);
    await fireEvent.click(await screen.findByRole("button", { name: "Delete binding for acme/fw" }));
    await screen.findByRole("heading", { name: /Delete the binding for "acme\/fw"/ });
    await fireEvent.click(screen.getByRole("button", { name: "Delete" }));
    await waitFor(() => expect(del).toHaveBeenCalledWith("acme/fw"));
    await waitFor(() => expect(list).toHaveBeenCalledTimes(2));
  });

  it("calls nothing when the confirm is cancelled", async () => {
    list.mockResolvedValue({ bindings: [binding()] });
    render(SigningKeysView);
    await fireEvent.click(await screen.findByRole("button", { name: "Delete binding for acme/fw" }));
    await fireEvent.click(await screen.findByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByRole("heading", { name: /Delete the binding/ })).toBeNull());
    expect(del).not.toHaveBeenCalled();
    expect(list).toHaveBeenCalledTimes(1);
  });
});

describe("SigningKeysView resolve", () => {
  async function lookUp(repository: string): Promise<void> {
    await fireEvent.input(await screen.findByLabelText("Repository to resolve"), { target: { value: repository } });
    await fireEvent.click(screen.getByRole("button", { name: "Resolve" }));
  }

  it("shows that the release key signs an unbound repository", async () => {
    list.mockResolvedValue({ bindings: [] });
    resolve.mockResolvedValue({ repository: "acme/fw", key_id: "release", default: true });
    render(SigningKeysView);
    await lookUp("acme/fw");
    await waitFor(() => expect(resolve).toHaveBeenCalledWith("acme/fw"));
    await screen.findByText(/release key signs acme\/fw/i);
  });

  it("shows the bound key id and backend", async () => {
    list.mockResolvedValue({ bindings: [] });
    resolve.mockResolvedValue({ repository: "acme/fw", key_id: "fw-key", backend: "software", default: false });
    render(SigningKeysView);
    await lookUp("acme/fw");
    const result = await screen.findByTestId("resolve-result");
    expect(result.textContent).toContain("fw-key");
    expect(result.textContent).toContain("software");
    expect(result.textContent).not.toMatch(/release key/i);
  });
});
