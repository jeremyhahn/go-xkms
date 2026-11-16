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

// Each view acts on the target it loaded: a response for a target that is
// no longer current is dropped, and Save/Start/Stop/Apply never send one
// target's state to another. Every response here is resolved by hand.

import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/svelte";

interface Deferred<T = unknown> {
  resolve: (v: T) => void;
  reject: (e: unknown) => void;
  promise: Promise<T>;
}

function deferred<T = unknown>(): Deferred<T> {
  let resolve!: (v: T) => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { resolve, reject, promise };
}

// One pending response per call, in call order, keyed by a call label.
const pending: Array<{ label: string; args: unknown[]; d: Deferred }> = [];

function call(label: string, args: unknown[]): Promise<unknown> {
  const d = deferred();
  pending.push({ label, args, d });
  return d.promise;
}

function take(label: string): Deferred {
  const i = pending.findIndex((p) => p.label === label);
  if (i < 0) throw new Error(`no pending ${label}; have ${pending.map((p) => p.label).join(", ")}`);
  return pending.splice(i, 1)[0]!.d;
}

async function settle(): Promise<void> {
  for (let i = 0; i < 5; i++) await new Promise((r) => setTimeout(r, 0));
}

const request = vi.fn((method: string, path: string, opts?: unknown) => call(`${method} ${path}`, [opts]));
const list = vi.fn(() => Promise.resolve({ tenants: [{ id: "ta", name: "A" }, { id: "tb", name: "B" }] }));
const getTPMMode = vi.fn((id: string) => call(`mode ${id}`, [id]));
const vtpmStatus = vi.fn((id: string) => call(`status ${id}`, [id]));
const setTPMMode = vi.fn((id: string, req: unknown) => call(`set ${id}`, [id, req]));
const vtpmStart = vi.fn((id: string) => call(`start ${id}`, [id]));
const vtpmStop = vi.fn((id: string) => call(`stop ${id}`, [id]));

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({
    http: { request },
    tenants: { list, getTPMMode, setTPMMode, vtpmStatus, vtpmStart, vtpmStop },
  }),
  resetSDKClient: () => {},
}));

vi.mock("../src/stores/toast.svelte.ts", () => ({
  showToast: () => {},
}));

import KeyAccessPolicyView from "../src/views/KeyAccessPolicyView.svelte";
import TenantTpmView from "../src/views/TenantTpmView.svelte";
import KeyMetadataView from "../src/views/KeyMetadataView.svelte";

beforeEach(() => {
  vi.clearAllMocks();
  pending.length = 0;
});

async function setKey(id: string, backend: string): Promise<void> {
  await fireEvent.input(screen.getByPlaceholderText("Key ID"), { target: { value: id } });
  await fireEvent.input(screen.getByPlaceholderText("Backend"), { target: { value: backend } });
}

describe("KeyAccessPolicyView target binding", () => {
  it("never saves key A's policy to key B typed while A's load was in flight", async () => {
    render(KeyAccessPolicyView);
    await setKey("ka", "software");
    await fireEvent.click(screen.getByRole("button", { name: "Load" }));
    const getA = take("GET /api/v1/keys/ka/policy");

    await fireEvent.input(screen.getByPlaceholderText("Key ID"), { target: { value: "kb" } });
    getA.resolve({ policy: { version: 4, allowed_principals: ["alice"] } });
    await settle();

    await fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await settle();
    const puts = request.mock.calls.filter(([m]) => m === "PUT");
    for (const [, path, opts] of puts) {
      const body = (opts as { body: { policy: { allowed_principals?: string[] } } }).body;
      expect(path === "/api/v1/keys/kb/policy" && (body.policy.allowed_principals ?? []).includes("alice")).toBe(false);
    }
    expect(screen.queryByText("alice")).not.toBeInTheDocument();
  });
});

describe("TenantTpmView target binding", () => {
  it("shows and acts on the last selected tenant when an older selection resolves last", async () => {
    render(TenantTpmView);
    const select = await screen.findByLabelText("Tenant");
    await waitFor(() => expect(screen.getByRole("option", { name: "B (tb)" })).toBeInTheDocument());

    await fireEvent.change(select, { target: { value: "ta" } });
    await fireEvent.change(select, { target: { value: "tb" } });
    const modeA = take("mode ta");

    take("mode tb").resolve({ mode: "vtpm" });
    await settle();
    take("status tb").resolve({ running: false, socket: "/run/b.sock", pid: 0, restarts: 0 });
    await settle();

    modeA.resolve({ mode: "vtpm" });
    await settle();
    if (pending.some((p) => p.label === "status ta")) {
      take("status ta").resolve({ running: true, socket: "/run/a.sock", pid: 7, restarts: 1 });
      await settle();
    }

    expect(screen.getByTestId("current-mode")).toHaveTextContent("vtpm");
    expect(screen.getByText("/run/b.sock")).toBeInTheDocument();
    expect(screen.queryByText("/run/a.sock")).not.toBeInTheDocument();
    expect(screen.getByText("stopped")).toBeInTheDocument();

    await fireEvent.click(screen.getByRole("button", { name: "Start" }));
    expect(vtpmStart).toHaveBeenCalledWith("tb");
    take("start tb").resolve({ running: true, socket: "/run/b.sock", pid: 9, restarts: 0 });
    await settle();

    await fireEvent.click(screen.getByRole("button", { name: "Stop" }));
    await fireEvent.click(screen.getByRole("button", { name: "Stop vTPM" }));
    expect(vtpmStop).toHaveBeenCalledWith("tb");
    take("stop tb").resolve({ running: false, socket: "/run/b.sock", pid: 0, restarts: 0 });
    await settle();

    await fireEvent.change(screen.getByLabelText("New mode"), { target: { value: "none" } });
    await fireEvent.click(screen.getByRole("button", { name: "Apply" }));
    await fireEvent.click(screen.getByRole("button", { name: "Change mode" }));
    expect(setTPMMode).toHaveBeenCalledWith("tb", expect.objectContaining({ tenant_id: "tb", mode: "none" }));
    expect(vtpmStart).not.toHaveBeenCalledWith("ta");
    expect(vtpmStop).not.toHaveBeenCalledWith("ta");
    expect(setTPMMode).not.toHaveBeenCalledWith("ta", expect.anything());
  });
});

describe("KeyMetadataView target binding", () => {
  function md(id: string, name: string): Record<string, unknown> {
    return { key_id: id, name, description: `${id} text`, status: "enabled", version: 1, tags: {} };
  }

  it("keeps showing key B when a save of key A finishes after B loaded", async () => {
    render(KeyMetadataView);
    await setKey("ka", "software");
    await fireEvent.click(screen.getByRole("button", { name: "Load" }));
    take("GET /api/v1/keys/ka/metadata").resolve({ metadata: md("ka", "alpha") });
    await screen.findByText("ka");

    await fireEvent.input(screen.getByDisplayValue("alpha"), { target: { value: "alpha2" } });
    await fireEvent.click(screen.getByRole("button", { name: "Save" }));
    const putA = take("PUT /api/v1/keys/ka/metadata");

    await fireEvent.input(screen.getByPlaceholderText("Key ID"), { target: { value: "kb" } });
    await fireEvent.click(screen.getByRole("button", { name: "Load" }));
    if (pending.some((p) => p.label === "GET /api/v1/keys/kb/metadata")) {
      take("GET /api/v1/keys/kb/metadata").resolve({ metadata: md("kb", "beta") });
      await settle();
    }

    putA.resolve({ metadata: md("ka", "alpha2") });
    await settle();

    if (!request.mock.calls.some(([m, p]) => m === "GET" && p === "/api/v1/keys/kb/metadata")) {
      await fireEvent.click(screen.getByRole("button", { name: "Load" }));
      take("GET /api/v1/keys/kb/metadata").resolve({ metadata: md("kb", "beta") });
      await settle();
    }

    expect(screen.getByText("kb")).toBeInTheDocument();
    expect(screen.queryByText("ka")).not.toBeInTheDocument();
    expect(screen.getByDisplayValue("beta")).toBeInTheDocument();

    await fireEvent.input(screen.getByDisplayValue("beta"), { target: { value: "beta2" } });
    await fireEvent.click(screen.getByRole("button", { name: "Save" }));
    const last = request.mock.calls.at(-1)!;
    expect(last[0]).toBe("PUT");
    expect(last[1]).toBe("/api/v1/keys/kb/metadata");
    const body = (last[2] as { body: Record<string, unknown> }).body;
    expect(body).toEqual({ backend: "software", key_id: "kb", name: "beta2" });
  });
});
