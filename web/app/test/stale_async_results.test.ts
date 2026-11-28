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

// A result for inputs that are no longer current is dropped: the input is
// changed while the request is pending, and the old result must not show.
// Every response here is resolved by hand.

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

const pending: Array<{ label: string; d: Deferred }> = [];

function call(label: string): Promise<unknown> {
  const d = deferred();
  pending.push({ label, d });
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

const ssh = {
  listKnownHosts: vi.fn(() => Promise.resolve({ items: [] })),
  listAuthorizedKeys: vi.fn(() => Promise.resolve({ items: [] })),
  verifyKnownHost: vi.fn((host: string) => call(`verify ${host}`)),
};

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({ ssh }),
  resetSDKClient: () => {},
}));

vi.mock("../src/stores/toast.svelte.ts", () => ({
  showToast: () => {},
}));

vi.mock("../src/lib/keyRotationPolicy.ts", async (orig) => ({
  ...(await orig<typeof import("../src/lib/keyRotationPolicy.ts")>()),
  getRotationPolicy: vi.fn((id: string) => call(`rotation ${id}`)),
  setRotationPolicy: vi.fn(() => Promise.resolve({})),
}));

vi.mock("../src/lib/tpmPolicyDetail.ts", async (orig) => ({
  ...(await orig<typeof import("../src/lib/tpmPolicyDetail.ts")>()),
  listScopes: vi.fn(() => Promise.resolve([])),
  listPolicyNames: vi.fn(() => Promise.resolve(["pa", "pb"])),
  loadPolicy: vi.fn((n: string) => call(`load ${n}`)),
  policyObjects: vi.fn((n: string) => call(`objects ${n}`)),
  verifyPolicy: vi.fn((n: string) => call(`verify ${n}`)),
}));

import SshTrustView from "../src/views/SshTrustView.svelte";
import KeyRotationPolicyView from "../src/views/KeyRotationPolicyView.svelte";
import TpmPolicyDetailView from "../src/views/TpmPolicyDetailView.svelte";

beforeEach(() => {
  vi.clearAllMocks();
  pending.length = 0;
});

describe("SshTrustView verify results", () => {
  async function verify(host: string): Promise<void> {
    await fireEvent.input(screen.getByLabelText("Host to verify"), { target: { value: host } });
    await fireEvent.input(screen.getByLabelText("Offered public key"), { target: { value: "ssh-ed25519 AAAA" } });
    await fireEvent.click(screen.getByRole("button", { name: "Verify host" }));
  }

  it("drops a success whose host field changed while it was pending", async () => {
    render(SshTrustView);
    await settle();
    await verify("a.example");
    const a = take("verify a.example");
    await fireEvent.input(screen.getByLabelText("Host to verify"), { target: { value: "b.example" } });
    a.resolve({});
    await settle();
    expect(screen.queryByText(/Host key matches/)).not.toBeInTheDocument();
  });

  it("never lets an older success replace a newer mismatch", async () => {
    render(SshTrustView);
    await settle();
    await verify("a.example");
    const a = take("verify a.example");
    await verify("b.example");
    take("verify b.example").reject(Object.assign(new Error("b.example mismatch"), { status: 409 }));
    await settle();
    a.resolve({});
    await settle();
    expect(screen.queryByText(/Host key matches/)).not.toBeInTheDocument();
    expect(screen.getByText("b.example mismatch")).toBeInTheDocument();
  });
});

describe("KeyRotationPolicyView target binding", () => {
  async function setKey(id: string): Promise<void> {
    await fireEvent.input(screen.getByPlaceholderText("Key ID"), { target: { value: id } });
    await fireEvent.input(screen.getByPlaceholderText("Backend"), { target: { value: "software" } });
  }
  const week = { enabled: true, interval_seconds: 7 * 86400 };

  it("drops key A's policy when the key changed while A's load was pending", async () => {
    render(KeyRotationPolicyView);
    await setKey("ka");
    await fireEvent.click(screen.getByRole("button", { name: "Load" }));
    const a = take("rotation ka");
    await fireEvent.input(screen.getByPlaceholderText("Key ID"), { target: { value: "kb" } });
    a.resolve({ policy: week });
    await settle();
    expect(screen.queryByText("Current policy")).not.toBeInTheDocument();
    expect(screen.getByLabelText("Enabled")).not.toBeChecked();
    expect(screen.getByLabelText("Interval")).toHaveValue(30);
  });

  it("resets the form when the loaded key has no policy", async () => {
    render(KeyRotationPolicyView);
    await setKey("ka");
    await fireEvent.click(screen.getByRole("button", { name: "Load" }));
    take("rotation ka").resolve({ policy: week });
    await settle();
    expect(screen.getByLabelText("Interval")).toHaveValue(7);
    await fireEvent.input(screen.getByPlaceholderText("Key ID"), { target: { value: "kb" } });
    await fireEvent.click(screen.getByRole("button", { name: "Load" }));
    take("rotation kb").resolve({});
    await settle();
    expect(screen.getByText("No rotation policy")).toBeInTheDocument();
    expect(screen.getByLabelText("Enabled")).not.toBeChecked();
    expect(screen.getByLabelText("Interval")).toHaveValue(30);
  });
});

describe("TpmPolicyDetailView selection binding", () => {
  async function pick(n: string): Promise<void> {
    await fireEvent.change(screen.getByLabelText("Policy"), { target: { value: n } });
  }
  const verdict = { match: true, approved: true, branches: [] };

  async function ready(): Promise<void> {
    render(TpmPolicyDetailView);
    await waitFor(() => expect(screen.getByRole("option", { name: "pb" })).toBeInTheDocument());
  }

  it("drops policy A's verdict when policy B was picked while it was pending", async () => {
    await ready();
    await pick("pa");
    await fireEvent.click(screen.getByRole("button", { name: "Verify" }));
    const a = take("verify pa");
    await pick("pb");
    a.resolve(verdict);
    await settle();
    expect(screen.queryByText(/Live PCR check/)).not.toBeInTheDocument();
  });

  it("drops policy A's load and objects when policy B was picked", async () => {
    await ready();
    await pick("pa");
    await fireEvent.click(screen.getByRole("button", { name: "Load" }));
    await fireEvent.click(screen.getByRole("button", { name: "Objects" }));
    const load = take("load pa");
    const objs = take("objects pa");
    await pick("pb");
    load.resolve({ name: "pa", index: 1, approved: true, branches: [], created_at: "now" });
    objs.resolve(["obj-a"]);
    await settle();
    expect(screen.queryByRole("heading", { name: "pa" })).not.toBeInTheDocument();
    expect(screen.queryByText("obj-a")).not.toBeInTheDocument();
  });

  it("names the policy with its verdict", async () => {
    await ready();
    await pick("pb");
    await fireEvent.click(screen.getByRole("button", { name: "Verify" }));
    take("verify pb").resolve(verdict);
    await settle();
    expect(screen.getByText("Live PCR check of pb")).toBeInTheDocument();
  });
});
