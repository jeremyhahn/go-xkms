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
import { render, screen, fireEvent, waitFor, within } from "@testing-library/svelte";

const request = vi.fn<(method: string, path: string, opts?: unknown) => Promise<unknown>>();

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

import KeySafetyView from "../src/views/KeySafetyView.svelte";

const warning = {
  type: "key",
  path: "software/k1",
  usage_percent: 85.5,
  status: "warning",
  operations_used: 855,
  bytes_used: 0,
  max_operations: 1000,
};

const critical = {
  type: "key",
  path: "pkcs11/k2",
  usage_percent: 97,
  status: "critical",
  operations_used: 970,
  bytes_used: 0,
  max_operations: 1000,
};

const report = {
  all_items: [warning, critical],
  total_keys: 7,
  total_deks: 0,
  keys_at_warning: 1,
  keys_at_critical: 1,
  deks_at_warning: 0,
  deks_at_critical: 0,
  timestamp: 1,
};

const emptyReport = { ...report, all_items: [], total_keys: 2, keys_at_warning: 0, keys_at_critical: 0 };

type Responder = (method: string, path: string, opts?: unknown) => Promise<unknown>;

function answer(over: Partial<Record<string, Responder>> = {}, warnings = [warning, critical], rep = report): void {
  request.mockImplementation((method, path, opts) => {
    const key = `${method} ${path}`;
    const fn = over[key];
    if (fn) return fn(method, path, opts);
    if (key === "GET /api/v1/safety/check") return Promise.resolve({ warnings, timestamp: 1 });
    if (key === "GET /api/v1/safety/report") return Promise.resolve(rep);
    if (method === "PUT" || method === "DELETE") return Promise.resolve({ success: true, key_id: "k1", timestamp: 1 });
    return Promise.reject(new Error(`unexpected ${key}`));
  });
}

function calls(method: string, path: string): unknown[][] {
  return request.mock.calls.filter((c) => c[0] === method && c[1] === path);
}

async function fill(fields: Record<string, string>): Promise<void> {
  for (const [label, value] of Object.entries(fields)) {
    await fireEvent.input(screen.getByLabelText(label), { target: { value } });
  }
}

beforeEach(() => {
  vi.clearAllMocks();
  toasts.length = 0;
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("KeySafetyView", () => {
  it("loads the safety check and report once and renders totals and warnings", async () => {
    answer();
    render(KeySafetyView);

    expect(await screen.findByText("Total keys: 7")).toBeInTheDocument();
    expect(screen.getByText("Keys at warning: 1")).toBeInTheDocument();
    expect(screen.getByText("Keys at critical: 1")).toBeInTheDocument();

    const table = screen.getByRole("table", { name: "Key usage warnings" });
    expect(within(table).getByText("software/k1")).toBeInTheDocument();
    expect(within(table).getByText("warning")).toBeInTheDocument();
    expect(within(table).getByText("85.5%")).toBeInTheDocument();
    expect(within(table).getByText("pkcs11/k2")).toBeInTheDocument();
    expect(within(table).getByText("critical")).toBeInTheDocument();
    expect(within(table).getByText("97.0%")).toBeInTheDocument();

    expect(calls("GET", "/api/v1/safety/check")).toHaveLength(1);
    expect(calls("GET", "/api/v1/safety/report")).toHaveLength(1);
  });

  it("shows the empty state when no key is near its limits", async () => {
    answer({}, [], emptyReport);
    render(KeySafetyView);

    expect(await screen.findByText("No keys near their limits")).toBeInTheDocument();
    expect(screen.getByText("Total keys: 2")).toBeInTheDocument();
  });

  it("sets limits with PUT, omits an empty max bytes, toasts and reloads", async () => {
    answer();
    render(KeySafetyView);
    await screen.findByText("Total keys: 7");

    await fill({ "Key ID": "k1", Backend: "software", "Max operations": "1000", "Warning percent": "80" });
    await fireEvent.click(screen.getByRole("button", { name: "Set limits" }));

    await waitFor(() => expect(calls("PUT", "/api/v1/keys/k1/safety")).toHaveLength(1));
    const [, , opts] = calls("PUT", "/api/v1/keys/k1/safety")[0]!;
    expect(opts).toEqual({
      body: { backend: "software", key_id: "k1", max_operations: 1000, warning_percent: 80 },
    });
    await waitFor(() => expect(toasts.some((t) => t.kind === "success")).toBe(true));
    await waitFor(() => expect(calls("GET", "/api/v1/safety/check")).toHaveLength(2));
    expect(calls("GET", "/api/v1/safety/report")).toHaveLength(2);
  });

  it("clears limits with DELETE and the backend query after a confirm", async () => {
    answer();
    vi.spyOn(window, "confirm").mockReturnValue(true);
    render(KeySafetyView);
    await screen.findByText("Total keys: 7");

    await fill({ "Key ID": "k1", Backend: "software" });
    await fireEvent.click(screen.getByRole("button", { name: "Clear limits" }));

    await waitFor(() => expect(calls("DELETE", "/api/v1/keys/k1/safety")).toHaveLength(1));
    const [, , opts] = calls("DELETE", "/api/v1/keys/k1/safety")[0]!;
    expect(opts).toEqual({ query: { backend: "software" } });
    await waitFor(() => expect(toasts.some((t) => t.kind === "success")).toBe(true));
  });

  it("sends nothing when the clear confirm is declined", async () => {
    answer();
    vi.spyOn(window, "confirm").mockReturnValue(false);
    render(KeySafetyView);
    await screen.findByText("Total keys: 7");

    await fill({ "Key ID": "k1", Backend: "software" });
    await fireEvent.click(screen.getByRole("button", { name: "Clear limits" }));

    expect(window.confirm).toHaveBeenCalledOnce();
    expect(request.mock.calls.filter((c) => c[0] === "DELETE")).toHaveLength(0);
  });

  it.each([
    [{ "Key ID": "", Backend: "software" }, "Key ID and backend are required."],
    [{ "Key ID": "k1", Backend: "" }, "Key ID and backend are required."],
    [{ "Key ID": "k1", Backend: "software", "Max operations": "-1" }, "Max operations must be a whole number of 0 or more."],
    [{ "Key ID": "k1", Backend: "software", "Max bytes": "1.5" }, "Max bytes must be a whole number of 0 or more."],
    [{ "Key ID": "k1", Backend: "software", "Warning percent": "0" }, "Warning percent must be a whole number from 1 to 100."],
    [{ "Key ID": "k1", Backend: "software", "Warning percent": "101" }, "Warning percent must be a whole number from 1 to 100."],
  ])("rejects invalid input %j inline without a PUT", async (fields, message) => {
    answer();
    render(KeySafetyView);
    await screen.findByText("Total keys: 7");

    await fill(fields);
    await fireEvent.click(screen.getByRole("button", { name: "Set limits" }));

    expect(await screen.findByText(message)).toBeInTheDocument();
    expect(request.mock.calls.filter((c) => c[0] === "PUT")).toHaveLength(0);
  });

  it("shows an error alert when the safety check fails", async () => {
    answer({ "GET /api/v1/safety/check": () => Promise.reject(new Error("safety monitor offline")) });
    render(KeySafetyView);

    expect(await screen.findByText("safety monitor offline")).toBeInTheDocument();
  });

  it("shows an error alert when setting limits fails", async () => {
    answer({ "PUT /api/v1/keys/k1/safety": () => Promise.reject(new Error("key not found")) });
    render(KeySafetyView);
    await screen.findByText("Total keys: 7");

    await fill({ "Key ID": "k1", Backend: "software", "Max operations": "1000" });
    await fireEvent.click(screen.getByRole("button", { name: "Set limits" }));

    expect(await screen.findByText("key not found")).toBeInTheDocument();
    expect(toasts.some((t) => t.kind === "success")).toBe(false);
  });
});
