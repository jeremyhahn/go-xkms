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

const list = vi.fn();
const request = vi.fn();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({ backends: { list }, http: { request } }),
  resetSDKClient: () => {},
}));

const toasts: Array<{ kind: string; message: string }> = [];
vi.mock("../src/stores/toast.svelte.ts", () => ({
  showToast: (kind: string, message: string) => {
    toasts.push({ kind, message });
  },
}));

import BackendDiagnosticsView from "../src/views/BackendDiagnosticsView.svelte";

const backends = {
  backends: [
    { id: "tpm0", type: "tpm2", hardware_backed: true, capabilities: {} },
    { id: "soft0", type: "software", hardware_backed: false, capabilities: {} },
  ],
  pagination: { page: 1, page_size: 50, total: 2 },
};

const tpmStatus = {
  backend_type: "tpm2",
  status: "healthy",
  device: "/dev/tpmrm0",
  pcr_banks: ["sha256", "sha384"],
  capabilities: { sign: true, decrypt: false, seal: true },
  timestamp: "2026-11-12T00:00:00Z",
};

type Handler = (path: string, opts?: unknown) => Promise<unknown>;

function route(over: Partial<Record<"status" | "algorithms" | "test", Handler>> = {}): void {
  request.mockImplementation((method: string, path: string, opts?: unknown) => {
    if (method === "GET" && path === "/api/v1/backend/status") {
      return over.status ? over.status(path, opts) : Promise.resolve(tpmStatus);
    }
    if (method === "GET" && path === "/api/v1/backend/algorithms") {
      return over.algorithms
        ? over.algorithms(path, opts)
        : Promise.resolve({ algorithms: ["RSA-2048", "ECDSA-P256"] });
    }
    if (method === "POST" && path === "/api/v1/backend/test") {
      return over.test
        ? over.test(path, opts)
        : Promise.resolve({ success: true, duration_ms: 12, timestamp: "2026-11-12T00:00:00Z" });
    }
    return Promise.reject(new Error(`unexpected ${method} ${path}`));
  });
}

async function choose(id: string): Promise<void> {
  const select = await screen.findByLabelText("Backend");
  await screen.findByRole("option", { name: id });
  await fireEvent.change(select, { target: { value: id } });
}

beforeEach(() => {
  vi.clearAllMocks();
  toasts.length = 0;
  list.mockResolvedValue(backends);
});

describe("BackendDiagnosticsView load", () => {
  it("lists the backends and loads status and algorithms of the chosen one", async () => {
    route();
    render(BackendDiagnosticsView);

    expect(await screen.findByRole("option", { name: "tpm0" })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: "soft0" })).toBeInTheDocument();
    expect(list).toHaveBeenCalledOnce();
    expect(request).not.toHaveBeenCalled();

    await choose("tpm0");

    await waitFor(() =>
      expect(request).toHaveBeenCalledWith("GET", "/api/v1/backend/status", { query: { backend: "tpm0" } }),
    );
    expect(request).toHaveBeenCalledWith("GET", "/api/v1/backend/algorithms", { query: { backend: "tpm0" } });

    expect(await screen.findByText("tpm2")).toBeInTheDocument();
    expect(screen.getByText("healthy")).toBeInTheDocument();
    expect(screen.getByText("/dev/tpmrm0")).toBeInTheDocument();
    expect(screen.getByText("sha256, sha384")).toBeInTheDocument();
    expect(screen.getByText("sign")).toBeInTheDocument();
    expect(screen.getByText("seal")).toBeInTheDocument();
    expect(screen.queryByText("decrypt")).toBeNull();
    expect(await screen.findByText("RSA-2048")).toBeInTheDocument();
    expect(screen.getByText("ECDSA-P256")).toBeInTheDocument();

    // Absent optional fields render nothing.
    expect(screen.queryByText("Region")).toBeNull();
    expect(screen.queryByText("Key ID")).toBeNull();
    expect(screen.queryByText("PCR registers")).toBeNull();
    expect(document.body.textContent).not.toContain("undefined");
    // The self-test exercises the device: it never runs on load.
    expect(request).not.toHaveBeenCalledWith("POST", "/api/v1/backend/test", expect.anything());
  });
});

describe("BackendDiagnosticsView self-test", () => {
  it("runs the self-test and shows the duration", async () => {
    route();
    render(BackendDiagnosticsView);
    await choose("tpm0");
    await screen.findByText("/dev/tpmrm0");

    await fireEvent.click(screen.getByRole("button", { name: "Run self-test" }));

    await waitFor(() =>
      expect(request).toHaveBeenCalledWith("POST", "/api/v1/backend/test", { body: { backend: "tpm0" } }),
    );
    expect(await screen.findByText(/passed in 12 ms/)).toBeInTheDocument();
  });

  it("shows a failure badge with the message", async () => {
    route({
      test: () => Promise.resolve({ success: false, duration_ms: 3, message: "device busy", timestamp: "t" }),
    });
    render(BackendDiagnosticsView);
    await choose("tpm0");
    await screen.findByText("/dev/tpmrm0");

    await fireEvent.click(screen.getByRole("button", { name: "Run self-test" }));

    expect(await screen.findByText("failed")).toBeInTheDocument();
    expect(screen.getByText("device busy")).toBeInTheDocument();
  });
});

describe("BackendDiagnosticsView disabled", () => {
  it("keeps Run self-test disabled until a backend is chosen and while a test runs", async () => {
    let finish: (v: unknown) => void = () => {};
    route({ test: () => new Promise((resolve) => { finish = resolve; }) });
    render(BackendDiagnosticsView);
    await screen.findByRole("option", { name: "tpm0" });

    expect(screen.getByRole("button", { name: "Run self-test" })).toBeDisabled();

    await choose("tpm0");
    await screen.findByText("/dev/tpmrm0");
    const button = screen.getByRole("button", { name: "Run self-test" });
    expect(button).toBeEnabled();

    await fireEvent.click(button);
    await waitFor(() => expect(screen.getByRole("button", { name: "Run self-test" })).toBeDisabled());

    finish({ success: true, duration_ms: 5, timestamp: "t" });
    expect(await screen.findByText(/passed in 5 ms/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Run self-test" })).toBeEnabled();
  });
});

describe("BackendDiagnosticsView errors", () => {
  it("shows a backends.list failure", async () => {
    list.mockRejectedValue(new Error("backends unavailable"));
    route();
    render(BackendDiagnosticsView);

    expect(await screen.findByText("backends unavailable")).toBeInTheDocument();
  });

  it("shows a status failure", async () => {
    route({ status: () => Promise.reject(new Error("tpm not responding")) });
    render(BackendDiagnosticsView);
    await choose("tpm0");

    expect(await screen.findByText("tpm not responding")).toBeInTheDocument();
  });

  it("shows a self-test failure", async () => {
    route({ test: () => Promise.reject(new Error("self-test forbidden")) });
    render(BackendDiagnosticsView);
    await choose("tpm0");
    await screen.findByText("/dev/tpmrm0");

    await fireEvent.click(screen.getByRole("button", { name: "Run self-test" }));

    expect(await screen.findByText("self-test forbidden")).toBeInTheDocument();
  });

  it("keeps the status card when the algorithms call fails", async () => {
    route({ algorithms: () => Promise.reject(new Error("keys:list denied")) });
    render(BackendDiagnosticsView);
    await choose("tpm0");

    expect(await screen.findByText("keys:list denied")).toBeInTheDocument();
    expect(screen.getByText("/dev/tpmrm0")).toBeInTheDocument();
    expect(screen.getByText("healthy")).toBeInTheDocument();
  });
});
