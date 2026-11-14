// Tests for the Data Keys view: it asks a key to generate a fresh data key
// returned only wrapped, and never touches the plaintext data-key route.
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/svelte";
import WrappedDataKeyView from "../src/views/WrappedDataKeyView.svelte";

const request = vi.fn<(method: string, path: string, opts?: { body?: unknown }) => Promise<unknown>>();

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

const wrapped = { ciphertext: "d3JhcA==", nonce: "bm4=", tag: "dGc=", key_version: 3 };

beforeEach(() => {
  vi.clearAllMocks();
  toasts.length = 0;
});

afterEach(() => {
  // Never plaintext: no call in any test reaches the plaintext data-key route.
  for (const call of request.mock.calls) {
    expect(call[1].endsWith("/data-key")).toBe(false);
  }
});

async function fill(keyId: string, backend: string): Promise<void> {
  await fireEvent.input(screen.getByLabelText("Key ID"), { target: { value: keyId } });
  await fireEvent.input(screen.getByLabelText("Backend"), { target: { value: backend } });
}

describe("WrappedDataKeyView", () => {
  it("generates a wrapped data key and renders the wrapped fields", async () => {
    request.mockResolvedValue({ wrapped });

    render(WrappedDataKeyView);
    await fill("kek1", "software");
    await fireEvent.click(screen.getByRole("button", { name: "Generate" }));

    await waitFor(() => expect(request).toHaveBeenCalledOnce());
    expect(request).toHaveBeenCalledWith("POST", "/api/v1/keys/kek1/wrapped-data-key", {
      body: { backend: "software" },
    });
    expect(await screen.findByText("d3JhcA==")).toBeInTheDocument();
    expect(screen.getByText("bm4=")).toBeInTheDocument();
    expect(screen.getByText("dGc=")).toBeInTheDocument();
    expect(screen.getByText("3")).toBeInTheDocument();
  });

  it("sends the key size, base64 additional data and an encoded key ID", async () => {
    request.mockResolvedValue({ wrapped });

    render(WrappedDataKeyView);
    await fill("team/kek", "software");
    await fireEvent.change(screen.getByLabelText("Key size"), { target: { value: "16" } });
    await fireEvent.input(screen.getByLabelText("Additional data"), { target: { value: "svc-a" } });
    await fireEvent.click(screen.getByRole("button", { name: "Generate" }));

    await waitFor(() => expect(request).toHaveBeenCalledOnce());
    expect(request).toHaveBeenCalledWith("POST", "/api/v1/keys/team%2Fkek/wrapped-data-key", {
      body: { backend: "software", key_size: 16, additional_data: "c3ZjLWE=" },
    });
  });

  it("copies the wrapped object as JSON and shows a success toast", async () => {
    request.mockResolvedValue({ wrapped });
    const writeText = vi.fn<(s: string) => Promise<void>>().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });

    render(WrappedDataKeyView);
    await fill("kek1", "software");
    await fireEvent.click(screen.getByRole("button", { name: "Generate" }));
    await screen.findByText("d3JhcA==");
    await fireEvent.click(screen.getByRole("button", { name: "Copy as JSON" }));

    await waitFor(() => expect(writeText).toHaveBeenCalledOnce());
    expect(JSON.parse(writeText.mock.calls[0]![0])).toEqual(wrapped);
    await waitFor(() => expect(toasts.some((t) => t.kind === "success")).toBe(true));
  });

  it("keeps Generate disabled until key ID and backend are set", async () => {
    render(WrappedDataKeyView);
    const button = screen.getByRole("button", { name: "Generate" });
    expect(button).toBeDisabled();

    await fireEvent.input(screen.getByLabelText("Key ID"), { target: { value: "kek1" } });
    expect(button).toBeDisabled();

    await fireEvent.input(screen.getByLabelText("Backend"), { target: { value: "software" } });
    expect(button).toBeEnabled();
    expect(request).not.toHaveBeenCalled();
  });

  it("shows an error alert when the call is rejected", async () => {
    request.mockRejectedValue(new Error("key kek1 not found"));

    render(WrappedDataKeyView);
    await fill("kek1", "software");
    await fireEvent.click(screen.getByRole("button", { name: "Generate" }));

    expect(await screen.findByText("key kek1 not found")).toBeInTheDocument();
  });
});
