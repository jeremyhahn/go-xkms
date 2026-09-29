import { describe, it, expect, afterEach, vi } from 'vitest';
import { render, fireEvent, waitFor, cleanup } from '@testing-library/svelte';
import APIExplorer from './APIExplorer.svelte';
import { SAFE_DEFAULT_SANDBOX_POLICY } from '$lib/utils/sandboxPolicy';

/**
 * Component-level coverage for go-xkms#1274: the API Explorer response
 * preview must never render its iframe with a sandbox policy that combines
 * allow-scripts and allow-same-origin, regardless of what the stored config
 * says. These tests drive the real component through window.go (the same
 * seam the Wails runtime uses) rather than mocking $lib/api/backend, so
 * they exercise the exact code path a real desktop build runs.
 */

interface MockConfig {
  api_explorer_sandbox_policy?: string;
}

function installWailsMock(config: MockConfig, responseBody: string): void {
  (window as any).go = {
    services: {
      AppService: {
        GetConfig: vi.fn().mockResolvedValue(config),
      },
      APIExplorerService: {
        GetHistory: vi.fn().mockResolvedValue([]),
        Execute: vi.fn().mockResolvedValue({
          status_code: 200,
          status: '200 OK',
          headers: { 'Content-Type': 'text/html' },
          body: responseBody,
          duration_ms: 12,
          error: '',
        }),
      },
    },
  };
}

async function sendRequest(getByTestId: (id: string) => HTMLElement): Promise<void> {
  const urlInput = getByTestId('url-input') as HTMLInputElement;
  await fireEvent.input(urlInput, { target: { value: 'https://api.example.com/resource' } });

  const sendButton = getByTestId('send-button').querySelector('button') as HTMLButtonElement;
  await fireEvent.click(sendButton);
}

afterEach(() => {
  cleanup();
  delete (window as any).go;
  vi.restoreAllMocks();
});

describe('APIExplorer response preview iframe sandbox', () => {
  it('never renders allow-scripts and allow-same-origin together, even when configured', async () => {
    installWailsMock(
      { api_explorer_sandbox_policy: 'allow-same-origin allow-scripts allow-forms allow-popups' },
      '<p>hello</p>',
    );

    const { getByTestId, container } = render(APIExplorer);

    // Let onMount's GetConfig promise resolve before driving the UI.
    await waitFor(() => {
      expect((window as any).go.services.AppService.GetConfig).toHaveBeenCalled();
    });

    await sendRequest(getByTestId);

    const iframe = await waitFor(() => {
      const el = container.querySelector('iframe.response-preview-iframe');
      if (!el) throw new Error('preview iframe not yet rendered');
      return el as HTMLIFrameElement;
    });

    const sandbox = iframe.getAttribute('sandbox') ?? '';
    expect(sandbox).toBe(SAFE_DEFAULT_SANDBOX_POLICY);
    expect(sandbox).not.toContain('allow-same-origin');
    expect(sandbox.split(' ')).not.toEqual(
      expect.arrayContaining(['allow-scripts', 'allow-same-origin']),
    );
  });

  it('renders a safe configured policy unchanged', async () => {
    installWailsMock(
      { api_explorer_sandbox_policy: 'allow-forms' },
      '<p>hello</p>',
    );

    const { getByTestId, container } = render(APIExplorer);

    await waitFor(() => {
      expect((window as any).go.services.AppService.GetConfig).toHaveBeenCalled();
    });

    await sendRequest(getByTestId);

    const iframe = await waitFor(() => {
      const el = container.querySelector('iframe.response-preview-iframe');
      if (!el) throw new Error('preview iframe not yet rendered');
      return el as HTMLIFrameElement;
    });

    expect(iframe.getAttribute('sandbox')).toBe('allow-forms');
  });

  it('uses the safe default when no policy is configured', async () => {
    installWailsMock({}, '<p>hello</p>');

    const { getByTestId, container } = render(APIExplorer);

    await waitFor(() => {
      expect((window as any).go.services.AppService.GetConfig).toHaveBeenCalled();
    });

    await sendRequest(getByTestId);

    const iframe = await waitFor(() => {
      const el = container.querySelector('iframe.response-preview-iframe');
      if (!el) throw new Error('preview iframe not yet rendered');
      return el as HTMLIFrameElement;
    });

    expect(iframe.getAttribute('sandbox')).toBe(SAFE_DEFAULT_SANDBOX_POLICY);
  });
});
