import '@testing-library/jest-dom/vitest';
import { describe, it, expect, afterEach, vi } from 'vitest';
import { render, fireEvent, waitFor, cleanup } from '@testing-library/svelte';
import VaultBrowserRequestDialog from './VaultBrowserRequestDialog.svelte';

function installMock() {
  const svc = {
    ApproveBrowserVaultRequest: vi.fn().mockResolvedValue(undefined),
    DenyBrowserVaultRequest: vi.fn().mockResolvedValue(undefined),
  };
  (window as any).go = { services: { StaticPasswordService: svc } };
  return svc;
}

afterEach(() => {
  cleanup();
  delete (window as any).go;
});

describe('VaultBrowserRequestDialog', () => {
  it('shows the requesting origin and the factor, and approves the request', async () => {
    const svc = installMock();
    const onClose = vi.fn();
    const view = render(VaultBrowserRequestDialog, {
      props: { open: true, requestId: 'r1', origin: 'https://kms.example.com', factors: ['PIV card (desk)'], onClose },
    });
    expect(view.getByTestId('vault-request-origin')).toHaveTextContent('https://kms.example.com');
    expect(view.getByText(/PIV card \(desk\)/)).toBeInTheDocument();

    await fireEvent.click(view.getByText('Approve'));
    await waitFor(() => expect(svc.ApproveBrowserVaultRequest).toHaveBeenCalledWith('r1'));
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(svc.DenyBrowserVaultRequest).not.toHaveBeenCalled();
  });

  it('denies the request', async () => {
    const svc = installMock();
    const view = render(VaultBrowserRequestDialog, {
      props: { open: true, requestId: 'r2', origin: 'https://kms.example.com', factors: [] },
    });
    await fireEvent.click(view.getByText('Deny'));
    await waitFor(() => expect(svc.DenyBrowserVaultRequest).toHaveBeenCalledWith('r2'));
    expect(svc.ApproveBrowserVaultRequest).not.toHaveBeenCalled();
  });
});
