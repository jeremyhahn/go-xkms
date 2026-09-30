import '@testing-library/jest-dom/vitest';
import { describe, it, expect, afterEach, vi } from 'vitest';
import { render, fireEvent, waitFor, cleanup, within } from '@testing-library/svelte';
import Seal from './Seal.svelte';

/**
 * The Seal view seals under a TPM policy chosen with SealPolicyPicker, and
 * unseals a blob bound to a policy through the policy first, falling back to
 * its password when the platform state changed.
 */

const blob = {
  id: 'b1', label: 'api-token', size_bytes: 5, tpm_policy: 'boot', password_protected: true,
  created_at: '2026-01-01T00:00:00Z', category: 'user', backend_id: 'tpm2', storage_type: 'disk',
};

function installMock() {
  const seal = {
    ListBlobs: vi.fn().mockResolvedValue([blob]),
    CanSeal: vi.fn().mockResolvedValue(true),
    AvailableSealers: vi.fn().mockResolvedValue([{ id: 'tpm2', available: true, hardware_backed: true, security_level: 3, label: 'TPM 2.0', description: '', is_default: true }]),
    SealData: vi.fn().mockImplementation((req: any) => Promise.resolve({ ...blob, id: 'b2', label: req.label })),
    UnsealData: vi.fn(),
    DeleteBlob: vi.fn().mockResolvedValue(undefined),
  };
  (window as any).go = {
    services: {
      AppService: { GetConfig: vi.fn().mockResolvedValue({ clipboard_timeout: 30 }) },
      SealService: seal,
      TPMPolicyService: {
        ListPolicies: vi.fn().mockResolvedValue([
          { name: 'platform', builtin: true, approved: true, auto_unseal: false, object_count: 0 },
          { name: 'boot', builtin: false, branches: [{ conditions: [{ type: 'pcr', bank: 'sha256', pcrs: [0, 7] }] }], approved: true, auto_unseal: false, object_count: 1 },
        ]),
      },
      ClipboardService: { ClearClipboard: vi.fn().mockResolvedValue(undefined), CopyWithClear: vi.fn().mockResolvedValue(undefined) },
    },
  };
  return seal;
}

afterEach(() => {
  cleanup();
  delete (window as any).go;
  vi.restoreAllMocks();
});

describe('Seal view', () => {
  it('seals under the chosen named TPM policy', async () => {
    const seal = installMock();
    const view = render(Seal);
    await waitFor(() => expect(view.getByText('Seal New Data')).not.toBeDisabled());
    await fireEvent.click(view.getByText('Seal New Data'));
    const dialog = view.getByRole('dialog');
    const inputs = dialog.querySelectorAll('input');
    await fireEvent.input(inputs[0], { target: { value: 'db-password' } });
    await fireEvent.input(dialog.querySelector('textarea') as HTMLTextAreaElement, { target: { value: 'hunter2' } });
    const select = within(dialog).getByLabelText('TPM policy') as HTMLSelectElement;
    await waitFor(() => expect(select.options.length).toBe(3));
    await fireEvent.change(select, { target: { value: 'boot' } });
    await fireEvent.click(within(dialog).getByText('Seal'));
    await waitFor(() => expect(seal.SealData).toHaveBeenCalled());
    const req = seal.SealData.mock.calls[0][0];
    expect(req.tpm_policy).toBe('boot');
    expect(req.password).toBe('');
    expect(req.label).toBe('db-password');
  });

  it('falls back to the password when the TPM policy is not satisfied', async () => {
    const seal = installMock();
    seal.UnsealData
      .mockRejectedValueOnce(new Error('tpm: policy check failed'))
      .mockResolvedValueOnce(btoa('secret'));
    const view = render(Seal);
    await waitFor(() => expect(view.getByText('api-token')).toBeInTheDocument());
    await fireEvent.click(view.getByTitle('Unseal & Copy'));
    await waitFor(() => expect(seal.UnsealData).toHaveBeenCalledWith('b1', ''));
    const dialog = await waitFor(() => view.getByText(/The TPM policy is not satisfied/).closest('[role="dialog"]') as HTMLElement);
    const password = dialog.querySelector('input[type="password"]') as HTMLInputElement;
    await fireEvent.input(password, { target: { value: 'fallback' } });
    await fireEvent.click(within(dialog).getByText('Unseal'));
    await waitFor(() => expect(seal.UnsealData).toHaveBeenCalledWith('b1', 'fallback'));
  });
});
