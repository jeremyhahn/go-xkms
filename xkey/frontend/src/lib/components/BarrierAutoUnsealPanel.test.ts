import '@testing-library/jest-dom/vitest';
import { describe, it, expect, afterEach, vi } from 'vitest';
import { render, fireEvent, waitFor, cleanup } from '@testing-library/svelte';
import BarrierAutoUnsealPanel from './BarrierAutoUnsealPanel.svelte';

const policies = [
  { name: 'platform', builtin: true, approved: true, auto_unseal: false, object_count: 0 },
  { name: 'boot', builtin: false, bank: 'sha256', pcrs: [0, 7], approved: true, auto_unseal: false, object_count: 0 },
];

function installMock(status: Record<string, unknown>) {
  const barrier = {
    GetAutoUnsealStatus: vi.fn().mockResolvedValue(status),
    EnableAutoUnseal: vi.fn().mockResolvedValue(undefined),
    DisableAutoUnseal: vi.fn().mockResolvedValue(undefined),
  };
  (window as any).go = {
    services: {
      BarrierAutoUnsealService: barrier,
      TPMPolicyService: { ListPolicies: vi.fn().mockResolvedValue(policies) },
    },
  };
  return barrier;
}

const notConfigured = {
  available: true, barrier_sealed: false, policy_configured: false, policy_name: '',
  credential_sealed: false, pcrs_match: false,
};

afterEach(() => {
  cleanup();
  delete (window as any).go;
  vi.restoreAllMocks();
});

describe('BarrierAutoUnsealPanel', () => {
  it('enables auto-unseal with the chosen named policy and the barrier password', async () => {
    const barrier = installMock(notConfigured);
    const view = render(BarrierAutoUnsealPanel);
    const select = await waitFor(() => view.getByLabelText('TPM policy') as HTMLSelectElement);
    expect(Array.from(select.options).map((o) => o.value)).toEqual(['boot']);
    const password = document.getElementById('barrier-auto-unseal-password') as HTMLInputElement;
    await fireEvent.input(password, { target: { value: 'barrier secret' } });
    await fireEvent.click(view.getByText('Enable'));
    await waitFor(() => expect(barrier.EnableAutoUnseal).toHaveBeenCalledWith('boot', 'barrier secret'));
  });

  it('requires the barrier password', async () => {
    const barrier = installMock(notConfigured);
    const view = render(BarrierAutoUnsealPanel);
    await waitFor(() => view.getByLabelText('TPM policy'));
    await fireEvent.click(view.getByText('Enable'));
    await waitFor(() => expect(view.getByRole('alert')).toHaveTextContent('barrier password'));
    expect(barrier.EnableAutoUnseal).not.toHaveBeenCalled();
  });

  it('shows the configured policy and its platform state, and disables it', async () => {
    const barrier = installMock({
      ...notConfigured, policy_configured: true, policy_name: 'boot', credential_sealed: true, pcrs_match: false,
    });
    const view = render(BarrierAutoUnsealPanel);
    await waitFor(() => expect(view.getByTestId('auto-unseal-policy')).toHaveTextContent('boot'));
    expect(view.getByText(/will need a manual unlock/)).toBeInTheDocument();
    await fireEvent.click(view.getByText('Disable'));
    await waitFor(() => expect(barrier.DisableAutoUnseal).toHaveBeenCalled());
  });

  it('reports the backend error when enabling fails', async () => {
    const barrier = installMock(notConfigured);
    barrier.EnableAutoUnseal.mockRejectedValue(new Error('tpmpolicy: policy not found'));
    const view = render(BarrierAutoUnsealPanel);
    await waitFor(() => view.getByLabelText('TPM policy'));
    await fireEvent.input(document.getElementById('barrier-auto-unseal-password') as HTMLInputElement,
      { target: { value: 'barrier secret' } });
    await fireEvent.click(view.getByText('Enable'));
    await waitFor(() => expect(view.getByRole('alert')).toHaveTextContent('policy not found'));
  });

  it('is unavailable without a local TPM policy service', async () => {
    installMock({ available: false, reason: 'no TPM', barrier_sealed: false, policy_configured: false,
      policy_name: '', credential_sealed: false, pcrs_match: false });
    const view = render(BarrierAutoUnsealPanel);
    await waitFor(() => expect(view.getByRole('status')).toHaveTextContent('unavailable: no TPM'));
  });
});
