import '@testing-library/jest-dom/vitest';
import { describe, it, expect, afterEach, vi } from 'vitest';
import { render, fireEvent, waitFor, cleanup, within } from '@testing-library/svelte';
import TPMPolicyPanel from './TPMPolicyPanel.svelte';

/**
 * TPMPolicyPanel drives TPMPolicyService (and, for local barrier auto-unseal,
 * BarrierAutoUnsealService) through window.go -- the seam the Wails runtime
 * uses -- so these tests exercise the calls a desktop build makes.
 */

const platform = { name: 'platform', builtin: true, approved: true, auto_unseal: false, object_count: 3 };
const boot = {
  name: 'boot', builtin: false, bank: 'sha256', pcrs: [0, 7], approved: true,
  auto_unseal: false, object_count: 2, index: 0x01500000,
};

function installMock(mode: 'local' | 'server', policies = [platform, boot]) {
  const tpm = {
    GetStatus: vi.fn().mockResolvedValue({ available: true, mode, scope: mode === 'local' ? 'system' : '' }),
    ListPolicies: vi.fn().mockResolvedValue(policies),
    CreatePolicy: vi.fn().mockResolvedValue({ ...boot, name: 'new' }),
    UpdatePolicy: vi.fn().mockResolvedValue(boot),
    RevokePolicy: vi.fn().mockResolvedValue({ ...boot, approved: false }),
    VerifyPolicy: vi.fn().mockResolvedValue({ name: 'boot', match: false, mismatched: [7], approved: true }),
    DeletePolicy: vi.fn().mockResolvedValue(undefined),
    PolicyObjects: vi.fn().mockResolvedValue(['key/signer', 'sealed/xkey-sealed-1']),
    SetAutoUnseal: vi.fn().mockResolvedValue({ ...boot, auto_unseal: true }),
    RotateAuthority: vi.fn().mockResolvedValue({ generation: 2, authority_name: '000b', epoch: 1 }),
    GetPolicy: vi.fn().mockResolvedValue({ ...boot, pcr_values: { 7: 'bb', 0: 'aa' }, epoch: 3, authority_generation: 1 }),
  };
  const barrier = {
    EnableAutoUnseal: vi.fn().mockResolvedValue(undefined),
    DisableAutoUnseal: vi.fn().mockResolvedValue(undefined),
  };
  (window as any).go = { services: { TPMPolicyService: tpm, BarrierAutoUnsealService: barrier } };
  return { tpm, barrier };
}

afterEach(() => {
  cleanup();
  delete (window as any).go;
  vi.restoreAllMocks();
});

async function renderLoaded(mode: 'local' | 'server' = 'local') {
  const mocks = installMock(mode);
  const view = render(TPMPolicyPanel);
  await waitFor(() => expect(view.getByTestId('policy-row-boot')).toBeInTheDocument());
  return { ...mocks, view };
}

describe('TPMPolicyPanel', () => {
  it('lists the built-in platform policy and named policies with object counts', async () => {
    const { view } = await renderLoaded();
    const platformRow = view.getByTestId('policy-row-platform');
    expect(within(platformRow).getByText('built-in')).toBeInTheDocument();
    expect(within(platformRow).getByLabelText('Objects bound to platform')).toHaveTextContent('3');
    expect(within(platformRow).queryByText('Delete')).toBeNull();

    const bootRow = view.getByTestId('policy-row-boot');
    expect(within(bootRow).getByText('sha256: 0, 7')).toBeInTheDocument();
    expect(within(bootRow).getByLabelText('Objects bound to boot')).toHaveTextContent('2');
    expect(view.getByTestId('policy-mode')).toHaveTextContent('Local TPM (system scope)');
  });

  it('reports when there is no TPM policy service', async () => {
    installMock('local');
    (window as any).go.services.TPMPolicyService.GetStatus.mockResolvedValue({ available: false, mode: 'unavailable', scope: '' });
    const view = render(TPMPolicyPanel);
    await waitFor(() => expect(view.getByRole('alert')).toHaveTextContent('No TPM policy service'));
  });

  it('creates a policy over the selected PCRs', async () => {
    const { tpm, view } = await renderLoaded();
    await fireEvent.click(view.getByText('Create Policy'));
    const nameInput = document.getElementById('policy-name') as HTMLInputElement;
    await fireEvent.input(nameInput, { target: { value: 'kernel' } });
    await fireEvent.change(document.getElementById('policy-bank') as HTMLSelectElement, { target: { value: 'sha384' } });
    await fireEvent.click(view.getByLabelText('PCR 7'));
    await fireEvent.click(view.getByLabelText('PCR 0'));
    await fireEvent.click(view.getByText('Create'));
    await waitFor(() => expect(tpm.CreatePolicy).toHaveBeenCalledWith('kernel', 'sha384', [0, 7], false, ''));
  });

  it('refuses to create a policy without PCRs', async () => {
    const { tpm, view } = await renderLoaded();
    await fireEvent.click(view.getByText('Create Policy'));
    await fireEvent.input(document.getElementById('policy-name') as HTMLInputElement, { target: { value: 'kernel' } });
    await fireEvent.click(view.getByText('Create'));
    await waitFor(() => expect(view.getByText('Select at least one PCR.')).toBeInTheDocument());
    expect(tpm.CreatePolicy).not.toHaveBeenCalled();
  });

  it('shows the refusal, with the objects, when a policy in use is deleted', async () => {
    const { tpm, view } = await renderLoaded();
    tpm.DeletePolicy.mockRejectedValue(new Error('tpmpolicy: policy "boot" is assigned to 2 object(s): key/signer, sealed/s1'));
    await fireEvent.click(within(view.getByTestId('policy-row-boot')).getByText('Delete'));
    const dialog = view.getByRole('dialog');
    await fireEvent.click(within(dialog).getByText('Delete'));
    await waitFor(() => expect(within(dialog).getByRole('alert')).toHaveTextContent('key/signer, sealed/s1'));
    expect(tpm.DeletePolicy).toHaveBeenCalledWith('boot', '');
  });

  it('shows the verification result', async () => {
    const { tpm, view } = await renderLoaded();
    await fireEvent.click(within(view.getByTestId('policy-row-boot')).getByText('Verify'));
    await waitFor(() => expect(view.getByTestId('verify-result')).toHaveTextContent('PCRs changed since capture: 7'));
    expect(tpm.VerifyPolicy).toHaveBeenCalledWith('boot');
  });

  it('lists the objects bound to a policy', async () => {
    const { view } = await renderLoaded();
    await fireEvent.click(view.getByLabelText('Objects bound to boot'));
    await waitFor(() => expect(view.getByTestId('policy-objects')).toHaveTextContent('key/signer'));
  });

  it('updates and revokes a policy', async () => {
    const { tpm, view } = await renderLoaded();
    const row = view.getByTestId('policy-row-boot');
    await fireEvent.click(within(row).getByText('Update'));
    await waitFor(() => expect(tpm.UpdatePolicy).toHaveBeenCalledWith('boot'));
    await fireEvent.click(within(view.getByTestId('policy-row-boot')).getByText('Revoke'));
    await waitFor(() => expect(tpm.RevokePolicy).toHaveBeenCalledWith('boot'));
  });

  it('enables local barrier auto-unseal by sealing the barrier password under the policy', async () => {
    const { barrier, tpm, view } = await renderLoaded('local');
    await fireEvent.click(within(view.getByTestId('policy-row-boot')).getByRole('switch'));
    const password = await waitFor(() => document.getElementById('auto-unseal-password') as HTMLInputElement);
    await fireEvent.input(password, { target: { value: 'barrier secret' } });
    await fireEvent.click(view.getByText('Enable'));
    await waitFor(() => expect(barrier.EnableAutoUnseal).toHaveBeenCalledWith('boot', 'barrier secret'));
    expect(tpm.SetAutoUnseal).not.toHaveBeenCalled();
  });

  it('sets the auto-unseal mark directly on a server', async () => {
    const { barrier, tpm, view } = await renderLoaded('server');
    expect(view.getByTestId('policy-mode')).toHaveTextContent('Connected server');
    await fireEvent.click(within(view.getByTestId('policy-row-boot')).getByRole('switch'));
    await waitFor(() => expect(tpm.SetAutoUnseal).toHaveBeenCalledWith('boot', true));
    expect(barrier.EnableAutoUnseal).not.toHaveBeenCalled();
  });

  it('rotates the policy authority', async () => {
    const { tpm, view } = await renderLoaded();
    await fireEvent.click(view.getByText('Rotate Authority'));
    await fireEvent.click(view.getByText('Rotate'));
    await waitFor(() => expect(tpm.RotateAuthority).toHaveBeenCalled());
  });
});

describe('TPMPolicyPanel details', () => {
  it('shows the PCR values the policy captured', async () => {
    const { tpm, view } = await renderLoaded();
    await fireEvent.click(view.getByLabelText('Details of boot'));
    const detailsView = await waitFor(() => view.getByTestId('policy-details'));
    expect(tpm.GetPolicy).toHaveBeenCalledWith('boot');
    expect(detailsView).toHaveTextContent('approved at epoch 3');
    const rows = detailsView.querySelectorAll('tbody tr');
    expect(rows[0]).toHaveTextContent('0aa');
    expect(rows[1]).toHaveTextContent('7bb');
  });
});
