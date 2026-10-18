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
  name: 'boot', builtin: false, description: 'firmware and Secure Boot', approved: true,
  branches: [{ name: 'current', conditions: [{ type: 'pcr', bank: 'sha256', pcrs: [0, 7] }], approved: true }],
  auto_unseal: false, object_count: 2, index: 0x01500000,
};

function installMock(mode: 'local' | 'server', policies = [platform, boot]) {
  const tpm = {
    GetStatus: vi.fn().mockResolvedValue({ available: true, mode, scope: mode === 'local' ? 'system' : '' }),
    ListPolicies: vi.fn().mockResolvedValue(policies),
    CreatePolicy: vi.fn().mockResolvedValue({ ...boot, name: 'new' }),
    UpdatePolicy: vi.fn().mockResolvedValue(boot),
    UpdateBranch: vi.fn().mockResolvedValue(boot),
    RevokePolicy: vi.fn().mockResolvedValue({ ...boot, approved: false }),
    VerifyPolicy: vi.fn().mockResolvedValue({
      name: 'boot', match: false, approved: true,
      branches: [
        { name: 'current', match: false, mismatched: [7], approved: true },
        { name: 'next', match: true, approved: false },
      ],
    }),
    SetDescription: vi.fn().mockResolvedValue({ ...boot, description: 'kernel' }),
    DeletePolicy: vi.fn().mockResolvedValue(undefined),
    PolicyObjects: vi.fn().mockResolvedValue(['key/signer', 'sealed/xkey-sealed-1']),
    SetAutoUnseal: vi.fn().mockResolvedValue({ ...boot, auto_unseal: true }),
    RotateAuthority: vi.fn().mockResolvedValue({ generation: 2, authority_name: '000b', epoch: 1 }),
    GetPolicy: vi.fn().mockResolvedValue({
      ...boot, epoch: 3, authority_generation: 1,
      branches: [
        { name: 'current', conditions: [{ type: 'pcr', bank: 'sha256', pcrs: [0, 7], pcr_values: { 7: 'bb', 0: 'aa' } }], approved: true },
        { name: 'recovery', conditions: [{ type: 'auth_value' }], approved: true },
      ],
    }),
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
    expect(within(bootRow).getByText('sha256 PCR 0, 7')).toBeInTheDocument();
    expect(within(bootRow).getByText('firmware and Secure Boot')).toBeInTheDocument();
    expect(within(bootRow).getByLabelText('Objects bound to boot')).toHaveTextContent('2');
    expect(view.getByTestId('policy-mode')).toHaveTextContent('Local TPM (system scope)');
  });

  it('reports when there is no TPM policy service', async () => {
    installMock('local');
    (window as any).go.services.TPMPolicyService.GetStatus.mockResolvedValue({ available: false, mode: 'unavailable', scope: '' });
    const view = render(TPMPolicyPanel);
    await waitFor(() => expect(view.getByRole('alert')).toHaveTextContent('No TPM policy service'));
  });

  it('creates a one-branch policy over the selected PCRs in simple mode', async () => {
    const { tpm, view } = await renderLoaded();
    await fireEvent.click(view.getByText('Create Policy'));
    const nameInput = document.getElementById('policy-name') as HTMLInputElement;
    await fireEvent.input(nameInput, { target: { value: 'kernel' } });
    await fireEvent.change(document.getElementById('policy-bank') as HTMLSelectElement, { target: { value: 'sha384' } });
    await fireEvent.click(view.getByLabelText('PCR 7'));
    await fireEvent.click(view.getByLabelText('PCR 0'));
    await fireEvent.input(document.getElementById('policy-description') as HTMLInputElement, { target: { value: 'kernel PCRs' } });
    await fireEvent.click(view.getByText('Create'));
    await waitFor(() => expect(tpm.CreatePolicy).toHaveBeenCalledWith(
      'kernel', 'kernel PCRs', [{ conditions: [{ type: 'pcr', bank: 'sha384', pcrs: [0, 7] }] }], false, '',
    ));
  });

  it('creates a composite policy in advanced mode', async () => {
    const { tpm, view } = await renderLoaded();
    await fireEvent.click(view.getByText('Create Policy'));
    await fireEvent.input(document.getElementById('policy-name') as HTMLInputElement, { target: { value: 'strict' } });
    await fireEvent.click(view.getByRole('tab', { name: 'Advanced' }));
    await fireEvent.click(view.getByLabelText('Branch 1 locality condition'));
    await fireEvent.click(view.getByText('Add branch'));
    await fireEvent.click(view.getByLabelText('Branch 2 PCR condition'));
    await fireEvent.click(view.getByLabelText('Branch 2 password condition'));
    await fireEvent.click(view.getByText('Create'));
    await waitFor(() => expect(tpm.CreatePolicy).toHaveBeenCalledWith('strict', '', [
      { conditions: [{ type: 'pcr', bank: 'sha256', pcrs: [0, 7] }, { type: 'locality', localities: [0] }] },
      { conditions: [{ type: 'auth_value' }] },
    ], false, ''));
  });

  it('creates named current and next branches', async () => {
    const { tpm, view } = await renderLoaded();
    await fireEvent.click(view.getByText('Create Policy'));
    await fireEvent.input(document.getElementById('policy-name') as HTMLInputElement, { target: { value: 'unlock' } });
    await fireEvent.click(view.getByRole('tab', { name: 'Advanced' }));
    await fireEvent.click(view.getByText('Add branch'));
    await fireEvent.input(document.getElementById('policy-branch-1-name') as HTMLInputElement, { target: { value: 'current' } });
    await fireEvent.input(document.getElementById('policy-branch-2-name') as HTMLInputElement, { target: { value: 'next' } });
    await fireEvent.click(view.getByText('Create'));
    await waitFor(() => expect(tpm.CreatePolicy).toHaveBeenCalledWith('unlock', '', [
      { name: 'current', conditions: [{ type: 'pcr', bank: 'sha256', pcrs: [0, 7] }] },
      { name: 'next', conditions: [{ type: 'pcr', bank: 'sha256', pcrs: [0, 7] }] },
    ], false, ''));
  });

  it('refuses an advanced branch without conditions, and removes a branch', async () => {
    const { tpm, view } = await renderLoaded();
    await fireEvent.click(view.getByText('Create Policy'));
    await fireEvent.input(document.getElementById('policy-name') as HTMLInputElement, { target: { value: 'strict' } });
    await fireEvent.click(view.getByRole('tab', { name: 'Advanced' }));
    await fireEvent.click(view.getByText('Add branch'));
    await fireEvent.click(view.getByLabelText('Branch 2 PCR condition'));
    await fireEvent.click(view.getByText('Create'));
    await waitFor(() => expect(view.getByText('Branch 2: Choose at least one condition.')).toBeInTheDocument());
    expect(tpm.CreatePolicy).not.toHaveBeenCalled();

    await fireEvent.click(view.getByText('Remove branch 2'));
    expect(view.queryByTestId('branch-2')).toBeNull();
    await fireEvent.click(view.getByText('Create'));
    await waitFor(() => expect(tpm.CreatePolicy).toHaveBeenCalledOnce());
  });

  it('sets a policy description', async () => {
    const { tpm, view } = await renderLoaded();
    await fireEvent.click(within(view.getByTestId('policy-row-boot')).getByText('Describe'));
    const input = document.getElementById('policy-describe') as HTMLInputElement;
    expect(input.value).toBe('firmware and Secure Boot');
    await fireEvent.input(input, { target: { value: 'kernel' } });
    await fireEvent.click(view.getByText('Save'));
    await waitFor(() => expect(tpm.SetDescription).toHaveBeenCalledWith('boot', 'kernel'));
  });

  it('shows a refused description in its dialog', async () => {
    const { tpm, view } = await renderLoaded();
    tpm.SetDescription.mockRejectedValue(new Error('tpmpolicy: description too long'));
    await fireEvent.click(within(view.getByTestId('policy-row-boot')).getByText('Describe'));
    await fireEvent.click(view.getByText('Save'));
    await waitFor(() => expect(view.getByRole('alert')).toHaveTextContent('description too long'));
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

  it('shows the verification result of each branch', async () => {
    const { tpm, view } = await renderLoaded();
    await fireEvent.click(within(view.getByTestId('policy-row-boot')).getByText('Verify'));
    await waitFor(() => expect(view.getByTestId('verify-result')).toHaveTextContent('Branch current: PCRs changed: 7; approval current'));
    expect(view.getByTestId('verify-result')).toHaveTextContent('Branch next: PCRs match; approval not current');
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
  it('shows each branch and the PCR values it captured', async () => {
    const { tpm, view } = await renderLoaded();
    await fireEvent.click(view.getByLabelText('Details of boot'));
    const detailsView = await waitFor(() => view.getByTestId('policy-details'));
    expect(tpm.GetPolicy).toHaveBeenCalledWith('boot');
    expect(detailsView).toHaveTextContent('approved at epoch 3');
    expect(detailsView).toHaveTextContent('Branch current: sha256 PCR 0, 7');
    expect(detailsView).toHaveTextContent('Branch recovery: password');
    const rows = detailsView.querySelectorAll('tbody tr');
    expect(rows[0]).toHaveTextContent('0aa');
    expect(rows[1]).toHaveTextContent('7bb');
    expect(view.queryByTestId('branch-current-reference')).toBeNull();
    expect(view.queryByLabelText('Reference values for branch recovery')).toBeNull();
  });

  it('updates the named branch from a signed CoRIM and shows its reference', async () => {
    const { tpm, view } = await renderLoaded();
    const current = { name: 'current', conditions: [{ type: 'pcr', bank: 'sha256', pcrs: [0, 7], pcr_values: { 0: 'aa', 7: 'bb' } }], approved: true };
    tpm.GetPolicy.mockResolvedValue({
      ...boot, epoch: 3,
      branches: [current, { ...current, name: 'next' }],
    });
    tpm.UpdateBranch.mockResolvedValue({
      ...boot, epoch: 4,
      branches: [current, {
        name: 'next',
        conditions: [{ type: 'pcr', bank: 'sha256', pcrs: [0, 7], pcr_values: { 0: 'aa', 7: 'cc' } }],
        approved: true,
        reference: { id: 'boot-image-v2', signer: 'Example Provider', digest: 'q80=' },
      }],
    });
    await fireEvent.click(view.getByLabelText('Details of boot'));
    const input = await waitFor(() => view.getByLabelText('Reference values for branch next') as HTMLInputElement);
    await fireEvent.change(input, { target: { files: [corimFile([0xd2, 0x84])] } });

    await waitFor(() => expect(tpm.UpdateBranch).toHaveBeenCalledWith('boot', 'next', [0xd2, 0x84]));
    expect(view.queryByTestId('branch-current-reference')).toBeNull();
    await waitFor(() => expect(view.getByTestId('branch-next-reference'))
      .toHaveTextContent('Reference values: boot-image-v2 signed by Example Provider, sha256 abcd'));
    expect(view.getByTestId('policy-details')).toHaveTextContent('approved at epoch 4');
  });

  it('keeps the details when the server refuses the reference values', async () => {
    const { tpm, view } = await renderLoaded();
    tpm.UpdateBranch.mockRejectedValue(new Error('tpmpolicy: invalid reference values: verify the signed CoRIM'));
    await fireEvent.click(view.getByLabelText('Details of boot'));
    const input = await waitFor(() => view.getByLabelText('Reference values for branch current') as HTMLInputElement);
    await fireEvent.change(input, { target: { files: [corimFile([0x00])] } });

    await waitFor(() => expect(tpm.UpdateBranch).toHaveBeenCalledOnce());
    expect(view.getByTestId('policy-details')).toHaveTextContent('approved at epoch 3');
    expect(view.queryByTestId('branch-current-reference')).toBeNull();
  });

  it('shows the reference values a verified branch is approved for', async () => {
    const { tpm, view } = await renderLoaded();
    tpm.VerifyPolicy.mockResolvedValue({
      name: 'boot', match: false, approved: true,
      branches: [{ name: 'next', match: false, mismatched: [7], approved: true, reference: { id: 'boot-image-v2', digest: 'q80=' } }],
    });
    await fireEvent.click(within(view.getByTestId('policy-row-boot')).getByText('Verify'));
    await waitFor(() => expect(view.getByTestId('verify-result'))
      .toHaveTextContent('Branch next: PCRs changed: 7; approval current; approved for reference values boot-image-v2, sha256 abcd'));
  });
});

/**
 * corimFile is a picked CoRIM file of bytes. Its arrayBuffer is defined
 * explicitly so the tests do not depend on the DOM implementation's Blob.
 */
function corimFile(bytes: number[]): File {
  const file = new File([new Uint8Array(bytes)], 'boot.corim');
  Object.defineProperty(file, 'arrayBuffer', { value: async () => new Uint8Array(bytes).buffer });
  return file;
}
