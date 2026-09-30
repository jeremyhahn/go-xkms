import '@testing-library/jest-dom/vitest';
import { describe, it, expect, afterEach, vi } from 'vitest';
import { render, fireEvent, waitFor, cleanup } from '@testing-library/svelte';
import PasswordVaultPanel from './PasswordVaultPanel.svelte';

const factor = { id: 'f-1', factor: 'passphrase', label: 'laptop', created_at: '2026-09-30T00:00:00Z' };

function installMock(status: Record<string, unknown> | Error) {
  const svc = {
    VaultStatus: status instanceof Error ? vi.fn().mockRejectedValue(status) : vi.fn().mockResolvedValue(status),
    EnrollPassphrase: vi.fn().mockResolvedValue({ factor, recovery_code: 'ABCD-EFGH-IJKL' }),
    RotatePassphrase: vi.fn().mockResolvedValue({ factor: { ...factor, id: 'f-9' } }),
    RecoverWithPassphrase: vi.fn().mockResolvedValue({ factor, recovery_code: 'NEW-CODE-0001' }),
    RemoveVaultFactor: vi.fn().mockResolvedValue(undefined),
    Unlock: vi.fn().mockResolvedValue(undefined),
    Lock: vi.fn().mockResolvedValue(undefined),
  };
  (window as any).go = { services: { StaticPasswordService: svc } };
  return svc;
}

async function type(id: string, value: string) {
  await fireEvent.input(document.getElementById(id) as HTMLInputElement, { target: { value } });
}

afterEach(() => {
  cleanup();
  delete (window as any).go;
  vi.restoreAllMocks();
});

describe('PasswordVaultPanel', () => {
  it('enrolls the first passphrase and shows the recovery code until it is acknowledged', async () => {
    const svc = installMock({ initialized: false, unlocked: false, factors: [] });
    const view = render(PasswordVaultPanel);
    await waitFor(() => view.getByText('Create vault'));

    await type('vault-new-passphrase', 'correct horse');
    await type('vault-confirm-passphrase', 'correct horse');
    await type('vault-label', 'laptop');
    svc.VaultStatus.mockResolvedValue({ initialized: true, unlocked: true, factors: [factor] });
    await fireEvent.click(view.getByText('Create vault'));

    await waitFor(() => expect(view.getByTestId('vault-recovery-code')).toHaveTextContent('ABCD-EFGH-IJKL'));
    expect(svc.EnrollPassphrase).toHaveBeenCalledWith('correct horse', 'laptop');
    expect(view.getByText(/it will not be shown again/)).toBeInTheDocument();

    const done = view.getByText('Done').closest('button') as HTMLButtonElement;
    expect(done).toBeDisabled();
    await fireEvent.click(view.getByLabelText('I have stored my recovery code'));
    expect(done).not.toBeDisabled();
    await fireEvent.click(done);
    await waitFor(() => expect(view.queryByTestId('vault-recovery-code')).not.toBeInTheDocument());
    expect(view.getByText('laptop')).toBeInTheDocument();
  });

  it('refuses mismatched passphrases without calling the server', async () => {
    const svc = installMock({ initialized: false, unlocked: false, factors: [] });
    const view = render(PasswordVaultPanel);
    await waitFor(() => view.getByText('Create vault'));

    await type('vault-new-passphrase', 'correct horse');
    await type('vault-confirm-passphrase', 'correct hose');
    await fireEvent.click(view.getByText('Create vault'));

    await waitFor(() => expect(view.getByRole('alert')).toHaveTextContent('do not match'));
    expect(svc.EnrollPassphrase).not.toHaveBeenCalled();
  });

  it('unlocks a locked vault with the passphrase', async () => {
    const svc = installMock({ initialized: true, unlocked: false, factors: [factor] });
    const view = render(PasswordVaultPanel);
    await waitFor(() => view.getByText('Unlock'));

    await type('vault-passphrase', 'correct horse');
    svc.VaultStatus.mockResolvedValue({ initialized: true, unlocked: true, factors: [factor] });
    await fireEvent.click(view.getByText('Unlock'));

    await waitFor(() => expect(svc.Unlock).toHaveBeenCalledWith('correct horse'));
    await waitFor(() => expect(view.getByText('Unlocked')).toBeInTheDocument());
  });

  it('reports a rejected passphrase', async () => {
    const svc = installMock({ initialized: true, unlocked: false, factors: [factor] });
    svc.Unlock.mockRejectedValue(new Error('Credential rejected'));
    const view = render(PasswordVaultPanel);
    await waitFor(() => view.getByText('Unlock'));

    await type('vault-passphrase', 'wrong');
    await fireEvent.click(view.getByText('Unlock'));

    await waitFor(() => expect(view.getByRole('alert')).toHaveTextContent('Credential rejected'));
  });

  it('recovers with the recovery code and shows the replacement code', async () => {
    const svc = installMock({ initialized: true, unlocked: false, factors: [factor] });
    const view = render(PasswordVaultPanel);
    await waitFor(() => view.getByText('Use recovery code'));
    await fireEvent.click(view.getByText('Use recovery code'));

    await type('vault-recovery-code', 'OLD-CODE');
    await type('vault-new-passphrase', 'fresh phrase');
    await type('vault-confirm-passphrase', 'fresh phrase');
    await fireEvent.click(view.getByText('Recover'));

    await waitFor(() => expect(view.getByTestId('vault-recovery-code')).toHaveTextContent('NEW-CODE-0001'));
    expect(svc.RecoverWithPassphrase).toHaveBeenCalledWith('OLD-CODE', 'fresh phrase', '');
  });

  it('requires the recovery code before recovering', async () => {
    const svc = installMock({ initialized: true, unlocked: false, factors: [factor] });
    const view = render(PasswordVaultPanel);
    await waitFor(() => view.getByText('Use recovery code'));
    await fireEvent.click(view.getByText('Use recovery code'));
    await fireEvent.click(view.getByText('Recover'));

    await waitFor(() => expect(view.getByRole('alert')).toHaveTextContent('recovery code'));
    expect(svc.RecoverWithPassphrase).not.toHaveBeenCalled();
  });

  it('rotates a passphrase factor keeping its label, and removes a factor', async () => {
    const passkey = { id: 'f-2', factor: 'passkey', label: 'yubikey', created_at: '2026-09-30T00:00:00Z' };
    const svc = installMock({ initialized: true, unlocked: true, factors: [factor, passkey] });
    const view = render(PasswordVaultPanel);
    await waitFor(() => view.getByText('laptop'));

    // Only the passphrase factor can be rotated here.
    expect(view.getAllByText('Rotate')).toHaveLength(1);
    await fireEvent.click(view.getByText('Rotate'));
    await type('vault-new-passphrase', 'rotated phrase');
    await type('vault-confirm-passphrase', 'rotated phrase');
    const buttons = view.getAllByText('Rotate');
    await fireEvent.click(buttons[buttons.length - 1]);
    await waitFor(() => expect(svc.RotatePassphrase).toHaveBeenCalledWith('f-1', 'rotated phrase', 'laptop'));

    await waitFor(() => view.getAllByText('Remove'));
    await fireEvent.click(view.getAllByText('Remove')[1]);
    await waitFor(() => expect(svc.RemoveVaultFactor).toHaveBeenCalledWith('f-2'));
  });

  it('explains that the vault needs a server connection', async () => {
    installMock(new Error('staticpw_service: no connected client'));
    const view = render(PasswordVaultPanel);
    await waitFor(() => expect(view.getByRole('status')).toHaveTextContent('connect to one'));
    expect(view.getByRole('status')).toHaveTextContent('no connected client');
  });
});
