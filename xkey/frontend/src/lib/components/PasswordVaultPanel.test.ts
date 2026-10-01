import '@testing-library/jest-dom/vitest';
import { describe, it, expect, afterEach, vi } from 'vitest';
import { render, fireEvent, waitFor, cleanup } from '@testing-library/svelte';
import PasswordVaultPanel from './PasswordVaultPanel.svelte';

const factor = { id: 'f-1', factor: 'passphrase', label: 'laptop', created_at: '2026-09-30T00:00:00Z' };
const passkey = { id: 'f-2', factor: 'passkey', label: 'yubikey', created_at: '2026-09-30T00:00:00Z' };
const keyFactor = { id: 'f-3', factor: 'tpm', label: 'this laptop', created_at: '2026-09-30T00:00:00Z', key_backend: 'tpm2', key_id: 'vault-tpm', tpm_policy: 'platform' };

function installMock(status: Record<string, unknown> | Error) {
  const svc = {
    VaultStatus: status instanceof Error ? vi.fn().mockRejectedValue(status) : vi.fn().mockResolvedValue(status),
    EnrollPassphrase: vi.fn().mockResolvedValue({ factor, recovery_code: 'ABCD-EFGH-IJKL' }),
    RotatePassphrase: vi.fn().mockResolvedValue({ factor: { ...factor, id: 'f-9' } }),
    RecoverWithPassphrase: vi.fn().mockResolvedValue({ factor, recovery_code: 'NEW-CODE-0001' }),
    EnrollPasskey: vi.fn().mockResolvedValue({ factor: passkey, recovery_code: 'ABCD-EFGH-IJKL' }),
    UnlockWithPasskey: vi.fn().mockResolvedValue(undefined),
    RecoverWithPasskey: vi.fn().mockResolvedValue({ factor: passkey, recovery_code: 'NEW-CODE-0002' }),
    RemoveVaultFactor: vi.fn().mockResolvedValue(undefined),
    EnrollKeyFactor: vi.fn().mockResolvedValue({ factor: keyFactor, recovery_code: 'KEY-CODE-0001' }),
    RecoverWithKeyFactor: vi.fn().mockResolvedValue({ factor: keyFactor, recovery_code: 'KEY-CODE-0002' }),
    UnlockWithKeyFactor: vi.fn().mockResolvedValue(undefined),
    Unlock: vi.fn().mockResolvedValue(undefined),
    Lock: vi.fn().mockResolvedValue(undefined),
  };
  (window as any).go = { services: { StaticPasswordService: svc } };
  return svc;
}

/** deferred returns a promise the test settles, to observe a pending call. */
function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
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
const keyFactor = { id: 'f-3', factor: 'tpm', label: 'this laptop', created_at: '2026-09-30T00:00:00Z', key_backend: 'tpm2', key_id: 'vault-tpm', tpm_policy: 'platform' };
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

  describe('security key', () => {
    it('creates the vault with a security key, asking for a touch, and shows the recovery code', async () => {
      const svc = installMock({ initialized: false, unlocked: false, factors: [] });
      const pending = deferred<unknown>();
      svc.EnrollPasskey.mockReturnValue(pending.promise);
      const view = render(PasswordVaultPanel);
      await waitFor(() => view.getByText('Use security key'));

      await fireEvent.click(view.getByText('Use security key'));
      expect(document.getElementById('vault-new-passphrase')).toBeNull();
      await type('vault-pin', '123456');
      await type('vault-label', 'yubikey');
      svc.VaultStatus.mockResolvedValue({ initialized: true, unlocked: true, factors: [passkey] });
      await fireEvent.click(view.getByText('Create vault'));

      await waitFor(() => expect(view.getByTestId('vault-touch-prompt')).toHaveTextContent('Touch your security key'));
      expect(svc.EnrollPasskey).toHaveBeenCalledWith('yubikey', '123456');
      expect(svc.EnrollPassphrase).not.toHaveBeenCalled();

      pending.resolve({ factor: passkey, recovery_code: 'ABCD-EFGH-IJKL' });
      await waitFor(() => expect(view.getByTestId('vault-recovery-code')).toHaveTextContent('ABCD-EFGH-IJKL'));
      expect(view.queryByTestId('vault-touch-prompt')).not.toBeInTheDocument();
      expect(view.getByText(/it will not be shown again/)).toBeInTheDocument();
    });

    it('requires the security key PIN before touching the key', async () => {
      const svc = installMock({ initialized: false, unlocked: false, factors: [] });
      const view = render(PasswordVaultPanel);
      await waitFor(() => view.getByText('Use security key'));
      await fireEvent.click(view.getByText('Use security key'));
      await fireEvent.click(view.getByText('Create vault'));

      await waitFor(() => expect(view.getByRole('alert')).toHaveTextContent('security key PIN'));
      expect(svc.EnrollPasskey).not.toHaveBeenCalled();
    });

    it('unlocks with the security key', async () => {
      const svc = installMock({ initialized: true, unlocked: false, factors: [factor, passkey] });
      const pending = deferred<undefined>();
      svc.UnlockWithPasskey.mockReturnValue(pending.promise);
      const view = render(PasswordVaultPanel);
      await waitFor(() => view.getByText('Use security key'));

      await fireEvent.click(view.getByText('Use security key'));
      await type('vault-pin', '123456');
      svc.VaultStatus.mockResolvedValue({ initialized: true, unlocked: true, factors: [factor, passkey] });
      await fireEvent.click(view.getByText('Unlock'));

      await waitFor(() => expect(view.getByTestId('vault-touch-prompt')).toBeInTheDocument());
      expect(svc.UnlockWithPasskey).toHaveBeenCalledWith('123456');
      expect(svc.Unlock).not.toHaveBeenCalled();
      pending.resolve(undefined);
      await waitFor(() => expect(view.getByText('Unlocked')).toBeInTheDocument());
      expect(view.queryByTestId('vault-touch-prompt')).not.toBeInTheDocument();
    });

    it('reports a wrong security key PIN and clears it', async () => {
      const svc = installMock({ initialized: true, unlocked: false, factors: [passkey] });
      svc.UnlockWithPasskey.mockRejectedValue(new Error('fido2: invalid PIN'));
      const view = render(PasswordVaultPanel);
      // A vault with only passkeys offers the security key first.
      await waitFor(() => expect(document.getElementById('vault-pin')).not.toBeNull());
      expect(document.getElementById('vault-passphrase')).toBeNull();

      await type('vault-pin', '000000');
      await fireEvent.click(view.getByText('Unlock'));

      await waitFor(() => expect(view.getByRole('alert')).toHaveTextContent('invalid PIN'));
      expect((document.getElementById('vault-pin') as HTMLInputElement).value).toBe('');
      expect(view.queryByTestId('vault-touch-prompt')).not.toBeInTheDocument();
    });

    it('requires the PIN to unlock with the security key', async () => {
      const svc = installMock({ initialized: true, unlocked: false, factors: [passkey] });
      const view = render(PasswordVaultPanel);
      await waitFor(() => expect(document.getElementById('vault-pin')).not.toBeNull());
      await fireEvent.click(view.getByText('Unlock'));

      await waitFor(() => expect(view.getByRole('alert')).toHaveTextContent('security key PIN'));
      expect(svc.UnlockWithPasskey).not.toHaveBeenCalled();
    });

    it('recovers with a new security key and shows the replacement code', async () => {
      const svc = installMock({ initialized: true, unlocked: false, factors: [factor] });
      const view = render(PasswordVaultPanel);
      await waitFor(() => view.getByText('Use recovery code'));
      await fireEvent.click(view.getByText('Use recovery code'));
      await fireEvent.click(view.getByText('Use security key'));

      await type('vault-recovery-code', 'OLD-CODE');
      await type('vault-pin', '123456');
      await type('vault-label', 'spare key');
      await fireEvent.click(view.getByText('Recover'));

      await waitFor(() => expect(view.getByTestId('vault-recovery-code')).toHaveTextContent('NEW-CODE-0002'));
      expect(svc.RecoverWithPasskey).toHaveBeenCalledWith('OLD-CODE', 'spare key', '123456');
      expect(svc.RecoverWithPassphrase).not.toHaveBeenCalled();
    });

    it('adds a security key to an unlocked vault without a recovery code', async () => {
      const svc = installMock({ initialized: true, unlocked: true, factors: [factor] });
      svc.EnrollPasskey.mockResolvedValue({ factor: passkey });
      const view = render(PasswordVaultPanel);
      await waitFor(() => view.getByText('Add security key'));

      await fireEvent.click(view.getByText('Add security key'));
      expect(view.getByText('Add a security key')).toBeInTheDocument();
      await type('vault-pin', '123456');
      await type('vault-label', 'yubikey');
      svc.VaultStatus.mockResolvedValue({ initialized: true, unlocked: true, factors: [factor, passkey] });
      await fireEvent.click(view.getByText('Add'));

      await waitFor(() => expect(svc.EnrollPasskey).toHaveBeenCalledWith('yubikey', '123456'));
      await waitFor(() => expect(view.getByText('yubikey')).toBeInTheDocument());
      expect(view.queryByTestId('vault-recovery-code')).not.toBeInTheDocument();
    });
  });
});

describe('PasswordVaultPanel key factors', () => {
  it('creates the vault with a TPM key under a named policy', async () => {
    const svc = installMock({ initialized: false, unlocked: false, factors: [] });
    const view = render(PasswordVaultPanel);
    await waitFor(() => view.getByText('Use a key'));
    await fireEvent.click(view.getByText('Use a key'));

    await fireEvent.change(view.container.querySelector('#vault-key-factor') as HTMLSelectElement, { target: { value: 'tpm' } });
    await type('vault-key-backend', 'tpm2');
    await type('vault-key-id', 'vault-tpm');
    await type('vault-key-policy', 'platform');
    await type('vault-label', 'this laptop');
    svc.VaultStatus.mockResolvedValue({ initialized: true, unlocked: true, factors: [keyFactor] });
    await fireEvent.click(view.getByText('Create vault'));

    await waitFor(() => expect(view.getByTestId('vault-recovery-code')).toHaveTextContent('KEY-CODE-0001'));
    expect(svc.EnrollKeyFactor).toHaveBeenCalledWith('tpm', 'tpm2', 'vault-tpm', 'platform', 'this laptop');
  });

  it('refuses a key factor without a backend before calling xKey', async () => {
    const svc = installMock({ initialized: false, unlocked: false, factors: [] });
    const view = render(PasswordVaultPanel);
    await waitFor(() => view.getByText('Use a key'));
    await fireEvent.click(view.getByText('Use a key'));
    await fireEvent.click(view.getByText('Create vault'));
    await waitFor(() => view.getByRole('alert'));
    expect(view.getByRole('alert')).toHaveTextContent('backend');
    expect(svc.EnrollKeyFactor).not.toHaveBeenCalled();
  });

  it('unlocks with a key when the vault has a key factor, and shows the reason when it cannot', async () => {
    const svc = installMock({ initialized: true, unlocked: false, factors: [factor, keyFactor] });
    const view = render(PasswordVaultPanel);
    await waitFor(() => view.getByText('Unlock with key'));
    svc.UnlockWithKeyFactor.mockRejectedValueOnce(new Error('none of the vault\'s key factors has its token here'));
    await fireEvent.click(view.getByText('Unlock with key'));
    await waitFor(() => expect(view.getByRole('alert')).toHaveTextContent('token here'));

    svc.VaultStatus.mockResolvedValue({ initialized: true, unlocked: true, factors: [factor, keyFactor] });
    await fireEvent.click(view.getByText('Unlock with key'));
    await waitFor(() => view.getByText('Unlocked'));
    expect(svc.UnlockWithKeyFactor).toHaveBeenCalledTimes(2);
  });

  it('offers no key unlock without a key factor', async () => {
    installMock({ initialized: true, unlocked: false, factors: [factor] });
    const view = render(PasswordVaultPanel);
    await waitFor(() => view.getByText('Use recovery code'));
    expect(view.queryByText('Unlock with key')).toBeNull();
  });

  it('adds a PIV key while unlocked and recovers with one while locked', async () => {
    const svc = installMock({ initialized: true, unlocked: true, factors: [factor] });
    const view = render(PasswordVaultPanel);
    await waitFor(() => view.getByText('Add key'));
    await fireEvent.click(view.getByText('Add key'));
    await type('vault-key-backend', 'pkcs11');
    await fireEvent.click(view.getByText('Add'));
    await waitFor(() => expect(svc.EnrollKeyFactor).toHaveBeenCalledWith('piv', 'pkcs11', '', '', ''));
  });
});
