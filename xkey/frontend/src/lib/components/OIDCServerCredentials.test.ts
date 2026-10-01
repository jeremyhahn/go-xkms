import '@testing-library/jest-dom/vitest';
import { describe, it, expect, afterEach, vi } from 'vitest';
import { render, fireEvent, waitFor, cleanup, within } from '@testing-library/svelte';
import { tick } from 'svelte';
import OIDCServerCredentials from './OIDCServerCredentials.svelte';

/**
 * OIDCServerCredentials drives OIDCServerService through window.go -- the
 * seam the Wails runtime uses -- so these tests exercise the calls a desktop
 * build makes.
 */

const active = {
  scope: 'tenant', name: 'codex', template: 'openai', status: 'active', refreshable: true,
  expires_at: '2026-10-01T12:00:00Z', supports_device: true,
};
const relogin = {
  scope: 'user', owner: 'alice', name: 'mine', template: 'openai', status: 'relogin_required',
  status_reason: 'refresh token revoked', refreshable: true, supports_device: true,
};
const claude = {
  scope: 'tenant', name: 'claude', template: 'anthropic', status: 'expired', refreshable: false, supports_device: false,
};
const templates = [
  { name: 'anthropic', description: 'Claude token', requires_issuer: false, supports_device: false, supports_import: true, no_refresh: true },
  { name: 'okta', description: 'Okta', requires_issuer: true, supports_device: false, supports_import: false, no_refresh: false },
  { name: 'openai', description: 'ChatGPT', issuer: 'https://auth.openai.com', requires_issuer: false, supports_device: true, supports_import: true, no_refresh: false },
];

function installMock(connected = true, credentials: unknown[] = [active, relogin, claude]) {
  const svc = {
    Connected: vi.fn().mockResolvedValue(connected),
    ServerTemplates: vi.fn().mockResolvedValue(templates),
    ListServerCredentials: vi.fn().mockResolvedValue(credentials),
    CreateServerCredential: vi.fn().mockResolvedValue({ ...active, name: 'new', status: 'pending' }),
    ImportServerTokens: vi.fn().mockResolvedValue({ ...claude, status: 'active' }),
    ImportCodexAuth: vi.fn().mockResolvedValue(active),
    StartServerDeviceLogin: vi.fn().mockResolvedValue({
      ...active, status: 'pending',
      device_login: {
        user_code: 'ABCD-1234', verification_uri: 'https://auth.example.com/device',
        interval_seconds: 5, expires_at: '2099-01-01T00:00:00Z',
      },
    }),
    PollServerDeviceLogin: vi.fn().mockResolvedValue({ ...active }),
    RefreshServerCredential: vi.fn().mockResolvedValue(active),
    DeleteServerCredential: vi.fn().mockResolvedValue(undefined),
    CopyServerAccessToken: vi.fn().mockResolvedValue(undefined),
  };
  (window as any).go = { services: { OIDCServerService: svc } };
  return svc;
}

async function type(id: string, value: string) {
  await fireEvent.input(document.getElementById(id) as HTMLInputElement, { target: { value } });
}

async function renderLoaded() {
  const svc = installMock();
  const view = render(OIDCServerCredentials);
  await waitFor(() => expect(view.getByTestId('server-cred-codex')).toBeInTheDocument());
  return { svc, view };
}

const codexRef = { tenant_id: '', scope: 'tenant', owner: '', name: 'codex' };

afterEach(() => {
  cleanup();
  delete (window as any).go;
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe('OIDCServerCredentials', () => {
  it('renders nothing and lists nothing when no server is connected', async () => {
    const svc = installMock(false);
    const view = render(OIDCServerCredentials);
    await waitFor(() => expect(svc.Connected).toHaveBeenCalled());
    expect(view.queryByTestId('oidc-server-credentials')).toBeNull();
    expect(svc.ListServerCredentials).not.toHaveBeenCalled();
  });

  it('lists the server credentials with status badges, flagging those needing attention', async () => {
    const { svc, view } = await renderLoaded();
    expect(svc.ListServerCredentials).toHaveBeenCalledWith('');

    const codex = view.getByTestId('server-cred-codex');
    expect(within(codex).getByText('Active')).toBeInTheDocument();
    expect(within(codex).getByText('Shared')).toBeInTheDocument();
    expect(codex).not.toHaveClass('attention');

    const mine = view.getByTestId('server-cred-mine');
    expect(within(mine).getByText('Re-login required')).toBeInTheDocument();
    expect(within(mine).getByText('refresh token revoked')).toBeInTheDocument();
    expect(within(mine).getByText('Personal (alice)')).toBeInTheDocument();
    expect(mine).toHaveClass('attention');
    expect(within(mine).queryByText('Copy token')).toBeNull();

    const claudeRow = view.getByTestId('server-cred-claude');
    expect(within(claudeRow).getByText('Expired')).toBeInTheDocument();
    expect(claudeRow).toHaveClass('attention');
    expect(within(claudeRow).queryByText('Device login')).toBeNull();
    expect(within(claudeRow).queryByText('Refresh')).toBeNull();
  });

  it('shows a listing error', async () => {
    const svc = installMock();
    svc.ListServerCredentials.mockRejectedValue(new Error('permission denied'));
    const view = render(OIDCServerCredentials);
    await waitFor(() => expect(view.getByRole('alert')).toHaveTextContent('permission denied'));
  });

  it('creates a credential from a template and scope', async () => {
    const { svc, view } = await renderLoaded();
    await fireEvent.click(view.getByText('Add server credential'));
    await type('server-cred-name', ' codex2 ');
    await fireEvent.change(document.getElementById('server-cred-scope') as HTMLSelectElement, { target: { value: 'tenant' } });
    await fireEvent.click(view.getByText('Create'));
    await waitFor(() => expect(svc.CreateServerCredential).toHaveBeenCalledWith(
      { scope: 'tenant', name: 'codex2' },
      { template: 'openai', issuer: '', client_id: '', scopes: [], device_authorization_endpoint: '' },
    ));
  });

  it('refuses a create without a name or a required issuer', async () => {
    const { svc, view } = await renderLoaded();
    await fireEvent.click(view.getByText('Add server credential'));
    await fireEvent.click(view.getByText('Create'));
    await waitFor(() => expect(view.getByRole('alert')).toHaveTextContent('A credential name is required.'));

    await type('server-cred-name', 'corp');
    await fireEvent.change(document.getElementById('server-cred-template') as HTMLSelectElement, { target: { value: 'okta' } });
    await fireEvent.click(view.getByText('Create'));
    await waitFor(() => expect(view.getByRole('alert')).toHaveTextContent('needs an issuer URL'));
    expect(svc.CreateServerCredential).not.toHaveBeenCalled();
  });

  it('shows a refused create in its dialog', async () => {
    const { svc, view } = await renderLoaded();
    svc.CreateServerCredential.mockRejectedValue(new Error('oidc credential exists'));
    await fireEvent.click(view.getByText('Add server credential'));
    await type('server-cred-name', 'codex');
    await fireEvent.click(view.getByText('Create'));
    await waitFor(() => expect(view.getByRole('alert')).toHaveTextContent('oidc credential exists'));
  });

  it('imports tokens and clears them after submit', async () => {
    const { svc, view } = await renderLoaded();
    await fireEvent.click(view.getByText('Import login'));
    await type('server-import-name', 'claude');
    await type('server-import-access', 'sk-ant-secret');
    const buttons = view.getAllByText('Import');
    await fireEvent.click(buttons[buttons.length - 1]);
    await waitFor(() => expect(svc.ImportServerTokens).toHaveBeenCalledWith(
      { scope: 'user', name: 'claude' },
      { access_token: 'sk-ant-secret', refresh_token: '', expires_at: '' },
      'anthropic', true,
    ));
    expect(view.queryByDisplayValue('sk-ant-secret')).toBeNull();
  });

  it('imports a pasted codex auth.json and clears it even when refused', async () => {
    const { svc, view } = await renderLoaded();
    svc.ImportCodexAuth.mockRejectedValue(new Error('oidc: invalid codex auth.json'));
    await fireEvent.click(within(view.getByTestId('server-cred-codex')).getByText('Import'));
    expect(view.getByRole('tab', { name: 'codex auth.json' })).toHaveAttribute('aria-selected', 'true');
    const area = document.getElementById('server-import-codex') as HTMLTextAreaElement;
    await fireEvent.input(area, { target: { value: '{"tokens":{}}' } });
    const buttons = view.getAllByText('Import');
    await fireEvent.click(buttons[buttons.length - 1]);
    await waitFor(() => expect(svc.ImportCodexAuth).toHaveBeenCalledWith(
      { scope: 'tenant', name: 'codex' }, '{"tokens":{}}', false,
    ));
    await waitFor(() => expect(view.getByRole('alert')).toHaveTextContent('invalid codex auth.json'));
    expect((document.getElementById('server-import-codex') as HTMLTextAreaElement).value).toBe('');
  });

  it('refuses an import without an access token', async () => {
    const { svc, view } = await renderLoaded();
    await fireEvent.click(view.getByText('Import login'));
    await type('server-import-name', 'claude');
    const buttons = view.getAllByText('Import');
    await fireEvent.click(buttons[buttons.length - 1]);
    await waitFor(() => expect(view.getByRole('alert')).toHaveTextContent('An access token is required.'));
    expect(svc.ImportServerTokens).not.toHaveBeenCalled();
  });

  it('runs a device login: shows the code and polls at the interval until active', async () => {
    const { svc, view } = await renderLoaded();
    vi.useFakeTimers();
    svc.PollServerDeviceLogin
      .mockResolvedValueOnce({ ...active, status: 'pending', device_login: { user_code: 'ABCD-1234', verification_uri: 'https://auth.example.com/device', interval_seconds: 10, expires_at: '2099-01-01T00:00:00Z' } })
      .mockResolvedValueOnce({ ...active });
    await fireEvent.click(within(view.getByTestId('server-cred-codex')).getByText('Device login'));
    await vi.advanceTimersByTimeAsync(0);
    await tick();
    expect(svc.StartServerDeviceLogin).toHaveBeenCalledWith(codexRef);
    expect(view.getByTestId('device-user-code')).toHaveTextContent('ABCD-1234');
    expect(view.getByText('https://auth.example.com/device')).toBeInTheDocument();

    await vi.advanceTimersByTimeAsync(4900);
    expect(svc.PollServerDeviceLogin).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(100);
    expect(svc.PollServerDeviceLogin).toHaveBeenCalledTimes(1);

    await vi.advanceTimersByTimeAsync(9900);
    expect(svc.PollServerDeviceLogin).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(100);
    expect(svc.PollServerDeviceLogin).toHaveBeenCalledTimes(2);
    await tick();
    expect(view.queryByTestId('device-login')).toBeNull();
  });

  it('stops polling when the device dialog is closed', async () => {
    const { svc, view } = await renderLoaded();
    vi.useFakeTimers();
    svc.PollServerDeviceLogin.mockResolvedValue({ ...active, status: 'pending' });
    await fireEvent.click(within(view.getByTestId('server-cred-codex')).getByText('Device login'));
    await vi.advanceTimersByTimeAsync(0);
    await tick();
    await fireEvent.click(view.getByText('Close'));
    await vi.advanceTimersByTimeAsync(60_000);
    expect(svc.PollServerDeviceLogin).not.toHaveBeenCalled();
  });

  it('reports an expired device login and stops polling', async () => {
    const { svc, view } = await renderLoaded();
    vi.useFakeTimers();
    svc.PollServerDeviceLogin.mockResolvedValue({ ...active, status: 'expired' });
    await fireEvent.click(within(view.getByTestId('server-cred-codex')).getByText('Device login'));
    await vi.advanceTimersByTimeAsync(5000);
    await tick();
    expect(view.getByRole('alert')).toHaveTextContent('not approved in time');
    await vi.advanceTimersByTimeAsync(60_000);
    expect(svc.PollServerDeviceLogin).toHaveBeenCalledTimes(1);
  });

  it('refreshes, copies the token on click only, and deletes', async () => {
    const { svc, view } = await renderLoaded();
    expect(svc.CopyServerAccessToken).not.toHaveBeenCalled();
    const row = view.getByTestId('server-cred-codex');

    await fireEvent.click(within(row).getByText('Refresh'));
    await waitFor(() => expect(svc.RefreshServerCredential).toHaveBeenCalledWith(codexRef));

    await fireEvent.click(within(row).getByText('Copy token'));
    await waitFor(() => expect(svc.CopyServerAccessToken).toHaveBeenCalledWith(codexRef));

    await fireEvent.click(within(row).getByText('Delete'));
    const buttons = view.getAllByText('Delete');
    await fireEvent.click(buttons[buttons.length - 1]);
    await waitFor(() => expect(svc.DeleteServerCredential).toHaveBeenCalledWith(codexRef));
  });

  it('keeps the list when a refresh or delete is refused', async () => {
    const { svc, view } = await renderLoaded();
    svc.RefreshServerCredential.mockRejectedValue(new Error('relogin required'));
    svc.DeleteServerCredential.mockRejectedValue(new Error('permission denied'));
    const row = view.getByTestId('server-cred-codex');
    await fireEvent.click(within(row).getByText('Refresh'));
    await waitFor(() => expect(svc.RefreshServerCredential).toHaveBeenCalled());
    await fireEvent.click(within(row).getByText('Delete'));
    const buttons = view.getAllByText('Delete');
    await fireEvent.click(buttons[buttons.length - 1]);
    await waitFor(() => expect(svc.DeleteServerCredential).toHaveBeenCalled());
    expect(svc.ListServerCredentials).toHaveBeenCalledTimes(1);
    expect(view.getByTestId('server-cred-codex')).toBeInTheDocument();
  });
});
