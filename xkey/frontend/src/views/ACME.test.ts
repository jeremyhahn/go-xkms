import '@testing-library/jest-dom/vitest';
import { describe, it, expect, afterEach, vi } from 'vitest';
import { render, fireEvent, waitFor, cleanup, within } from '@testing-library/svelte';
import ACME from './ACME.svelte';

/**
 * The ACME view is a thin caller of the bound ACMEService: it builds one
 * connection from the form and passes it to every account, revoke and renew
 * call. It handles paths only, never key material.
 */

function installMock() {
  const acme = {
    RegisterAccount: vi.fn().mockResolvedValue({ uri: 'https://ca.test/acct/1', status: 'valid', contacts: ['mailto:a@x'] }),
    UpdateAccount: vi.fn().mockImplementation((_c: any, contacts: string[]) =>
      Promise.resolve({ uri: 'https://ca.test/acct/1', status: 'valid', contacts })),
    DeactivateAccount: vi.fn().mockResolvedValue({ uri: 'https://ca.test/acct/1', status: 'deactivated', contacts: [] }),
    RevokeCertificate: vi.fn().mockResolvedValue(undefined),
    RenewCertificate: vi.fn().mockResolvedValue('-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n'),
    EnrollDevice: vi.fn().mockResolvedValue({
      idevidPem: '-----BEGIN CERTIFICATE-----\nIDEVID\n-----END CERTIFICATE-----\n',
      iakPem: '-----BEGIN CERTIFICATE-----\nIAK\n-----END CERTIFICATE-----\n',
      chainPem: '-----BEGIN CERTIFICATE-----\nCHAIN\n-----END CERTIFICATE-----\n',
    }),
    EndorseDevice: vi.fn().mockResolvedValue('-----BEGIN CERTIFICATE-----\nEK\n-----END CERTIFICATE-----\n'),
  };
  (window as any).go = {
    services: {
      AppService: { GetConfig: vi.fn().mockResolvedValue({ clipboard_timeout: 30 }) },
      ACMEService: acme,
    },
  };
  return acme;
}

async function fillConnection(view: { getByLabelText: (text: string) => HTMLElement }) {
  await fireEvent.input(view.getByLabelText('Directory URL'), { target: { value: 'https://ca.test/directory' } });
  await fireEvent.input(view.getByLabelText('Account key path'), { target: { value: '/keys/account.pem' } });
  await fireEvent.input(view.getByLabelText('Trusted root paths'), { target: { value: ' /r1.pem\n\n/r2.pem \n' } });
}

const conn = {
  directoryUrl: 'https://ca.test/directory',
  accountKeyPath: '/keys/account.pem',
  trustedRootPaths: ['/r1.pem', '/r2.pem'],
  systemRoots: false,
};

afterEach(() => {
  cleanup();
  delete (window as any).go;
  vi.restoreAllMocks();
});

describe('ACME view', () => {
  it('registers with the connection from the form and shows the account', async () => {
    const acme = installMock();
    const view = render(ACME);
    await fillConnection(view);
    await fireEvent.input(view.getByLabelText('Contact email'), { target: { value: 'mailto:a@x' } });
    await fireEvent.click(view.getByRole('button', { name: 'Register' }));
    await waitFor(() => expect(acme.RegisterAccount).toHaveBeenCalledTimes(1));
    expect(acme.RegisterAccount).toHaveBeenCalledWith(conn, 'mailto:a@x');
    const account = await view.findByTestId('acme-account');
    await waitFor(() => expect(account).toHaveTextContent('https://ca.test/acct/1'));
    expect(account).toHaveTextContent('valid');
  });

  it('updates contacts from a comma separated list', async () => {
    const acme = installMock();
    const view = render(ACME);
    await fillConnection(view);
    await fireEvent.input(view.getByLabelText('Contacts'), { target: { value: 'mailto:a@x, mailto:b@x' } });
    await fireEvent.click(view.getByRole('button', { name: 'Update contacts' }));
    await waitFor(() => expect(acme.UpdateAccount).toHaveBeenCalledTimes(1));
    expect(acme.UpdateAccount).toHaveBeenCalledWith(conn, ['mailto:a@x', 'mailto:b@x']);
  });

  it('deactivates only after confirm', async () => {
    const acme = installMock();
    const view = render(ACME);
    await fillConnection(view);
    await fireEvent.click(view.getByRole('button', { name: 'Deactivate' }));
    let dialog = await view.findByRole('dialog');
    expect(dialog).toHaveTextContent(/permanent/i);
    await fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(view.queryByRole('dialog')).not.toBeInTheDocument());
    expect(acme.DeactivateAccount).not.toHaveBeenCalled();

    await fireEvent.click(view.getByRole('button', { name: 'Deactivate' }));
    dialog = await view.findByRole('dialog');
    await fireEvent.click(within(dialog).getByRole('button', { name: 'Deactivate account' }));
    await waitFor(() => expect(acme.DeactivateAccount).toHaveBeenCalledTimes(1));
    expect(acme.DeactivateAccount).toHaveBeenCalledWith(conn, true);
  });

  it('revokes with the chosen reason', async () => {
    const acme = installMock();
    const view = render(ACME);
    await fillConnection(view);
    await fireEvent.input(view.getByLabelText('Certificate to revoke'), { target: { value: '/certs/a.pem' } });
    await fireEvent.change(view.getByLabelText('Revocation reason'), { target: { value: 'keyCompromise' } });
    await fireEvent.click(view.getByRole('button', { name: 'Revoke' }));
    await waitFor(() => expect(acme.RevokeCertificate).toHaveBeenCalledTimes(1));
    expect(acme.RevokeCertificate).toHaveBeenCalledWith(conn, '/certs/a.pem', 'keyCompromise');
  });

  it('revokes with reason unspecified by default', async () => {
    const acme = installMock();
    const view = render(ACME);
    await fillConnection(view);
    await fireEvent.input(view.getByLabelText('Certificate to revoke'), { target: { value: '/certs/a.pem' } });
    await fireEvent.click(view.getByRole('button', { name: 'Revoke' }));
    await waitFor(() => expect(acme.RevokeCertificate).toHaveBeenCalledTimes(1));
    expect(acme.RevokeCertificate).toHaveBeenCalledWith(conn, '/certs/a.pem', 'unspecified');
  });

  it('renews and shows the returned certificate', async () => {
    const acme = installMock();
    const view = render(ACME);
    await fillConnection(view);
    await fireEvent.input(view.getByLabelText('Certificate to renew'), { target: { value: '/certs/a.pem' } });
    await fireEvent.input(view.getByLabelText('Domain'), { target: { value: 'a.test' } });
    await fireEvent.input(view.getByLabelText('Challenge'), { target: { value: 'dns-01' } });
    await fireEvent.input(view.getByLabelText('CSR path'), { target: { value: '/certs/a.csr' } });
    await fireEvent.click(view.getByRole('button', { name: 'Renew' }));
    await waitFor(() => expect(acme.RenewCertificate).toHaveBeenCalledTimes(1));
    expect(acme.RenewCertificate).toHaveBeenCalledWith(conn, {
      certPath: '/certs/a.pem', domain: 'a.test', authzType: 'dns', challenge: 'dns-01', csrPath: '/certs/a.csr',
    });
    await waitFor(() =>
      expect((view.getByLabelText('Renewed certificate') as HTMLTextAreaElement).value).toContain('BEGIN CERTIFICATE'));
  });

  it('shows a rejected renew as an alert and no certificate', async () => {
    const acme = installMock();
    acme.RenewCertificate.mockRejectedValue(new Error('order failed'));
    const view = render(ACME);
    await fillConnection(view);
    await fireEvent.input(view.getByLabelText('Certificate to renew'), { target: { value: '/certs/a.pem' } });
    await fireEvent.input(view.getByLabelText('Domain'), { target: { value: 'a.test' } });
    await fireEvent.click(view.getByRole('button', { name: 'Renew' }));
    await waitFor(() => expect(view.getByRole('alert')).toHaveTextContent('order failed'));
    expect(view.queryByLabelText('Renewed certificate')).not.toBeInTheDocument();
  });

  it('keeps actions disabled without directory URL or account key path', async () => {
    const acme = installMock();
    const view = render(ACME);
    for (const name of ['Register', 'Update contacts', 'Deactivate', 'Revoke', 'Renew']) {
      expect(view.getByRole('button', { name })).toBeDisabled();
    }
    await fireEvent.input(view.getByLabelText('Directory URL'), { target: { value: 'https://ca.test/directory' } });
    expect(view.getByRole('button', { name: 'Register' })).toBeDisabled();
    await fireEvent.click(view.getByRole('button', { name: 'Register' }));
    for (const fn of Object.values(acme)) expect(fn).not.toHaveBeenCalled();
  });

  it('shows no backend connection without the Wails runtime', () => {
    const view = render(ACME);
    expect(view.getByRole('alert')).toHaveTextContent('No backend connection');
  });

  it('enrolls the device and shows the three certificates', async () => {
    const acme = installMock();
    const view = render(ACME);
    await fillConnection(view);
    await fireEvent.input(view.getByLabelText('IP address'), { target: { value: '192.0.2.10' } });
    await fireEvent.input(view.getByLabelText('Port'), { target: { value: '9090' } });
    await fireEvent.input(view.getByLabelText('Listen host'), { target: { value: '0.0.0.0' } });
    await fireEvent.input(view.getByLabelText('Common name'), { target: { value: 'device-1' } });
    await fireEvent.click(view.getByRole('button', { name: 'Enroll' }));
    await waitFor(() => expect(acme.EnrollDevice).toHaveBeenCalledTimes(1));
    expect(acme.EnrollDevice).toHaveBeenCalledWith(conn, {
      challenge: 'enroll-01', ipAddress: '192.0.2.10', port: 9090, listenHost: '0.0.0.0',
      commonName: 'device-1', pcrs: [], timeoutSeconds: 0,
    });
    await waitFor(() =>
      expect((view.getByLabelText('IDevID certificate') as HTMLTextAreaElement).value).toContain('IDEVID'));
    expect((view.getByLabelText('IAK certificate') as HTMLTextAreaElement).value).toContain('IAK');
    expect((view.getByLabelText('Chain') as HTMLTextAreaElement).value).toContain('CHAIN');
  });

  it('enrolls with device-attest-01 and PCRs without an IP address', async () => {
    const acme = installMock();
    const view = render(ACME);
    await fillConnection(view);
    await fireEvent.change(view.getByLabelText('Device challenge'), { target: { value: 'device-attest-01' } });
    await fireEvent.input(view.getByLabelText('PCRs'), { target: { value: '0, 1, , 7' } });
    const enroll = view.getByRole('button', { name: 'Enroll' });
    expect(enroll).not.toBeDisabled();
    await fireEvent.click(enroll);
    await waitFor(() => expect(acme.EnrollDevice).toHaveBeenCalledTimes(1));
    expect(acme.EnrollDevice.mock.calls[0][1]).toMatchObject({ challenge: 'device-attest-01', ipAddress: '', pcrs: [0, 1, 7] });
  });

  it('keeps Enroll and Request EK certificate disabled without an IP address', async () => {
    const acme = installMock();
    const view = render(ACME);
    await fillConnection(view);
    const enroll = view.getByRole('button', { name: 'Enroll' });
    const endorse = view.getByRole('button', { name: 'Request EK certificate' });
    expect(enroll).toBeDisabled();
    expect(endorse).toBeDisabled();
    await fireEvent.click(enroll);
    await fireEvent.click(endorse);
    expect(acme.EnrollDevice).not.toHaveBeenCalled();
    expect(acme.EndorseDevice).not.toHaveBeenCalled();
  });

  it('requests the EK certificate and shows it', async () => {
    const acme = installMock();
    const view = render(ACME);
    await fillConnection(view);
    await fireEvent.input(view.getByLabelText('IP address'), { target: { value: '192.0.2.10' } });
    await fireEvent.click(view.getByRole('button', { name: 'Request EK certificate' }));
    await waitFor(() => expect(acme.EndorseDevice).toHaveBeenCalledTimes(1));
    expect(acme.EndorseDevice.mock.calls[0][0]).toEqual(conn);
    expect(acme.EndorseDevice.mock.calls[0][1]).toMatchObject({ ipAddress: '192.0.2.10' });
    await waitFor(() =>
      expect((view.getByLabelText('EK certificate') as HTMLTextAreaElement).value).toContain('EK'));
  });

  it('shows a rejected EK request as an alert and no certificate', async () => {
    const acme = installMock();
    acme.EndorseDevice.mockRejectedValue(new Error('endorse failed'));
    const view = render(ACME);
    await fillConnection(view);
    await fireEvent.input(view.getByLabelText('IP address'), { target: { value: '192.0.2.10' } });
    await fireEvent.click(view.getByRole('button', { name: 'Request EK certificate' }));
    await waitFor(() => expect(view.getByRole('alert')).toHaveTextContent('endorse failed'));
    expect(view.queryByLabelText('EK certificate')).not.toBeInTheDocument();
  });
});
