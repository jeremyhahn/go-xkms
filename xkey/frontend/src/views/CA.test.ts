import '@testing-library/jest-dom/vitest';
import { describe, it, expect, afterEach, vi } from 'vitest';
import { render, fireEvent, waitFor, cleanup } from '@testing-library/svelte';
import CA from './CA.svelte';

/**
 * The CA view shows which CA serves (xKey's local CA with no server
 * connected, else the server's), its certificate, and issues certificates.
 */

function caInfo(subject: string) {
  return {
    subject, issuer: subject, serial: '1234', algorithm: 'ECDSA',
    not_before: '2026-01-01T00:00:00Z', not_after: '2036-01-01T00:00:00Z', is_ca: true,
  };
}

function installMock(mode: string, subject: string) {
  const ca = {
    GetCAMode: vi.fn().mockResolvedValue(mode),
    GetCAInfo: vi.fn().mockResolvedValue(caInfo(subject)),
    IssueCertificate: vi.fn().mockResolvedValue({
      serial: '99', subject: 'CN=web.example', certificate_pem: '-----BEGIN CERTIFICATE-----\nISSUED\n-----END CERTIFICATE-----',
    }),
  };
  (window as any).go = { services: { CAService: ca } };
  return ca;
}

afterEach(() => {
  cleanup();
  delete (window as any).go;
  vi.restoreAllMocks();
});

describe('CA view', () => {
  it('shows the local CA when no server is connected', async () => {
    installMock('local', 'CN=xkey Root CA');
    const view = render(CA);
    await waitFor(() => expect(view.getAllByText('CN=xkey Root CA', { selector: 'dd' }).length).toBeGreaterThan(0));
    expect(view.getByTestId('ca-mode')).toHaveTextContent('Local CA');
    expect(view.getByText('Certificate Authority')).toBeInTheDocument();
  });

  it('shows the server CA when a server is connected', async () => {
    installMock('remote', 'CN=Server CA');
    const view = render(CA);
    await waitFor(() => expect(view.getByTestId('ca-mode')).toHaveTextContent('Server CA'));
    await waitFor(() => expect(view.getAllByText('CN=Server CA', { selector: 'dd' }).length).toBeGreaterThan(0));
  });

  it('issues a certificate with the entered common name and profile', async () => {
    const ca = installMock('local', 'CN=xkey Root CA');
    const view = render(CA);
    await waitFor(() => expect(view.getByLabelText('Common name')).toBeInTheDocument());
    await fireEvent.change(view.getByLabelText('Profile'), { target: { value: 'client' } });
    await fireEvent.input(view.getByLabelText('Common name'), { target: { value: 'web.example' } });
    await fireEvent.click(view.getByText('Issue'));
    await waitFor(() => expect(ca.IssueCertificate).toHaveBeenCalled());
    const args = ca.IssueCertificate.mock.calls[0];
    expect(args[0]).toBe('client');
    expect(args[1]).toBe('web.example');
    await waitFor(() => expect(view.getByTestId('ca-issued-pem')).toHaveTextContent('ISSUED'));
  });
});
