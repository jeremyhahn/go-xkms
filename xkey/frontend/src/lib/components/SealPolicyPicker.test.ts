import '@testing-library/jest-dom/vitest';
import { describe, it, expect, afterEach, vi } from 'vitest';
import { render, fireEvent, waitFor, cleanup } from '@testing-library/svelte';
import SealPolicyPicker from './SealPolicyPicker.svelte';
import SealPolicyPickerHarness from './test-harness/SealPolicyPickerHarness.svelte';

function installMock() {
  (window as any).go = {
    services: {
      TPMPolicyService: {
        ListPolicies: vi.fn().mockResolvedValue([
          { name: 'platform', builtin: true, approved: true, auto_unseal: false, object_count: 0 },
          { name: 'boot', builtin: false, bank: 'sha256', pcrs: [0, 7], approved: true, auto_unseal: false, object_count: 1 },
        ]),
      },
    },
  };
}

afterEach(() => {
  cleanup();
  delete (window as any).go;
  vi.restoreAllMocks();
});

describe('SealPolicyPicker', () => {
  it('offers none, the platform policy (default) and named policies on tpm2', async () => {
    installMock();
    const view = render(SealPolicyPicker, { props: { backend: 'tpm2' } });
    const select = view.getByLabelText('TPM policy') as HTMLSelectElement;
    await waitFor(() => expect(select.options.length).toBe(3));
    expect(select.value).toBe('platform');
    expect(Array.from(select.options).map((o) => o.value)).toEqual(['platform', 'boot', '']);
  });

  it('binds the chosen named policy', async () => {
    installMock();
    const view = render(SealPolicyPickerHarness, { props: { backend: 'tpm2' } });
    const select = view.getByLabelText('TPM policy') as HTMLSelectElement;
    await waitFor(() => expect(select.options.length).toBe(3));
    await fireEvent.change(select, { target: { value: 'boot' } });
    await waitFor(() => expect(view.getByTestId('bound-policy')).toHaveTextContent('boot'));
  });

  it('has no TPM policy on a non-TPM backend', async () => {
    installMock();
    const view = render(SealPolicyPickerHarness, { props: { backend: 'software', tpmPolicy: 'platform' } });
    expect(view.queryByLabelText('TPM policy')).toBeNull();
    await waitFor(() => expect(view.getByTestId('bound-policy').textContent).toBe(''));
  });

  it('asks for a matching password only when one is required', async () => {
    installMock();
    const view = render(SealPolicyPicker, { props: { backend: 'tpm2' } });
    expect(view.queryByLabelText('Password')).toBeNull();
    await fireEvent.click(view.getByRole('switch'));
    const inputs = view.container.querySelectorAll('input[type="password"]');
    expect(inputs.length).toBe(2);
    await fireEvent.input(inputs[0], { target: { value: 'one' } });
    await fireEvent.input(inputs[1], { target: { value: 'two' } });
    await waitFor(() => expect(view.getByRole('alert')).toHaveTextContent('Passwords do not match'));
    expect(view.getByText('The password also unseals the data after the platform state changes.')).toBeInTheDocument();
  });
});
