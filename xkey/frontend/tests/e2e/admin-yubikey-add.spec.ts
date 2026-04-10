import { test, expect } from '@playwright/test';
import * as fs from 'fs';

const ADMIN_PATH = '/home/jhahn/sources/go-xkms/xkey/frontend/src/views/Admin.svelte';

test.describe('Admin YubiKey backend add flow', () => {
  test("Admin.svelte testConfig builds yubikey config with library_path, user_pin, slot_id", async () => {
    const content = fs.readFileSync(ADMIN_PATH, 'utf8');
    expect(content).toMatch(/selectedBackendType\.type === 'yubikey'[\s\S]{0,400}testConfig\[['"]library_path['"]\]\s*=\s*yukLibraryPath/);
    expect(content).toMatch(/selectedBackendType\.type === 'yubikey'[\s\S]{0,400}testConfig\[['"]user_pin['"]\]\s*=\s*yukUserPin/);
  });

  test("Admin.svelte yubikey test connection requires yukUserPin", async () => {
    const content = fs.readFileSync(ADMIN_PATH, 'utf8');
    expect(content).toMatch(/yubikey[\s\S]{0,400}!yukUserPin[\s\S]{0,200}User PIN is required/);
  });

  test('PKCS11Service.Connect signature includes soPin parameter', async () => {
    const content = fs.readFileSync(
      '/home/jhahn/sources/go-xkms/xkey/pkg/gui/services/pkcs11_service.go', 'utf8');
    expect(content).toMatch(/func \(s \*PKCS11Service\) Connect\([^)]*soPin[^)]*\)/);
    expect(content).toMatch(/manager\.Connect\([^)]*userPin[^)]*soPin[^)]*\)/);
  });

  test('pkcs11backend Config has SOPIN field', async () => {
    const content = fs.readFileSync(
      '/home/jhahn/sources/go-xkms/pkg/backend/pkcs11/config.go', 'utf8');
    expect(content).toMatch(/SOPIN\s+string/);
  });

  test('generateECDSAKeyPair uses WithSOSession when YubiKey PIV', async () => {
    const content = fs.readFileSync(
      '/home/jhahn/sources/go-xkms/pkg/backend/pkcs11/signer_ecdsa.go', 'utf8');
    expect(content).toMatch(/isYubiKeyPIV[\s\S]{0,500}WithSOSession/);
  });

  test('generateRSAKeyPair uses WithSOSession when YubiKey PIV', async () => {
    const content = fs.readFileSync(
      '/home/jhahn/sources/go-xkms/pkg/backend/pkcs11/signer_rsa.go', 'utf8');
    expect(content).toMatch(/isYubiKeyPIV[\s\S]{0,500}WithSOSession/);
  });

  test('TestConnection retains module registration for reuse', async () => {
    const content = fs.readFileSync(
      '/home/jhahn/sources/go-xkms/xkey/pkg/gui/services/pkcs11_service.go', 'utf8');
    expect(content).toMatch(/testedModules\s+map\[string\]string/);
    expect(content).toMatch(/testedModules\[libraryPath\]\s*=\s*moduleID/);
  });
});
