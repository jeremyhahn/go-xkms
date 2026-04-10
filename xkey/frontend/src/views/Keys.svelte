<script lang="ts">
  import { onMount } from 'svelte';
  import GradientHeader from '$lib/components/GradientHeader.svelte';
  import Card from '$lib/components/Card.svelte';
  import Button from '$lib/components/Button.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import EmptyState from '$lib/components/EmptyState.svelte';
  import DataTable from '$lib/components/DataTable.svelte';
  import Modal from '$lib/components/Modal.svelte';
  import { getBackendLabel, getBackendIcon, isHardwareBackend } from '$lib/utils/backends';
  import {
    mdiKey, mdiPlus, mdiShieldCheckOutline,
    mdiDelete, mdiExport, mdiFingerprint, mdiRefresh,
    mdiFilter, mdiShieldHalfFull, mdiLockOutline,
    mdiLockOpen, mdiCheckCircle, mdiCloseCircle, mdiDotsVertical,
    mdiSwapHorizontal, mdiContentCopy, mdiDownload, mdiFolderOpen,
    mdiContentSave, mdiAlertCircle
  } from '$lib/utils/icons';
  import {
    textToBase64, base64ToText, base64ToHex, hexToBase64, copyToClipboard
  } from '$lib/utils/encoding';
  import { addNotification } from '$lib/stores/notifications';
  import { isWailsAvailable, callBackend, callBackendVoid } from '$lib/api/backend';
  import type {
    RemoteKeyInfo, RemoteBackendInfo, GenerateKeyParams,
    GenerateKeyResult, AttestKeyResult, BackendCapabilities
  } from '$lib/api/backend';

  let keys: RemoteKeyInfo[] = [];
  let backends: RemoteBackendInfo[] = [];
  let selectedBackend = 'all';
  let selectedKeyType = 'all';
  let loading = false;
  let selectedKeyIds = new Set<string>();

  // Generate Key dialog state
  let showGenerateDialog = false;
  let generateBackend = '';
  let generateKeyId = '';
  let generatePurpose = 'SIGNING';
  let generateAlgorithm = 'ecdsa';
  let generateKeySize = 256;
  let generateCurve = 'P-256';
  let generateExportable = false;
  let generateHierarchy: string = 'owner';
  let generateIsPrimary: boolean = false;
  let generateHandle: number = 0;
  let generateParentHandle: number = 0;
  let generating = false;

  // Kebab menu state
  let openMenuKeyId: string | null = null;

  // Sign/Verify dialog state
  let showSignDialog = false;
  let signKeyBackend = '';
  let signKeyId = '';
  let signData = '';
  let signHashAlgo = 'SHA-256';
  let signResult = '';
  let signing = false;
  let signInputMode: 'text' | 'file' = 'text';
  let signFilePath = '';
  let signOutputEncoding: 'base64' | 'hex' = 'base64';
  let showVerifyDialog = false;
  let verifyData = '';
  let verifySignature = '';
  let verifyHashAlgo = 'SHA-256';
  let verifyKeyBackend = '';
  let verifyKeyId = '';
  let verifyResult: boolean | null = null;
  let verifying = false;
  let verifyInputMode: 'text' | 'file' = 'text';
  let verifyDataFilePath = '';
  let verifySigFilePath = '';
  let verifySigEncoding: 'base64' | 'hex' = 'base64';

  // Encrypt/Decrypt dialog state
  let showEncryptDialog = false;
  let encryptKeyBackend = '';
  let encryptKeyId = '';
  let encryptPlaintext = '';
  let encryptResult = '';
  let encrypting = false;
  let encryptInputMode: 'text' | 'file' = 'text';
  let encryptFilePath = '';
  let encryptOutputEncoding: 'base64' | 'hex' = 'base64';
  let showDecryptDialog = false;
  let decryptKeyBackend = '';
  let decryptKeyId = '';
  let decryptCiphertext = '';
  let decryptResult = '';
  let decrypting = false;
  let decryptInputMode: 'text' | 'file' = 'text';
  let decryptFilePath = '';
  let decryptInputEncoding: 'base64' | 'hex' = 'base64';

  // Attestation dialog state
  let showAttestDialog = false;
  let attestKeyBackend = '';
  let attestKeyId = '';
  let attestNonce = '';
  let attestResult: AttestKeyResult | null = null;
  let attesting = false;

  // Export dialog state
  let showExportDialog = false;
  let exportKeyBackend = '';
  let exportKeyId = '';
  let exportFormat = 'pkcs8';
  let exportResult = '';
  let exporting = false;

  // Delete confirmation dialog state
  let showDeleteConfirmDialog = false;
  let deleteTargetBackend = '';
  let deleteTargetKeyId = '';


  const keySizeOptions: Record<string, number[]> = {
    rsa: [2048, 3072, 4096],
    ecdsa: [256, 384, 521],
    ed25519: [256],
    'aes128-gcm': [128],
    'aes192-gcm': [192],
    'aes256-gcm': [256],
    'chacha20-poly1305': [256],
    'xchacha20-poly1305': [256],
  };

  const curveOptions: Record<number, string> = {
    256: 'P-256',
    384: 'P-384',
    521: 'P-521',
  };

  const hashAlgorithms = ['SHA-256', 'SHA-384', 'SHA-512'];

  // Key purpose definitions
  interface KeyPurpose {
    value: string;
    label: string;
    desc: string;
  }
  const basePurposes: KeyPurpose[] = [
    { value: 'SIGNING', label: 'Signing', desc: 'Digital signatures' },
    { value: 'ENCRYPTION', label: 'Encryption', desc: 'Data encryption / key agreement' },
    { value: 'TLS', label: 'TLS', desc: 'TLS server/client certificates' },
    { value: 'CA', label: 'Certificate Authority', desc: 'Issue and sign certificates' },
    { value: 'SECRET', label: 'Secret (Symmetric)', desc: 'Symmetric encryption keys' },
    { value: 'HMAC', label: 'HMAC', desc: 'Message authentication codes' },
  ];

  interface AlgorithmOption {
    value: string;
    label: string;
    sizes?: number[];
  }

  function getAlgorithmsForPurpose(purpose: string, caps?: BackendCapabilities): AlgorithmOption[] {
    if (purpose === 'SECRET') {
      return [
        { value: 'aes128-gcm', label: 'AES-128-GCM', sizes: [128] },
        { value: 'aes192-gcm', label: 'AES-192-GCM', sizes: [192] },
        { value: 'aes256-gcm', label: 'AES-256-GCM', sizes: [256] },
        { value: 'chacha20-poly1305', label: 'ChaCha20-Poly1305', sizes: [256] },
        { value: 'xchacha20-poly1305', label: 'XChaCha20-Poly1305', sizes: [256] },
      ];
    }
    if (purpose === 'HMAC') {
      return [
        { value: 'hmac-sha256', label: 'HMAC-SHA256', sizes: [256] },
        { value: 'hmac-sha384', label: 'HMAC-SHA384', sizes: [384] },
        { value: 'hmac-sha512', label: 'HMAC-SHA512', sizes: [512] },
      ];
    }
    const algos: AlgorithmOption[] = [
      { value: 'ecdsa', label: 'ECDSA', sizes: [256, 384, 521] },
      { value: 'rsa', label: 'RSA', sizes: [2048, 3072, 4096] },
      { value: 'ed25519', label: 'Ed25519' },
    ];
    if (purpose === 'ENCRYPTION') {
      algos.push({ value: 'x25519', label: 'X25519 (Key Agreement)' });
    }
    if (caps?.QuantumSigning && purpose === 'SIGNING') {
      algos.push(
        { value: 'ml-dsa-44', label: 'ML-DSA-44' },
        { value: 'ml-dsa-65', label: 'ML-DSA-65' },
        { value: 'ml-dsa-87', label: 'ML-DSA-87' },
      );
    }
    if (caps?.KeyEncapsulation && purpose === 'ENCRYPTION') {
      algos.push(
        { value: 'ml-kem-512', label: 'ML-KEM-512' },
        { value: 'ml-kem-768', label: 'ML-KEM-768' },
        { value: 'ml-kem-1024', label: 'ML-KEM-1024' },
      );
    }
    return algos;
  }

  // Build capabilities map for quick lookup by backend ID
  $: backendCaps = new Map<string, BackendCapabilities>(backends.map(b => [b.id, b.capabilities]));

  // Available purposes: add ATTESTATION when selected backend supports it
  $: availablePurposes = (() => {
    const caps = backends.find(b => b.id === generateBackend)?.capabilities;
    const list = [...basePurposes];
    if (caps?.Attestation) {
      list.push({ value: 'ATTESTATION', label: 'Attestation', desc: 'Hardware attestation key' });
    }
    return list;
  })();

  // Available algorithms based on selected purpose and backend
  $: availableAlgorithms = (() => {
    const caps = backends.find(b => b.id === generateBackend)?.capabilities;
    return getAlgorithmsForPurpose(generatePurpose, caps);
  })();

  // Server's Backends() returns only full-service backends (excludes partial key providers)
  $: keyProviders = backends;

  // Kebab menu helpers
  interface MenuItem {
    id: string;
    label: string;
    icon: string;
    danger?: boolean;
    divider?: boolean;
  }

  function getKeyOps(key: RemoteKeyInfo): MenuItem[] {
    const caps = backendCaps.get(key.backend);
    if (!caps) return [{ id: 'delete', label: 'Delete', icon: mdiDelete, danger: true }];
    const ops: MenuItem[] = [];
    if (caps.Signing) {
      ops.push({ id: 'sign', label: 'Sign', icon: mdiFingerprint });
      ops.push({ id: 'verify', label: 'Verify', icon: mdiShieldCheckOutline });
    }
    if (caps.Decryption) {
      ops.push({ id: 'encrypt', label: 'Encrypt', icon: mdiLockOutline });
      ops.push({ id: 'decrypt', label: 'Decrypt', icon: mdiLockOpen });
    }
    if (caps.Attestation && caps.HardwareBacked) {
      ops.push({ id: 'attest', label: 'Attest', icon: mdiShieldHalfFull });
    }
    if (caps.Export) {
      ops.push({ id: 'export', label: 'Export', icon: mdiExport });
    }
    if (caps.KeyRotation) {
      ops.push({ id: 'rotate', label: 'Rotate', icon: mdiSwapHorizontal });
    }
    ops.push({ id: 'divider', label: '', icon: '', divider: true });
    ops.push({ id: 'delete', label: 'Delete', icon: mdiDelete, danger: true });
    return ops;
  }

  function toggleKeyMenu(keyId: string): void {
    openMenuKeyId = openMenuKeyId === keyId ? null : keyId;
  }

  function closeKeyMenu(): void {
    openMenuKeyId = null;
  }

  function handleWindowClick(e: MouseEvent): void {
    if (openMenuKeyId) {
      const target = e.target as HTMLElement;
      if (!target.closest('.menu-wrapper')) {
        openMenuKeyId = null;
      }
    }
  }

  function handleMenuAction(key: RemoteKeyInfo, actionId: string): void {
    closeKeyMenu();
    switch (actionId) {
      case 'sign': openSignDialog(key); break;
      case 'verify': openVerifyDialog(key); break;
      case 'encrypt': openEncryptDialog(key); break;
      case 'decrypt': openDecryptDialog(key); break;
      case 'attest': openAttestDialog(key); break;
      case 'export': openExportDialog(key); break;
      case 'rotate': handleRotate(key); break;
      case 'delete': openDeleteConfirm(key); break;
    }
  }

  // Purpose label for key card display
  function getPurposeLabel(key: RemoteKeyInfo): string {
    const t = key.key_type?.toUpperCase();
    const purposeNames = ['SIGNING', 'ENCRYPTION', 'CA', 'TLS', 'SECRET', 'HMAC', 'ATTESTATION'];
    if (purposeNames.includes(t)) return t;
    if (['RSA', 'ECDSA', 'ED25519', 'X25519'].includes(t)) return 'Asymmetric';
    if (['AES', 'AES128-GCM', 'AES192-GCM', 'AES256-GCM', 'CHACHA20-POLY1305', 'XCHACHA20-POLY1305'].includes(t)) return 'Symmetric';
    if (['HMAC-SHA256', 'HMAC-SHA384', 'HMAC-SHA512'].includes(t)) return 'HMAC';
    return t || 'Unknown';
  }

  $: filteredKeys = keys.filter((k) => {
    if (selectedBackend !== 'all' && k.backend !== selectedBackend) return false;
    if (selectedKeyType !== 'all' && k.key_type !== selectedKeyType) return false;
    return true;
  });

  // Dynamic key type filter chips from actual keys
  $: uniqueKeyTypes = [...new Set(keys.map(k => k.key_type))].sort();

  $: {
    const sizes = keySizeOptions[generateAlgorithm] ?? [];
    if (sizes.length > 0 && !sizes.includes(generateKeySize)) {
      generateKeySize = sizes[0];
    }
    if (generateAlgorithm === 'ecdsa') {
      generateCurve = curveOptions[generateKeySize] ?? 'P-256';
    }
  }

  // When purpose changes, reset algorithm to first available
  $: {
    const algos = availableAlgorithms;
    if (algos.length > 0 && !algos.find(a => a.value === generateAlgorithm)) {
      generateAlgorithm = algos[0].value;
    }
  }

  async function loadData(): Promise<void> {
    if (!isWailsAvailable()) return;
    loading = true;
    const [backendList, registeredList, keyList] = await Promise.all([
      callBackend<RemoteBackendInfo[]>('KeyService', 'ListBackends', 'local'),
      callBackend<RemoteBackendInfo[]>('KeyService', 'ListRegisteredBackends'),
      callBackend<RemoteKeyInfo[]>('KeyService', 'ListAllKeys', 'local'),
    ]);
    // Merge: start with registered (has all backends), overlay SDK data (has capabilities)
    const byId = new Map<string, RemoteBackendInfo>();
    for (const b of (registeredList ?? [])) byId.set(b.id, b);
    for (const b of (backendList ?? [])) {
      const existing = byId.get(b.id);
      if (existing) {
        byId.set(b.id, { ...existing, ...b });
      } else {
        byId.set(b.id, b);
      }
    }
    backends = Array.from(byId.values());
    keys = keyList ?? [];
    loading = false;
  }

  async function deleteKey(backend: string, keyId: string): Promise<void> {
    const ok = await callBackendVoid('KeyService', 'DeleteKey', 'local', backend, keyId);
    if (ok) {
      addNotification('success', `Key "${keyId}" deleted`);
      showDeleteConfirmDialog = false;
      await loadData();
    } else {
      addNotification('error', `Failed to delete key "${keyId}"`);
    }
  }

  function openDeleteConfirm(key: RemoteKeyInfo): void {
    deleteTargetBackend = key.backend;
    deleteTargetKeyId = key.key_id;
    showDeleteConfirmDialog = true;
  }

  async function handleGenerate(): Promise<void> {
    if (!generateKeyId.trim()) {
      addNotification('error', 'Key ID is required');
      return;
    }
    generating = true;
    const isTPM = generateBackend === 'tpm2' || keyProviders.find(b => b.id === generateBackend)?.type === 'tpm2';
    const params: GenerateKeyParams = {
      key_id: generateKeyId,
      backend: generateBackend,
      purpose: generatePurpose,
      algorithm: generateAlgorithm,
      exportable: generateExportable,
    };
    if (generateAlgorithm === 'rsa') {
      params.key_size = generateKeySize;
    }
    if (generateAlgorithm === 'ecdsa') {
      params.curve = generateCurve;
    }
    if (isTPM) {
      params.hierarchy = generateHierarchy;
      params.handle = generateHandle;
      params.is_primary = generateIsPrimary;
      params.parent_handle = generateParentHandle;
    }

    const result = await callBackend<GenerateKeyResult>('KeyService', 'GenerateKey', 'local', params);
    generating = false;

    if (result) {
      addNotification('success', `Key "${result.key_id}" generated successfully`);
      showGenerateDialog = false;
      resetGenerateForm();
      await loadData();
    } else {
      addNotification('error', 'Failed to generate key');
    }
  }

  function resetGenerateForm(): void {
    generateKeyId = '';
    generatePurpose = 'SIGNING';
    generateAlgorithm = 'ecdsa';
    generateKeySize = 256;
    generateCurve = 'P-256';
    generateExportable = false;
    generateHierarchy = 'owner';
    generateIsPrimary = false;
    generateHandle = 0;
    generateParentHandle = 0;
  }

  function openGenerateDialog(): void {
    resetGenerateForm();
    if (keyProviders.length > 0) {
      generateBackend = keyProviders[0].id;
    }
    showGenerateDialog = true;
  }

  function openSignDialog(key: RemoteKeyInfo): void {
    signKeyBackend = key.backend;
    signKeyId = key.key_id;
    signData = '';
    signHashAlgo = 'SHA-256';
    signResult = '';
    signInputMode = 'text';
    signFilePath = '';
    signOutputEncoding = 'base64';
    showSignDialog = true;
  }

  async function handleSign(): Promise<void> {
    signing = true;
    if (signInputMode === 'file') {
      if (!signFilePath) {
        addNotification('error', 'Select a file to sign');
        signing = false;
        return;
      }
      const outPath = await callBackend<string>('KeyService', 'SaveFileAs', 'signature.sig');
      if (!outPath) { signing = false; return; }
      const ok = await callBackendVoid(
        'KeyService', 'SignFile', 'local', signKeyBackend, signKeyId,
        signHashAlgo, signFilePath, outPath, signOutputEncoding
      );
      signing = false;
      if (ok) {
        addNotification('success', 'File signed successfully');
      } else {
        addNotification('error', 'File signing failed');
      }
    } else {
      if (!signData.trim()) {
        addNotification('error', 'Data to sign is required');
        signing = false;
        return;
      }
      const b64Data = textToBase64(signData);
      const result = await callBackend<string>(
        'KeyService', 'SignData', 'local', signKeyBackend, signKeyId, signHashAlgo, b64Data
      );
      signing = false;
      if (result !== null) {
        signResult = signOutputEncoding === 'hex' ? base64ToHex(result) : result;
        addNotification('success', 'Data signed successfully');
      } else {
        addNotification('error', 'Signing failed');
      }
    }
  }

  async function browseSignFile(): Promise<void> {
    const path = await callBackend<string>('KeyService', 'BrowseFile');
    if (path) signFilePath = path;
  }

  function openVerifyDialog(key: RemoteKeyInfo): void {
    verifyKeyBackend = key.backend;
    verifyKeyId = key.key_id;
    verifyData = '';
    verifySignature = '';
    verifyHashAlgo = 'SHA-256';
    verifyResult = null;
    verifyInputMode = 'text';
    verifyDataFilePath = '';
    verifySigFilePath = '';
    verifySigEncoding = 'base64';
    showVerifyDialog = true;
  }

  async function handleVerify(): Promise<void> {
    verifying = true;
    if (verifyInputMode === 'file') {
      if (!verifyDataFilePath || !verifySigFilePath) {
        addNotification('error', 'Select both data file and signature file');
        verifying = false;
        return;
      }
      const result = await callBackend<boolean>(
        'KeyService', 'VerifyFileSignature', 'local', verifyKeyBackend, verifyKeyId,
        verifyHashAlgo, verifyDataFilePath, verifySigFilePath, verifySigEncoding
      );
      verifying = false;
      if (result !== null) {
        verifyResult = result;
        addNotification(result ? 'success' : 'warning', result ? 'Signature is valid' : 'Signature is invalid');
      } else {
        addNotification('error', 'Verification failed');
      }
    } else {
      if (!verifyData.trim() || !verifySignature.trim()) {
        addNotification('error', 'Data and signature are required');
        verifying = false;
        return;
      }
      const b64Data = textToBase64(verifyData);
      const sigB64 = verifySigEncoding === 'hex' ? hexToBase64(verifySignature) : verifySignature;
      const result = await callBackend<boolean>(
        'KeyService', 'VerifySignature', 'local', verifyKeyBackend, verifyKeyId, verifyHashAlgo, b64Data, sigB64
      );
      verifying = false;
      if (result !== null) {
        verifyResult = result;
        addNotification(result ? 'success' : 'warning', result ? 'Signature is valid' : 'Signature is invalid');
      } else {
        addNotification('error', 'Verification failed');
      }
    }
  }

  async function browseVerifyDataFile(): Promise<void> {
    const path = await callBackend<string>('KeyService', 'BrowseFile');
    if (path) verifyDataFilePath = path;
  }

  async function browseVerifySigFile(): Promise<void> {
    const path = await callBackend<string>('KeyService', 'BrowseFile');
    if (path) verifySigFilePath = path;
  }

  function openEncryptDialog(key: RemoteKeyInfo): void {
    encryptKeyBackend = key.backend;
    encryptKeyId = key.key_id;
    encryptPlaintext = '';
    encryptResult = '';
    encryptInputMode = 'text';
    encryptFilePath = '';
    encryptOutputEncoding = 'base64';
    showEncryptDialog = true;
  }

  async function handleEncrypt(): Promise<void> {
    encrypting = true;
    if (encryptInputMode === 'file') {
      if (!encryptFilePath) {
        addNotification('error', 'Select a file to encrypt');
        encrypting = false;
        return;
      }
      const outPath = await callBackend<string>('KeyService', 'SaveFileAs', 'encrypted.enc');
      if (!outPath) { encrypting = false; return; }
      const ok = await callBackendVoid(
        'KeyService', 'EncryptFile', 'local', encryptKeyBackend, encryptKeyId,
        encryptFilePath, outPath, encryptOutputEncoding
      );
      encrypting = false;
      if (ok) {
        addNotification('success', 'File encrypted successfully');
      } else {
        addNotification('error', 'File encryption failed');
      }
    } else {
      if (!encryptPlaintext.trim()) {
        addNotification('error', 'Plaintext data is required');
        encrypting = false;
        return;
      }
      const b64Input = textToBase64(encryptPlaintext);
      const result = await callBackend<string>(
        'KeyService', 'EncryptData', 'local', encryptKeyBackend, encryptKeyId, '', b64Input
      );
      encrypting = false;
      if (result !== null) {
        encryptResult = encryptOutputEncoding === 'hex' ? base64ToHex(result) : result;
        addNotification('success', 'Data encrypted successfully');
      } else {
        addNotification('error', 'Encryption failed');
      }
    }
  }

  async function browseEncryptFile(): Promise<void> {
    const path = await callBackend<string>('KeyService', 'BrowseFile');
    if (path) encryptFilePath = path;
  }

  function openDecryptDialog(key: RemoteKeyInfo): void {
    decryptKeyBackend = key.backend;
    decryptKeyId = key.key_id;
    decryptCiphertext = '';
    decryptResult = '';
    decryptInputMode = 'text';
    decryptFilePath = '';
    decryptInputEncoding = 'base64';
    showDecryptDialog = true;
  }

  async function handleDecrypt(): Promise<void> {
    decrypting = true;
    if (decryptInputMode === 'file') {
      if (!decryptFilePath) {
        addNotification('error', 'Select a file to decrypt');
        decrypting = false;
        return;
      }
      const outPath = await callBackend<string>('KeyService', 'SaveFileAs', 'decrypted.bin');
      if (!outPath) { decrypting = false; return; }
      const ok = await callBackendVoid(
        'KeyService', 'DecryptFile', 'local', decryptKeyBackend, decryptKeyId,
        decryptFilePath, outPath, decryptInputEncoding
      );
      decrypting = false;
      if (ok) {
        addNotification('success', 'File decrypted successfully');
      } else {
        addNotification('error', 'File decryption failed');
      }
    } else {
      if (!decryptCiphertext.trim()) {
        addNotification('error', 'Ciphertext is required');
        decrypting = false;
        return;
      }
      const ciphertextB64 = decryptInputEncoding === 'hex' ? hexToBase64(decryptCiphertext) : decryptCiphertext;
      const result = await callBackend<string>(
        'KeyService', 'DecryptData', 'local', decryptKeyBackend, decryptKeyId, '', ciphertextB64
      );
      decrypting = false;
      if (result !== null) {
        decryptResult = base64ToText(result);
        addNotification('success', 'Data decrypted successfully');
      } else {
        addNotification('error', 'Decryption failed');
      }
    }
  }

  async function browseDecryptFile(): Promise<void> {
    const path = await callBackend<string>('KeyService', 'BrowseFile');
    if (path) decryptFilePath = path;
  }

  function openAttestDialog(key: RemoteKeyInfo): void {
    attestKeyBackend = key.backend;
    attestKeyId = key.key_id;
    attestNonce = '';
    attestResult = null;
    showAttestDialog = true;
  }

  async function handleAttest(): Promise<void> {
    attesting = true;
    const result = await callBackend<AttestKeyResult>(
      'KeyService', 'AttestKey', 'local', attestKeyBackend, attestKeyId, attestNonce
    );
    attesting = false;
    if (result) {
      attestResult = result;
      addNotification('success', 'Attestation retrieved successfully');
    } else {
      addNotification('error', 'Attestation failed');
    }
  }

  function openExportDialog(key: RemoteKeyInfo): void {
    exportKeyBackend = key.backend;
    exportKeyId = key.key_id;
    exportFormat = 'pkcs8';
    exportResult = '';
    showExportDialog = true;
  }

  async function handleExport(): Promise<void> {
    exporting = true;
    const result = await callBackend<string>(
      'KeyService', 'ExportKey', 'local', exportKeyBackend, exportKeyId, exportFormat
    );
    exporting = false;
    if (result !== null) {
      exportResult = result;
      addNotification('success', 'Key exported successfully');
    } else {
      addNotification('error', 'Export failed');
    }
  }

  async function saveExportToFile(): Promise<void> {
    const outPath = await callBackend<string>('KeyService', 'SaveFileAs', `${exportKeyId}.key`);
    if (!outPath) return;
    // Write via backend since we need file system access
    addNotification('info', 'Use the copy button and save manually');
  }

  async function handleRotate(key: RemoteKeyInfo): Promise<void> {
    const result = await callBackend<RemoteKeyInfo>(
      'KeyService', 'RotateKey', 'local', key.backend, key.key_id
    );
    if (result) {
      addNotification('success', `Key "${key.key_id}" rotated successfully`);
      await loadData();
    } else {
      addNotification('error', 'Key rotation failed');
    }
  }

  async function handleCopy(text: string, label: string): Promise<void> {
    const ok = await copyToClipboard(text);
    if (ok) {
      addNotification('success', `${label} copied to clipboard`);
    } else {
      addNotification('error', 'Failed to copy to clipboard');
    }
  }

  async function handleBulkDeleteKeys(): Promise<void> {
    const ids = Array.from(selectedKeyIds);
    for (const keyId of ids) {
      const key = keys.find(k => k.key_id === keyId);
      if (key) {
        await callBackendVoid('KeyService', 'DeleteKey', 'local', key.backend, key.key_id);
      }
    }
    selectedKeyIds = new Set();
    addNotification('success', `Deleted ${ids.length} key(s)`);
    await loadData();
  }

  onMount(() => {
    loadData();
  });
</script>

<svelte:window on:click={handleWindowClick} />

<div class="keys-view">
  <GradientHeader
    title="Key Management"
    subtitle="Local key operations"
  />

  <div class="keys-content">
    <!-- Summary -->
      <div class="summary-row">
        <Card variant="elevated">
          <div class="summary-card">
            <span class="text-display-small summary-count">{keys.length}</span>
            <span class="text-label-large summary-label">Total Keys</span>
          </div>
        </Card>
        <Card variant="elevated">
          <div class="summary-card">
            <span class="text-display-small summary-count">{backends.length}</span>
            <span class="text-label-large summary-label">Backends</span>
          </div>
        </Card>
        <Card variant="elevated">
          <div class="summary-card action-card">
            <Button variant="primary" icon={mdiPlus} on:click={openGenerateDialog}>
              Generate Key
            </Button>
          </div>
        </Card>
      </div>

      <!-- Filters -->
      <div class="filter-bar">
        <Icon path={mdiFilter} size={18} />
        <button class="filter-chip" class:active={selectedBackend === 'all'} on:click={() => (selectedBackend = 'all')}>
          All Backends
        </button>
        {#each backends as b}
          <button class="filter-chip" class:active={selectedBackend === b.id} on:click={() => (selectedBackend = b.id)}>
            {b.id}
          </button>
        {/each}
        <span class="filter-sep">|</span>
        <button class="filter-chip" class:active={selectedKeyType === 'all'} on:click={() => (selectedKeyType = 'all')}>
          All Types
        </button>
        {#each uniqueKeyTypes as kt}
          <button class="filter-chip" class:active={selectedKeyType === kt} on:click={() => (selectedKeyType = kt)}>
            {kt.toUpperCase()}
          </button>
        {/each}
        <div class="filter-spacer"></div>
        {#if selectedKeyIds.size > 0}
          <Button variant="outline" icon={mdiDelete} size="sm" on:click={handleBulkDeleteKeys}>
            Delete ({selectedKeyIds.size})
          </Button>
        {/if}
        <Button variant="outline" icon={mdiRefresh} size="sm" on:click={loadData}>Refresh</Button>
      </div>

      <!-- Key Table -->
      <DataTable
        columns={[
          { key: 'key_id', label: 'Key ID', sortable: true },
          { key: 'backend', label: 'Backend', width: '120px', sortable: true },
          { key: 'key_type', label: 'Purpose', width: '120px', sortable: true },
          { key: 'algorithm', label: 'Algorithm', width: '150px', sortable: true },
        ]}
        rows={filteredKeys}
        rowKey="key_id"
        selectable={true}
        bind:selectedIds={selectedKeyIds}
        emptyIcon={mdiKey}
        emptyTitle="No Keys Found"
        emptyDescription={loading ? 'Loading keys...' : 'Generate or import a key to get started.'}
        loading={loading}
        pageSize={25}
        on:rowdblclick={(e) => {/* future: open key detail */}}
      >
        <svelte:fragment slot="cell" let:row let:column let:value>
          {#if column.key === 'key_id'}
            <div class="key-id-cell">
              <Icon path={getBackendIcon(row.backend)} size={16} />
              <span class="text-body-medium">{value}</span>
            </div>
          {:else if column.key === 'backend'}
            <span class="backend-badge" class:backend-hw={isHardwareBackend(row.backend)} class:backend-sw={!isHardwareBackend(row.backend)}>
              {#if isHardwareBackend(row.backend)}
                <Icon path={getBackendIcon(row.backend)} size={14} />
              {/if}
              {getBackendLabel(row.backend)}
            </span>
          {:else if column.key === 'key_type'}
            <span class="purpose-badge">{getPurposeLabel(row)}</span>
          {:else if column.key === 'algorithm'}
            <span class="algo-text">{value || row.key_type}</span>
          {:else}
            {value ?? ''}
          {/if}
        </svelte:fragment>
        <svelte:fragment slot="actions" let:row>
          <div class="menu-wrapper">
            <button class="action-btn" on:click|stopPropagation={() => toggleKeyMenu(row.key_id)} title="Actions">
              <Icon path={mdiDotsVertical} size={18} />
            </button>
            {#if openMenuKeyId === row.key_id}
              <div class="menu-dropdown">
                {#each getKeyOps(row) as op}
                  {#if op.divider}
                    <div class="menu-divider"></div>
                  {:else}
                    <button
                      class="menu-item"
                      class:menu-item-danger={op.danger}
                      on:click={() => handleMenuAction(row, op.id)}
                    >
                      <Icon path={op.icon} size={16} />
                      <span>{op.label}</span>
                    </button>
                  {/if}
                {/each}
              </div>
            {/if}
          </div>
        </svelte:fragment>
      </DataTable>
  </div>
</div>

<!-- Generate Key Dialog -->
<Modal bind:open={showGenerateDialog} title="Generate Key" maxWidth="520px">
  <div class="dialog-form">
    <div class="form-field">
      <label class="text-label-large" for="gen-backend">Backend</label>
      <select id="gen-backend" class="form-select" bind:value={generateBackend}>
        {#each keyProviders as b}
          <option value={b.id}>{getBackendLabel(b.type) || getBackendLabel(b.id)}</option>
        {/each}
      </select>
    </div>
    <div class="form-field">
      <label class="text-label-large" for="gen-key-id">Key ID</label>
      <input id="gen-key-id" class="form-input" type="text" placeholder="my-signing-key" bind:value={generateKeyId} />
    </div>
    <div class="form-field">
      <label class="text-label-large" for="gen-purpose">Key Purpose</label>
      <select id="gen-purpose" class="form-select" bind:value={generatePurpose}>
        {#each availablePurposes as p}
          <option value={p.value} title={p.desc}>{p.label}</option>
        {/each}
      </select>
      <span class="text-body-small form-hint">
        {availablePurposes.find(p => p.value === generatePurpose)?.desc ?? ''}
      </span>
    </div>
    <div class="form-field">
      <label class="text-label-large" for="gen-algorithm">Algorithm</label>
      <select id="gen-algorithm" class="form-select" bind:value={generateAlgorithm}>
        {#each availableAlgorithms as algo}
          <option value={algo.value}>{algo.label}</option>
        {/each}
      </select>
    </div>
    {#if (keySizeOptions[generateAlgorithm] ?? []).length > 1}
      <div class="form-field">
        <label class="text-label-large" for="gen-key-size">
          {generateAlgorithm === 'ecdsa' ? 'Curve' : 'Key Size'}
        </label>
        <select id="gen-key-size" class="form-select" bind:value={generateKeySize}>
          {#each (keySizeOptions[generateAlgorithm] ?? []) as size}
            <option value={size}>
              {#if generateAlgorithm === 'ecdsa'}
                {curveOptions[size] ?? `${size}-bit`}
              {:else}
                {size}-bit
              {/if}
            </option>
          {/each}
        </select>
      </div>
    {/if}
    <div class="form-field form-field-inline">
      <label class="form-toggle-label">
        <input type="checkbox" class="form-checkbox" bind:checked={generateExportable} />
        <span class="text-label-large">Exportable</span>
      </label>
      <span class="text-body-small form-hint">Allow the private key to be exported</span>
    </div>

    {#if generateBackend === 'tpm2' || (keyProviders.find(b => b.id === generateBackend)?.type === 'tpm2')}
      <div class="form-field">
        <label class="text-label-large" for="gen-hierarchy">Hierarchy</label>
        <select id="gen-hierarchy" class="form-select" bind:value={generateHierarchy}>
          <option value="owner">Owner (Storage)</option>
          <option value="endorsement">Endorsement</option>
          <option value="platform">Platform</option>
          <option value="null">Null</option>
        </select>
      </div>

      <div class="form-field">
        <span class="text-label-large">Key Type</span>
        <div class="radio-group">
          <label class="radio-label">
            <input type="radio" bind:group={generateIsPrimary} value={false} />
            <span>Child Key (under SRK)</span>
          </label>
          <label class="radio-label">
            <input type="radio" bind:group={generateIsPrimary} value={true} />
            <span>Primary Key</span>
          </label>
        </div>
      </div>

      <div class="form-field">
        <label class="text-label-large" for="gen-handle">Handle (0 = auto-allocate)</label>
        <input id="gen-handle" type="number" class="form-input" bind:value={generateHandle} min="0" />
      </div>

      {#if !generateIsPrimary}
        <div class="form-field">
          <label class="text-label-large" for="gen-parent">Parent Handle (0 = default SRK)</label>
          <input id="gen-parent" type="number" class="form-input" bind:value={generateParentHandle} min="0" />
        </div>
      {/if}
    {/if}
  </div>
  <svelte:fragment slot="actions">
    <Button variant="text" on:click={() => (showGenerateDialog = false)} disabled={generating}>Cancel</Button>
    <Button
      variant="primary"
      loading={generating}
      on:click={handleGenerate}
      disabled={!generateKeyId.trim()}
    >
      Generate
    </Button>
  </svelte:fragment>
</Modal>

<!-- Sign Dialog -->
<Modal bind:open={showSignDialog} title="Sign Data" maxWidth="560px">
  <div class="dialog-form">
    <div class="dialog-key-info">
      <span class="text-label-small">Key:</span>
      <span class="text-body-medium font-mono">{signKeyId}</span>
      <span class="text-label-small key-backend-badge">{signKeyBackend}</span>
    </div>
    <div class="form-field">
      <label class="text-label-large" for="sign-hash">Hash Algorithm</label>
      <select id="sign-hash" class="form-select" bind:value={signHashAlgo}>
        {#each hashAlgorithms as algo}
          <option value={algo}>{algo}</option>
        {/each}
      </select>
    </div>
    <div class="form-field">
      <span class="text-label-large">Input Mode</span>
      <div class="mode-toggle">
        <button class="mode-btn" class:active={signInputMode === 'text'} on:click={() => (signInputMode = 'text')}>Text</button>
        <button class="mode-btn" class:active={signInputMode === 'file'} on:click={() => (signInputMode = 'file')}>File</button>
      </div>
    </div>
    {#if signInputMode === 'text'}
      <div class="form-field">
        <label class="text-label-large" for="sign-data">Data</label>
        <textarea id="sign-data" class="form-textarea" rows="4" placeholder="Enter text data to sign..." bind:value={signData}></textarea>
      </div>
    {:else}
      <div class="form-field">
        <span class="text-label-large">File</span>
        <div class="file-browse">
          <span class="file-path">{signFilePath || 'No file selected'}</span>
          <Button variant="outline" size="sm" icon={mdiFolderOpen} on:click={browseSignFile}>Browse</Button>
        </div>
      </div>
    {/if}
    <div class="form-field">
      <span class="text-label-large">Output Encoding</span>
      <div class="mode-toggle">
        <button class="mode-btn" class:active={signOutputEncoding === 'base64'} on:click={() => (signOutputEncoding = 'base64')}>Base64</button>
        <button class="mode-btn" class:active={signOutputEncoding === 'hex'} on:click={() => (signOutputEncoding = 'hex')}>Hex</button>
      </div>
    </div>
    {#if signResult && signInputMode === 'text'}
      <div class="form-field">
        <div class="result-header">
          <span class="text-label-large">Signature</span>
          <button class="copy-btn" title="Copy" on:click={() => handleCopy(signResult, 'Signature')}>
            <Icon path={mdiContentCopy} size={16} />
          </button>
        </div>
        <textarea class="form-textarea result-output" rows="4" readonly value={signResult}></textarea>
      </div>
    {/if}
  </div>
  <svelte:fragment slot="actions">
    <Button variant="text" on:click={() => (showSignDialog = false)} disabled={signing}>Close</Button>
    <Button variant="primary" loading={signing} on:click={handleSign}
      disabled={signInputMode === 'text' ? !signData.trim() : !signFilePath}>Sign</Button>
  </svelte:fragment>
</Modal>

<!-- Verify Dialog -->
<Modal bind:open={showVerifyDialog} title="Verify Signature" maxWidth="560px">
  <div class="dialog-form">
    <div class="dialog-key-info">
      <span class="text-label-small">Key:</span>
      <span class="text-body-medium font-mono">{verifyKeyId}</span>
      <span class="text-label-small key-backend-badge">{verifyKeyBackend}</span>
    </div>
    <div class="form-field">
      <label class="text-label-large" for="verify-hash">Hash Algorithm</label>
      <select id="verify-hash" class="form-select" bind:value={verifyHashAlgo}>
        {#each hashAlgorithms as algo}
          <option value={algo}>{algo}</option>
        {/each}
      </select>
    </div>
    <div class="form-field">
      <span class="text-label-large">Input Mode</span>
      <div class="mode-toggle">
        <button class="mode-btn" class:active={verifyInputMode === 'text'} on:click={() => (verifyInputMode = 'text')}>Text</button>
        <button class="mode-btn" class:active={verifyInputMode === 'file'} on:click={() => (verifyInputMode = 'file')}>File</button>
      </div>
    </div>
    {#if verifyInputMode === 'text'}
      <div class="form-field">
        <label class="text-label-large" for="verify-data">Data</label>
        <textarea id="verify-data" class="form-textarea" rows="3" placeholder="Enter original text data..." bind:value={verifyData}></textarea>
      </div>
      <div class="form-field">
        <span class="text-label-large">Signature Encoding</span>
        <div class="mode-toggle">
          <button class="mode-btn" class:active={verifySigEncoding === 'base64'} on:click={() => (verifySigEncoding = 'base64')}>Base64</button>
          <button class="mode-btn" class:active={verifySigEncoding === 'hex'} on:click={() => (verifySigEncoding = 'hex')}>Hex</button>
        </div>
      </div>
      <div class="form-field">
        <label class="text-label-large" for="verify-sig">Signature ({verifySigEncoding === 'hex' ? 'Hex' : 'Base64'})</label>
        <textarea id="verify-sig" class="form-textarea" rows="3" placeholder="Paste signature..." bind:value={verifySignature}></textarea>
      </div>
    {:else}
      <div class="form-field">
        <span class="text-label-large">Data File</span>
        <div class="file-browse">
          <span class="file-path">{verifyDataFilePath || 'No file selected'}</span>
          <Button variant="outline" size="sm" icon={mdiFolderOpen} on:click={browseVerifyDataFile}>Browse</Button>
        </div>
      </div>
      <div class="form-field">
        <span class="text-label-large">Signature Encoding</span>
        <div class="mode-toggle">
          <button class="mode-btn" class:active={verifySigEncoding === 'base64'} on:click={() => (verifySigEncoding = 'base64')}>Base64</button>
          <button class="mode-btn" class:active={verifySigEncoding === 'hex'} on:click={() => (verifySigEncoding = 'hex')}>Hex</button>
        </div>
      </div>
      <div class="form-field">
        <span class="text-label-large">Signature File</span>
        <div class="file-browse">
          <span class="file-path">{verifySigFilePath || 'No file selected'}</span>
          <Button variant="outline" size="sm" icon={mdiFolderOpen} on:click={browseVerifySigFile}>Browse</Button>
        </div>
      </div>
    {/if}
    {#if verifyResult !== null}
      <div class="verify-result" class:verify-valid={verifyResult} class:verify-invalid={!verifyResult}>
        <Icon path={verifyResult ? mdiCheckCircle : mdiCloseCircle} size={20} />
        <span class="text-title-small">{verifyResult ? 'Signature is valid' : 'Signature is invalid'}</span>
      </div>
    {/if}
  </div>
  <svelte:fragment slot="actions">
    <Button variant="text" on:click={() => (showVerifyDialog = false)} disabled={verifying}>Close</Button>
    <Button
      variant="primary"
      loading={verifying}
      on:click={handleVerify}
      disabled={verifyInputMode === 'text' ? (!verifyData.trim() || !verifySignature.trim()) : (!verifyDataFilePath || !verifySigFilePath)}
    >
      Verify
    </Button>
  </svelte:fragment>
</Modal>

<!-- Encrypt Dialog -->
<Modal bind:open={showEncryptDialog} title="Encrypt Data" maxWidth="560px">
  <div class="dialog-form">
    <div class="dialog-key-info">
      <span class="text-label-small">Key:</span>
      <span class="text-body-medium font-mono">{encryptKeyId}</span>
      <span class="text-label-small key-backend-badge">{encryptKeyBackend}</span>
    </div>
    <div class="form-field">
      <span class="text-label-large">Input Mode</span>
      <div class="mode-toggle">
        <button class="mode-btn" class:active={encryptInputMode === 'text'} on:click={() => (encryptInputMode = 'text')}>Text</button>
        <button class="mode-btn" class:active={encryptInputMode === 'file'} on:click={() => (encryptInputMode = 'file')}>File</button>
      </div>
    </div>
    {#if encryptInputMode === 'text'}
      <div class="form-field">
        <label class="text-label-large" for="encrypt-data">Plaintext</label>
        <textarea id="encrypt-data" class="form-textarea" rows="4" placeholder="Enter text to encrypt..." bind:value={encryptPlaintext}></textarea>
      </div>
    {:else}
      <div class="form-field">
        <span class="text-label-large">File</span>
        <div class="file-browse">
          <span class="file-path">{encryptFilePath || 'No file selected'}</span>
          <Button variant="outline" size="sm" icon={mdiFolderOpen} on:click={browseEncryptFile}>Browse</Button>
        </div>
      </div>
    {/if}
    <div class="form-field">
      <span class="text-label-large">Output Encoding</span>
      <div class="mode-toggle">
        <button class="mode-btn" class:active={encryptOutputEncoding === 'base64'} on:click={() => (encryptOutputEncoding = 'base64')}>Base64</button>
        <button class="mode-btn" class:active={encryptOutputEncoding === 'hex'} on:click={() => (encryptOutputEncoding = 'hex')}>Hex</button>
      </div>
    </div>
    {#if encryptResult && encryptInputMode === 'text'}
      <div class="form-field">
        <div class="result-header">
          <span class="text-label-large">Ciphertext</span>
          <button class="copy-btn" title="Copy" on:click={() => handleCopy(encryptResult, 'Ciphertext')}>
            <Icon path={mdiContentCopy} size={16} />
          </button>
        </div>
        <textarea class="form-textarea result-output" rows="4" readonly value={encryptResult}></textarea>
      </div>
    {/if}
  </div>
  <svelte:fragment slot="actions">
    <Button variant="text" on:click={() => (showEncryptDialog = false)} disabled={encrypting}>Close</Button>
    <Button variant="primary" loading={encrypting} on:click={handleEncrypt}
      disabled={encryptInputMode === 'text' ? !encryptPlaintext.trim() : !encryptFilePath}>Encrypt</Button>
  </svelte:fragment>
</Modal>

<!-- Decrypt Dialog -->
<Modal bind:open={showDecryptDialog} title="Decrypt Data" maxWidth="560px">
  <div class="dialog-form">
    <div class="dialog-key-info">
      <span class="text-label-small">Key:</span>
      <span class="text-body-medium font-mono">{decryptKeyId}</span>
      <span class="text-label-small key-backend-badge">{decryptKeyBackend}</span>
    </div>
    <div class="form-field">
      <span class="text-label-large">Input Mode</span>
      <div class="mode-toggle">
        <button class="mode-btn" class:active={decryptInputMode === 'text'} on:click={() => (decryptInputMode = 'text')}>Text</button>
        <button class="mode-btn" class:active={decryptInputMode === 'file'} on:click={() => (decryptInputMode = 'file')}>File</button>
      </div>
    </div>
    <div class="form-field">
      <span class="text-label-large">Ciphertext Encoding</span>
      <div class="mode-toggle">
        <button class="mode-btn" class:active={decryptInputEncoding === 'base64'} on:click={() => (decryptInputEncoding = 'base64')}>Base64</button>
        <button class="mode-btn" class:active={decryptInputEncoding === 'hex'} on:click={() => (decryptInputEncoding = 'hex')}>Hex</button>
      </div>
    </div>
    {#if decryptInputMode === 'text'}
      <div class="form-field">
        <label class="text-label-large" for="decrypt-data">Ciphertext ({decryptInputEncoding === 'hex' ? 'Hex' : 'Base64'})</label>
        <textarea id="decrypt-data" class="form-textarea" rows="4" placeholder="Paste ciphertext..." bind:value={decryptCiphertext}></textarea>
      </div>
    {:else}
      <div class="form-field">
        <span class="text-label-large">File</span>
        <div class="file-browse">
          <span class="file-path">{decryptFilePath || 'No file selected'}</span>
          <Button variant="outline" size="sm" icon={mdiFolderOpen} on:click={browseDecryptFile}>Browse</Button>
        </div>
      </div>
    {/if}
    {#if decryptResult && decryptInputMode === 'text'}
      <div class="form-field">
        <div class="result-header">
          <span class="text-label-large">Plaintext</span>
          <button class="copy-btn" title="Copy" on:click={() => handleCopy(decryptResult, 'Plaintext')}>
            <Icon path={mdiContentCopy} size={16} />
          </button>
        </div>
        <textarea class="form-textarea result-output" rows="4" readonly value={decryptResult}></textarea>
      </div>
    {/if}
  </div>
  <svelte:fragment slot="actions">
    <Button variant="text" on:click={() => (showDecryptDialog = false)} disabled={decrypting}>Close</Button>
    <Button variant="primary" loading={decrypting} on:click={handleDecrypt}
      disabled={decryptInputMode === 'text' ? !decryptCiphertext.trim() : !decryptFilePath}>Decrypt</Button>
  </svelte:fragment>
</Modal>

<!-- Attestation Dialog -->
<Modal bind:open={showAttestDialog} title="Key Attestation" maxWidth="640px">
  <div class="dialog-form">
    <div class="dialog-key-info">
      <span class="text-label-small">Key:</span>
      <span class="text-body-medium font-mono">{attestKeyId}</span>
      <span class="text-label-small key-backend-badge">{attestKeyBackend}</span>
      <span class="hw-badge hw-badge-hardware">Hardware</span>
    </div>
    <div class="form-field">
      <label class="text-label-large" for="attest-nonce">Nonce (optional, Base64)</label>
      <input id="attest-nonce" class="form-input" type="text" placeholder="Optional challenge nonce..." bind:value={attestNonce} />
    </div>
    {#if attestResult}
      <div class="attest-results">
        <div class="attest-field">
          <span class="text-label-small field-label">Format</span>
          <span class="text-body-medium">{attestResult.format}</span>
        </div>
        <div class="attest-field">
          <div class="result-header">
            <span class="text-label-small field-label">Attestation Data</span>
            <button class="copy-btn" title="Copy" on:click={() => handleCopy(attestResult?.attestation_data ?? '', 'Attestation data')}>
              <Icon path={mdiContentCopy} size={14} />
            </button>
          </div>
          <textarea class="form-textarea result-output" rows="3" readonly value={attestResult.attestation_data}></textarea>
        </div>
        <div class="attest-field">
          <div class="result-header">
            <span class="text-label-small field-label">Signature</span>
            <button class="copy-btn" title="Copy" on:click={() => handleCopy(attestResult?.signature ?? '', 'Signature')}>
              <Icon path={mdiContentCopy} size={14} />
            </button>
          </div>
          <textarea class="form-textarea result-output" rows="2" readonly value={attestResult.signature}></textarea>
        </div>
        {#if attestResult.certificate_chain && attestResult.certificate_chain.length > 0}
          <div class="attest-field">
            <span class="text-label-small field-label">Certificate Chain ({attestResult.certificate_chain.length} certificates)</span>
            {#each attestResult.certificate_chain as cert, i}
              <div class="chain-cert">
                <div class="result-header">
                  <span class="text-label-small chain-label">Certificate {i + 1}</span>
                  <button class="copy-btn" title="Copy" on:click={() => handleCopy(cert, `Certificate ${i + 1}`)}>
                    <Icon path={mdiContentCopy} size={14} />
                  </button>
                </div>
                <textarea class="form-textarea result-output chain-textarea" rows="3" readonly value={cert}></textarea>
              </div>
            {/each}
          </div>
        {/if}
      </div>
    {/if}
  </div>
  <svelte:fragment slot="actions">
    <Button variant="text" on:click={() => (showAttestDialog = false)} disabled={attesting}>Close</Button>
    <Button variant="primary" loading={attesting} on:click={handleAttest}>
      {attestResult ? 'Re-attest' : 'Attest'}
    </Button>
  </svelte:fragment>
</Modal>

<!-- Export Dialog -->
<Modal bind:open={showExportDialog} title="Export Key" maxWidth="560px">
  <div class="dialog-form">
    <div class="dialog-key-info">
      <span class="text-label-small">Key:</span>
      <span class="text-body-medium font-mono">{exportKeyId}</span>
      <span class="text-label-small key-backend-badge">{exportKeyBackend}</span>
    </div>
    <div class="form-field">
      <label class="text-label-large" for="export-format">Format</label>
      <select id="export-format" class="form-select" bind:value={exportFormat}>
        <option value="pkcs8">PKCS#8</option>
        <option value="raw">Raw</option>
      </select>
    </div>
    {#if exportResult}
      <div class="form-field">
        <div class="result-header">
          <span class="text-label-large">Exported Key Material</span>
          <button class="copy-btn" title="Copy" on:click={() => handleCopy(exportResult, 'Key material')}>
            <Icon path={mdiContentCopy} size={16} />
          </button>
        </div>
        <textarea class="form-textarea result-output mono-result" rows="6" readonly value={exportResult}></textarea>
      </div>
    {/if}
  </div>
  <svelte:fragment slot="actions">
    <Button variant="text" on:click={() => (showExportDialog = false)} disabled={exporting}>Close</Button>
    <Button variant="primary" loading={exporting} on:click={handleExport}>
      {exportResult ? 'Re-export' : 'Export'}
    </Button>
  </svelte:fragment>
</Modal>

<!-- Delete Confirmation Dialog -->
<Modal bind:open={showDeleteConfirmDialog} title="Delete Key" maxWidth="440px">
  <div class="dialog-form">
    <div class="delete-confirm-body">
      <Icon path={mdiAlertCircle} size={40} color="var(--color-error)" />
      <p class="text-body-large">Are you sure you want to delete this key?</p>
      <div class="dialog-key-info">
        <span class="text-label-small">Key:</span>
        <span class="text-body-medium font-mono">{deleteTargetKeyId}</span>
        <span class="text-label-small key-backend-badge">{deleteTargetBackend}</span>
      </div>
      <p class="text-body-small delete-warning">This action cannot be undone. The key and all associated data will be permanently removed.</p>
    </div>
  </div>
  <svelte:fragment slot="actions">
    <Button variant="text" on:click={() => (showDeleteConfirmDialog = false)}>Cancel</Button>
    <Button variant="danger" on:click={() => deleteKey(deleteTargetBackend, deleteTargetKeyId)}>Delete</Button>
  </svelte:fragment>
</Modal>

<style>
  .keys-view {
    height: 100%;
    display: flex;
    flex-direction: column;
  }

  .keys-content {
    flex: 1;
    overflow-y: auto;
    padding: 24px;
    display: flex;
    flex-direction: column;
    gap: 20px;
  }

  .summary-row {
    display: grid;
    grid-template-columns: 1fr 1fr 1fr;
    gap: 16px;
  }

  .summary-card {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 4px;
    padding: 8px 0;
  }

  .summary-count {
    color: var(--color-primary);
    font-weight: 600;
  }

  .summary-label {
    color: var(--color-on-surface-variant);
  }

  .action-card {
    justify-content: center;
  }

  .filter-bar {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
    color: var(--color-on-surface-variant);
  }

  .filter-chip {
    padding: 6px 14px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-full);
    background: transparent;
    color: var(--color-on-surface-variant);
    cursor: pointer;
    font-family: var(--font-sans);
    font-size: 13px;
    transition: all var(--transition-fast);
  }

  .filter-chip:hover {
    background-color: var(--color-surface-container);
  }

  .filter-chip.active {
    background-color: var(--color-primary-95);
    color: var(--color-primary);
    border-color: var(--color-primary);
    font-weight: 600;
  }

  :global([data-theme="dark"]) .filter-chip.active {
    background-color: var(--color-primary-container);
    color: var(--color-on-primary-container);
  }

  .filter-sep {
    color: var(--color-outline-variant);
    margin: 0 4px;
  }

  .filter-spacer {
    flex: 1;
  }

  /* DataTable cell styles */
  .key-id-cell {
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }

  .backend-badge {
    display: inline-flex;
    align-items: center;
    gap: 0.25rem;
    padding: 0.125rem 0.5rem;
    border-radius: 99px;
    font-size: 0.75rem;
    font-weight: 500;
  }

  .backend-hw {
    background: var(--md-sys-color-tertiary-container);
    color: var(--md-sys-color-on-tertiary-container);
  }

  .backend-sw {
    background: var(--md-sys-color-surface-container-highest);
    color: var(--md-sys-color-on-surface-variant);
  }

  .purpose-badge {
    display: inline-flex;
    align-items: center;
    padding: 2px 8px;
    border-radius: var(--radius-full);
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.3px;
    white-space: nowrap;
    background-color: var(--color-primary-95);
    color: var(--color-primary);
    text-transform: uppercase;
  }

  :global([data-theme="dark"]) .purpose-badge {
    background-color: var(--color-primary-container);
    color: var(--color-on-primary-container);
  }

  .algo-text {
    font-family: var(--font-mono);
    font-size: 0.8125rem;
  }

  .action-btn {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 32px;
    height: 32px;
    border: none;
    border-radius: var(--radius-full);
    background: transparent;
    color: var(--color-on-surface-variant);
    cursor: pointer;
    transition: background-color var(--transition-fast);
  }

  .action-btn:hover {
    background-color: var(--color-surface-container);
  }

  .key-backend-badge {
    padding: 3px 10px;
    border-radius: var(--radius-full);
    background-color: var(--color-surface-container-high);
    color: var(--color-on-surface-variant);
    text-transform: uppercase;
    letter-spacing: 0.5px;
    font-family: var(--font-mono);
  }

  .hw-badge {
    display: inline-flex;
    align-items: center;
    padding: 2px 8px;
    border-radius: var(--radius-full);
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.3px;
    white-space: nowrap;
  }

  .hw-badge-hardware {
    background-color: #d4edda;
    color: #155724;
  }

  :global([data-theme="dark"]) .hw-badge-hardware {
    background-color: rgba(21, 87, 36, 0.3);
    color: #a3d9a5;
  }

  /* Kebab context menu */
  .menu-wrapper {
    position: relative;
    margin-left: auto;
  }

  .menu-dropdown {
    position: absolute;
    top: 100%;
    right: 0;
    z-index: 50;
    min-width: 180px;
    margin-top: 4px;
    padding: 4px 0;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-md);
    background-color: var(--color-surface-container-low);
    box-shadow: var(--shadow-2);
  }

  .menu-item {
    display: flex;
    align-items: center;
    gap: 10px;
    width: 100%;
    padding: 8px 14px;
    border: none;
    background: transparent;
    color: var(--color-on-surface);
    font-family: var(--font-sans);
    font-size: 13px;
    cursor: pointer;
    transition: background-color var(--transition-fast);
    text-align: left;
  }

  .menu-item:hover {
    background-color: var(--color-surface-container);
  }

  .menu-item-danger {
    color: var(--color-error);
  }

  .menu-item-danger:hover {
    background-color: var(--color-error-container);
  }

  .menu-divider {
    height: 1px;
    margin: 4px 0;
    background-color: var(--color-outline-variant);
  }

  /* Dialog form styles */
  .dialog-form {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  .dialog-key-info {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 10px 14px;
    border-radius: var(--radius-sm);
    background-color: var(--color-surface-container-low);
    flex-wrap: wrap;
  }

  .form-field {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .form-field label {
    color: var(--color-on-surface-variant);
  }

  .form-field-inline {
    gap: 4px;
  }

  .form-toggle-label {
    display: flex;
    align-items: center;
    gap: 8px;
    cursor: pointer;
  }

  .form-checkbox {
    width: 18px;
    height: 18px;
    accent-color: var(--color-primary);
    cursor: pointer;
  }

  .form-hint {
    color: var(--color-on-surface-variant);
    opacity: 0.7;
    margin-left: 26px;
  }

  .form-input {
    padding: 10px 12px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-sm);
    background: var(--color-surface);
    color: var(--color-on-surface);
    font-family: var(--font-sans);
    font-size: 14px;
    outline: none;
    transition: border-color var(--transition-fast);
  }

  .form-input:focus {
    border-color: var(--color-primary);
  }

  .form-select {
    padding: 10px 12px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-sm);
    background: var(--color-surface);
    color: var(--color-on-surface);
    font-family: var(--font-sans);
    font-size: 14px;
    outline: none;
    cursor: pointer;
    transition: border-color var(--transition-fast);
  }

  .form-select:focus {
    border-color: var(--color-primary);
  }

  .form-textarea {
    padding: 10px 12px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-sm);
    background: var(--color-surface);
    color: var(--color-on-surface);
    font-family: var(--font-mono, monospace);
    font-size: 13px;
    outline: none;
    resize: vertical;
    transition: border-color var(--transition-fast);
  }

  .form-textarea:focus {
    border-color: var(--color-primary);
  }

  .result-output {
    background-color: var(--color-surface-container-low);
    cursor: text;
    font-size: 12px;
  }

  /* Verify result indicator */
  .verify-result {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 12px 16px;
    border-radius: var(--radius-sm);
  }

  .verify-valid {
    background-color: #d4edda;
    color: #155724;
  }

  :global([data-theme="dark"]) .verify-valid {
    background-color: rgba(21, 87, 36, 0.3);
    color: #a3d9a5;
  }

  .verify-invalid {
    background-color: var(--color-error-container);
    color: var(--color-error);
  }

  /* Attestation results */
  .attest-results {
    display: flex;
    flex-direction: column;
    gap: 12px;
    padding-top: 8px;
    border-top: 1px solid var(--color-outline-variant);
  }

  .attest-field {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .field-label {
    color: var(--color-on-surface-variant);
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .chain-cert {
    display: flex;
    flex-direction: column;
    gap: 4px;
    margin-top: 4px;
  }

  .chain-label {
    color: var(--color-on-surface-variant);
    font-weight: 600;
  }

  .chain-textarea {
    font-size: 11px;
  }

  /* Mode toggle (text/file, base64/hex) */
  .mode-toggle {
    display: flex;
    gap: 0;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-sm);
    overflow: hidden;
    width: fit-content;
  }

  .mode-btn {
    padding: 6px 16px;
    border: none;
    background: transparent;
    color: var(--color-on-surface-variant);
    font-family: var(--font-sans);
    font-size: 13px;
    font-weight: 500;
    cursor: pointer;
    transition: all var(--transition-fast);
  }

  .mode-btn + .mode-btn {
    border-left: 1px solid var(--color-outline-variant);
  }

  .mode-btn.active {
    background-color: var(--color-primary);
    color: var(--color-on-primary);
  }

  /* File browse row */
  .file-browse {
    display: flex;
    align-items: center;
    gap: 10px;
  }

  .file-path {
    flex: 1;
    padding: 8px 12px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-sm);
    background: var(--color-surface-container-low);
    color: var(--color-on-surface-variant);
    font-family: var(--font-mono);
    font-size: 12px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  /* Result header with copy button */
  .result-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
  }

  .copy-btn {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 28px;
    height: 28px;
    border: none;
    border-radius: var(--radius-full);
    background: transparent;
    color: var(--color-on-surface-variant);
    cursor: pointer;
    transition: background-color var(--transition-fast);
  }

  .copy-btn:hover {
    background-color: var(--color-surface-container);
  }

  /* Monospace result for export */
  .mono-result {
    font-family: var(--font-mono, monospace);
    font-size: 11px;
    word-break: break-all;
  }

  /* Delete confirmation */
  .delete-confirm-body {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 12px;
    text-align: center;
    padding: 8px 0;
  }

  .delete-warning {
    color: var(--color-error);
    margin: 0;
  }

  @media (max-width: 900px) {
    .summary-row {
      grid-template-columns: 1fr 1fr;
    }
  }
</style>
