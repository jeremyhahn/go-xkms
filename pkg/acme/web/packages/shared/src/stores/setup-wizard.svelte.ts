/**
 * Copyright (C) 2024 Trusted CA Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0, or alternatively, under the terms of the
 * GNU Affero General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any
 * later version. A commercial license is available from the authors.
 *
 * First-run setup wizard state store.
 *
 * Implements a linear step-based state machine for initializing a new
 * go-trusted-ca server. Steps proceed in a fixed sequence:
 * barrier → ca → summary → creating → complete
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** All possible step identifiers in the setup wizard. */
export type SetupWizardStep =
  | 'barrier'
  | 'ca'
  | 'summary'
  | 'creating'
  | 'complete';

/** Barrier strategy options. */
export type BarrierStrategy = 'none' | 'software' | 'shamir';

/** Shape of the reactive setup wizard state. */
export interface SetupWizardState {
  /** Current active step in the wizard flow. */
  currentStep: SetupWizardStep;

  // Barrier configuration
  /** Encryption barrier strategy. */
  barrierStrategy: BarrierStrategy;
  /** Passphrase for the software barrier strategy. */
  barrierSecret: string;
  /** Passphrase confirmation (validated client-side only). */
  barrierSecretConfirm: string;
  /** Minimum shares required to reconstruct the secret (M). */
  shamirThreshold: number;
  /** Total number of shares to generate (N). */
  shamirTotal: number;

  // CA configuration
  /** Common name for the root Certificate Authority. */
  rootCAName: string;
  /** Common name for the intermediate Certificate Authority. */
  intermediateCAName: string;
  /** Key algorithm used when generating CA key pairs. */
  keyAlgorithm: string;
  /** Validity period in years for the issued CA certificates. */
  validityYears: number;

  // CA subject fields
  /** Organization name for the CA subject. */
  organization: string;
  /** Organizational unit for the CA subject. */
  organizationalUnit: string;
  /** Two-letter ISO country code for the CA subject. */
  country: string;
  /** State or province for the CA subject. */
  state: string;
  /** Locality or city for the CA subject. */
  locality: string;

  // Results
  /** Shamir shares returned by the server after barrier initialization. */
  shamirShares: string[];
}

// ---------------------------------------------------------------------------
// Step sequence
// ---------------------------------------------------------------------------

/** Fixed step sequence for the setup wizard. */
const setupSteps: readonly SetupWizardStep[] = [
  'barrier',
  'ca',
  'summary',
  'creating',
  'complete',
] as const;

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

/** Reactive setup wizard state singleton. */
export const setupWizardStore: SetupWizardState = $state({
  currentStep: 'barrier',

  barrierStrategy: 'none',
  barrierSecret: '',
  barrierSecretConfirm: '',
  shamirThreshold: 3,
  shamirTotal: 5,

  rootCAName: 'Trusted ACME Root CA',
  intermediateCAName: 'Trusted ACME Intermediate CA',
  keyAlgorithm: 'ECDSA',
  validityYears: 10,

  organization: '',
  organizationalUnit: '',
  country: '',
  state: '',
  locality: '',

  shamirShares: [],
});

// ---------------------------------------------------------------------------
// Mutations
// ---------------------------------------------------------------------------

/**
 * nextStep advances the wizard to the next step in the fixed sequence.
 * No-op when already on the final step.
 */
export function nextStep(): void {
  const currentIndex = setupSteps.indexOf(setupWizardStore.currentStep);
  if (currentIndex === -1 || currentIndex >= setupSteps.length - 1) {
    return;
  }
  const next = setupSteps[currentIndex + 1];
  if (next !== undefined) {
    setupWizardStore.currentStep = next;
  }
}

/**
 * prevStep moves the wizard back to the previous step in the fixed sequence.
 * No-op when already on the first step.
 */
export function prevStep(): void {
  const currentIndex = setupSteps.indexOf(setupWizardStore.currentStep);
  if (currentIndex <= 0) {
    return;
  }
  const prev = setupSteps[currentIndex - 1];
  if (prev !== undefined) {
    setupWizardStore.currentStep = prev;
  }
}

/**
 * resetSetupWizard resets the wizard to its initial state, clearing all
 * user-provided configuration values.
 */
export function resetSetupWizard(): void {
  setupWizardStore.currentStep = 'barrier';

  setupWizardStore.barrierStrategy = 'none';
  setupWizardStore.barrierSecret = '';
  setupWizardStore.barrierSecretConfirm = '';
  setupWizardStore.shamirThreshold = 3;
  setupWizardStore.shamirTotal = 5;

  setupWizardStore.rootCAName = 'Trusted ACME Root CA';
  setupWizardStore.intermediateCAName = 'Trusted ACME Intermediate CA';
  setupWizardStore.keyAlgorithm = 'ECDSA';
  setupWizardStore.validityYears = 10;

  setupWizardStore.organization = '';
  setupWizardStore.organizationalUnit = '';
  setupWizardStore.country = '';
  setupWizardStore.state = '';
  setupWizardStore.locality = '';

  setupWizardStore.shamirShares = [];
}
