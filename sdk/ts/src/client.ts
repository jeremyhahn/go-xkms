// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

import { resolveAuthPaths, type AuthPaths, type XkmsClientConfig } from './config.js';
import { HttpCore } from './http.js';
import { AuthClient } from './clients/auth.js';
import { BackendsClient } from './clients/backends.js';
import { CaClient } from './clients/ca.js';
import { CapabilitiesClient } from './clients/capabilities.js';
import { CertsClient } from './clients/certs.js';
import { CredentialsClient } from './clients/credentials.js';
import { FrostClient } from './clients/frost.js';
import { HealthClient } from './clients/health.js';
import { KeysClient } from './clients/keys.js';
import { OidcCredentialClient } from './clients/oidcCredential.js';
import { SigningKeyClient } from './clients/signingKey.js';
import { PasswordsClient } from './clients/passwords.js';
import { PinClient } from './clients/pin.js';
import { PivClient } from './clients/piv.js';
import { PlatformClient } from './clients/platform.js';
import { SealClient } from './clients/seal.js';
import { SshClient } from './clients/ssh.js';
import { TenantsClient } from './clients/tenants.js';
import { TpmPolicyClient } from './clients/tpmPolicy.js';
import { UsersClient } from './clients/users.js';

/**
 * XkmsClient is the full REST client facade for the xkms web UI: one shared
 * HTTP core (base URL, token provider, injectable fetch) composing every
 * domain client.
 */
export class XkmsClient {
  readonly http: HttpCore;
  readonly authPaths: AuthPaths;

  readonly health: HealthClient;
  readonly capabilities: CapabilitiesClient;
  readonly auth: AuthClient;
  readonly backends: BackendsClient;
  readonly keys: KeysClient;
  readonly certs: CertsClient;
  readonly seal: SealClient;
  readonly frost: FrostClient;
  readonly pin: PinClient;
  readonly piv: PivClient;
  readonly ca: CaClient;
  readonly tenants: TenantsClient;
  readonly passwords: PasswordsClient;
  readonly oidcCredentials: OidcCredentialClient;
  readonly signingKeys: SigningKeyClient;
  readonly platform: PlatformClient;
  readonly tpmPolicies: TpmPolicyClient;
  readonly credentials: CredentialsClient;
  readonly users: UsersClient;
  readonly ssh: SshClient;

  constructor(config: XkmsClientConfig) {
    this.http = new HttpCore(config);
    this.authPaths = resolveAuthPaths(config.authPaths);

    this.health = new HealthClient(this.http);
    this.capabilities = new CapabilitiesClient(this.http, this.authPaths);
    this.auth = new AuthClient(this.http, this.authPaths);
    this.backends = new BackendsClient(this.http);
    this.keys = new KeysClient(this.http);
    this.certs = new CertsClient(this.http);
    this.seal = new SealClient(this.http);
    this.frost = new FrostClient(this.http);
    this.pin = new PinClient(this.http);
    this.piv = new PivClient(this.http);
    this.ca = new CaClient(this.http);
    this.tenants = new TenantsClient(this.http);
    this.passwords = new PasswordsClient(this.http);
    this.oidcCredentials = new OidcCredentialClient(this.http);
    this.signingKeys = new SigningKeyClient(this.http);
    this.platform = new PlatformClient(this.http);
    this.tpmPolicies = new TpmPolicyClient(this.http);
    this.credentials = new CredentialsClient(this.http);
    this.users = new UsersClient(this.http);
    this.ssh = new SshClient(this.http);
  }
}

/** createClient constructs an XkmsClient from a config. */
export function createClient(config: XkmsClientConfig): XkmsClient {
  return new XkmsClient(config);
}
