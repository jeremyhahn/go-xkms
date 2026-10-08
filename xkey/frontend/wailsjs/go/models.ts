export namespace agent {
	
	export class EnrollmentService {
	
	
	    static createFrom(source: any = {}) {
	        return new EnrollmentService(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	
	    }
	}

}

export namespace authenticator {
	
	export class Authenticator {
	    // Go type: atomic
	    TamperDetected: any;
	
	    static createFrom(source: any = {}) {
	        return new Authenticator(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.TamperDetected = this.convertValues(source["TamperDetected"], null);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace autofill {
	
	export class AutoFillPolicy {
	    fill_mode: string;
	    totp_policy: string;
	    session_timeout_sec: number;
	    require_authentication: boolean;
	    allowed_domains: string[];
	    blocked_domains: string[];
	    max_fills_per_minute: number;
	    audit_enabled: boolean;
	
	    static createFrom(source: any = {}) {
	        return new AutoFillPolicy(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.fill_mode = source["fill_mode"];
	        this.totp_policy = source["totp_policy"];
	        this.session_timeout_sec = source["session_timeout_sec"];
	        this.require_authentication = source["require_authentication"];
	        this.allowed_domains = source["allowed_domains"];
	        this.blocked_domains = source["blocked_domains"];
	        this.max_fills_per_minute = source["max_fills_per_minute"];
	        this.audit_enabled = source["audit_enabled"];
	    }
	}

}

export namespace config {
	
	export class PolicySection {
	    min_pin_length: number;
	    pin_max_attempts: number;
	    require_so_pin: boolean;
	    require_user_pin: boolean;
	    require_encrypted_storage: boolean;
	    storage_type: string;
	    require_tpm: boolean;
	    platform_pcr_bank: string;
	    allowed_backends: string[];
	    default_backend: string;
	    fido2_always_uv: boolean;
	    fido2_require_user_presence: boolean;
	    fido2_user_intent_check: boolean;
	    attestation_mode: string;
	    allow_auto_unseal: boolean;
	    user_can_configure_auto_unseal: boolean;
	    user_can_configure_theme: boolean;
	    user_can_manage_trust_store: boolean;
	    user_can_view_audit_log: boolean;
	    user_can_manage_sealed_data: boolean;
	    user_can_change_own_pin: boolean;
	    api_explorer_enabled: boolean;
	    api_explorer_sandbox_policy: string;
	    developer_tools_enabled: boolean;
	    user_can_toggle_dev_tools: boolean;
	    extension_enabled: boolean;
	    extension_require_authentication: boolean;
	    extension_require_pairing: boolean;
	    extension_force_audit: boolean;
	    extension_allowed_domains: string[];
	    extension_blocked_domains: string[];
	    extension_max_fills_per_minute: number;
	    user_can_configure_extension: boolean;
	    pairing_allow_unattestable_devices: boolean;
	    lock_pairing_attestation_policy: boolean;
	    pairing_allowed_applications: pairing.AllowedApplication[];
	    pairing_allow_unpinned_signatures: boolean;
	    lock_pairing_application_policy: boolean;
	    phone_sync_allow_secret_export: boolean;
	    lock_phone_sync_policy: boolean;
	    organization_name: string;
	    policy_version: number;
	
	    static createFrom(source: any = {}) {
	        return new PolicySection(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.min_pin_length = source["min_pin_length"];
	        this.pin_max_attempts = source["pin_max_attempts"];
	        this.require_so_pin = source["require_so_pin"];
	        this.require_user_pin = source["require_user_pin"];
	        this.require_encrypted_storage = source["require_encrypted_storage"];
	        this.storage_type = source["storage_type"];
	        this.require_tpm = source["require_tpm"];
	        this.platform_pcr_bank = source["platform_pcr_bank"];
	        this.allowed_backends = source["allowed_backends"];
	        this.default_backend = source["default_backend"];
	        this.fido2_always_uv = source["fido2_always_uv"];
	        this.fido2_require_user_presence = source["fido2_require_user_presence"];
	        this.fido2_user_intent_check = source["fido2_user_intent_check"];
	        this.attestation_mode = source["attestation_mode"];
	        this.allow_auto_unseal = source["allow_auto_unseal"];
	        this.user_can_configure_auto_unseal = source["user_can_configure_auto_unseal"];
	        this.user_can_configure_theme = source["user_can_configure_theme"];
	        this.user_can_manage_trust_store = source["user_can_manage_trust_store"];
	        this.user_can_view_audit_log = source["user_can_view_audit_log"];
	        this.user_can_manage_sealed_data = source["user_can_manage_sealed_data"];
	        this.user_can_change_own_pin = source["user_can_change_own_pin"];
	        this.api_explorer_enabled = source["api_explorer_enabled"];
	        this.api_explorer_sandbox_policy = source["api_explorer_sandbox_policy"];
	        this.developer_tools_enabled = source["developer_tools_enabled"];
	        this.user_can_toggle_dev_tools = source["user_can_toggle_dev_tools"];
	        this.extension_enabled = source["extension_enabled"];
	        this.extension_require_authentication = source["extension_require_authentication"];
	        this.extension_require_pairing = source["extension_require_pairing"];
	        this.extension_force_audit = source["extension_force_audit"];
	        this.extension_allowed_domains = source["extension_allowed_domains"];
	        this.extension_blocked_domains = source["extension_blocked_domains"];
	        this.extension_max_fills_per_minute = source["extension_max_fills_per_minute"];
	        this.user_can_configure_extension = source["user_can_configure_extension"];
	        this.pairing_allow_unattestable_devices = source["pairing_allow_unattestable_devices"];
	        this.lock_pairing_attestation_policy = source["lock_pairing_attestation_policy"];
	        this.pairing_allowed_applications = this.convertValues(source["pairing_allowed_applications"], pairing.AllowedApplication);
	        this.pairing_allow_unpinned_signatures = source["pairing_allow_unpinned_signatures"];
	        this.lock_pairing_application_policy = source["lock_pairing_application_policy"];
	        this.phone_sync_allow_secret_export = source["phone_sync_allow_secret_export"];
	        this.lock_phone_sync_policy = source["lock_phone_sync_policy"];
	        this.organization_name = source["organization_name"];
	        this.policy_version = source["policy_version"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace events {
	
	export class Event {
	    type: string;
	    payload: any;
	    // Go type: time
	    time: any;
	
	    static createFrom(source: any = {}) {
	        return new Event(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.type = source["type"];
	        this.payload = source["payload"];
	        this.time = this.convertValues(source["time"], null);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace ipc {
	
	export class AutofillAssertion {
	    auth_data: string;
	    signature: string;
	    credential_id: string;
	    public_key?: string;
	
	    static createFrom(source: any = {}) {
	        return new AutofillAssertion(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.auth_data = source["auth_data"];
	        this.signature = source["signature"];
	        this.credential_id = source["credential_id"];
	        this.public_key = source["public_key"];
	    }
	}
	export class AutofillCredential {
	    id: string;
	    title: string;
	    username: string;
	    url: string;
	    has_totp: boolean;
	    totp_id?: string;
	
	    static createFrom(source: any = {}) {
	        return new AutofillCredential(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.title = source["title"];
	        this.username = source["username"];
	        this.url = source["url"];
	        this.has_totp = source["has_totp"];
	        this.totp_id = source["totp_id"];
	    }
	}
	export class AutofillFillResult {
	    username: string;
	    password: string;
	    assertion?: AutofillAssertion;
	
	    static createFrom(source: any = {}) {
	        return new AutofillFillResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.username = source["username"];
	        this.password = source["password"];
	        this.assertion = this.convertValues(source["assertion"], AutofillAssertion);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class AutofillPolicyResult {
	    fill_mode: string;
	    totp_policy: string;
	    session_timeout_sec: number;
	    require_authentication: boolean;
	    allowed_domains: string[];
	    blocked_domains: string[];
	    max_fills_per_minute: number;
	    audit_enabled: boolean;
	
	    static createFrom(source: any = {}) {
	        return new AutofillPolicyResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.fill_mode = source["fill_mode"];
	        this.totp_policy = source["totp_policy"];
	        this.session_timeout_sec = source["session_timeout_sec"];
	        this.require_authentication = source["require_authentication"];
	        this.allowed_domains = source["allowed_domains"];
	        this.blocked_domains = source["blocked_domains"];
	        this.max_fills_per_minute = source["max_fills_per_minute"];
	        this.audit_enabled = source["audit_enabled"];
	    }
	}
	export class AutofillStatus {
	    available: boolean;
	    app_locked: boolean;
	    fill_mode: string;
	    extension_enabled: boolean;
	
	    static createFrom(source: any = {}) {
	        return new AutofillStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.available = source["available"];
	        this.app_locked = source["app_locked"];
	        this.fill_mode = source["fill_mode"];
	        this.extension_enabled = source["extension_enabled"];
	    }
	}
	export class AutofillTOTP {
	    code: string;
	    time_left: number;
	    period: number;
	    account_id: string;
	    issuer: string;
	
	    static createFrom(source: any = {}) {
	        return new AutofillTOTP(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.code = source["code"];
	        this.time_left = source["time_left"];
	        this.period = source["period"];
	        this.account_id = source["account_id"];
	        this.issuer = source["issuer"];
	    }
	}
	export class AutofillResult {
	    credentials?: AutofillCredential[];
	    fill?: AutofillFillResult;
	    totp?: AutofillTOTP;
	    status?: AutofillStatus;
	    policy?: AutofillPolicyResult;
	    saved?: boolean;
	    exists?: boolean;
	
	    static createFrom(source: any = {}) {
	        return new AutofillResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.credentials = this.convertValues(source["credentials"], AutofillCredential);
	        this.fill = this.convertValues(source["fill"], AutofillFillResult);
	        this.totp = this.convertValues(source["totp"], AutofillTOTP);
	        this.status = this.convertValues(source["status"], AutofillStatus);
	        this.policy = this.convertValues(source["policy"], AutofillPolicyResult);
	        this.saved = source["saved"];
	        this.exists = source["exists"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	
	export class UnlockResult {
	    success: boolean;
	    error?: string;
	    unlocked?: string[];
	    still_locked?: string[];
	    remaining_attempts?: number;
	
	    static createFrom(source: any = {}) {
	        return new UnlockResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.success = source["success"];
	        this.error = source["error"];
	        this.unlocked = source["unlocked"];
	        this.still_locked = source["still_locked"];
	        this.remaining_attempts = source["remaining_attempts"];
	    }
	}

}

export namespace keybackend {
	
	export class CompositeBackend {
	
	
	    static createFrom(source: any = {}) {
	        return new CompositeBackend(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	
	    }
	}

}

export namespace localtpm {
	
	export class Policies {
	
	
	    static createFrom(source: any = {}) {
	        return new Policies(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	
	    }
	}

}

export namespace nativemsg {
	
	export class PairingVerifier {
	
	
	    static createFrom(source: any = {}) {
	        return new PairingVerifier(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	
	    }
	}

}

export namespace net {
	
	export class IPNet {
	    IP: number[];
	    Mask: number[];
	
	    static createFrom(source: any = {}) {
	        return new IPNet(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.IP = source["IP"];
	        this.Mask = source["Mask"];
	    }
	}

}

export namespace oidc {
	
	export class Callback {
	    Host: string;
	    Port: number;
	
	    static createFrom(source: any = {}) {
	        return new Callback(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Host = source["Host"];
	        this.Port = source["Port"];
	    }
	}
	export class Provider {
	    issuer: string;
	    authorization_endpoint: string;
	    token_endpoint: string;
	    userinfo_endpoint?: string;
	    jwks_uri: string;
	    registration_endpoint?: string;
	    revocation_endpoint?: string;
	    introspection_endpoint?: string;
	    end_session_endpoint?: string;
	    device_authorization_endpoint?: string;
	    scopes_supported?: string[];
	    response_types_supported?: string[];
	    response_modes_supported?: string[];
	    grant_types_supported?: string[];
	    subject_types_supported?: string[];
	    id_token_signing_alg_values_supported?: string[];
	    token_endpoint_auth_methods_supported?: string[];
	    code_challenge_methods_supported?: string[];
	    claims_supported?: string[];
	    dpop_signing_alg_values_supported?: string[];
	
	    static createFrom(source: any = {}) {
	        return new Provider(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.issuer = source["issuer"];
	        this.authorization_endpoint = source["authorization_endpoint"];
	        this.token_endpoint = source["token_endpoint"];
	        this.userinfo_endpoint = source["userinfo_endpoint"];
	        this.jwks_uri = source["jwks_uri"];
	        this.registration_endpoint = source["registration_endpoint"];
	        this.revocation_endpoint = source["revocation_endpoint"];
	        this.introspection_endpoint = source["introspection_endpoint"];
	        this.end_session_endpoint = source["end_session_endpoint"];
	        this.device_authorization_endpoint = source["device_authorization_endpoint"];
	        this.scopes_supported = source["scopes_supported"];
	        this.response_types_supported = source["response_types_supported"];
	        this.response_modes_supported = source["response_modes_supported"];
	        this.grant_types_supported = source["grant_types_supported"];
	        this.subject_types_supported = source["subject_types_supported"];
	        this.id_token_signing_alg_values_supported = source["id_token_signing_alg_values_supported"];
	        this.token_endpoint_auth_methods_supported = source["token_endpoint_auth_methods_supported"];
	        this.code_challenge_methods_supported = source["code_challenge_methods_supported"];
	        this.claims_supported = source["claims_supported"];
	        this.dpop_signing_alg_values_supported = source["dpop_signing_alg_values_supported"];
	    }
	}

}

export namespace pairing {
	
	export class AllowedApplication {
	    package_name: string;
	    signing_digests?: string[];
	
	    static createFrom(source: any = {}) {
	        return new AllowedApplication(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.package_name = source["package_name"];
	        this.signing_digests = source["signing_digests"];
	    }
	}
	export class ApplicationPolicy {
	    allowed_applications: AllowedApplication[];
	    allow_unpinned_signatures: boolean;
	
	    static createFrom(source: any = {}) {
	        return new ApplicationPolicy(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.allowed_applications = this.convertValues(source["allowed_applications"], AllowedApplication);
	        this.allow_unpinned_signatures = source["allow_unpinned_signatures"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class PairedDeviceAttestationPolicy {
	    enabled: boolean;
	    boot_hash: string;
	    boot_key_hash: string;
	    boot_state: string;
	    device_locked: boolean;
	    min_security_level: string;
	    // Go type: time
	    set_at: any;
	
	    static createFrom(source: any = {}) {
	        return new PairedDeviceAttestationPolicy(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.enabled = source["enabled"];
	        this.boot_hash = source["boot_hash"];
	        this.boot_key_hash = source["boot_key_hash"];
	        this.boot_state = source["boot_state"];
	        this.device_locked = source["device_locked"];
	        this.min_security_level = source["min_security_level"];
	        this.set_at = this.convertValues(source["set_at"], null);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace pin {
	
	export class LockoutStatus {
	    failed_attempts: number;
	    max_attempts: number;
	    is_locked: boolean;
	    // Go type: time
	    lockout_until?: any;
	    recovery_seconds: number;
	
	    static createFrom(source: any = {}) {
	        return new LockoutStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.failed_attempts = source["failed_attempts"];
	        this.max_attempts = source["max_attempts"];
	        this.is_locked = source["is_locked"];
	        this.lockout_until = this.convertValues(source["lockout_until"], null);
	        this.recovery_seconds = source["recovery_seconds"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class Service {
	
	
	    static createFrom(source: any = {}) {
	        return new Service(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	
	    }
	}

}

export namespace pkix {
	
	export class AttributeTypeAndValue {
	    Type: number[];
	    Value: any;
	
	    static createFrom(source: any = {}) {
	        return new AttributeTypeAndValue(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Type = source["Type"];
	        this.Value = source["Value"];
	    }
	}
	export class Extension {
	    Id: number[];
	    Critical: boolean;
	    Value: number[];
	
	    static createFrom(source: any = {}) {
	        return new Extension(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Id = source["Id"];
	        this.Critical = source["Critical"];
	        this.Value = source["Value"];
	    }
	}
	export class Name {
	    Country: string[];
	    Organization: string[];
	    OrganizationalUnit: string[];
	    Locality: string[];
	    Province: string[];
	    StreetAddress: string[];
	    PostalCode: string[];
	    SerialNumber: string;
	    CommonName: string;
	    Names: AttributeTypeAndValue[];
	    ExtraNames: AttributeTypeAndValue[];
	
	    static createFrom(source: any = {}) {
	        return new Name(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Country = source["Country"];
	        this.Organization = source["Organization"];
	        this.OrganizationalUnit = source["OrganizationalUnit"];
	        this.Locality = source["Locality"];
	        this.Province = source["Province"];
	        this.StreetAddress = source["StreetAddress"];
	        this.PostalCode = source["PostalCode"];
	        this.SerialNumber = source["SerialNumber"];
	        this.CommonName = source["CommonName"];
	        this.Names = this.convertValues(source["Names"], AttributeTypeAndValue);
	        this.ExtraNames = this.convertValues(source["ExtraNames"], AttributeTypeAndValue);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace seal {
	
	export class BarrierStatus {
	    sealed: boolean;
	    strategy: string;
	    hardware_backed: boolean;
	    // Go type: time
	    initialized_at: any;
	    shamir_threshold?: number;
	    shamir_total?: number;
	
	    static createFrom(source: any = {}) {
	        return new BarrierStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.sealed = source["sealed"];
	        this.strategy = source["strategy"];
	        this.hardware_backed = source["hardware_backed"];
	        this.initialized_at = this.convertValues(source["initialized_at"], null);
	        this.shamir_threshold = source["shamir_threshold"];
	        this.shamir_total = source["shamir_total"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class StorageBarrier {
	
	
	    static createFrom(source: any = {}) {
	        return new StorageBarrier(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	
	    }
	}

}

export namespace services {
	
	export class AddFactorRequest {
	    type: string;
	    label: string;
	    cert_pem?: string;
	    webauthn_response?: string;
	    piv_cert_pem?: string;
	    piv_slot?: string;
	
	    static createFrom(source: any = {}) {
	        return new AddFactorRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.type = source["type"];
	        this.label = source["label"];
	        this.cert_pem = source["cert_pem"];
	        this.webauthn_response = source["webauthn_response"];
	        this.piv_cert_pem = source["piv_cert_pem"];
	        this.piv_slot = source["piv_slot"];
	    }
	}
	export class AuthFactor {
	    id: string;
	    user_id: string;
	    type: string;
	    label: string;
	    metadata: Record<string, string>;
	    registered_at: string;
	    last_used_at?: string;
	    revoked_at?: string;
	    created_by: string;
	
	    static createFrom(source: any = {}) {
	        return new AuthFactor(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.user_id = source["user_id"];
	        this.type = source["type"];
	        this.label = source["label"];
	        this.metadata = source["metadata"];
	        this.registered_at = source["registered_at"];
	        this.last_used_at = source["last_used_at"];
	        this.revoked_at = source["revoked_at"];
	        this.created_by = source["created_by"];
	    }
	}
	export class AddFactorResponse {
	    factor: AuthFactor;
	
	    static createFrom(source: any = {}) {
	        return new AddFactorResponse(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.factor = this.convertValues(source["factor"], AuthFactor);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class AddPasswordParams {
	    name: string;
	    title: string;
	    username: string;
	    password: string;
	    url: string;
	    match_patterns?: string[];
	    notes: string;
	    folder_path: string;
	    expires_at: string;
	    read_only: boolean;
	
	    static createFrom(source: any = {}) {
	        return new AddPasswordParams(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.title = source["title"];
	        this.username = source["username"];
	        this.password = source["password"];
	        this.url = source["url"];
	        this.match_patterns = source["match_patterns"];
	        this.notes = source["notes"];
	        this.folder_path = source["folder_path"];
	        this.expires_at = source["expires_at"];
	        this.read_only = source["read_only"];
	    }
	}
	export class AdminService {
	
	
	    static createFrom(source: any = {}) {
	        return new AdminService(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	
	    }
	}
	export class AgentDeviceInfo {
	    id: string;
	    name: string;
	    address: string;
	    certificate_fingerprint: string;
	    enrolled_at: string;
	    last_seen: string;
	    status: string;
	    connected: boolean;
	
	    static createFrom(source: any = {}) {
	        return new AgentDeviceInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	        this.address = source["address"];
	        this.certificate_fingerprint = source["certificate_fingerprint"];
	        this.enrolled_at = source["enrolled_at"];
	        this.last_seen = source["last_seen"];
	        this.status = source["status"];
	        this.connected = source["connected"];
	    }
	}
	export class AgentServerStatus {
	    running: boolean;
	    listen_address: string;
	    connected_count: number;
	    enrolled_count: number;
	    enrollment_methods: string[];
	
	    static createFrom(source: any = {}) {
	        return new AgentServerStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.running = source["running"];
	        this.listen_address = source["listen_address"];
	        this.connected_count = source["connected_count"];
	        this.enrolled_count = source["enrolled_count"];
	        this.enrollment_methods = source["enrollment_methods"];
	    }
	}
	export class AppLockStatus {
	    is_locked: boolean;
	    auto_lock_minutes: number;
	    lock_on_screen_lock: boolean;
	
	    static createFrom(source: any = {}) {
	        return new AppLockStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.is_locked = source["is_locked"];
	        this.auto_lock_minutes = source["auto_lock_minutes"];
	        this.lock_on_screen_lock = source["lock_on_screen_lock"];
	    }
	}
	export class AppStatus {
	    version: string;
	    uptime: string;
	    phone_connected: boolean;
	    phone_device_name?: string;
	    key_count: number;
	    bridge_running: boolean;
	    platform: string;
	    go_version: string;
	    server_connected: boolean;
	    server_address?: string;
	    remote_key_count: number;
	    oath_account_count: number;
	    fido2_cred_count: number;
	    piv_cert_count: number;
	    tpm_available: boolean;
	    tpm_device_exists: boolean;
	    tpm_provisioned: boolean;
	    storage_encrypted: boolean;
	    storage_mounted: boolean;
	    mode: string;
	    sealed: boolean;
	    pin_configured: boolean;
	    pin_locked: boolean;
	    pin_strategy: string;
	    seal_strategy: string;
	    hardware_backed: boolean;
	
	    static createFrom(source: any = {}) {
	        return new AppStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.version = source["version"];
	        this.uptime = source["uptime"];
	        this.phone_connected = source["phone_connected"];
	        this.phone_device_name = source["phone_device_name"];
	        this.key_count = source["key_count"];
	        this.bridge_running = source["bridge_running"];
	        this.platform = source["platform"];
	        this.go_version = source["go_version"];
	        this.server_connected = source["server_connected"];
	        this.server_address = source["server_address"];
	        this.remote_key_count = source["remote_key_count"];
	        this.oath_account_count = source["oath_account_count"];
	        this.fido2_cred_count = source["fido2_cred_count"];
	        this.piv_cert_count = source["piv_cert_count"];
	        this.tpm_available = source["tpm_available"];
	        this.tpm_device_exists = source["tpm_device_exists"];
	        this.tpm_provisioned = source["tpm_provisioned"];
	        this.storage_encrypted = source["storage_encrypted"];
	        this.storage_mounted = source["storage_mounted"];
	        this.mode = source["mode"];
	        this.sealed = source["sealed"];
	        this.pin_configured = source["pin_configured"];
	        this.pin_locked = source["pin_locked"];
	        this.pin_strategy = source["pin_strategy"];
	        this.seal_strategy = source["seal_strategy"];
	        this.hardware_backed = source["hardware_backed"];
	    }
	}
	export class AttestCertInfo {
	    label: string;
	    subject: string;
	    issuer: string;
	    algorithm: string;
	    public_key_fp: string;
	    cert_fp: string;
	    not_before: string;
	    not_after: string;
	    is_ca: boolean;
	    is_trust_anchor: boolean;
	
	    static createFrom(source: any = {}) {
	        return new AttestCertInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.label = source["label"];
	        this.subject = source["subject"];
	        this.issuer = source["issuer"];
	        this.algorithm = source["algorithm"];
	        this.public_key_fp = source["public_key_fp"];
	        this.cert_fp = source["cert_fp"];
	        this.not_before = source["not_before"];
	        this.not_after = source["not_after"];
	        this.is_ca = source["is_ca"];
	        this.is_trust_anchor = source["is_trust_anchor"];
	    }
	}
	export class AttestKeyResult {
	    format: string;
	    certificate_chain: string[];
	    attestation_data: string;
	    signature: string;
	
	    static createFrom(source: any = {}) {
	        return new AttestKeyResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.format = source["format"];
	        this.certificate_chain = source["certificate_chain"];
	        this.attestation_data = source["attestation_data"];
	        this.signature = source["signature"];
	    }
	}
	export class AttestationResult {
	    device_name: string;
	    verified: boolean;
	    chain_length: number;
	    // Go type: time
	    attest_time: any;
	    error_message?: string;
	    security_level: string;
	    boot_state: string;
	    boot_hash: string;
	    boot_key_hash: string;
	    device_locked: boolean;
	    key_algorithm: string;
	    key_size: number;
	    key_purposes: string[];
	    key_origin: string;
	    attest_version: number;
	    keymaster_version: number;
	    keymaster_security: string;
	    certificates: AttestCertInfo[];
	    trust_anchor_subject?: string;
	    trust_anchor_fingerprint?: string;
	
	    static createFrom(source: any = {}) {
	        return new AttestationResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.device_name = source["device_name"];
	        this.verified = source["verified"];
	        this.chain_length = source["chain_length"];
	        this.attest_time = this.convertValues(source["attest_time"], null);
	        this.error_message = source["error_message"];
	        this.security_level = source["security_level"];
	        this.boot_state = source["boot_state"];
	        this.boot_hash = source["boot_hash"];
	        this.boot_key_hash = source["boot_key_hash"];
	        this.device_locked = source["device_locked"];
	        this.key_algorithm = source["key_algorithm"];
	        this.key_size = source["key_size"];
	        this.key_purposes = source["key_purposes"];
	        this.key_origin = source["key_origin"];
	        this.attest_version = source["attest_version"];
	        this.keymaster_version = source["keymaster_version"];
	        this.keymaster_security = source["keymaster_security"];
	        this.certificates = this.convertValues(source["certificates"], AttestCertInfo);
	        this.trust_anchor_subject = source["trust_anchor_subject"];
	        this.trust_anchor_fingerprint = source["trust_anchor_fingerprint"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class AuditEntry {
	    // Go type: time
	    timestamp: any;
	    operation: string;
	    backend: string;
	    key_id: string;
	    device_id: string;
	    device_name: string;
	    success: boolean;
	    error?: string;
	    duration_ms: number;
	    details?: Record<string, any>;
	
	    static createFrom(source: any = {}) {
	        return new AuditEntry(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.timestamp = this.convertValues(source["timestamp"], null);
	        this.operation = source["operation"];
	        this.backend = source["backend"];
	        this.key_id = source["key_id"];
	        this.device_id = source["device_id"];
	        this.device_name = source["device_name"];
	        this.success = source["success"];
	        this.error = source["error"];
	        this.duration_ms = source["duration_ms"];
	        this.details = source["details"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class AuditFilter {
	    operation?: string;
	    backend?: string;
	    key_id?: string;
	    device_id?: string;
	    success?: boolean;
	    // Go type: time
	    since?: any;
	    // Go type: time
	    until?: any;
	    limit?: number;
	    offset?: number;
	
	    static createFrom(source: any = {}) {
	        return new AuditFilter(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.operation = source["operation"];
	        this.backend = source["backend"];
	        this.key_id = source["key_id"];
	        this.device_id = source["device_id"];
	        this.success = source["success"];
	        this.since = this.convertValues(source["since"], null);
	        this.until = this.convertValues(source["until"], null);
	        this.limit = source["limit"];
	        this.offset = source["offset"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	export class AutoUnsealResult {
	    success: boolean;
	    message: string;
	
	    static createFrom(source: any = {}) {
	        return new AutoUnsealResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.success = source["success"];
	        this.message = source["message"];
	    }
	}
	export class AutoUnsealService {
	
	
	    static createFrom(source: any = {}) {
	        return new AutoUnsealService(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	
	    }
	}
	export class AutoUnsealStatus {
	    available: boolean;
	    configured: boolean;
	    blob_id: string;
	
	    static createFrom(source: any = {}) {
	        return new AutoUnsealStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.available = source["available"];
	        this.configured = source["configured"];
	        this.blob_id = source["blob_id"];
	    }
	}
	export class AvailableBackendType {
	    type: string;
	    name: string;
	    description: string;
	    available: boolean;
	
	    static createFrom(source: any = {}) {
	        return new AvailableBackendType(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.type = source["type"];
	        this.name = source["name"];
	        this.description = source["description"];
	        this.available = source["available"];
	    }
	}
	export class AvailableToken {
	    id: string;
	    source: string;
	    label: string;
	    token: string;
	    expires_at: string;
	    is_expired: boolean;
	
	    static createFrom(source: any = {}) {
	        return new AvailableToken(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.source = source["source"];
	        this.label = source["label"];
	        this.token = source["token"];
	        this.expires_at = source["expires_at"];
	        this.is_expired = source["is_expired"];
	    }
	}
	export class BackendCapability {
	    signing: boolean;
	    encryption: boolean;
	    decryption: boolean;
	    key_encapsulation: boolean;
	    sealing: boolean;
	    attestation: boolean;
	    hardware_backed: boolean;
	    quantum_signing: boolean;
	    fido2: boolean;
	    piv: boolean;
	    oath: boolean;
	    passwords: boolean;
	
	    static createFrom(source: any = {}) {
	        return new BackendCapability(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.signing = source["signing"];
	        this.encryption = source["encryption"];
	        this.decryption = source["decryption"];
	        this.key_encapsulation = source["key_encapsulation"];
	        this.sealing = source["sealing"];
	        this.attestation = source["attestation"];
	        this.hardware_backed = source["hardware_backed"];
	        this.quantum_signing = source["quantum_signing"];
	        this.fido2 = source["fido2"];
	        this.piv = source["piv"];
	        this.oath = source["oath"];
	        this.passwords = source["passwords"];
	    }
	}
	export class BackendInfo {
	    id: string;
	    type: string;
	    enabled: boolean;
	    connected: boolean;
	    key_count: number;
	    algorithms: string[];
	    description: string;
	    display_name?: string;
	    device_name?: string;
	    capabilities?: BackendCapability;
	    metadata?: Record<string, string>;
	
	    static createFrom(source: any = {}) {
	        return new BackendInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.type = source["type"];
	        this.enabled = source["enabled"];
	        this.connected = source["connected"];
	        this.key_count = source["key_count"];
	        this.algorithms = source["algorithms"];
	        this.description = source["description"];
	        this.display_name = source["display_name"];
	        this.device_name = source["device_name"];
	        this.capabilities = this.convertValues(source["capabilities"], BackendCapability);
	        this.metadata = source["metadata"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class BarrierAutoUnsealService {
	
	
	    static createFrom(source: any = {}) {
	        return new BarrierAutoUnsealService(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	
	    }
	}
	export class BarrierAutoUnsealStatus {
	    available: boolean;
	    reason?: string;
	    barrier_sealed: boolean;
	    policy_configured: boolean;
	    policy_name: string;
	    credential_sealed: boolean;
	    pcrs_match: boolean;
	
	    static createFrom(source: any = {}) {
	        return new BarrierAutoUnsealStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.available = source["available"];
	        this.reason = source["reason"];
	        this.barrier_sealed = source["barrier_sealed"];
	        this.policy_configured = source["policy_configured"];
	        this.policy_name = source["policy_name"];
	        this.credential_sealed = source["credential_sealed"];
	        this.pcrs_match = source["pcrs_match"];
	    }
	}
	export class BarrierSealInfo {
	    initialized: boolean;
	    sealed: boolean;
	    strategy: string;
	    strategy_label: string;
	    hardware_backed: boolean;
	    data_dir: string;
	    root_key_entry: string;
	
	    static createFrom(source: any = {}) {
	        return new BarrierSealInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.initialized = source["initialized"];
	        this.sealed = source["sealed"];
	        this.strategy = source["strategy"];
	        this.strategy_label = source["strategy_label"];
	        this.hardware_backed = source["hardware_backed"];
	        this.data_dir = source["data_dir"];
	        this.root_key_entry = source["root_key_entry"];
	    }
	}
	export class BarrierService {
	
	
	    static createFrom(source: any = {}) {
	        return new BarrierService(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	
	    }
	}
	export class BarrierStrategyInfo {
	    id: string;
	    available: boolean;
	    hardware_backed: boolean;
	    label: string;
	
	    static createFrom(source: any = {}) {
	        return new BarrierStrategyInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.available = source["available"];
	        this.hardware_backed = source["hardware_backed"];
	        this.label = source["label"];
	    }
	}
	export class BridgeStatus {
	    running: boolean;
	    // Go type: time
	    started_at?: any;
	    uptime?: string;
	    requests: number;
	    device_name?: string;
	    connection_type?: string;
	
	    static createFrom(source: any = {}) {
	        return new BridgeStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.running = source["running"];
	        this.started_at = this.convertValues(source["started_at"], null);
	        this.uptime = source["uptime"];
	        this.requests = source["requests"];
	        this.device_name = source["device_name"];
	        this.connection_type = source["connection_type"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class BrowserBundleStatus {
	    exists: boolean;
	    stale: boolean;
	    cert_count: number;
	    last_generated: string;
	    bundle_path: string;
	
	    static createFrom(source: any = {}) {
	        return new BrowserBundleStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.exists = source["exists"];
	        this.stale = source["stale"];
	        this.cert_count = source["cert_count"];
	        this.last_generated = source["last_generated"];
	        this.bundle_path = source["bundle_path"];
	    }
	}
	export class BrowserConfig {
	    default_browser: string;
	    custom_command?: string;
	    include_trust_bundle: boolean;
	    chrome_profile_mode: string;
	    firefox_profile_mode: string;
	    include_extensions: boolean;
	
	    static createFrom(source: any = {}) {
	        return new BrowserConfig(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.default_browser = source["default_browser"];
	        this.custom_command = source["custom_command"];
	        this.include_trust_bundle = source["include_trust_bundle"];
	        this.chrome_profile_mode = source["chrome_profile_mode"];
	        this.firefox_profile_mode = source["firefox_profile_mode"];
	        this.include_extensions = source["include_extensions"];
	    }
	}
	export class BrowserInfo {
	    name: string;
	    path: string;
	
	    static createFrom(source: any = {}) {
	        return new BrowserInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.path = source["path"];
	    }
	}
	export class CSRSubject {
	    common_name: string;
	    organization: string;
	    organizational_unit: string;
	    country: string;
	    state: string;
	    locality: string;
	
	    static createFrom(source: any = {}) {
	        return new CSRSubject(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.common_name = source["common_name"];
	        this.organization = source["organization"];
	        this.organizational_unit = source["organizational_unit"];
	        this.country = source["country"];
	        this.state = source["state"];
	        this.locality = source["locality"];
	    }
	}
	export class ExtensionInfo {
	    oid: string;
	    name: string;
	    critical: boolean;
	    value: string;
	
	    static createFrom(source: any = {}) {
	        return new ExtensionInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.oid = source["oid"];
	        this.name = source["name"];
	        this.critical = source["critical"];
	        this.value = source["value"];
	    }
	}
	export class CertificateDetails {
	    version: number;
	    serial_number: string;
	    subject_cn: string;
	    subject_org: string;
	    subject_org_unit: string;
	    subject_country: string;
	    subject_province: string;
	    subject_locality: string;
	    subject_serial_number: string;
	    issuer_cn: string;
	    issuer_org: string;
	    issuer_org_unit: string;
	    issuer_country: string;
	    not_before: string;
	    not_after: string;
	    signature_algorithm: string;
	    signature_hex: string;
	    fingerprint_sha256: string;
	    fingerprint_sha1: string;
	    fingerprint_md5: string;
	    public_key_algorithm: string;
	    public_key_size: number;
	    public_key_hex: string;
	    subject_key_id: string;
	    is_ca: boolean;
	    max_path_len: number;
	    max_path_len_zero: boolean;
	    key_usage: string;
	    ext_key_usage: string[];
	    subject_alt_names: string;
	    extensions: ExtensionInfo[];
	
	    static createFrom(source: any = {}) {
	        return new CertificateDetails(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.version = source["version"];
	        this.serial_number = source["serial_number"];
	        this.subject_cn = source["subject_cn"];
	        this.subject_org = source["subject_org"];
	        this.subject_org_unit = source["subject_org_unit"];
	        this.subject_country = source["subject_country"];
	        this.subject_province = source["subject_province"];
	        this.subject_locality = source["subject_locality"];
	        this.subject_serial_number = source["subject_serial_number"];
	        this.issuer_cn = source["issuer_cn"];
	        this.issuer_org = source["issuer_org"];
	        this.issuer_org_unit = source["issuer_org_unit"];
	        this.issuer_country = source["issuer_country"];
	        this.not_before = source["not_before"];
	        this.not_after = source["not_after"];
	        this.signature_algorithm = source["signature_algorithm"];
	        this.signature_hex = source["signature_hex"];
	        this.fingerprint_sha256 = source["fingerprint_sha256"];
	        this.fingerprint_sha1 = source["fingerprint_sha1"];
	        this.fingerprint_md5 = source["fingerprint_md5"];
	        this.public_key_algorithm = source["public_key_algorithm"];
	        this.public_key_size = source["public_key_size"];
	        this.public_key_hex = source["public_key_hex"];
	        this.subject_key_id = source["subject_key_id"];
	        this.is_ca = source["is_ca"];
	        this.max_path_len = source["max_path_len"];
	        this.max_path_len_zero = source["max_path_len_zero"];
	        this.key_usage = source["key_usage"];
	        this.ext_key_usage = source["ext_key_usage"];
	        this.subject_alt_names = source["subject_alt_names"];
	        this.extensions = this.convertValues(source["extensions"], ExtensionInfo);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class CertifyKeyResult {
	    attested: string;
	    signature: string;
	    nonce: string;
	
	    static createFrom(source: any = {}) {
	        return new CertifyKeyResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.attested = source["attested"];
	        this.signature = source["signature"];
	        this.nonce = source["nonce"];
	    }
	}
	export class ConnectionInfo {
	    state: string;
	    protocol: string;
	    address: string;
	    tls: boolean;
	    spki_pin?: string;
	    version?: string;
	    error?: string;
	
	    static createFrom(source: any = {}) {
	        return new ConnectionInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.state = source["state"];
	        this.protocol = source["protocol"];
	        this.address = source["address"];
	        this.tls = source["tls"];
	        this.spki_pin = source["spki_pin"];
	        this.version = source["version"];
	        this.error = source["error"];
	    }
	}
	export class ConnectionTestResult {
	    success: boolean;
	    message: string;
	
	    static createFrom(source: any = {}) {
	        return new ConnectionTestResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.success = source["success"];
	        this.message = source["message"];
	    }
	}
	export class CreateVolumeParams {
	    size_gb: number;
	    passphrase: string;
	
	    static createFrom(source: any = {}) {
	        return new CreateVolumeParams(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.size_gb = source["size_gb"];
	        this.passphrase = source["passphrase"];
	    }
	}
	export class DeviceStatus {
	    name: string;
	    address: string;
	    connected: boolean;
	    battery_level: number;
	    rssi: number;
	    firmware: string;
	
	    static createFrom(source: any = {}) {
	        return new DeviceStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.address = source["address"];
	        this.connected = source["connected"];
	        this.battery_level = source["battery_level"];
	        this.rssi = source["rssi"];
	        this.firmware = source["firmware"];
	    }
	}
	export class DiscoveredDevice {
	    name: string;
	    address: string;
	    rssi: number;
	
	    static createFrom(source: any = {}) {
	        return new DiscoveredDevice(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.address = source["address"];
	        this.rssi = source["rssi"];
	    }
	}
	export class EKECCInfo {
	    present: boolean;
	    algorithm: string;
	    key_size: number;
	    certificate?: string;
	    verified: boolean;
	
	    static createFrom(source: any = {}) {
	        return new EKECCInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.present = source["present"];
	        this.algorithm = source["algorithm"];
	        this.key_size = source["key_size"];
	        this.certificate = source["certificate"];
	        this.verified = source["verified"];
	    }
	}
	export class EKInfo {
	    present: boolean;
	    algorithm: string;
	    key_size: number;
	    certificate?: string;
	    verified: boolean;
	
	    static createFrom(source: any = {}) {
	        return new EKInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.present = source["present"];
	        this.algorithm = source["algorithm"];
	        this.key_size = source["key_size"];
	        this.certificate = source["certificate"];
	        this.verified = source["verified"];
	    }
	}
	export class EnrollmentApprovalResult {
	    request_id: string;
	    certificate_pem: number[];
	    ca_certificate_pem: number[];
	
	    static createFrom(source: any = {}) {
	        return new EnrollmentApprovalResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.request_id = source["request_id"];
	        this.certificate_pem = source["certificate_pem"];
	        this.ca_certificate_pem = source["ca_certificate_pem"];
	    }
	}
	export class EnrollmentCodeInfo {
	    code: string;
	    expires_at: string;
	
	    static createFrom(source: any = {}) {
	        return new EnrollmentCodeInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.code = source["code"];
	        this.expires_at = source["expires_at"];
	    }
	}
	export class EnterpriseExtensionPolicy {
	    Enabled: boolean;
	    RequireAuthentication: boolean;
	    ForceAudit: boolean;
	    AllowedDomains: string[];
	    BlockedDomains: string[];
	    MaxFillsPerMinute: number;
	    UserCanConfigure: boolean;
	
	    static createFrom(source: any = {}) {
	        return new EnterpriseExtensionPolicy(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Enabled = source["Enabled"];
	        this.RequireAuthentication = source["RequireAuthentication"];
	        this.ForceAudit = source["ForceAudit"];
	        this.AllowedDomains = source["AllowedDomains"];
	        this.BlockedDomains = source["BlockedDomains"];
	        this.MaxFillsPerMinute = source["MaxFillsPerMinute"];
	        this.UserCanConfigure = source["UserCanConfigure"];
	    }
	}
	export class SealerInfo {
	    id: string;
	    available: boolean;
	    hardware_backed: boolean;
	    security_level: number;
	    label: string;
	    description: string;
	    is_default: boolean;
	    details?: Record<string, string>;
	
	    static createFrom(source: any = {}) {
	        return new SealerInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.available = source["available"];
	        this.hardware_backed = source["hardware_backed"];
	        this.security_level = source["security_level"];
	        this.label = source["label"];
	        this.description = source["description"];
	        this.is_default = source["is_default"];
	        this.details = source["details"];
	    }
	}
	export class EnvironmentProbe {
	    tpm_available: boolean;
	    tpm_device_exists: boolean;
	    tpm_device_path: string;
	    tpm_init_error?: string;
	    luks_available: boolean;
	    server_reachable: boolean;
	    server_address: string;
	    platform: string;
	    setup_complete: boolean;
	    storage_exists: boolean;
	    storage_mounted: boolean;
	    barrier_strategies: BarrierStrategyInfo[];
	    available_sealers: SealerInfo[];
	    available_backends: BackendInfo[];
	
	    static createFrom(source: any = {}) {
	        return new EnvironmentProbe(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.tpm_available = source["tpm_available"];
	        this.tpm_device_exists = source["tpm_device_exists"];
	        this.tpm_device_path = source["tpm_device_path"];
	        this.tpm_init_error = source["tpm_init_error"];
	        this.luks_available = source["luks_available"];
	        this.server_reachable = source["server_reachable"];
	        this.server_address = source["server_address"];
	        this.platform = source["platform"];
	        this.setup_complete = source["setup_complete"];
	        this.storage_exists = source["storage_exists"];
	        this.storage_mounted = source["storage_mounted"];
	        this.barrier_strategies = this.convertValues(source["barrier_strategies"], BarrierStrategyInfo);
	        this.available_sealers = this.convertValues(source["available_sealers"], SealerInfo);
	        this.available_backends = this.convertValues(source["available_backends"], BackendInfo);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class EventLogEntry {
	    pcr_index: number;
	    event_type: string;
	    digest_hex: string;
	    event_data: string;
	
	    static createFrom(source: any = {}) {
	        return new EventLogEntry(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.pcr_index = source["pcr_index"];
	        this.event_type = source["event_type"];
	        this.digest_hex = source["digest_hex"];
	        this.event_data = source["event_data"];
	    }
	}
	export class PCRReplayEntry {
	    pcr_index: number;
	    bank: string;
	    expected: string;
	    actual: string;
	    match: boolean;
	
	    static createFrom(source: any = {}) {
	        return new PCRReplayEntry(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.pcr_index = source["pcr_index"];
	        this.bank = source["bank"];
	        this.expected = source["expected"];
	        this.actual = source["actual"];
	        this.match = source["match"];
	    }
	}
	export class EventLogReplayResult {
	    success: boolean;
	    total_pcrs: number;
	    match_count: number;
	    mismatch_count: number;
	    entries: PCRReplayEntry[];
	    banks: string[];
	    event_count: number;
	    error?: string;
	
	    static createFrom(source: any = {}) {
	        return new EventLogReplayResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.success = source["success"];
	        this.total_pcrs = source["total_pcrs"];
	        this.match_count = source["match_count"];
	        this.mismatch_count = source["mismatch_count"];
	        this.entries = this.convertValues(source["entries"], PCRReplayEntry);
	        this.banks = source["banks"];
	        this.event_count = source["event_count"];
	        this.error = source["error"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class ExplorerRequest {
	    method: string;
	    url: string;
	    headers: Record<string, string>;
	    body: string;
	
	    static createFrom(source: any = {}) {
	        return new ExplorerRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.method = source["method"];
	        this.url = source["url"];
	        this.headers = source["headers"];
	        this.body = source["body"];
	    }
	}
	export class ExplorerResponse {
	    status_code: number;
	    status: string;
	    headers: Record<string, string>;
	    body: string;
	    duration_ms: number;
	    error?: string;
	
	    static createFrom(source: any = {}) {
	        return new ExplorerResponse(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.status_code = source["status_code"];
	        this.status = source["status"];
	        this.headers = source["headers"];
	        this.body = source["body"];
	        this.duration_ms = source["duration_ms"];
	        this.error = source["error"];
	    }
	}
	export class ManifestInfo {
	    browser: string;
	    name: string;
	    installed: boolean;
	    path: string;
	
	    static createFrom(source: any = {}) {
	        return new ManifestInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.browser = source["browser"];
	        this.name = source["name"];
	        this.installed = source["installed"];
	        this.path = source["path"];
	    }
	}
	export class PairingStatus {
	    paired: boolean;
	    origin?: string;
	    paired_at?: string;
	
	    static createFrom(source: any = {}) {
	        return new PairingStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.paired = source["paired"];
	        this.origin = source["origin"];
	        this.paired_at = source["paired_at"];
	    }
	}
	export class ExtensionFullStatus {
	    ipc_running: boolean;
	    ipc_socket_path: string;
	    paired_extensions: PairingStatus[];
	    manifests: ManifestInfo[];
	
	    static createFrom(source: any = {}) {
	        return new ExtensionFullStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ipc_running = source["ipc_running"];
	        this.ipc_socket_path = source["ipc_socket_path"];
	        this.paired_extensions = this.convertValues(source["paired_extensions"], PairingStatus);
	        this.manifests = this.convertValues(source["manifests"], ManifestInfo);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	export class FIDO2AuthResponse {
	    credential_id: string;
	    rpid: string;
	    token: string;
	    token_type: string;
	    // Go type: time
	    created_at: any;
	    // Go type: time
	    expires_at: any;
	
	    static createFrom(source: any = {}) {
	        return new FIDO2AuthResponse(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.credential_id = source["credential_id"];
	        this.rpid = source["rpid"];
	        this.token = source["token"];
	        this.token_type = source["token_type"];
	        this.created_at = this.convertValues(source["created_at"], null);
	        this.expires_at = this.convertValues(source["expires_at"], null);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class FIDO2Credential {
	    id: string;
	    relying_party_id: string;
	    relying_party: string;
	    user_name: string;
	    user_display_name: string;
	    algorithm: string;
	    key_type: string;
	    cred_protect: number;
	    backend_type: string;
	    backend_id: string;
	    // Go type: time
	    created_at: any;
	    // Go type: time
	    last_used: any;
	    use_count: number;
	    discoverable: boolean;
	
	    static createFrom(source: any = {}) {
	        return new FIDO2Credential(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.relying_party_id = source["relying_party_id"];
	        this.relying_party = source["relying_party"];
	        this.user_name = source["user_name"];
	        this.user_display_name = source["user_display_name"];
	        this.algorithm = source["algorithm"];
	        this.key_type = source["key_type"];
	        this.cred_protect = source["cred_protect"];
	        this.backend_type = source["backend_type"];
	        this.backend_id = source["backend_id"];
	        this.created_at = this.convertValues(source["created_at"], null);
	        this.last_used = this.convertValues(source["last_used"], null);
	        this.use_count = source["use_count"];
	        this.discoverable = source["discoverable"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class FIDO2DeviceStatus {
	    running: boolean;
	    device_name: string;
	    vendor_id: string;
	    product_id: string;
	    has_pending_touch: boolean;
	    reason?: string;
	    raw_reason?: string;
	    authenticator_available: boolean;
	
	    static createFrom(source: any = {}) {
	        return new FIDO2DeviceStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.running = source["running"];
	        this.device_name = source["device_name"];
	        this.vendor_id = source["vendor_id"];
	        this.product_id = source["product_id"];
	        this.has_pending_touch = source["has_pending_touch"];
	        this.reason = source["reason"];
	        this.raw_reason = source["raw_reason"];
	        this.authenticator_available = source["authenticator_available"];
	    }
	}
	export class FIDO2RPPolicy {
	    rpid: string;
	    uv_override: string;
	    up_override: string;
	    attestation_override: string;
	    enterprise: boolean;
	    blocked: boolean;
	
	    static createFrom(source: any = {}) {
	        return new FIDO2RPPolicy(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.rpid = source["rpid"];
	        this.uv_override = source["uv_override"];
	        this.up_override = source["up_override"];
	        this.attestation_override = source["attestation_override"];
	        this.enterprise = source["enterprise"];
	        this.blocked = source["blocked"];
	    }
	}
	export class FactorLoginResult {
	    token: string;
	
	    static createFrom(source: any = {}) {
	        return new FactorLoginResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.token = source["token"];
	    }
	}
	export class IdentityConfig {
	    common_name: string;
	    organization: string;
	    organizational_unit: string;
	    country: string;
	    province: string;
	    locality: string;
	
	    static createFrom(source: any = {}) {
	        return new IdentityConfig(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.common_name = source["common_name"];
	        this.organization = source["organization"];
	        this.organizational_unit = source["organizational_unit"];
	        this.country = source["country"];
	        this.province = source["province"];
	        this.locality = source["locality"];
	    }
	}
	export class GUIConfigData {
	    auto_tray: boolean;
	    theme: string;
	    start_minimized: boolean;
	    notifications: boolean;
	    window_width: number;
	    window_height: number;
	    remember_position: boolean;
	    window_x: number;
	    window_y: number;
	    server_address: string;
	    server_protocol: string;
	    server_tls_enabled: boolean;
	    server_tls_skip_verify: boolean;
	    server_tls_ca_file: string;
	    server_auto_connect: boolean;
	    auto_unseal_enabled: boolean;
	    auto_unseal_blob_id: string;
	    auto_unseal_tpm_policy: string;
	    auto_unseal_backend: string;
	    fido2_authenticator_enabled: boolean;
	    clipboard_timeout: number;
	    require_auth: boolean;
	    setup_complete: boolean;
	    storage_type: string;
	    barrier_initialized: boolean;
	    barrier_strategy: string;
	    barrier_auto_unseal_enabled: boolean;
	    app_auto_lock_minutes: number;
	    app_lock_on_screen_lock: boolean;
	    sealer_backend?: string;
	    api_explorer_sandbox_policy: string;
	    browser_extension_enabled: boolean;
	    developer_tools: boolean;
	    fido2_require_user_presence: boolean;
	    fido2_user_intent_check: boolean;
	    autofill_policy?: autofill.AutoFillPolicy;
	    identity: IdentityConfig;
	
	    static createFrom(source: any = {}) {
	        return new GUIConfigData(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.auto_tray = source["auto_tray"];
	        this.theme = source["theme"];
	        this.start_minimized = source["start_minimized"];
	        this.notifications = source["notifications"];
	        this.window_width = source["window_width"];
	        this.window_height = source["window_height"];
	        this.remember_position = source["remember_position"];
	        this.window_x = source["window_x"];
	        this.window_y = source["window_y"];
	        this.server_address = source["server_address"];
	        this.server_protocol = source["server_protocol"];
	        this.server_tls_enabled = source["server_tls_enabled"];
	        this.server_tls_skip_verify = source["server_tls_skip_verify"];
	        this.server_tls_ca_file = source["server_tls_ca_file"];
	        this.server_auto_connect = source["server_auto_connect"];
	        this.auto_unseal_enabled = source["auto_unseal_enabled"];
	        this.auto_unseal_blob_id = source["auto_unseal_blob_id"];
	        this.auto_unseal_tpm_policy = source["auto_unseal_tpm_policy"];
	        this.auto_unseal_backend = source["auto_unseal_backend"];
	        this.fido2_authenticator_enabled = source["fido2_authenticator_enabled"];
	        this.clipboard_timeout = source["clipboard_timeout"];
	        this.require_auth = source["require_auth"];
	        this.setup_complete = source["setup_complete"];
	        this.storage_type = source["storage_type"];
	        this.barrier_initialized = source["barrier_initialized"];
	        this.barrier_strategy = source["barrier_strategy"];
	        this.barrier_auto_unseal_enabled = source["barrier_auto_unseal_enabled"];
	        this.app_auto_lock_minutes = source["app_auto_lock_minutes"];
	        this.app_lock_on_screen_lock = source["app_lock_on_screen_lock"];
	        this.sealer_backend = source["sealer_backend"];
	        this.api_explorer_sandbox_policy = source["api_explorer_sandbox_policy"];
	        this.browser_extension_enabled = source["browser_extension_enabled"];
	        this.developer_tools = source["developer_tools"];
	        this.fido2_require_user_presence = source["fido2_require_user_presence"];
	        this.fido2_user_intent_check = source["fido2_user_intent_check"];
	        this.autofill_policy = this.convertValues(source["autofill_policy"], autofill.AutoFillPolicy);
	        this.identity = this.convertValues(source["identity"], IdentityConfig);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class GenerateKeyParams {
	    key_id: string;
	    backend: string;
	    purpose?: string;
	    algorithm: string;
	    key_size?: number;
	    curve?: string;
	    exportable?: boolean;
	    tpm_policy?: string;
	    hierarchy?: string;
	    handle?: number;
	    is_primary?: boolean;
	    parent_handle?: number;
	
	    static createFrom(source: any = {}) {
	        return new GenerateKeyParams(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.key_id = source["key_id"];
	        this.backend = source["backend"];
	        this.purpose = source["purpose"];
	        this.algorithm = source["algorithm"];
	        this.key_size = source["key_size"];
	        this.curve = source["curve"];
	        this.exportable = source["exportable"];
	        this.tpm_policy = source["tpm_policy"];
	        this.hierarchy = source["hierarchy"];
	        this.handle = source["handle"];
	        this.is_primary = source["is_primary"];
	        this.parent_handle = source["parent_handle"];
	    }
	}
	export class GenerateKeyResult {
	    key_id: string;
	    key_type: string;
	    public_key_pem?: string;
	    message: string;
	
	    static createFrom(source: any = {}) {
	        return new GenerateKeyResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.key_id = source["key_id"];
	        this.key_type = source["key_type"];
	        this.public_key_pem = source["public_key_pem"];
	        this.message = source["message"];
	    }
	}
	export class GeneratedPINs {
	    so_pin: string;
	    user_pin: string;
	
	    static createFrom(source: any = {}) {
	        return new GeneratedPINs(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.so_pin = source["so_pin"];
	        this.user_pin = source["user_pin"];
	    }
	}
	export class HOTPCode {
	    code: string;
	    counter: number;
	    account_id: string;
	
	    static createFrom(source: any = {}) {
	        return new HOTPCode(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.code = source["code"];
	        this.counter = source["counter"];
	        this.account_id = source["account_id"];
	    }
	}
	export class HandleInfo {
	    handle: string;
	    algorithm?: string;
	    type: string;
	    description?: string;
	
	    static createFrom(source: any = {}) {
	        return new HandleInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.handle = source["handle"];
	        this.algorithm = source["algorithm"];
	        this.type = source["type"];
	        this.description = source["description"];
	    }
	}
	export class HistoryEntry {
	    id: string;
	    // Go type: time
	    timestamp: any;
	    request?: ExplorerRequest;
	    response?: ExplorerResponse;
	
	    static createFrom(source: any = {}) {
	        return new HistoryEntry(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.timestamp = this.convertValues(source["timestamp"], null);
	        this.request = this.convertValues(source["request"], ExplorerRequest);
	        this.response = this.convertValues(source["response"], ExplorerResponse);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class IAKInfo {
	    present: boolean;
	    algorithm: string;
	    key_size: number;
	    handle: string;
	    certificate?: string;
	
	    static createFrom(source: any = {}) {
	        return new IAKInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.present = source["present"];
	        this.algorithm = source["algorithm"];
	        this.key_size = source["key_size"];
	        this.handle = source["handle"];
	        this.certificate = source["certificate"];
	    }
	}
	export class IDevIDInfo {
	    present: boolean;
	    algorithm: string;
	    key_size: number;
	    certificate?: string;
	    verified: boolean;
	
	    static createFrom(source: any = {}) {
	        return new IDevIDInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.present = source["present"];
	        this.algorithm = source["algorithm"];
	        this.key_size = source["key_size"];
	        this.certificate = source["certificate"];
	        this.verified = source["verified"];
	    }
	}
	
	export class ImportError {
	    entry_name: string;
	    error: string;
	
	    static createFrom(source: any = {}) {
	        return new ImportError(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.entry_name = source["entry_name"];
	        this.error = source["error"];
	    }
	}
	export class ImportKeyParams {
	    key_id: string;
	    backend: string;
	    key_type: string;
	    key_data: string;
	    format: string;
	    exportable?: boolean;
	
	    static createFrom(source: any = {}) {
	        return new ImportKeyParams(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.key_id = source["key_id"];
	        this.backend = source["backend"];
	        this.key_type = source["key_type"];
	        this.key_data = source["key_data"];
	        this.format = source["format"];
	        this.exportable = source["exportable"];
	    }
	}
	export class ImportParams {
	    file_path: string;
	    format: string;
	    password?: string;
	    target_folder: string;
	    skip_duplicates: boolean;
	    overwrite_duplicates: boolean;
	    import_totp: boolean;
	
	    static createFrom(source: any = {}) {
	        return new ImportParams(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.file_path = source["file_path"];
	        this.format = source["format"];
	        this.password = source["password"];
	        this.target_folder = source["target_folder"];
	        this.skip_duplicates = source["skip_duplicates"];
	        this.overwrite_duplicates = source["overwrite_duplicates"];
	        this.import_totp = source["import_totp"];
	    }
	}
	export class ImportPreviewEntry {
	    title: string;
	    username: string;
	    url: string;
	    folder_path: string;
	    has_totp: boolean;
	    tags?: string[];
	
	    static createFrom(source: any = {}) {
	        return new ImportPreviewEntry(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.title = source["title"];
	        this.username = source["username"];
	        this.url = source["url"];
	        this.folder_path = source["folder_path"];
	        this.has_totp = source["has_totp"];
	        this.tags = source["tags"];
	    }
	}
	export class ImportPreviewResult {
	    entries: ImportPreviewEntry[];
	    total: number;
	    format: string;
	
	    static createFrom(source: any = {}) {
	        return new ImportPreviewResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.entries = this.convertValues(source["entries"], ImportPreviewEntry);
	        this.total = source["total"];
	        this.format = source["format"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class ImportResult {
	    imported: number;
	    skipped: number;
	    failed: number;
	    errors?: ImportError[];
	    totp_imported?: number;
	    duration_ms: number;
	
	    static createFrom(source: any = {}) {
	        return new ImportResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.imported = source["imported"];
	        this.skipped = source["skipped"];
	        this.failed = source["failed"];
	        this.errors = this.convertValues(source["errors"], ImportError);
	        this.totp_imported = source["totp_imported"];
	        this.duration_ms = source["duration_ms"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class KeyViewData {
	    name: string;
	    algorithm: string;
	    key_size: number;
	    handle?: string;
	    public_key_pem?: string;
	    certificate?: string;
	
	    static createFrom(source: any = {}) {
	        return new KeyViewData(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.algorithm = source["algorithm"];
	        this.key_size = source["key_size"];
	        this.handle = source["handle"];
	        this.public_key_pem = source["public_key_pem"];
	        this.certificate = source["certificate"];
	    }
	}
	export class LaunchOptions {
	    IncludeExtensions: boolean;
	    ExtensionIDs: string[];
	    SourceProfile: string;
	
	    static createFrom(source: any = {}) {
	        return new LaunchOptions(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.IncludeExtensions = source["IncludeExtensions"];
	        this.ExtensionIDs = source["ExtensionIDs"];
	        this.SourceProfile = source["SourceProfile"];
	    }
	}
	export class LaunchResult {
	    browser: string;
	    family: string;
	    mode: string;
	    cert_count: number;
	    pid: number;
	    extensions_imported: number;
	
	    static createFrom(source: any = {}) {
	        return new LaunchResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.browser = source["browser"];
	        this.family = source["family"];
	        this.mode = source["mode"];
	        this.cert_count = source["cert_count"];
	        this.pid = source["pid"];
	        this.extensions_imported = source["extensions_imported"];
	    }
	}
	export class ListFactorsResponse {
	    factors: AuthFactor[];
	    total: number;
	
	    static createFrom(source: any = {}) {
	        return new ListFactorsResponse(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.factors = this.convertValues(source["factors"], AuthFactor);
	        this.total = source["total"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class LockoutInfo {
	    counter: number;
	    max_fail: number;
	    interval: number;
	    recovery: number;
	    is_locked: boolean;
	
	    static createFrom(source: any = {}) {
	        return new LockoutInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.counter = source["counter"];
	        this.max_fail = source["max_fail"];
	        this.interval = source["interval"];
	        this.recovery = source["recovery"];
	        this.is_locked = source["is_locked"];
	    }
	}
	export class LoginResult {
	    success: boolean;
	    mode: string;
	    policy_verified: boolean;
	    tamper_detected: boolean;
	    error?: string;
	
	    static createFrom(source: any = {}) {
	        return new LoginResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.success = source["success"];
	        this.mode = source["mode"];
	        this.policy_verified = source["policy_verified"];
	        this.tamper_detected = source["tamper_detected"];
	        this.error = source["error"];
	    }
	}
	export class MFAPolicyRequest {
	    tenant_id: string;
	    require_factor_count: number;
	
	    static createFrom(source: any = {}) {
	        return new MFAPolicyRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.tenant_id = source["tenant_id"];
	        this.require_factor_count = source["require_factor_count"];
	    }
	}
	
	export class NVIndexEntry {
	    handle: string;
	    type: string;
	    size: number;
	    auth_read: boolean;
	    auth_write: boolean;
	
	    static createFrom(source: any = {}) {
	        return new NVIndexEntry(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.handle = source["handle"];
	        this.type = source["type"];
	        this.size = source["size"];
	        this.auth_read = source["auth_read"];
	        this.auth_write = source["auth_write"];
	    }
	}
	export class NVSummary {
	    indexes_defined: number;
	    indexes_max: number;
	    indexes: NVIndexEntry[];
	
	    static createFrom(source: any = {}) {
	        return new NVSummary(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.indexes_defined = source["indexes_defined"];
	        this.indexes_max = source["indexes_max"];
	        this.indexes = this.convertValues(source["indexes"], NVIndexEntry);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class NotificationRequest {
	    title: string;
	    message: string;
	
	    static createFrom(source: any = {}) {
	        return new NotificationRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.title = source["title"];
	        this.message = source["message"];
	    }
	}
	export class OATHAccount {
	    id: string;
	    name: string;
	    issuer: string;
	    account_name: string;
	    type: string;
	    algorithm: string;
	    digits: number;
	    period: number;
	    counter: number;
	    // Go type: time
	    created_at: any;
	    backend_id: string;
	
	    static createFrom(source: any = {}) {
	        return new OATHAccount(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	        this.issuer = source["issuer"];
	        this.account_name = source["account_name"];
	        this.type = source["type"];
	        this.algorithm = source["algorithm"];
	        this.digits = source["digits"];
	        this.period = source["period"];
	        this.counter = source["counter"];
	        this.created_at = this.convertValues(source["created_at"], null);
	        this.backend_id = source["backend_id"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class OIDCExecResult {
	    success: boolean;
	    exit_code: number;
	    stdout: string;
	    stderr: string;
	    error?: string;
	
	    static createFrom(source: any = {}) {
	        return new OIDCExecResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.success = source["success"];
	        this.exit_code = source["exit_code"];
	        this.stdout = source["stdout"];
	        this.stderr = source["stderr"];
	        this.error = source["error"];
	    }
	}
	export class OIDCTokenInfo {
	    provider: string;
	    issuer: string;
	    subject: string;
	    email: string;
	    name: string;
	    expires_at: string;
	    expires_in: number;
	    scopes: string[];
	    is_expired: boolean;
	    has_refresh: boolean;
	    has_dpop: boolean;
	
	    static createFrom(source: any = {}) {
	        return new OIDCTokenInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.provider = source["provider"];
	        this.issuer = source["issuer"];
	        this.subject = source["subject"];
	        this.email = source["email"];
	        this.name = source["name"];
	        this.expires_at = source["expires_at"];
	        this.expires_in = source["expires_in"];
	        this.scopes = source["scopes"];
	        this.is_expired = source["is_expired"];
	        this.has_refresh = source["has_refresh"];
	        this.has_dpop = source["has_dpop"];
	    }
	}
	export class OIDCLoginResult {
	    success: boolean;
	    token?: OIDCTokenInfo;
	    error?: string;
	
	    static createFrom(source: any = {}) {
	        return new OIDCLoginResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.success = source["success"];
	        this.token = this.convertValues(source["token"], OIDCTokenInfo);
	        this.error = source["error"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class OIDCProviderEntry {
	    name: string;
	    type: string;
	    template?: string;
	    issuer: string;
	    client_id: string;
	    client_secret?: string;
	    redirect_url: string;
	    scopes: string[];
	    exec?: string;
	    auto_refresh: number;
	    background: boolean;
	    log_file?: string;
	    dpop?: boolean;
	    aws_region?: string;
	    aws_profile?: string;
	    aws_credentials_file?: string;
	    aws_output?: string;
	    aws_cross_device?: boolean;
	    aws_session_store?: string;
	
	    static createFrom(source: any = {}) {
	        return new OIDCProviderEntry(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.type = source["type"];
	        this.template = source["template"];
	        this.issuer = source["issuer"];
	        this.client_id = source["client_id"];
	        this.client_secret = source["client_secret"];
	        this.redirect_url = source["redirect_url"];
	        this.scopes = source["scopes"];
	        this.exec = source["exec"];
	        this.auto_refresh = source["auto_refresh"];
	        this.background = source["background"];
	        this.log_file = source["log_file"];
	        this.dpop = source["dpop"];
	        this.aws_region = source["aws_region"];
	        this.aws_profile = source["aws_profile"];
	        this.aws_credentials_file = source["aws_credentials_file"];
	        this.aws_output = source["aws_output"];
	        this.aws_cross_device = source["aws_cross_device"];
	        this.aws_session_store = source["aws_session_store"];
	    }
	}
	export class OIDCProviderTemplateInfo {
	    name: string;
	    description: string;
	    issuer: string;
	    scopes: string[];
	    requires_region: boolean;
	    requires_issuer: boolean;
	    type: string;
	    dpop: boolean;
	
	    static createFrom(source: any = {}) {
	        return new OIDCProviderTemplateInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.description = source["description"];
	        this.issuer = source["issuer"];
	        this.scopes = source["scopes"];
	        this.requires_region = source["requires_region"];
	        this.requires_issuer = source["requires_issuer"];
	        this.type = source["type"];
	        this.dpop = source["dpop"];
	    }
	}
	export class OIDCRefreshStatus {
	    provider: string;
	    running: boolean;
	    last_refresh?: string;
	    next_refresh?: string;
	    refresh_count: number;
	    last_status?: string;
	    last_error?: string;
	
	    static createFrom(source: any = {}) {
	        return new OIDCRefreshStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.provider = source["provider"];
	        this.running = source["running"];
	        this.last_refresh = source["last_refresh"];
	        this.next_refresh = source["next_refresh"];
	        this.refresh_count = source["refresh_count"];
	        this.last_status = source["last_status"];
	        this.last_error = source["last_error"];
	    }
	}
	export class OIDCSavedScript {
	    name: string;
	    file_name: string;
	
	    static createFrom(source: any = {}) {
	        return new OIDCSavedScript(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.file_name = source["file_name"];
	    }
	}
	export class OIDCServerDeviceLogin {
	    user_code: string;
	    verification_uri: string;
	    verification_uri_complete?: string;
	    interval_seconds: number;
	    expires_at: string;
	
	    static createFrom(source: any = {}) {
	        return new OIDCServerDeviceLogin(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.user_code = source["user_code"];
	        this.verification_uri = source["verification_uri"];
	        this.verification_uri_complete = source["verification_uri_complete"];
	        this.interval_seconds = source["interval_seconds"];
	        this.expires_at = source["expires_at"];
	    }
	}
	export class OIDCServerCredentialInfo {
	    tenant_id?: string;
	    scope: string;
	    owner?: string;
	    name: string;
	    template?: string;
	    issuer?: string;
	    client_id?: string;
	    scopes?: string[];
	    status: string;
	    status_reason?: string;
	    expires_at?: string;
	    refreshable: boolean;
	    last_refresh?: string;
	    last_error?: string;
	    device_login?: OIDCServerDeviceLogin;
	    created_at?: string;
	    updated_at?: string;
	    created_by?: string;
	    supports_device: boolean;
	
	    static createFrom(source: any = {}) {
	        return new OIDCServerCredentialInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.tenant_id = source["tenant_id"];
	        this.scope = source["scope"];
	        this.owner = source["owner"];
	        this.name = source["name"];
	        this.template = source["template"];
	        this.issuer = source["issuer"];
	        this.client_id = source["client_id"];
	        this.scopes = source["scopes"];
	        this.status = source["status"];
	        this.status_reason = source["status_reason"];
	        this.expires_at = source["expires_at"];
	        this.refreshable = source["refreshable"];
	        this.last_refresh = source["last_refresh"];
	        this.last_error = source["last_error"];
	        this.device_login = this.convertValues(source["device_login"], OIDCServerDeviceLogin);
	        this.created_at = source["created_at"];
	        this.updated_at = source["updated_at"];
	        this.created_by = source["created_by"];
	        this.supports_device = source["supports_device"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	export class OIDCServerTemplateInfo {
	    name: string;
	    description: string;
	    issuer?: string;
	    scopes?: string[];
	    requires_issuer: boolean;
	    supports_device: boolean;
	    supports_import: boolean;
	    no_refresh: boolean;
	
	    static createFrom(source: any = {}) {
	        return new OIDCServerTemplateInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.description = source["description"];
	        this.issuer = source["issuer"];
	        this.scopes = source["scopes"];
	        this.requires_issuer = source["requires_issuer"];
	        this.supports_device = source["supports_device"];
	        this.supports_import = source["supports_import"];
	        this.no_refresh = source["no_refresh"];
	    }
	}
	export class OIDCServerTokens {
	    access_token: string;
	    refresh_token?: string;
	    id_token?: string;
	    expires_at?: string;
	
	    static createFrom(source: any = {}) {
	        return new OIDCServerTokens(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.access_token = source["access_token"];
	        this.refresh_token = source["refresh_token"];
	        this.id_token = source["id_token"];
	        this.expires_at = source["expires_at"];
	    }
	}
	
	
	export class PCRValue {
	    index: number;
	    bank: string;
	    digest: string;
	
	    static createFrom(source: any = {}) {
	        return new PCRValue(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.index = source["index"];
	        this.bank = source["bank"];
	        this.digest = source["digest"];
	    }
	}
	export class PINService {
	
	
	    static createFrom(source: any = {}) {
	        return new PINService(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	
	    }
	}
	export class PINStatusInfo {
	    so_pin_set: boolean;
	    user_pin_set: boolean;
	    initialized: boolean;
	    strategy: string;
	    so_pin_supported: boolean;
	
	    static createFrom(source: any = {}) {
	        return new PINStatusInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.so_pin_set = source["so_pin_set"];
	        this.user_pin_set = source["user_pin_set"];
	        this.initialized = source["initialized"];
	        this.strategy = source["strategy"];
	        this.so_pin_supported = source["so_pin_supported"];
	    }
	}
	export class PIVCardInfo {
	    reader_name: string;
	    card_vendor: string;
	    serial_number?: string;
	    has_piv_applet: boolean;
	
	    static createFrom(source: any = {}) {
	        return new PIVCardInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.reader_name = source["reader_name"];
	        this.card_vendor = source["card_vendor"];
	        this.serial_number = source["serial_number"];
	        this.has_piv_applet = source["has_piv_applet"];
	    }
	}
	export class PIVCertificate {
	    slot: string;
	    subject: string;
	    issuer: string;
	    serial_number: string;
	    algorithm: string;
	    key_size: number;
	    not_before: string;
	    not_after: string;
	    fingerprint: string;
	    pem: string;
	
	    static createFrom(source: any = {}) {
	        return new PIVCertificate(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.slot = source["slot"];
	        this.subject = source["subject"];
	        this.issuer = source["issuer"];
	        this.serial_number = source["serial_number"];
	        this.algorithm = source["algorithm"];
	        this.key_size = source["key_size"];
	        this.not_before = source["not_before"];
	        this.not_after = source["not_after"];
	        this.fingerprint = source["fingerprint"];
	        this.pem = source["pem"];
	    }
	}
	export class PIVGenerateAdvancedResult {
	    slot: string;
	    algorithm: string;
	    key_size: number;
	    subject: string;
	    message: string;
	    output_format: string;
	    cert_pem?: string;
	    public_key_pem?: string;
	    csr_pem?: string;
	    chain_pem?: string;
	
	    static createFrom(source: any = {}) {
	        return new PIVGenerateAdvancedResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.slot = source["slot"];
	        this.algorithm = source["algorithm"];
	        this.key_size = source["key_size"];
	        this.subject = source["subject"];
	        this.message = source["message"];
	        this.output_format = source["output_format"];
	        this.cert_pem = source["cert_pem"];
	        this.public_key_pem = source["public_key_pem"];
	        this.csr_pem = source["csr_pem"];
	        this.chain_pem = source["chain_pem"];
	    }
	}
	export class PIVGenerateKeyResult {
	    slot: string;
	    algorithm: string;
	    key_size: number;
	    subject: string;
	    message: string;
	
	    static createFrom(source: any = {}) {
	        return new PIVGenerateKeyResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.slot = source["slot"];
	        this.algorithm = source["algorithm"];
	        this.key_size = source["key_size"];
	        this.subject = source["subject"];
	        this.message = source["message"];
	    }
	}
	export class PIVGenerateOptions {
	    slot: string;
	    algorithm: string;
	    subject: string;
	    organization: string;
	    country: string;
	    output_format: string;
	    validity_days: number;
	    ca_source: string;
	
	    static createFrom(source: any = {}) {
	        return new PIVGenerateOptions(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.slot = source["slot"];
	        this.algorithm = source["algorithm"];
	        this.subject = source["subject"];
	        this.organization = source["organization"];
	        this.country = source["country"];
	        this.output_format = source["output_format"];
	        this.validity_days = source["validity_days"];
	        this.ca_source = source["ca_source"];
	    }
	}
	export class PIVSlot {
	    slot: string;
	    name: string;
	    description: string;
	    has_cert: boolean;
	    has_key: boolean;
	    subject?: string;
	    issuer?: string;
	    algorithm?: string;
	    key_size?: number;
	    not_before?: string;
	    not_after?: string;
	    fingerprint?: string;
	    backend?: string;
	    backend_display_name?: string;
	
	    static createFrom(source: any = {}) {
	        return new PIVSlot(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.slot = source["slot"];
	        this.name = source["name"];
	        this.description = source["description"];
	        this.has_cert = source["has_cert"];
	        this.has_key = source["has_key"];
	        this.subject = source["subject"];
	        this.issuer = source["issuer"];
	        this.algorithm = source["algorithm"];
	        this.key_size = source["key_size"];
	        this.not_before = source["not_before"];
	        this.not_after = source["not_after"];
	        this.fingerprint = source["fingerprint"];
	        this.backend = source["backend"];
	        this.backend_display_name = source["backend_display_name"];
	    }
	}
	export class PKCS11ConnectionInfo {
	    module_id: string;
	    slot_id: number;
	    token_label: string;
	
	    static createFrom(source: any = {}) {
	        return new PKCS11ConnectionInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.module_id = source["module_id"];
	        this.slot_id = source["slot_id"];
	        this.token_label = source["token_label"];
	    }
	}
	export class PKCS11SlotInfo {
	    slot_id: number;
	    label: string;
	    serial: string;
	    manufacturer: string;
	    model: string;
	    token_present: boolean;
	    initialized: boolean;
	    hardware_version: string;
	    firmware_version: string;
	
	    static createFrom(source: any = {}) {
	        return new PKCS11SlotInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.slot_id = source["slot_id"];
	        this.label = source["label"];
	        this.serial = source["serial"];
	        this.manufacturer = source["manufacturer"];
	        this.model = source["model"];
	        this.token_present = source["token_present"];
	        this.initialized = source["initialized"];
	        this.hardware_version = source["hardware_version"];
	        this.firmware_version = source["firmware_version"];
	    }
	}
	export class PKCS11ModuleInfo {
	    id: string;
	    display_name: string;
	    library_path: string;
	    state: string;
	    slots: PKCS11SlotInfo[];
	    error_msg?: string;
	
	    static createFrom(source: any = {}) {
	        return new PKCS11ModuleInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.display_name = source["display_name"];
	        this.library_path = source["library_path"];
	        this.state = source["state"];
	        this.slots = this.convertValues(source["slots"], PKCS11SlotInfo);
	        this.error_msg = source["error_msg"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	export class PKCS11TokenInfo {
	    module_id: string;
	    module_name: string;
	    slot_id: number;
	    label: string;
	    manufacturer: string;
	    model: string;
	    serial: string;
	    initialized: boolean;
	    connected: boolean;
	
	    static createFrom(source: any = {}) {
	        return new PKCS11TokenInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.module_id = source["module_id"];
	        this.module_name = source["module_name"];
	        this.slot_id = source["slot_id"];
	        this.label = source["label"];
	        this.manufacturer = source["manufacturer"];
	        this.model = source["model"];
	        this.serial = source["serial"];
	        this.initialized = source["initialized"];
	        this.connected = source["connected"];
	    }
	}
	export class PairedDevice {
	    name: string;
	    address: string;
	    // Go type: time
	    paired_at: any;
	    // Go type: time
	    last_seen: any;
	    connected: boolean;
	    is_backend: boolean;
	
	    static createFrom(source: any = {}) {
	        return new PairedDevice(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.address = source["address"];
	        this.paired_at = this.convertValues(source["paired_at"], null);
	        this.last_seen = this.convertValues(source["last_seen"], null);
	        this.connected = source["connected"];
	        this.is_backend = source["is_backend"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	export class PasswordProtectionStatus {
	    mode: string;
	    tpm_available: boolean;
	    key_source: string;
	    is_locked: boolean;
	    password_count: number;
	
	    static createFrom(source: any = {}) {
	        return new PasswordProtectionStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.mode = source["mode"];
	        this.tpm_available = source["tpm_available"];
	        this.key_source = source["key_source"];
	        this.is_locked = source["is_locked"];
	        this.password_count = source["password_count"];
	    }
	}
	export class PasswordStoreStatus {
	    access_mode: string;
	    is_locked: boolean;
	    auto_unsealed: boolean;
	    password_count: number;
	
	    static createFrom(source: any = {}) {
	        return new PasswordStoreStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.access_mode = source["access_mode"];
	        this.is_locked = source["is_locked"];
	        this.auto_unsealed = source["auto_unsealed"];
	        this.password_count = source["password_count"];
	    }
	}
	export class PasswordVaultFactor {
	    id: string;
	    factor: string;
	    label: string;
	    created_at: string;
	    key_fingerprint?: string;
	    key_backend?: string;
	    key_id?: string;
	    tpm_policy?: string;
	    certificate_subject?: string;
	
	    static createFrom(source: any = {}) {
	        return new PasswordVaultFactor(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.factor = source["factor"];
	        this.label = source["label"];
	        this.created_at = source["created_at"];
	        this.key_fingerprint = source["key_fingerprint"];
	        this.key_backend = source["key_backend"];
	        this.key_id = source["key_id"];
	        this.tpm_policy = source["tpm_policy"];
	        this.certificate_subject = source["certificate_subject"];
	    }
	}
	export class PasswordVaultEnrollResult {
	    factor: PasswordVaultFactor;
	    recovery_code?: string;
	
	    static createFrom(source: any = {}) {
	        return new PasswordVaultEnrollResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.factor = this.convertValues(source["factor"], PasswordVaultFactor);
	        this.recovery_code = source["recovery_code"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	export class PasswordVaultStatus {
	    initialized: boolean;
	    unlocked: boolean;
	    factors: PasswordVaultFactor[];
	    passkey_rp_id?: string;
	
	    static createFrom(source: any = {}) {
	        return new PasswordVaultStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.initialized = source["initialized"];
	        this.unlocked = source["unlocked"];
	        this.factors = this.convertValues(source["factors"], PasswordVaultFactor);
	        this.passkey_rp_id = source["passkey_rp_id"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class PendingEnrollmentInfo {
	    id: string;
	    fingerprint: string;
	    requested_at: string;
	    status: string;
	
	    static createFrom(source: any = {}) {
	        return new PendingEnrollmentInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.fingerprint = source["fingerprint"];
	        this.requested_at = source["requested_at"];
	        this.status = source["status"];
	    }
	}
	export class PlatformSRKInfo {
	    present: boolean;
	    algorithm: string;
	    handle: string;
	    policy_enabled: boolean;
	    policy_name?: string;
	    initialized: boolean;
	
	    static createFrom(source: any = {}) {
	        return new PlatformSRKInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.present = source["present"];
	        this.algorithm = source["algorithm"];
	        this.handle = source["handle"];
	        this.policy_enabled = source["policy_enabled"];
	        this.policy_name = source["policy_name"];
	        this.initialized = source["initialized"];
	    }
	}
	export class ProbeResult {
	    library_path: string;
	    display_name: string;
	
	    static createFrom(source: any = {}) {
	        return new ProbeResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.library_path = source["library_path"];
	        this.display_name = source["display_name"];
	    }
	}
	export class ProvisionOptions {
	    mode: string;
	    owner_auth: string;
	    endorsement_auth: string;
	    lockout_auth: string;
	    create_ek: boolean;
	    create_iak: boolean;
	    create_idevid: boolean;
	
	    static createFrom(source: any = {}) {
	        return new ProvisionOptions(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.mode = source["mode"];
	        this.owner_auth = source["owner_auth"];
	        this.endorsement_auth = source["endorsement_auth"];
	        this.lockout_auth = source["lockout_auth"];
	        this.create_ek = source["create_ek"];
	        this.create_iak = source["create_iak"];
	        this.create_idevid = source["create_idevid"];
	    }
	}
	export class QRScanResult {
	    uri: string;
	    display_index: number;
	
	    static createFrom(source: any = {}) {
	        return new QRScanResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.uri = source["uri"];
	        this.display_index = source["display_index"];
	    }
	}
	export class Quote {
	    quote_data: string;
	    signature: string;
	    pcr_digest: string;
	    nonce: string;
	    // Go type: time
	    created_at: any;
	
	    static createFrom(source: any = {}) {
	        return new Quote(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.quote_data = source["quote_data"];
	        this.signature = source["signature"];
	        this.pcr_digest = source["pcr_digest"];
	        this.nonce = source["nonce"];
	        this.created_at = this.convertValues(source["created_at"], null);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class RelyingParty {
	    id: string;
	    name: string;
	    credential_count: number;
	
	    static createFrom(source: any = {}) {
	        return new RelyingParty(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	        this.credential_count = source["credential_count"];
	    }
	}
	export class RemoteBackendInfo {
	    id: string;
	    type: string;
	    hardware_backed: boolean;
	    capabilities: transport.BackendCapabilities;
	
	    static createFrom(source: any = {}) {
	        return new RemoteBackendInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.type = source["type"];
	        this.hardware_backed = source["hardware_backed"];
	        this.capabilities = this.convertValues(source["capabilities"], transport.BackendCapabilities);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class RemoteCertificateInfo {
	    backend: string;
	    key_id: string;
	    subject: string;
	    issuer: string;
	    not_before: string;
	    not_after: string;
	    algorithm: string;
	    is_ca: boolean;
	    is_expired: boolean;
	    fingerprint: string;
	    pem: string;
	
	    static createFrom(source: any = {}) {
	        return new RemoteCertificateInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.backend = source["backend"];
	        this.key_id = source["key_id"];
	        this.subject = source["subject"];
	        this.issuer = source["issuer"];
	        this.not_before = source["not_before"];
	        this.not_after = source["not_after"];
	        this.algorithm = source["algorithm"];
	        this.is_ca = source["is_ca"];
	        this.is_expired = source["is_expired"];
	        this.fingerprint = source["fingerprint"];
	        this.pem = source["pem"];
	    }
	}
	export class RemoteKeyInfo {
	    key_id: string;
	    key_type: string;
	    algorithm: string;
	    backend: string;
	    public_key_pem?: string;
	
	    static createFrom(source: any = {}) {
	        return new RemoteKeyInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.key_id = source["key_id"];
	        this.key_type = source["key_type"];
	        this.algorithm = source["algorithm"];
	        this.backend = source["backend"];
	        this.public_key_pem = source["public_key_pem"];
	    }
	}
	export class RotateFactorRequest {
	    factor_id: string;
	    cert_pem?: string;
	    webauthn_response?: string;
	    piv_cert_pem?: string;
	    piv_slot?: string;
	
	    static createFrom(source: any = {}) {
	        return new RotateFactorRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.factor_id = source["factor_id"];
	        this.cert_pem = source["cert_pem"];
	        this.webauthn_response = source["webauthn_response"];
	        this.piv_cert_pem = source["piv_cert_pem"];
	        this.piv_slot = source["piv_slot"];
	    }
	}
	export class SSHBackendInfo {
	    id: string;
	    display_name: string;
	    category: string;
	    location: string;
	    is_default: boolean;
	
	    static createFrom(source: any = {}) {
	        return new SSHBackendInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.display_name = source["display_name"];
	        this.category = source["category"];
	        this.location = source["location"];
	        this.is_default = source["is_default"];
	    }
	}
	export class SSHConfigHostEntry {
	    alias: string;
	    hostname: string;
	    user: string;
	    port: number;
	    identity_files: string[];
	
	    static createFrom(source: any = {}) {
	        return new SSHConfigHostEntry(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.alias = source["alias"];
	        this.hostname = source["hostname"];
	        this.user = source["user"];
	        this.port = source["port"];
	        this.identity_files = source["identity_files"];
	    }
	}
	export class SSHConnectParams {
	    host: string;
	    port: number;
	    user: string;
	    key_scope: string;
	    key_owner: string;
	    key_name: string;
	    key_source: string;
	    ssh_config_alias: string;
	    local_identity: string;
	
	    static createFrom(source: any = {}) {
	        return new SSHConnectParams(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.host = source["host"];
	        this.port = source["port"];
	        this.user = source["user"];
	        this.key_scope = source["key_scope"];
	        this.key_owner = source["key_owner"];
	        this.key_name = source["key_name"];
	        this.key_source = source["key_source"];
	        this.ssh_config_alias = source["ssh_config_alias"];
	        this.local_identity = source["local_identity"];
	    }
	}
	export class SSHConsoleEndpoint {
	    url: string;
	    token: string;
	
	    static createFrom(source: any = {}) {
	        return new SSHConsoleEndpoint(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.url = source["url"];
	        this.token = source["token"];
	    }
	}
	export class SSHGenerateParams {
	    name: string;
	    algorithm: string;
	    rsa_bits: number;
	    comment: string;
	    backend: string;
	
	    static createFrom(source: any = {}) {
	        return new SSHGenerateParams(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.algorithm = source["algorithm"];
	        this.rsa_bits = source["rsa_bits"];
	        this.comment = source["comment"];
	        this.backend = source["backend"];
	    }
	}
	export class SSHKeyInfo {
	    name: string;
	    algorithm: string;
	    public_key: string;
	    fingerprint: string;
	    comment: string;
	    backend: string;
	    backend_key_id: string;
	    created_at: string;
	
	    static createFrom(source: any = {}) {
	        return new SSHKeyInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.algorithm = source["algorithm"];
	        this.public_key = source["public_key"];
	        this.fingerprint = source["fingerprint"];
	        this.comment = source["comment"];
	        this.backend = source["backend"];
	        this.backend_key_id = source["backend_key_id"];
	        this.created_at = source["created_at"];
	    }
	}
	export class SSHLocalKeyInfo {
	    source: string;
	    path: string;
	    key_type: string;
	    fingerprint: string;
	    comment: string;
	
	    static createFrom(source: any = {}) {
	        return new SSHLocalKeyInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.source = source["source"];
	        this.path = source["path"];
	        this.key_type = source["key_type"];
	        this.fingerprint = source["fingerprint"];
	        this.comment = source["comment"];
	    }
	}
	export class SSHProfileEntry {
	    id: string;
	    name: string;
	    folder_path: string;
	    host: string;
	    port: number;
	    user: string;
	    key_scope: string;
	    key_owner: string;
	    key_name: string;
	    key_source: string;
	    ssh_config_alias: string;
	    local_identity: string;
	    persist_session: boolean;
	    options?: string[];
	    console_mode: string;
	    notes: string;
	    created_at: string;
	    updated_at: string;
	
	    static createFrom(source: any = {}) {
	        return new SSHProfileEntry(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	        this.folder_path = source["folder_path"];
	        this.host = source["host"];
	        this.port = source["port"];
	        this.user = source["user"];
	        this.key_scope = source["key_scope"];
	        this.key_owner = source["key_owner"];
	        this.key_name = source["key_name"];
	        this.key_source = source["key_source"];
	        this.ssh_config_alias = source["ssh_config_alias"];
	        this.local_identity = source["local_identity"];
	        this.persist_session = source["persist_session"];
	        this.options = source["options"];
	        this.console_mode = source["console_mode"];
	        this.notes = source["notes"];
	        this.created_at = source["created_at"];
	        this.updated_at = source["updated_at"];
	    }
	}
	export class SSHProfileParams {
	    id?: string;
	    name: string;
	    folder_path: string;
	    host: string;
	    port: number;
	    user: string;
	    key_scope: string;
	    key_owner: string;
	    key_name: string;
	    key_source: string;
	    ssh_config_alias: string;
	    local_identity: string;
	    persist_session: boolean;
	    options?: string[];
	    console_mode: string;
	    notes: string;
	
	    static createFrom(source: any = {}) {
	        return new SSHProfileParams(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	        this.folder_path = source["folder_path"];
	        this.host = source["host"];
	        this.port = source["port"];
	        this.user = source["user"];
	        this.key_scope = source["key_scope"];
	        this.key_owner = source["key_owner"];
	        this.key_name = source["key_name"];
	        this.key_source = source["key_source"];
	        this.ssh_config_alias = source["ssh_config_alias"];
	        this.local_identity = source["local_identity"];
	        this.persist_session = source["persist_session"];
	        this.options = source["options"];
	        this.console_mode = source["console_mode"];
	        this.notes = source["notes"];
	    }
	}
	export class SSHProfileService {
	
	
	    static createFrom(source: any = {}) {
	        return new SSHProfileService(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	
	    }
	}
	export class SealProtectionStatus {
	    is_locked: boolean;
	    blob_count: number;
	
	    static createFrom(source: any = {}) {
	        return new SealProtectionStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.is_locked = source["is_locked"];
	        this.blob_count = source["blob_count"];
	    }
	}
	export class SealRequest {
	    label: string;
	    data: string;
	    tpm_policy: string;
	    password: string;
	    backend: string;
	    storage_type: string;
	
	    static createFrom(source: any = {}) {
	        return new SealRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.label = source["label"];
	        this.data = source["data"];
	        this.tpm_policy = source["tpm_policy"];
	        this.password = source["password"];
	        this.backend = source["backend"];
	        this.storage_type = source["storage_type"];
	    }
	}
	export class SealService {
	
	
	    static createFrom(source: any = {}) {
	        return new SealService(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	
	    }
	}
	export class SealedBlobEntry {
	    id: string;
	    label: string;
	    size_bytes: number;
	    tpm_policy: string;
	    password_protected: boolean;
	    created_at: string;
	    category: string;
	    backend_id: string;
	    storage_type: string;
	
	    static createFrom(source: any = {}) {
	        return new SealedBlobEntry(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.label = source["label"];
	        this.size_bytes = source["size_bytes"];
	        this.tpm_policy = source["tpm_policy"];
	        this.password_protected = source["password_protected"];
	        this.created_at = source["created_at"];
	        this.category = source["category"];
	        this.backend_id = source["backend_id"];
	        this.storage_type = source["storage_type"];
	    }
	}
	
	export class ServerStatus {
	    running: boolean;
	    version: string;
	    address: string;
	    uptime: string;
	    platform: string;
	    backend_count: number;
	
	    static createFrom(source: any = {}) {
	        return new ServerStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.running = source["running"];
	        this.version = source["version"];
	        this.address = source["address"];
	        this.uptime = source["uptime"];
	        this.platform = source["platform"];
	        this.backend_count = source["backend_count"];
	    }
	}
	export class SetupChoices {
	    mode: string;
	    server_address: string;
	    server_protocol: string;
	    enable_storage: boolean;
	    storage_size_gb: number;
	    storage_passphrase: string;
	    enable_master_password: boolean;
	    master_password: string;
	    tpm_seal_passwords: boolean;
	    password_store_mode: string;
	    so_pin: string;
	    user_pin: string;
	    use_user_pin_as_master: boolean;
	    set_hierarchy_auth: boolean;
	    enable_auto_unseal: boolean;
	    storage_type: string;
	    barrier_password: string;
	    sealer_backend: string;
	    quick_setup: boolean;
	    deployment_mode: string;
	    save_pins_to_store: boolean;
	    so_pin_recorded: boolean;
	    organization_name: string;
	    min_pin_length: number;
	    pin_max_attempts: number;
	    require_encrypted_storage: boolean;
	    require_tpm: boolean;
	    allow_auto_unseal: boolean;
	    allow_theme: boolean;
	    allow_trust_store: boolean;
	    allow_audit_log: boolean;
	    allow_sealed_data: boolean;
	    allow_change_pin: boolean;
	    allow_api_explorer: boolean;
	    api_explorer_sandbox_policy: string;
	    fido2_require_user_presence: boolean;
	    fido2_user_intent_check: boolean;
	    allow_extension: boolean;
	    force_extension_auth: boolean;
	    force_extension_pairing: boolean;
	    force_extension_audit: boolean;
	    allow_configure_extension: boolean;
	
	    static createFrom(source: any = {}) {
	        return new SetupChoices(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.mode = source["mode"];
	        this.server_address = source["server_address"];
	        this.server_protocol = source["server_protocol"];
	        this.enable_storage = source["enable_storage"];
	        this.storage_size_gb = source["storage_size_gb"];
	        this.storage_passphrase = source["storage_passphrase"];
	        this.enable_master_password = source["enable_master_password"];
	        this.master_password = source["master_password"];
	        this.tpm_seal_passwords = source["tpm_seal_passwords"];
	        this.password_store_mode = source["password_store_mode"];
	        this.so_pin = source["so_pin"];
	        this.user_pin = source["user_pin"];
	        this.use_user_pin_as_master = source["use_user_pin_as_master"];
	        this.set_hierarchy_auth = source["set_hierarchy_auth"];
	        this.enable_auto_unseal = source["enable_auto_unseal"];
	        this.storage_type = source["storage_type"];
	        this.barrier_password = source["barrier_password"];
	        this.sealer_backend = source["sealer_backend"];
	        this.quick_setup = source["quick_setup"];
	        this.deployment_mode = source["deployment_mode"];
	        this.save_pins_to_store = source["save_pins_to_store"];
	        this.so_pin_recorded = source["so_pin_recorded"];
	        this.organization_name = source["organization_name"];
	        this.min_pin_length = source["min_pin_length"];
	        this.pin_max_attempts = source["pin_max_attempts"];
	        this.require_encrypted_storage = source["require_encrypted_storage"];
	        this.require_tpm = source["require_tpm"];
	        this.allow_auto_unseal = source["allow_auto_unseal"];
	        this.allow_theme = source["allow_theme"];
	        this.allow_trust_store = source["allow_trust_store"];
	        this.allow_audit_log = source["allow_audit_log"];
	        this.allow_sealed_data = source["allow_sealed_data"];
	        this.allow_change_pin = source["allow_change_pin"];
	        this.allow_api_explorer = source["allow_api_explorer"];
	        this.api_explorer_sandbox_policy = source["api_explorer_sandbox_policy"];
	        this.fido2_require_user_presence = source["fido2_require_user_presence"];
	        this.fido2_user_intent_check = source["fido2_user_intent_check"];
	        this.allow_extension = source["allow_extension"];
	        this.force_extension_auth = source["force_extension_auth"];
	        this.force_extension_pairing = source["force_extension_pairing"];
	        this.force_extension_audit = source["force_extension_audit"];
	        this.allow_configure_extension = source["allow_configure_extension"];
	    }
	}
	export class SetupResult {
	    success: boolean;
	    errors: string[];
	    warnings: string[];
	    setup_complete: boolean;
	
	    static createFrom(source: any = {}) {
	        return new SetupResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.success = source["success"];
	        this.errors = source["errors"];
	        this.warnings = source["warnings"];
	        this.setup_complete = source["setup_complete"];
	    }
	}
	export class SharedSRKInfo {
	    present: boolean;
	    algorithm: string;
	    handle: string;
	
	    static createFrom(source: any = {}) {
	        return new SharedSRKInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.present = source["present"];
	        this.algorithm = source["algorithm"];
	        this.handle = source["handle"];
	    }
	}
	export class SlotOccupancyInfo {
	    slot: string;
	    name: string;
	    description: string;
	    occupied: boolean;
	    key_algorithm?: string;
	    has_cert: boolean;
	
	    static createFrom(source: any = {}) {
	        return new SlotOccupancyInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.slot = source["slot"];
	        this.name = source["name"];
	        this.description = source["description"];
	        this.occupied = source["occupied"];
	        this.key_algorithm = source["key_algorithm"];
	        this.has_cert = source["has_cert"];
	    }
	}
	export class StartupState {
	    setup_complete: boolean;
	    enterprise_mode: boolean;
	    enterprise_wizard_mode: string;
	    so_pin_set: boolean;
	    user_pin_set: boolean;
	    policy_verified: boolean;
	
	    static createFrom(source: any = {}) {
	        return new StartupState(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.setup_complete = source["setup_complete"];
	        this.enterprise_mode = source["enterprise_mode"];
	        this.enterprise_wizard_mode = source["enterprise_wizard_mode"];
	        this.so_pin_set = source["so_pin_set"];
	        this.user_pin_set = source["user_pin_set"];
	        this.policy_verified = source["policy_verified"];
	    }
	}
	export class StaticPasswordEntry {
	    id: string;
	    name: string;
	    title: string;
	    username: string;
	    password: string;
	    url: string;
	    match_patterns?: string[];
	    notes: string;
	    folder_path: string;
	    expires_at?: string;
	    created_at: string;
	    updated_at: string;
	    is_expired: boolean;
	    days_until_expiry: number;
	    read_only: boolean;
	
	    static createFrom(source: any = {}) {
	        return new StaticPasswordEntry(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	        this.title = source["title"];
	        this.username = source["username"];
	        this.password = source["password"];
	        this.url = source["url"];
	        this.match_patterns = source["match_patterns"];
	        this.notes = source["notes"];
	        this.folder_path = source["folder_path"];
	        this.expires_at = source["expires_at"];
	        this.created_at = source["created_at"];
	        this.updated_at = source["updated_at"];
	        this.is_expired = source["is_expired"];
	        this.days_until_expiry = source["days_until_expiry"];
	        this.read_only = source["read_only"];
	    }
	}
	export class StaticPasswordService {
	
	
	    static createFrom(source: any = {}) {
	        return new StaticPasswordService(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	
	    }
	}
	export class StorageService {
	
	
	    static createFrom(source: any = {}) {
	        return new StorageService(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	
	    }
	}
	export class StorageStatus {
	    volume_exists: boolean;
	    is_luks: boolean;
	    is_mounted: boolean;
	    is_open: boolean;
	    volume_path: string;
	    mount_point: string;
	    volume_size_bytes?: number;
	    elevation_available: boolean;
	
	    static createFrom(source: any = {}) {
	        return new StorageStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.volume_exists = source["volume_exists"];
	        this.is_luks = source["is_luks"];
	        this.is_mounted = source["is_mounted"];
	        this.is_open = source["is_open"];
	        this.volume_path = source["volume_path"];
	        this.mount_point = source["mount_point"];
	        this.volume_size_bytes = source["volume_size_bytes"];
	        this.elevation_available = source["elevation_available"];
	    }
	}
	export class SupportedKeyTypes {
	    algorithms: string[];
	    purposes: string[];
	    curves: string[];
	    key_sizes: number[];
	
	    static createFrom(source: any = {}) {
	        return new SupportedKeyTypes(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.algorithms = source["algorithms"];
	        this.purposes = source["purposes"];
	        this.curves = source["curves"];
	        this.key_sizes = source["key_sizes"];
	    }
	}
	export class TOTPCode {
	    code: string;
	    time_left: number;
	    period: number;
	    account_id: string;
	
	    static createFrom(source: any = {}) {
	        return new TOTPCode(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.code = source["code"];
	        this.time_left = source["time_left"];
	        this.period = source["period"];
	        this.account_id = source["account_id"];
	    }
	}
	export class TPMAccessor {
	
	
	    static createFrom(source: any = {}) {
	        return new TPMAccessor(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	
	    }
	}
	export class TPMAuthorityInfo {
	    generation: number;
	    authority_name: string;
	    epoch: number;
	
	    static createFrom(source: any = {}) {
	        return new TPMAuthorityInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.generation = source["generation"];
	        this.authority_name = source["authority_name"];
	        this.epoch = source["epoch"];
	    }
	}
	export class TPMClearRequest {
	    lockout_auth: string;
	    force: boolean;
	    sudo_password: string;
	
	    static createFrom(source: any = {}) {
	        return new TPMClearRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.lockout_auth = source["lockout_auth"];
	        this.force = source["force"];
	        this.sudo_password = source["sudo_password"];
	    }
	}
	export class TPMClearResult {
	    success: boolean;
	    message: string;
	    reboot_required: boolean;
	
	    static createFrom(source: any = {}) {
	        return new TPMClearResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.success = source["success"];
	        this.message = source["message"];
	        this.reboot_required = source["reboot_required"];
	    }
	}
	export class TPMInfo {
	    manufacturer: string;
	    vendor_id: string;
	    manufacturer_id?: string;
	    firmware_version: string;
	    family: string;
	    level: number;
	    revision: string;
	    version?: string;
	    max_rsa_key_size: number;
	    max_ecc_key_size: number;
	    pcr_banks: string[];
	    algorithms: string[];
	    fips_mode: boolean;
	    capabilities: string[];
	    max_nv_buffer_size: number;
	    lockout_counter: number;
	    max_auth_fail: number;
	    model: string;
	    active_sessions_max: number;
	    auth_sessions_loaded: number;
	    auth_sessions_active: number;
	    persistent_loaded: number;
	    persistent_avail: number;
	    transient_avail: number;
	    nv_indexes_defined: number;
	    nv_indexes_max: number;
	    commands: tpm2.CommandInfo[];
	    ecc_curves: string[];
	    input_buffer_max: number;
	    max_digest_size: number;
	    max_object_context: number;
	    lockout_interval: number;
	    lockout_recovery: number;
	    fixed_properties?: tpm2.TPMProperty[];
	    variable_properties?: tpm2.TPMProperty[];
	
	    static createFrom(source: any = {}) {
	        return new TPMInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.manufacturer = source["manufacturer"];
	        this.vendor_id = source["vendor_id"];
	        this.manufacturer_id = source["manufacturer_id"];
	        this.firmware_version = source["firmware_version"];
	        this.family = source["family"];
	        this.level = source["level"];
	        this.revision = source["revision"];
	        this.version = source["version"];
	        this.max_rsa_key_size = source["max_rsa_key_size"];
	        this.max_ecc_key_size = source["max_ecc_key_size"];
	        this.pcr_banks = source["pcr_banks"];
	        this.algorithms = source["algorithms"];
	        this.fips_mode = source["fips_mode"];
	        this.capabilities = source["capabilities"];
	        this.max_nv_buffer_size = source["max_nv_buffer_size"];
	        this.lockout_counter = source["lockout_counter"];
	        this.max_auth_fail = source["max_auth_fail"];
	        this.model = source["model"];
	        this.active_sessions_max = source["active_sessions_max"];
	        this.auth_sessions_loaded = source["auth_sessions_loaded"];
	        this.auth_sessions_active = source["auth_sessions_active"];
	        this.persistent_loaded = source["persistent_loaded"];
	        this.persistent_avail = source["persistent_avail"];
	        this.transient_avail = source["transient_avail"];
	        this.nv_indexes_defined = source["nv_indexes_defined"];
	        this.nv_indexes_max = source["nv_indexes_max"];
	        this.commands = this.convertValues(source["commands"], tpm2.CommandInfo);
	        this.ecc_curves = source["ecc_curves"];
	        this.input_buffer_max = source["input_buffer_max"];
	        this.max_digest_size = source["max_digest_size"];
	        this.max_object_context = source["max_object_context"];
	        this.lockout_interval = source["lockout_interval"];
	        this.lockout_recovery = source["lockout_recovery"];
	        this.fixed_properties = this.convertValues(source["fixed_properties"], tpm2.TPMProperty);
	        this.variable_properties = this.convertValues(source["variable_properties"], tpm2.TPMProperty);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class TPMKey {
	    id: string;
	    algorithm: string;
	    key_size: number;
	    persistent: boolean;
	    purpose: string;
	
	    static createFrom(source: any = {}) {
	        return new TPMKey(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.algorithm = source["algorithm"];
	        this.key_size = source["key_size"];
	        this.persistent = source["persistent"];
	        this.purpose = source["purpose"];
	    }
	}
	export class TPMObjectPolicyInfo {
	    object_id: string;
	    kind: string;
	    policy: string;
	    auth_policy?: string;
	    created_at?: string;
	
	    static createFrom(source: any = {}) {
	        return new TPMObjectPolicyInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.object_id = source["object_id"];
	        this.kind = source["kind"];
	        this.policy = source["policy"];
	        this.auth_policy = source["auth_policy"];
	        this.created_at = source["created_at"];
	    }
	}
	export class TPMPolicyInfo {
	    name: string;
	    builtin: boolean;
	    description?: string;
	    branches?: transport.TPMPolicyBranch[];
	    index?: number;
	    approved: boolean;
	    epoch?: number;
	    authority_generation?: number;
	    auto_unseal: boolean;
	    object_count: number;
	    created_at?: string;
	    updated_at?: string;
	
	    static createFrom(source: any = {}) {
	        return new TPMPolicyInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.builtin = source["builtin"];
	        this.description = source["description"];
	        this.branches = this.convertValues(source["branches"], transport.TPMPolicyBranch);
	        this.index = source["index"];
	        this.approved = source["approved"];
	        this.epoch = source["epoch"];
	        this.authority_generation = source["authority_generation"];
	        this.auto_unseal = source["auto_unseal"];
	        this.object_count = source["object_count"];
	        this.created_at = source["created_at"];
	        this.updated_at = source["updated_at"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class TPMPolicyService {
	
	
	    static createFrom(source: any = {}) {
	        return new TPMPolicyService(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	
	    }
	}
	export class TPMPolicyStatus {
	    available: boolean;
	    mode: string;
	    scope: string;
	
	    static createFrom(source: any = {}) {
	        return new TPMPolicyStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.available = source["available"];
	        this.mode = source["mode"];
	        this.scope = source["scope"];
	    }
	}
	export class TPMPolicyVerification {
	    name: string;
	    match: boolean;
	    approved: boolean;
	    branches: transport.TPMPolicyBranchVerification[];
	
	    static createFrom(source: any = {}) {
	        return new TPMPolicyVerification(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.match = source["match"];
	        this.approved = source["approved"];
	        this.branches = this.convertValues(source["branches"], transport.TPMPolicyBranchVerification);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class TPMService {
	
	
	    static createFrom(source: any = {}) {
	        return new TPMService(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	
	    }
	}
	export class TPMStatus {
	    available: boolean;
	    device_exists: boolean;
	    provisioned: boolean;
	    status_level: string;
	    manufacturer: string;
	    firmware_version: string;
	    device_path: string;
	    init_error?: string;
	
	    static createFrom(source: any = {}) {
	        return new TPMStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.available = source["available"];
	        this.device_exists = source["device_exists"];
	        this.provisioned = source["provisioned"];
	        this.status_level = source["status_level"];
	        this.manufacturer = source["manufacturer"];
	        this.firmware_version = source["firmware_version"];
	        this.device_path = source["device_path"];
	        this.init_error = source["init_error"];
	    }
	}
	export class TeamInfo {
	    id: number;
	    name: string;
	    tenant_id: string;
	    owner_id: string;
	    members: string[];
	    created_at: string;
	    updated_at: string;
	
	    static createFrom(source: any = {}) {
	        return new TeamInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	        this.tenant_id = source["tenant_id"];
	        this.owner_id = source["owner_id"];
	        this.members = source["members"];
	        this.created_at = source["created_at"];
	        this.updated_at = source["updated_at"];
	    }
	}
	export class TenantInfo {
	    id: string;
	    name: string;
	    created_at: string;
	    updated_at: string;
	
	    static createFrom(source: any = {}) {
	        return new TenantInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	        this.created_at = source["created_at"];
	        this.updated_at = source["updated_at"];
	    }
	}
	export class TrustCertInfo {
	    fingerprint: string;
	    subject: string;
	    issuer: string;
	    algorithm: string;
	    not_before: string;
	    not_after: string;
	    is_ca: boolean;
	    is_expired: boolean;
	    purpose: string;
	    source: string;
	    tags: string[];
	    system_installed: boolean;
	
	    static createFrom(source: any = {}) {
	        return new TrustCertInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.fingerprint = source["fingerprint"];
	        this.subject = source["subject"];
	        this.issuer = source["issuer"];
	        this.algorithm = source["algorithm"];
	        this.not_before = source["not_before"];
	        this.not_after = source["not_after"];
	        this.is_ca = source["is_ca"];
	        this.is_expired = source["is_expired"];
	        this.purpose = source["purpose"];
	        this.source = source["source"];
	        this.tags = source["tags"];
	        this.system_installed = source["system_installed"];
	    }
	}
	export class TrustStrapImportRequest {
	    method: string;
	    server: string;
	    bundle_path: string;
	    dns_server: string;
	    dns_over_tls: boolean;
	    server_static_key: string;
	    spki_pin_sha256: string;
	
	    static createFrom(source: any = {}) {
	        return new TrustStrapImportRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.method = source["method"];
	        this.server = source["server"];
	        this.bundle_path = source["bundle_path"];
	        this.dns_server = source["dns_server"];
	        this.dns_over_tls = source["dns_over_tls"];
	        this.server_static_key = source["server_static_key"];
	        this.spki_pin_sha256 = source["spki_pin_sha256"];
	    }
	}
	export class UnlockOutcome {
	    Unlocked: string[];
	    StillLocked: string[];
	
	    static createFrom(source: any = {}) {
	        return new UnlockOutcome(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Unlocked = source["Unlocked"];
	        this.StillLocked = source["StillLocked"];
	    }
	}
	export class UpdatePasswordParams {
	    id: string;
	    name: string;
	    title: string;
	    username: string;
	    password: string;
	    url: string;
	    match_patterns?: string[];
	    notes: string;
	    folder_path: string;
	    expires_at: string;
	
	    static createFrom(source: any = {}) {
	        return new UpdatePasswordParams(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	        this.title = source["title"];
	        this.username = source["username"];
	        this.password = source["password"];
	        this.url = source["url"];
	        this.match_patterns = source["match_patterns"];
	        this.notes = source["notes"];
	        this.folder_path = source["folder_path"];
	        this.expires_at = source["expires_at"];
	    }
	}
	export class UserOnboardingChoices {
	    so_pin: string;
	    user_pin: string;
	    barrier_password: string;
	
	    static createFrom(source: any = {}) {
	        return new UserOnboardingChoices(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.so_pin = source["so_pin"];
	        this.user_pin = source["user_pin"];
	        this.barrier_password = source["barrier_password"];
	    }
	}
	export class VerificationStatus {
	    verified: boolean;
	    issuer?: string;
	    error_message?: string;
	
	    static createFrom(source: any = {}) {
	        return new VerificationStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.verified = source["verified"];
	        this.issuer = source["issuer"];
	        this.error_message = source["error_message"];
	    }
	}
	export class YubiKeyDetectionResult {
	    found: boolean;
	    library_path?: string;
	    error?: string;
	
	    static createFrom(source: any = {}) {
	        return new YubiKeyDetectionResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.found = source["found"];
	        this.library_path = source["library_path"];
	        this.error = source["error"];
	    }
	}

}

export namespace sessions {
	
	export class Session {
	    id: string;
	    title: string;
	    host?: string;
	    port?: number;
	    user?: string;
	    key_scope?: string;
	    key_owner?: string;
	    key_name?: string;
	    key_source?: string;
	    local_identity?: string;
	    profile_id?: string;
	    alias?: string;
	    // Go type: time
	    created_at: any;
	    // Go type: time
	    last_connected_at: any;
	
	    static createFrom(source: any = {}) {
	        return new Session(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.title = source["title"];
	        this.host = source["host"];
	        this.port = source["port"];
	        this.user = source["user"];
	        this.key_scope = source["key_scope"];
	        this.key_owner = source["key_owner"];
	        this.key_name = source["key_name"];
	        this.key_source = source["key_source"];
	        this.local_identity = source["local_identity"];
	        this.profile_id = source["profile_id"];
	        this.alias = source["alias"];
	        this.created_at = this.convertValues(source["created_at"], null);
	        this.last_connected_at = this.convertValues(source["last_connected_at"], null);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace slog {
	
	export class Logger {
	
	
	    static createFrom(source: any = {}) {
	        return new Logger(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	
	    }
	}

}

export namespace staticpw {
	
	export class StaticPassword {
	    id: string;
	    name: string;
	    title?: string;
	    username?: string;
	    password: string;
	    url?: string;
	    match_patterns?: string[];
	    notes?: string;
	    folder_path?: string;
	    // Go type: time
	    expires_at?: any;
	    // Go type: time
	    created_at: any;
	    // Go type: time
	    updated_at: any;
	    read_only?: boolean;
	    owner_id?: string;
	    shared?: boolean;
	    attributes?: Record<string, string>;
	
	    static createFrom(source: any = {}) {
	        return new StaticPassword(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	        this.title = source["title"];
	        this.username = source["username"];
	        this.password = source["password"];
	        this.url = source["url"];
	        this.match_patterns = source["match_patterns"];
	        this.notes = source["notes"];
	        this.folder_path = source["folder_path"];
	        this.expires_at = this.convertValues(source["expires_at"], null);
	        this.created_at = this.convertValues(source["created_at"], null);
	        this.updated_at = this.convertValues(source["updated_at"], null);
	        this.read_only = source["read_only"];
	        this.owner_id = source["owner_id"];
	        this.shared = source["shared"];
	        this.attributes = source["attributes"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace tls {
	
	export class Certificate {
	    Certificate: number[][];
	    PrivateKey: any;
	    SupportedSignatureAlgorithms: number[];
	    OCSPStaple: number[];
	    SignedCertificateTimestamps: number[][];
	    Leaf?: x509.Certificate;
	
	    static createFrom(source: any = {}) {
	        return new Certificate(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Certificate = source["Certificate"];
	        this.PrivateKey = source["PrivateKey"];
	        this.SupportedSignatureAlgorithms = source["SupportedSignatureAlgorithms"];
	        this.OCSPStaple = source["OCSPStaple"];
	        this.SignedCertificateTimestamps = source["SignedCertificateTimestamps"];
	        this.Leaf = this.convertValues(source["Leaf"], x509.Certificate);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace tpm2 {
	
	export class CommandInfo {
	    code: string;
	    name: string;
	    description: string;
	
	    static createFrom(source: any = {}) {
	        return new CommandInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.code = source["code"];
	        this.name = source["name"];
	        this.description = source["description"];
	    }
	}
	export class TPMProperty {
	    name: string;
	    raw: string;
	    value: string;
	
	    static createFrom(source: any = {}) {
	        return new TPMProperty(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.raw = source["raw"];
	        this.value = source["value"];
	    }
	}

}

export namespace transport {
	
	export class BackendCapabilities {
	    Keys: boolean;
	    HardwareBacked: boolean;
	    Signing: boolean;
	    Decryption: boolean;
	    KeyRotation: boolean;
	    SymmetricEncryption: boolean;
	    Sealing: boolean;
	    Import: boolean;
	    Export: boolean;
	    KeyAgreement: boolean;
	    ECIES: boolean;
	    Attestation: boolean;
	    QuantumSigning: boolean;
	    KeyEncapsulation: boolean;
	
	    static createFrom(source: any = {}) {
	        return new BackendCapabilities(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Keys = source["Keys"];
	        this.HardwareBacked = source["HardwareBacked"];
	        this.Signing = source["Signing"];
	        this.Decryption = source["Decryption"];
	        this.KeyRotation = source["KeyRotation"];
	        this.SymmetricEncryption = source["SymmetricEncryption"];
	        this.Sealing = source["Sealing"];
	        this.Import = source["Import"];
	        this.Export = source["Export"];
	        this.KeyAgreement = source["KeyAgreement"];
	        this.ECIES = source["ECIES"];
	        this.Attestation = source["Attestation"];
	        this.QuantumSigning = source["QuantumSigning"];
	        this.KeyEncapsulation = source["KeyEncapsulation"];
	    }
	}
	export class HealthResponse {
	    status: string;
	    version?: string;
	    message?: string;
	
	    static createFrom(source: any = {}) {
	        return new HealthResponse(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.status = source["status"];
	        this.version = source["version"];
	        this.message = source["message"];
	    }
	}
	export class OIDCCredentialConfig {
	    template?: string;
	    issuer?: string;
	    client_id?: string;
	    client_secret?: string;
	    scopes?: string[];
	    authorization_endpoint?: string;
	    token_endpoint?: string;
	    device_authorization_endpoint?: string;
	    token_encoding?: string;
	    device_style?: string;
	    no_refresh?: boolean;
	    token_lifetime_seconds?: number;
	    refresh_margin_seconds?: number;
	
	    static createFrom(source: any = {}) {
	        return new OIDCCredentialConfig(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.template = source["template"];
	        this.issuer = source["issuer"];
	        this.client_id = source["client_id"];
	        this.client_secret = source["client_secret"];
	        this.scopes = source["scopes"];
	        this.authorization_endpoint = source["authorization_endpoint"];
	        this.token_endpoint = source["token_endpoint"];
	        this.device_authorization_endpoint = source["device_authorization_endpoint"];
	        this.token_encoding = source["token_encoding"];
	        this.device_style = source["device_style"];
	        this.no_refresh = source["no_refresh"];
	        this.token_lifetime_seconds = source["token_lifetime_seconds"];
	        this.refresh_margin_seconds = source["refresh_margin_seconds"];
	    }
	}
	export class OIDCCredentialRef {
	    tenant_id?: string;
	    scope: string;
	    owner?: string;
	    name: string;
	
	    static createFrom(source: any = {}) {
	        return new OIDCCredentialRef(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.tenant_id = source["tenant_id"];
	        this.scope = source["scope"];
	        this.owner = source["owner"];
	        this.name = source["name"];
	    }
	}
	export class TPMPolicyCondition {
	    type: string;
	    bank?: string;
	    pcrs?: number[];
	    pcr_values?: Record<number, string>;
	    pcr_digest?: string;
	    localities?: number[];
	
	    static createFrom(source: any = {}) {
	        return new TPMPolicyCondition(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.type = source["type"];
	        this.bank = source["bank"];
	        this.pcrs = source["pcrs"];
	        this.pcr_values = source["pcr_values"];
	        this.pcr_digest = source["pcr_digest"];
	        this.localities = source["localities"];
	    }
	}
	export class TPMPolicyBranch {
	    conditions: TPMPolicyCondition[];
	    approved: boolean;
	
	    static createFrom(source: any = {}) {
	        return new TPMPolicyBranch(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.conditions = this.convertValues(source["conditions"], TPMPolicyCondition);
	        this.approved = source["approved"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class TPMPolicyBranchVerification {
	    match: boolean;
	    mismatched?: number[];
	    approved: boolean;
	
	    static createFrom(source: any = {}) {
	        return new TPMPolicyBranchVerification(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.match = source["match"];
	        this.mismatched = source["mismatched"];
	        this.approved = source["approved"];
	    }
	}

}

export namespace url {
	
	export class Userinfo {
	
	
	    static createFrom(source: any = {}) {
	        return new Userinfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	
	    }
	}
	export class URL {
	    Scheme: string;
	    Opaque: string;
	    // Go type: Userinfo
	    User?: any;
	    Host: string;
	    Path: string;
	    Fragment: string;
	    RawQuery: string;
	    RawPath: string;
	    RawFragment: string;
	    ForceQuery: boolean;
	    OmitHost: boolean;
	
	    static createFrom(source: any = {}) {
	        return new URL(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Scheme = source["Scheme"];
	        this.Opaque = source["Opaque"];
	        this.User = this.convertValues(source["User"], null);
	        this.Host = source["Host"];
	        this.Path = source["Path"];
	        this.Fragment = source["Fragment"];
	        this.RawQuery = source["RawQuery"];
	        this.RawPath = source["RawPath"];
	        this.RawFragment = source["RawFragment"];
	        this.ForceQuery = source["ForceQuery"];
	        this.OmitHost = source["OmitHost"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace x509 {
	
	export class PolicyMapping {
	    // Go type: OID
	    IssuerDomainPolicy: any;
	    // Go type: OID
	    SubjectDomainPolicy: any;
	
	    static createFrom(source: any = {}) {
	        return new PolicyMapping(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.IssuerDomainPolicy = this.convertValues(source["IssuerDomainPolicy"], null);
	        this.SubjectDomainPolicy = this.convertValues(source["SubjectDomainPolicy"], null);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class OID {
	
	
	    static createFrom(source: any = {}) {
	        return new OID(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	
	    }
	}
	export class Certificate {
	    Raw: number[];
	    RawTBSCertificate: number[];
	    RawSubjectPublicKeyInfo: number[];
	    RawSubject: number[];
	    RawIssuer: number[];
	    RawSignatureAlgorithm: number[];
	    Signature: number[];
	    SignatureAlgorithm: number;
	    PublicKeyAlgorithm: number;
	    PublicKey: any;
	    Version: number;
	    // Go type: big
	    SerialNumber?: any;
	    Issuer: pkix.Name;
	    Subject: pkix.Name;
	    // Go type: time
	    NotBefore: any;
	    // Go type: time
	    NotAfter: any;
	    KeyUsage: number;
	    Extensions: pkix.Extension[];
	    ExtraExtensions: pkix.Extension[];
	    UnhandledCriticalExtensions: number[][];
	    ExtKeyUsage: number[];
	    UnknownExtKeyUsage: number[][];
	    BasicConstraintsValid: boolean;
	    IsCA: boolean;
	    MaxPathLen: number;
	    MaxPathLenZero: boolean;
	    SubjectKeyId: number[];
	    AuthorityKeyId: number[];
	    OCSPServer: string[];
	    IssuingCertificateURL: string[];
	    DNSNames: string[];
	    EmailAddresses: string[];
	    IPAddresses: number[][];
	    URIs: url.URL[];
	    PermittedDNSDomainsCritical: boolean;
	    PermittedDNSDomains: string[];
	    ExcludedDNSDomains: string[];
	    PermittedIPRanges: net.IPNet[];
	    ExcludedIPRanges: net.IPNet[];
	    PermittedEmailAddresses: string[];
	    ExcludedEmailAddresses: string[];
	    PermittedURIDomains: string[];
	    ExcludedURIDomains: string[];
	    CRLDistributionPoints: string[];
	    PolicyIdentifiers: number[][];
	    Policies: OID[];
	    InhibitAnyPolicy: number;
	    InhibitAnyPolicyZero: boolean;
	    InhibitPolicyMapping: number;
	    InhibitPolicyMappingZero: boolean;
	    RequireExplicitPolicy: number;
	    RequireExplicitPolicyZero: boolean;
	    PolicyMappings: PolicyMapping[];
	
	    static createFrom(source: any = {}) {
	        return new Certificate(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Raw = source["Raw"];
	        this.RawTBSCertificate = source["RawTBSCertificate"];
	        this.RawSubjectPublicKeyInfo = source["RawSubjectPublicKeyInfo"];
	        this.RawSubject = source["RawSubject"];
	        this.RawIssuer = source["RawIssuer"];
	        this.RawSignatureAlgorithm = source["RawSignatureAlgorithm"];
	        this.Signature = source["Signature"];
	        this.SignatureAlgorithm = source["SignatureAlgorithm"];
	        this.PublicKeyAlgorithm = source["PublicKeyAlgorithm"];
	        this.PublicKey = source["PublicKey"];
	        this.Version = source["Version"];
	        this.SerialNumber = this.convertValues(source["SerialNumber"], null);
	        this.Issuer = this.convertValues(source["Issuer"], pkix.Name);
	        this.Subject = this.convertValues(source["Subject"], pkix.Name);
	        this.NotBefore = this.convertValues(source["NotBefore"], null);
	        this.NotAfter = this.convertValues(source["NotAfter"], null);
	        this.KeyUsage = source["KeyUsage"];
	        this.Extensions = this.convertValues(source["Extensions"], pkix.Extension);
	        this.ExtraExtensions = this.convertValues(source["ExtraExtensions"], pkix.Extension);
	        this.UnhandledCriticalExtensions = source["UnhandledCriticalExtensions"];
	        this.ExtKeyUsage = source["ExtKeyUsage"];
	        this.UnknownExtKeyUsage = source["UnknownExtKeyUsage"];
	        this.BasicConstraintsValid = source["BasicConstraintsValid"];
	        this.IsCA = source["IsCA"];
	        this.MaxPathLen = source["MaxPathLen"];
	        this.MaxPathLenZero = source["MaxPathLenZero"];
	        this.SubjectKeyId = source["SubjectKeyId"];
	        this.AuthorityKeyId = source["AuthorityKeyId"];
	        this.OCSPServer = source["OCSPServer"];
	        this.IssuingCertificateURL = source["IssuingCertificateURL"];
	        this.DNSNames = source["DNSNames"];
	        this.EmailAddresses = source["EmailAddresses"];
	        this.IPAddresses = source["IPAddresses"];
	        this.URIs = this.convertValues(source["URIs"], url.URL);
	        this.PermittedDNSDomainsCritical = source["PermittedDNSDomainsCritical"];
	        this.PermittedDNSDomains = source["PermittedDNSDomains"];
	        this.ExcludedDNSDomains = source["ExcludedDNSDomains"];
	        this.PermittedIPRanges = this.convertValues(source["PermittedIPRanges"], net.IPNet);
	        this.ExcludedIPRanges = this.convertValues(source["ExcludedIPRanges"], net.IPNet);
	        this.PermittedEmailAddresses = source["PermittedEmailAddresses"];
	        this.ExcludedEmailAddresses = source["ExcludedEmailAddresses"];
	        this.PermittedURIDomains = source["PermittedURIDomains"];
	        this.ExcludedURIDomains = source["ExcludedURIDomains"];
	        this.CRLDistributionPoints = source["CRLDistributionPoints"];
	        this.PolicyIdentifiers = source["PolicyIdentifiers"];
	        this.Policies = this.convertValues(source["Policies"], OID);
	        this.InhibitAnyPolicy = source["InhibitAnyPolicy"];
	        this.InhibitAnyPolicyZero = source["InhibitAnyPolicyZero"];
	        this.InhibitPolicyMapping = source["InhibitPolicyMapping"];
	        this.InhibitPolicyMappingZero = source["InhibitPolicyMappingZero"];
	        this.RequireExplicitPolicy = source["RequireExplicitPolicy"];
	        this.RequireExplicitPolicyZero = source["RequireExplicitPolicyZero"];
	        this.PolicyMappings = this.convertValues(source["PolicyMappings"], PolicyMapping);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

