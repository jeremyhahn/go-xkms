// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

// This file re-exports gRPC protobuf types from pkg/api/grpc/proto/xkmsv1
// so that downstream consumers can implement xkms gRPC servers without
// importing internal packages directly.

package xkms

import (
	xkmspb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"google.golang.org/grpc"
)

// ==========================================================================
// gRPC Service Registration
// ==========================================================================

// ProtoRegisterKeystoreServiceServer registers a KeystoreServiceServer with a gRPC server.
var ProtoRegisterKeystoreServiceServer = xkmspb.RegisterKeystoreServiceServer

// ProtoUnimplementedKeystoreServiceServer is the embedded type for
// forward-compatible gRPC server implementations.
type ProtoUnimplementedKeystoreServiceServer = xkmspb.UnimplementedKeystoreServiceServer

// ProtoKeystoreServiceServer is the interface that gRPC server implementations must satisfy.
type ProtoKeystoreServiceServer = xkmspb.KeystoreServiceServer

// ==========================================================================
// Health
// ==========================================================================

// ProtoHealthRequest is the gRPC health check request.
type ProtoHealthRequest = xkmspb.HealthRequest

// ProtoHealthResponse is the gRPC health check response.
type ProtoHealthResponse = xkmspb.HealthResponse

// ==========================================================================
// Key Management
// ==========================================================================

// ProtoGenerateKeyRequest is the gRPC key generation request.
type ProtoGenerateKeyRequest = xkmspb.GenerateKeyRequest

// ProtoGenerateKeyResponse is the gRPC key generation response.
type ProtoGenerateKeyResponse = xkmspb.GenerateKeyResponse

// ProtoGetKeyRequest is the gRPC key retrieval request.
type ProtoGetKeyRequest = xkmspb.GetKeyRequest

// ProtoGetKeyResponse is the gRPC key retrieval response.
type ProtoGetKeyResponse = xkmspb.GetKeyResponse

// ProtoDeleteKeyRequest is the gRPC key deletion request.
type ProtoDeleteKeyRequest = xkmspb.DeleteKeyRequest

// ProtoDeleteKeyResponse is the gRPC key deletion response.
type ProtoDeleteKeyResponse = xkmspb.DeleteKeyResponse

// ProtoRotateKeyRequest is the gRPC key rotation request.
type ProtoRotateKeyRequest = xkmspb.RotateKeyRequest

// ProtoRotateKeyResponse is the gRPC key rotation response.
type ProtoRotateKeyResponse = xkmspb.RotateKeyResponse

// ProtoListKeysRequest is the gRPC key listing request.
type ProtoListKeysRequest = xkmspb.ListKeysRequest

// ProtoListKeysResponse is the gRPC key listing response.
type ProtoListKeysResponse = xkmspb.ListKeysResponse

// ProtoKeyInfo describes key metadata in gRPC responses.
type ProtoKeyInfo = xkmspb.KeyInfo

// ==========================================================================
// Cryptographic Operations
// ==========================================================================

// ProtoSignRequest is the gRPC sign request.
type ProtoSignRequest = xkmspb.SignRequest

// ProtoSignResponse is the gRPC sign response.
type ProtoSignResponse = xkmspb.SignResponse

// ProtoVerifyRequest is the gRPC verify request.
type ProtoVerifyRequest = xkmspb.VerifyRequest

// ProtoVerifyResponse is the gRPC verify response.
type ProtoVerifyResponse = xkmspb.VerifyResponse

// ProtoEncryptRequest is the gRPC encrypt request.
type ProtoEncryptRequest = xkmspb.EncryptRequest

// ProtoEncryptResponse is the gRPC encrypt response.
type ProtoEncryptResponse = xkmspb.EncryptResponse

// ProtoDecryptRequest is the gRPC decrypt request.
type ProtoDecryptRequest = xkmspb.DecryptRequest

// ProtoDecryptResponse is the gRPC decrypt response.
type ProtoDecryptResponse = xkmspb.DecryptResponse

// ==========================================================================
// Seal / Unseal
// ==========================================================================

// ProtoSealRequest is the gRPC seal request.
type ProtoSealRequest = xkmspb.SealRequest

// ProtoSealResponse is the gRPC seal response.
type ProtoSealResponse = xkmspb.SealResponse

// ProtoUnsealRequest is the gRPC unseal request.
type ProtoUnsealRequest = xkmspb.UnsealRequest

// ProtoUnsealResponse is the gRPC unseal response.
type ProtoUnsealResponse = xkmspb.UnsealResponse

// ProtoCanSealRequest is the gRPC can-seal request.
type ProtoCanSealRequest = xkmspb.CanSealRequest

// ProtoCanSealResponse is the gRPC can-seal response.
type ProtoCanSealResponse = xkmspb.CanSealResponse

// ==========================================================================
// Barrier
// ==========================================================================

// ProtoBarrierInitializeRequest is the gRPC barrier initialization request.
type ProtoBarrierInitializeRequest = xkmspb.BarrierInitializeRequest

// ProtoBarrierUnsealRequest is the gRPC barrier unseal request.
type ProtoBarrierUnsealRequest = xkmspb.BarrierUnsealRequest

// ProtoBarrierStatusResponse is the gRPC barrier status response.
type ProtoBarrierStatusResponse = xkmspb.BarrierStatusResponse

// ==========================================================================
// Backend
// ==========================================================================

// ProtoBackendInfo describes a backend in gRPC responses.
type ProtoBackendInfo = xkmspb.BackendInfo

// ProtoListBackendsRequest is the gRPC backend listing request.
type ProtoListBackendsRequest = xkmspb.ListBackendsRequest

// ProtoListBackendsResponse is the gRPC backend listing response.
type ProtoListBackendsResponse = xkmspb.ListBackendsResponse

// ProtoGetBackendInfoRequest is the gRPC backend info request.
type ProtoGetBackendInfoRequest = xkmspb.GetBackendInfoRequest

// ProtoGetBackendInfoResponse is the gRPC backend info response.
type ProtoGetBackendInfoResponse = xkmspb.GetBackendInfoResponse

// ==========================================================================
// Certificate Management
// ==========================================================================

// ProtoSaveCertRequest is the gRPC certificate save request.
type ProtoSaveCertRequest = xkmspb.SaveCertRequest

// ProtoSaveCertResponse is the gRPC certificate save response.
type ProtoSaveCertResponse = xkmspb.SaveCertResponse

// ProtoGetCertRequest is the gRPC certificate retrieval request.
type ProtoGetCertRequest = xkmspb.GetCertRequest

// ProtoGetCertResponse is the gRPC certificate retrieval response.
type ProtoGetCertResponse = xkmspb.GetCertResponse

// ProtoDeleteCertRequest is the gRPC certificate deletion request.
type ProtoDeleteCertRequest = xkmspb.DeleteCertRequest

// ProtoDeleteCertResponse is the gRPC certificate deletion response.
type ProtoDeleteCertResponse = xkmspb.DeleteCertResponse

// ProtoListCertsRequest is the gRPC certificate listing request.
type ProtoListCertsRequest = xkmspb.ListCertsRequest

// ProtoListCertsResponse is the gRPC certificate listing response.
type ProtoListCertsResponse = xkmspb.ListCertsResponse

// ProtoGetCABundleRequest is the gRPC CA bundle request.
type ProtoGetCABundleRequest = xkmspb.GetCABundleRequest

// ProtoGetCABundleResponse is the gRPC CA bundle response.
type ProtoGetCABundleResponse = xkmspb.GetCABundleResponse

// ==========================================================================
// PIN Management
// ==========================================================================

// ProtoSetSOPINRequest is the gRPC SO PIN set request.
type ProtoSetSOPINRequest = xkmspb.SetSOPINRequest

// ProtoSetUserPINRequest is the gRPC user PIN set request.
type ProtoSetUserPINRequest = xkmspb.SetUserPINRequest

// ProtoChangeSOPINRequest is the gRPC SO PIN change request.
type ProtoChangeSOPINRequest = xkmspb.ChangeSOPINRequest

// ProtoChangeUserPINRequest is the gRPC user PIN change request.
type ProtoChangeUserPINRequest = xkmspb.ChangeUserPINRequest

// ProtoVerifySOPINRequest is the gRPC SO PIN verification request.
type ProtoVerifySOPINRequest = xkmspb.VerifySOPINRequest

// ProtoVerifyUserPINRequest is the gRPC user PIN verification request.
type ProtoVerifyUserPINRequest = xkmspb.VerifyUserPINRequest

// ProtoLockoutStatusResponse is the gRPC lockout status response.
type ProtoLockoutStatusResponse = xkmspb.LockoutStatusResponse

// ProtoResetLockoutRequest is the gRPC lockout reset request.
type ProtoResetLockoutRequest = xkmspb.ResetLockoutRequest

// ==========================================================================
// PIV
// ==========================================================================

// ProtoGeneratePIVKeyRequest is the gRPC PIV key generation request.
type ProtoGeneratePIVKeyRequest = xkmspb.GeneratePIVKeyRequest

// ProtoGeneratePIVKeyResponse is the gRPC PIV key generation response.
type ProtoGeneratePIVKeyResponse = xkmspb.GeneratePIVKeyResponse

// ProtoGeneratePIVCSRRequest is the gRPC PIV CSR generation request.
type ProtoGeneratePIVCSRRequest = xkmspb.GeneratePIVCSRRequest

// ProtoGeneratePIVCSRResponse is the gRPC PIV CSR generation response.
type ProtoGeneratePIVCSRResponse = xkmspb.GeneratePIVCSRResponse

// ProtoGetPIVCertificateRequest is the gRPC PIV certificate retrieval request.
type ProtoGetPIVCertificateRequest = xkmspb.GetPIVCertificateRequest

// ProtoGetPIVCertificateResponse is the gRPC PIV certificate retrieval response.
type ProtoGetPIVCertificateResponse = xkmspb.GetPIVCertificateResponse

// ProtoStorePIVCertificateRequest is the gRPC PIV certificate store request.
type ProtoStorePIVCertificateRequest = xkmspb.StorePIVCertificateRequest

// ProtoDeletePIVCertificateRequest is the gRPC PIV certificate deletion request.
type ProtoDeletePIVCertificateRequest = xkmspb.DeletePIVCertificateRequest

// ProtoListPIVSlotsRequest is the gRPC PIV slot listing request.
type ProtoListPIVSlotsRequest = xkmspb.ListPIVSlotsRequest

// ProtoListPIVSlotsResponse is the gRPC PIV slot listing response.
type ProtoListPIVSlotsResponse = xkmspb.ListPIVSlotsResponse

// ProtoPIVSlotStatus describes a PIV slot's status.
type ProtoPIVSlotStatus = xkmspb.PIVSlotStatus

// ==========================================================================
// Convenience: ProtoRegister wraps RegisterKeystoreServiceServer for shorter calls.
// ==========================================================================

// ProtoRegister registers a KeystoreServiceServer with the given gRPC server.
func ProtoRegister(server *grpc.Server, impl ProtoKeystoreServiceServer) {
	xkmspb.RegisterKeystoreServiceServer(server, impl)
}
