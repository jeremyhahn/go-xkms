// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package handlers

import (
	"fmt"
	"log"

	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
)

// Example hook implementations demonstrating how to use the order finalization
// hook system. These examples show common use cases like DNS registration,
// device inventory management, and notifications.

// ExampleDNSRegistrationHook demonstrates how to register DNS records when
// certificates are issued. This would typically integrate with your DNS
// server API.
func ExampleDNSRegistrationHook(dnsService interface {
	Register(fqdn, ip string) error
}, internalDomain string) OrderFinalizeHook {
	return func(ctx *OrderFinalizeHookContext) error {
		// Only register DNS for TCG enrollments
		if !ctx.IsTCGCSR || ctx.TCGData == nil {
			return nil
		}

		// Construct FQDN from device identity
		fqdn := fmt.Sprintf("%s-%s.%s",
			ctx.TCGData.ProductModel,
			ctx.TCGData.ProductSerial,
			internalDomain)

		// Register with DNS server
		if err := dnsService.Register(fqdn, ctx.ClientIP); err != nil {
			return caerrors.InternalServerError("failed to register DNS record for %s: %v", fqdn, err)
		}

		log.Printf("Registered DNS record: %s -> %s", fqdn, ctx.ClientIP)
		return nil
	}
}

// ExampleDeviceInventoryHook demonstrates how to save device enrollment
// information to a device inventory system.
func ExampleDeviceInventoryHook(deviceService interface {
	SaveDevice(device interface{}) error
}) OrderFinalizeHook {
	return func(ctx *OrderFinalizeHookContext) error {
		// Only process TCG enrollments
		if !ctx.IsTCGCSR || ctx.TCGData == nil {
			return nil
		}

		// Create device record with all enrollment data
		device := map[string]interface{}{
			"id":           ctx.Certificate.SerialNumber.Uint64(),
			"model":        ctx.TCGData.ProductModel,
			"serial":       ctx.TCGData.ProductSerial,
			"permanent_id": ctx.TCGData.PermanentIdentifier,
			"ek_cert":      ctx.TCGData.EKCertificate,
			"event_log":    ctx.TCGData.EventLog,
			"enrolled_at":  ctx.Certificate.NotBefore,
			"client_ip":    ctx.ClientIP,
		}

		if err := deviceService.SaveDevice(device); err != nil {
			return caerrors.StorageFailureError("failed to save device to inventory: %v", err)
		}

		log.Printf("Saved device to inventory: %s-%s",
			ctx.TCGData.ProductModel,
			ctx.TCGData.ProductSerial)
		return nil
	}
}

// ExampleNotificationHook demonstrates how to send notifications when
// certificates are issued.
func ExampleNotificationHook(notifier interface {
	Send(message string) error
}) OrderFinalizeHook {
	return func(ctx *OrderFinalizeHookContext) error {
		var message string

		if ctx.IsTCGCSR && ctx.TCGData != nil {
			message = fmt.Sprintf(
				"TPM device enrolled: %s-%s (Serial: %s)",
				ctx.TCGData.ProductModel,
				ctx.TCGData.ProductSerial,
				ctx.Certificate.SerialNumber.String(),
			)
		} else {
			message = fmt.Sprintf(
				"Certificate issued: %s (Serial: %s)",
				ctx.Certificate.Subject.CommonName,
				ctx.Certificate.SerialNumber.String(),
			)
		}

		if err := notifier.Send(message); err != nil {
			// Log but don't fail the enrollment if notification fails
			log.Printf("Warning: failed to send notification: %v", err)
			return nil
		}

		return nil
	}
}

// ExamplePolicyEnforcementHook demonstrates how to enforce custom policies
// during certificate issuance.
func ExamplePolicyEnforcementHook() OrderFinalizeHook {
	return func(ctx *OrderFinalizeHookContext) error {
		// Example: Enforce that TPM devices must have specific attributes
		if ctx.IsTCGCSR && ctx.TCGData != nil {
			// Check for minimum event log size
			if len(ctx.TCGData.EventLog) < 100 {
				return caerrors.PolicyViolationError("policy violation: event log too small")
			}

			// Check for required product model prefix
			requiredPrefix := "ACME-"
			if len(ctx.TCGData.ProductModel) < len(requiredPrefix) ||
				ctx.TCGData.ProductModel[:len(requiredPrefix)] != requiredPrefix {
				return caerrors.PolicyViolationError("policy violation: invalid product model prefix")
			}
		}

		// Example: Enforce certificate validity constraints
		if ctx.Certificate.NotAfter.Sub(ctx.Certificate.NotBefore).Hours() > 8760 {
			return caerrors.PolicyViolationError("policy violation: certificate validity exceeds 1 year")
		}

		return nil
	}
}

// ExampleLoggingHook demonstrates how to implement comprehensive audit logging.
func ExampleLoggingHook(auditLogger interface {
	LogCertificateIssuance(data map[string]interface{}) error
}) OrderFinalizeHook {
	return func(ctx *OrderFinalizeHookContext) error {
		logData := map[string]interface{}{
			"timestamp":     ctx.Certificate.NotBefore,
			"serial_number": ctx.Certificate.SerialNumber.String(),
			"subject_cn":    ctx.Certificate.Subject.CommonName,
			"issuer_cn":     ctx.Certificate.Issuer.CommonName,
			"client_ip":     ctx.ClientIP,
			"is_tcg_csr":    ctx.IsTCGCSR,
		}

		if ctx.TCGData != nil {
			logData["product_model"] = ctx.TCGData.ProductModel
			logData["product_serial"] = ctx.TCGData.ProductSerial
			logData["permanent_id"] = ctx.TCGData.PermanentIdentifier
		}

		if ctx.Order != nil {
			logData["order_id"] = ctx.Order.ID
			logData["order_status"] = ctx.Order.Status
		}

		if err := auditLogger.LogCertificateIssuance(logData); err != nil {
			// Log but don't fail if audit logging fails
			log.Printf("Warning: failed to write audit log: %v", err)
		}

		return nil
	}
}

// Example of how to register hooks when creating the ACME server:
//
//	func main() {
//		// Create hook registry
//		hooks := handlers.NewOrderFinalizeHookRegistry()
//
//		// Register DNS hook (if DNS service is available)
//		if dnsService != nil {
//			hooks.Register(handlers.ExampleDNSRegistrationHook(dnsService, "example.com"))
//		}
//
//		// Register device inventory hook
//		if deviceService != nil {
//			hooks.Register(handlers.ExampleDeviceInventoryHook(deviceService))
//		}
//
//		// Register notification hook
//		if notificationService != nil {
//			hooks.Register(handlers.ExampleNotificationHook(notificationService))
//		}
//
//		// Register policy enforcement hook
//		hooks.Register(handlers.ExamplePolicyEnforcementHook())
//
//		// Register audit logging hook
//		if auditLogger != nil {
//			hooks.Register(handlers.ExampleLoggingHook(auditLogger))
//		}
//
//		// Create ACME server with hooks
//		params := &handlers.Params{
//			BaseRESTURI:        "https://acme.example.com",
//			CA:                 ca,
//			CAAIdentities:      []string{"example.com"},
//			ChallengeMap:       challengeMap,
//			Logger:             logger,
//			StorageFactory:     storageFactory,
//			TermsOfService:     "https://example.com/tos",
//			OrderFinalizeHooks: hooks,
//		}
//
//		service, err := handlers.NewRestService(params)
//		if err != nil {
//			log.Fatal(err)
//		}
//
//		// ... start server
//	}
