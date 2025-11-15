
# Combined coverage target for packages with hardware dependencies
.PHONY: test-coverage-hardware
test-coverage-hardware:
	@echo "$(CYAN)$(BOLD)→ Running hardware storage tests with coverage...$(RESET)"
	@mkdir -p coverage
	@# Run unit tests with pkcs11 tag
	@go test -tags=pkcs11 -coverprofile=coverage/hardware-unit.out ./pkg/storage/hardware
	@# Display coverage
	@go tool cover -func=coverage/hardware-unit.out | tail -1
	@echo ""
	@echo "Note: Full coverage requires integration tests with SoftHSM"
	@echo "Run: make integration-test-storage (when available)"

