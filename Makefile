.PHONY: contract-ready verify help

help:
	@echo "Targets:"
	@echo "  contract-ready  Verify the vendored AuthScope contract against the OPE capability manifest."
	@echo "                  Must exit 0 before Task 2 may begin. Currently expected to be RED."
	@echo "  verify          Run every available check (contract gate plus future test suites)."

contract-ready:
	scripts/verify-contract.sh

verify: contract-ready
	@echo "verify: no product test suites exist yet (blocked at Task 1 audit checkpoint)."
