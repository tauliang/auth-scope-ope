.PHONY: contract-ready verify e2e help

help:
	@echo "Targets:"
	@echo "  contract-ready  Verify the vendored AuthScope contract against the OPE capability manifest."
	@echo "                  Must exit 0 before Task 2 may begin."
	@echo "  verify          Run every available check (contract gate plus test suites)."
	@echo "  e2e             Run the browser e2e specs against two live instances."
	@echo "                  Tolerant: UI tests skip when no browser is installed."

contract-ready:
	scripts/verify-contract.sh

e2e:
	scripts/run-e2e.sh

verify: contract-ready
	go test -race ./...
	go vet ./...
	node scripts/generate-web-client.mjs --check
	@if [ ! -f web/node_modules/.modules.yaml ] || [ web/pnpm-lock.yaml -nt web/node_modules/.modules.yaml ]; then \
		pnpm --dir web install --frozen-lockfile; \
	fi
	pnpm --dir web lint
	pnpm --dir web typecheck
	pnpm --dir web test:coverage
	pnpm --dir web build
