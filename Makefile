.PHONY: contract-ready verify verify-release integration-real usability-gate e2e help build web-build docker-build clean privacy-check credential-check

GO ?= go
export GOSUMDB=off

help:
	@echo "Targets:"
	@echo "  contract-ready  Verify the vendored AuthScope contract against the OPE capability manifest."
	@echo "                  Must exit 0 before Task 2 may begin."
	@echo "  verify          Run every available check (contract gate plus test suites)."
	@echo "  verify-release  Run every release gate and report PASS/FAIL/BLOCKED per gate."
	@echo "                  The real-integration and usability gates report BLOCKED"
	@echo "                  (not failed) while their real prerequisites are absent;"
	@echo "                  the release is verified only when every gate passes."
	@echo "  integration-real"
	@echo "                  Run the real-integration suite against the pinned real"
	@echo "                  AuthScope, gateway, runtime, kit, and disposable GitHub repo."
	@echo "                  Preflights first and fails closed, naming each absent"
	@echo "                  prerequisite; never substitutes a fake."
	@echo "  usability-gate  Run the first-use usability gate. Fails closed without"
	@echo "                  eight real sessions; use --plan to print the procedure"
	@echo "                  or --results <csv> to verify recorded sessions."
	@echo "  e2e             Run the browser e2e specs against two live instances."
	@echo "                  Tolerant: UI tests skip when no browser is installed."
	@echo "  web-build       Build the web UI bundle into web/dist."
	@echo "  build           Build the Go binary with the web bundle embedded (needs web-build first)."
	@echo "  docker-build    Build the release image (multi-stage: web, then Go)."
	@echo "  privacy-check   Scan every durable surface for seeded secret canaries."
	@echo "  credential-check Prove runtime credentials reach the runner only on the anonymous FD."
	@echo "  clean           Remove build artifacts (never pushed)."

contract-ready:
	scripts/verify-contract.sh

privacy-check:
	scripts/check-secrets.sh

credential-check:
	scripts/check-runtime-leaks.sh

e2e:
	scripts/run-e2e.sh

verify: contract-ready
	$(GO) test -race ./...
	$(GO) vet ./...
	@if [ ! -f web/node_modules/.modules.yaml ] || [ web/pnpm-lock.yaml -nt web/node_modules/.modules.yaml ]; then \
		pnpm --dir web install --frozen-lockfile; \
	fi
	node scripts/generate-web-client.mjs --check
	pnpm --dir web lint
	pnpm --dir web typecheck
	pnpm --dir web test:coverage
	pnpm --dir web build

verify-release:
	scripts/verify-release.sh

integration-real:
	scripts/run-real-integration.sh

usability-gate:
	scripts/run-usability-gate.sh $(USABILITY_ARGS)

web-build:
	pnpm --dir web build

# The embedweb tag embeds web/dist in the binary. Build the web bundle
# first; without it the tag build fails.
build: web-build
	$(GO) build -tags embedweb -trimpath -o bin/authscope-ope ./cmd/authscope-ope

docker-build:
	docker build -t authscope-ope:latest .

clean:
	rm -rf bin web/dist web/coverage web/tsconfig.tsbuildinfo
	find web -name '*.js' -not -path '*/node_modules/*' -delete
