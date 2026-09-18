.PHONY: contract-ready verify e2e help build web-build docker-build clean

GO ?= go
export GOSUMDB=off

help:
	@echo "Targets:"
	@echo "  contract-ready  Verify the vendored AuthScope contract against the OPE capability manifest."
	@echo "                  Must exit 0 before Task 2 may begin."
	@echo "  verify          Run every available check (contract gate plus test suites)."
	@echo "  e2e             Run the browser e2e specs against two live instances."
	@echo "                  Tolerant: UI tests skip when no browser is installed."
	@echo "  web-build       Build the web UI bundle into web/dist."
	@echo "  build           Build the Go binary with the web bundle embedded (needs web-build first)."
	@echo "  docker-build    Build the release image (multi-stage: web, then Go)."
	@echo "  clean           Remove build artifacts (never pushed)."

contract-ready:
	scripts/verify-contract.sh

e2e:
	scripts/run-e2e.sh

verify: contract-ready
	$(GO) test -race ./...
	$(GO) vet ./...
	node scripts/generate-web-client.mjs --check
	@if [ ! -f web/node_modules/.modules.yaml ] || [ web/pnpm-lock.yaml -nt web/node_modules/.modules.yaml ]; then \
		pnpm --dir web install --frozen-lockfile; \
	fi
	pnpm --dir web lint
	pnpm --dir web typecheck
	pnpm --dir web test:coverage
	pnpm --dir web build

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
