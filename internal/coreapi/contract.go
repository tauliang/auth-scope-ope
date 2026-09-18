package coreapi

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// ContractReport is the result of verifying the vendored upstream contract
// on disk. It drives the /readyz gate.
type ContractReport struct {
	// CoreVersion is the locked immutable release identifier.
	CoreVersion string
	// DigestMatch reports that the vendored document matches the lock.
	DigestMatch bool
	// OperationsRequired is the manifest operation count.
	OperationsRequired int
	// OperationsPresent is the count found in the vendored document.
	OperationsPresent int
	// Problems lists human-readable verification failures.
	Problems []string
	// Warnings lists non-blocking verification notes, mirroring the
	// warnings scripts/verify-contract.sh emits for unresolvable schemas.
	Warnings []string
}

// Ready reports whether the vendored contract fully satisfies the manifest.
func (r ContractReport) Ready() bool {
	return r.DigestMatch && r.OperationsRequired > 0 &&
		r.OperationsPresent == r.OperationsRequired && len(r.Problems) == 0
}

var pathParamPattern = regexp.MustCompile(`\{[^}]+\}`)

// normPath normalizes path parameters so manifest and document paths compare
// equal regardless of parameter naming.
func normPath(p string) string {
	return pathParamPattern.ReplaceAllString(p, "{x}")
}

// hasWorkloadScheme reports whether the document defines a workload-identity
// or mTLS style security scheme.
func hasWorkloadScheme(schemes map[string]any) bool {
	for name := range schemes {
		lower := strings.ToLower(name)
		for _, key := range []string{"mtls", "mutualtls", "workload", "clientcert", "x509"} {
			if strings.Contains(lower, key) {
				return true
			}
		}
	}
	return false
}

// VerifyVendoredContract checks the vendored AuthScope OpenAPI document in
// root/contracts against the lock and the capability manifest. It mirrors
// scripts/verify-contract.sh so the running server can gate readiness on the
// same checks CI enforces.
func VerifyVendoredContract(root string) ContractReport {
	lock := LockedContract()
	manifest := RequiredManifest()
	report := ContractReport{
		CoreVersion:        lock.CoreVersion,
		OperationsRequired: len(manifest.RequiredOperations),
	}

	raw, err := os.ReadFile(filepath.Join(root, "contracts", "authscope-v1.yaml"))
	if err != nil {
		report.Problems = append(report.Problems, fmt.Sprintf("cannot read vendored OpenAPI: %v", err))
		return report
	}
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); got != lock.OpenAPISHA256 {
		report.Problems = append(report.Problems,
			fmt.Sprintf("vendored OpenAPI digest mismatch: got %s, lock wants %s", got, lock.OpenAPISHA256))
		return report
	}
	report.DigestMatch = true

	var doc struct {
		Paths      map[string]map[string]any `yaml:"paths"`
		Components struct {
			Schemas         map[string]any `yaml:"schemas"`
			SecuritySchemes map[string]any `yaml:"securitySchemes"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		report.Problems = append(report.Problems, fmt.Sprintf("vendored OpenAPI does not parse: %v", err))
		return report
	}

	methods := map[string]bool{
		"get": true, "post": true, "put": true, "patch": true,
		"delete": true, "head": true, "options": true,
	}
	indexed := map[string]bool{}
	for p, item := range doc.Paths {
		for m := range item {
			if methods[strings.ToLower(m)] {
				indexed[normPath(p)+"\x00"+strings.ToLower(m)] = true
			}
		}
	}

	workloadScheme := hasWorkloadScheme(doc.Components.SecuritySchemes)

	for _, op := range manifest.RequiredOperations {
		method := strings.ToLower(op.Method)
		if !indexed[normPath(op.Path)+"\x00"+method] {
			report.Problems = append(report.Problems,
				fmt.Sprintf("missing %s %s [%s]", op.Method, op.Path, op.Capability))
			continue
		}
		for _, schemaName := range []string{op.RequestSchema, op.ResponseSchema} {
			if schemaName == "" {
				continue
			}
			if _, ok := doc.Components.Schemas[schemaName]; !ok {
				report.Warnings = append(report.Warnings,
					fmt.Sprintf("schema %s not found for %s %s [%s]", schemaName, op.Method, op.Path, op.Capability))
			}
		}
		if rp := op.ReconcilePath; rp != "" {
			parts := strings.SplitN(rp, " ", 2)
			if len(parts) != 2 || !indexed[normPath(parts[1])+"\x00"+strings.ToLower(parts[0])] {
				report.Problems = append(report.Problems,
					fmt.Sprintf("missing reconcile %s for %s %s [%s]", rp, op.Method, op.Path, op.Capability))
				continue
			}
		}
		if op.SecurityScheme == "workload_identity_mtls" && !workloadScheme {
			report.Problems = append(report.Problems,
				fmt.Sprintf("no workload-identity/mTLS security scheme for %s %s [%s]", op.Method, op.Path, op.Capability))
			continue
		}
		report.OperationsPresent++
	}
	return report
}
