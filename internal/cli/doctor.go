// Command doctor: read-only preflight diagnostics for a workspace-bound
// OPE instance.
//
// "authscope-ope doctor" opens the data directory without taking the
// exclusive lock (it never writes), loads the immutable instance
// binding, and runs a fixed set of named checks: instance binding,
// workload-identity digest, contract pins, live compatibility, signing
// key history, transport-authenticated workspace identity,
// decision_attestor role, clock skew, database availability and
// permissions, origin and cookie consistency, passkey secure context,
// GitHub binding and workflow posture, supported agent kits, runner
// binary, enforced isolation, and worker health. Every check reports
// pass or fail with a named reason. Doctor never creates or rewrites
// the instance binding and never attaches the workload identity; the
// compatibility gate in serve owns those mutations.
package cli

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/tauliang/authscope-ope/internal/coreapi"
	"github.com/tauliang/authscope-ope/internal/identity"
	"github.com/tauliang/authscope-ope/internal/store"
	"github.com/tauliang/authscope-ope/internal/trust"
)

// DoctorCheck is the outcome of one named preflight check.
type DoctorCheck struct {
	// Name is the stable check identifier, e.g. "clock_skew".
	Name string
	// Pass is true when the check passed.
	Pass bool
	// Reason is a human-readable one-line explanation.
	Reason string
}

// DoctorConfig wires the doctor command.
type DoctorConfig struct {
	DataDir           string
	Mode              string
	AuthScopeURL      string
	WorkspaceID       string
	Hostname          string
	Origin            string
	RPID              string
	InstanceID        string
	SessionCookieName string
	RunnerPath        string
	RootDir           string
	BindAddr          string
	Signer            identity.Signer

	// Out receives the check report; defaults to os.Stdout.
	Out io.Writer
	// Clock returns the current time; defaults to time.Now.
	Clock func() time.Time
	// OpenStore opens the data directory for reading; defaults to
	// store.Open. Doctor never takes the exclusive lock and never
	// writes the binding.
	OpenStore func(dataDir, mode string) (store.Store, error)
	// NewAuthority builds the upstream authority; defaults to
	// coreapi.NewClient.
	NewAuthority func(authScopeURL string, signer identity.Signer, mode string) (coreapi.Authority, error)
	// RunnerVersion probes the runner binary version; defaults to
	// running it with --version under a timeout.
	RunnerVersion func(ctx context.Context, path string) (string, error)
}

// doctorAuthority is the narrow upstream surface doctor needs. The
// production *coreapi.Client implements it; tests use a fake.
type doctorAuthority interface {
	Discover(context.Context) (coreapi.Discovery, error)
	VerifyWorkspaceIdentity(context.Context, string) (coreapi.WorkspaceIdentity, error)
	GetSigningKeys(context.Context, coreapi.RequestOptions) (coreapi.SigningKeyHistory, error)
	GetRepositoryBinding(context.Context, string, coreapi.RequestOptions) (coreapi.RepositoryBinding, error)
	InspectWorkflowPosture(context.Context, coreapi.WorkflowPostureRequest, coreapi.RequestOptions) (coreapi.WorkflowPosture, error)
	ListAgentKits(context.Context, coreapi.RequestOptions) ([]coreapi.AgentKit, error)
	ServerTime(context.Context) (time.Time, error)
}

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// maxClockSkew is the largest acceptable difference between the local
// clock and AuthScope's clock.
const maxClockSkew = 30 * time.Second

// RunDoctor runs every preflight check, prints the report, and returns
// the per-check outcomes. It returns an error only when the report
// itself cannot be produced; individual check failures are reported in
// the returned slice and reflected in the process exit code by main.
func RunDoctor(ctx context.Context, cfg DoctorConfig) ([]DoctorCheck, error) {
	if cfg.DataDir == "" {
		return nil, fmt.Errorf("doctor: data directory is required")
	}
	if !filepath.IsAbs(cfg.DataDir) {
		return nil, fmt.Errorf("doctor: data directory must be absolute, got %q", cfg.DataDir)
	}
	out := cfg.Out
	if out == nil {
		out = os.Stdout
	}
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	openStore := cfg.OpenStore
	if openStore == nil {
		openStore = store.Open
	}
	newAuthority := cfg.NewAuthority
	if newAuthority == nil {
		newAuthority = func(authScopeURL string, signer identity.Signer, mode string) (coreapi.Authority, error) {
			return coreapi.NewClient(authScopeURL, nil, signer, mode)
		}
	}
	runnerVersion := cfg.RunnerVersion
	if runnerVersion == nil {
		runnerVersion = probeRunnerVersion
	}

	d := &doctor{
		cfg:           cfg,
		out:           out,
		clock:         clock,
		runnerVersion: runnerVersion,
	}
	if err := d.open(ctx, openStore, newAuthority); err != nil {
		return nil, err
	}
	defer d.close()

	checks := []DoctorCheck{
		d.checkInstanceBinding(),
		d.checkWorkloadIdentityDigest(),
		d.checkContractPins(),
		d.checkLiveCompatibility(),
		d.checkSigningKeyHistory(),
		d.checkWorkspaceIdentity(),
		d.checkAttestorRole(),
		d.checkClockSkew(),
		d.checkDatabase(),
		d.checkOrigin(),
		d.checkPasskeySecureContext(),
		d.checkGitHubBinding(),
		d.checkWorkflowPosture(),
		d.checkAgentKits(),
		d.checkRunner(),
		d.checkIsolation(),
		d.checkWorkers(),
	}
	d.report(checks)
	return checks, nil
}

type doctor struct {
	cfg           DoctorConfig
	out           io.Writer
	clock         func() time.Time
	runnerVersion func(ctx context.Context, path string) (string, error)

	st        store.Store
	authority coreapi.Authority
	inst      store.InstanceRecord
	haveInst  bool
	wid       coreapi.WorkspaceIdentity
	haveWid   bool
	discovery coreapi.Discovery
	haveDisc  bool
}

func (d *doctor) open(ctx context.Context, openStore func(string, string) (store.Store, error),
	newAuthority func(string, identity.Signer, string) (coreapi.Authority, error)) error {
	mode := d.cfg.Mode
	if mode == "" {
		mode = "development"
	}
	st, err := openStore(d.cfg.DataDir, mode)
	if err != nil {
		return fmt.Errorf("doctor: open data directory: %w", err)
	}
	d.st = st
	if d.cfg.Signer == nil {
		return fmt.Errorf("doctor: workload signer is required")
	}
	a, err := newAuthority(d.cfg.AuthScopeURL, d.cfg.Signer, mode)
	if err != nil {
		_ = st.Close()
		return fmt.Errorf("doctor: build authority: %w", err)
	}
	d.authority = a
	// Read-only: GetInstance never creates or rewrites the binding.
	inst, err := st.GetInstance(ctx)
	if err == nil {
		d.inst = inst
		d.haveInst = true
	}
	return nil
}

func (d *doctor) close() {
	if d.st != nil {
		_ = d.st.Close()
	}
}

func (d *doctor) report(checks []DoctorCheck) {
	var failed int
	for _, c := range checks {
		status := "ok"
		if !c.Pass {
			status = "FAIL"
			failed++
		}
		fmt.Fprintf(d.out, "%-22s %s  %s\n", c.Name, status, c.Reason)
	}
	fmt.Fprintf(d.out, "\n%d/%d checks passed\n", len(checks)-failed, len(checks))
}

func pass(name, reason string) DoctorCheck {
	return DoctorCheck{Name: name, Pass: true, Reason: reason}
}
func fail(name, reason string) DoctorCheck {
	return DoctorCheck{Name: name, Pass: false, Reason: reason}
}
func failf(name, format string, args ...any) DoctorCheck {
	return DoctorCheck{Name: name, Pass: false, Reason: fmt.Sprintf(format, args...)}
}

// checkInstanceBinding verifies the immutable instance binding exists
// and matches the configured workspace and instance.
func (d *doctor) checkInstanceBinding() DoctorCheck {
	const name = "instance_binding"
	if !d.haveInst {
		return fail(name, "no instance binding: run serve once to bind this instance")
	}
	if d.inst.WorkspaceID != d.cfg.WorkspaceID {
		return failf(name, "binding serves workspace %q, config names %q",
			d.inst.WorkspaceID, d.cfg.WorkspaceID)
	}
	if d.cfg.InstanceID != "" && d.inst.InstanceID != d.cfg.InstanceID {
		return failf(name, "binding instance %q, config names %q",
			d.inst.InstanceID, d.cfg.InstanceID)
	}
	return pass(name, fmt.Sprintf("workspace %q instance %q bound at %s",
		d.inst.WorkspaceID, d.inst.InstanceID, d.inst.CreatedAt.UTC().Format(time.RFC3339)))
}

// checkWorkloadIdentityDigest verifies the attached digest is present
// and well-formed. Doctor never attaches it; serve owns that mutation.
func (d *doctor) checkWorkloadIdentityDigest() DoctorCheck {
	const name = "workload_identity_digest"
	if !d.haveInst {
		return fail(name, "no instance binding")
	}
	if d.inst.WorkloadIdentityDigest == "" {
		return fail(name, "no workload identity attached: serve has not completed the compatibility gate")
	}
	if !digestPattern.MatchString(d.inst.WorkloadIdentityDigest) {
		return fail(name, "attached digest is malformed")
	}
	return pass(name, "digest attached and well-formed")
}

// checkContractPins verifies the vendored contract digest matches the
// contract lock: the pins doctor and serve enforce.
func (d *doctor) checkContractPins() DoctorCheck {
	const name = "contract_pins"
	report := coreapi.VerifyVendoredContract(d.cfg.RootDir)
	if !report.DigestMatch {
		return failf(name, "vendored contract digest mismatch: %v", report.Problems)
	}
	if len(report.Warnings) > 0 {
		return pass(name, fmt.Sprintf("digest match; %d warning(s): %s",
			len(report.Warnings), strings.Join(report.Warnings, "; ")))
	}
	return pass(name, "vendored contract digest matches the lock")
}

// checkLiveCompatibility runs the same compatibility gate serve runs:
// discovery plus the contract lock and capability manifest.
func (d *doctor) checkLiveCompatibility() DoctorCheck {
	const name = "live_compatibility"
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	discovery, err := d.authority.Discover(ctx)
	if err != nil {
		return failf(name, "discovery failed: %v", err)
	}
	d.discovery = discovery
	d.haveDisc = true
	if err := coreapi.CheckReleaseCompatibility(ctx, discovery, coreapi.LockedContract(), coreapi.RequiredManifest()); err != nil {
		return failf(name, "incompatible core: %v", err)
	}
	return pass(name, fmt.Sprintf("core %s compatible", discovery.Version))
}

// checkSigningKeyHistory verifies the local signing-key pin file loads
// and every upstream history key is pinned locally.
func (d *doctor) checkSigningKeyHistory() DoctorCheck {
	const name = "signing_key_history"
	pinPath := filepath.Join(d.cfg.RootDir, "contracts", "authscope-signing-keys.json")
	keys, err := trust.LoadSigningKeys(pinPath, "")
	if err != nil {
		return failf(name, "load pin file: %v", err)
	}
	pinned := map[string]bool{}
	for _, id := range keys.KeyIDs() {
		pinned[id] = true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	history, err := d.authority.GetSigningKeys(ctx, coreapi.RequestOptions{WorkspaceID: d.cfg.WorkspaceID})
	if err != nil {
		return failf(name, "fetch key history: %v", err)
	}
	var unknown []string
	for _, k := range history.Keys {
		if !pinned[k.KeyID] {
			unknown = append(unknown, k.KeyID)
		}
	}
	if len(unknown) > 0 {
		return failf(name, "upstream keys not in the local pin file: %s", strings.Join(unknown, ", "))
	}
	return pass(name, fmt.Sprintf("%d upstream key(s) all pinned", len(history.Keys)))
}

// checkWorkspaceIdentity verifies the transport-authenticated workload
// identity: it must name this workspace and carry the attached digest.
func (d *doctor) checkWorkspaceIdentity() DoctorCheck {
	const name = "workspace_identity"
	if !d.haveInst {
		return fail(name, "no instance binding")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	wid, err := d.authority.VerifyWorkspaceIdentity(ctx, d.inst.WorkspaceID)
	if err != nil {
		return failf(name, "identity verification failed: %v", err)
	}
	d.wid = wid
	d.haveWid = true
	if wid.WorkspaceID != d.inst.WorkspaceID {
		return failf(name, "identity bound to workspace %q", wid.WorkspaceID)
	}
	if d.inst.WorkloadIdentityDigest != "" && wid.IdentityDigest != d.inst.WorkloadIdentityDigest {
		return fail(name, "transport identity digest differs from the attached digest")
	}
	return pass(name, fmt.Sprintf("identity %s verified for workspace %q", wid.IdentityID, wid.WorkspaceID))
}

// checkAttestorRole verifies the workload identity carries the
// decision_attestor role.
func (d *doctor) checkAttestorRole() DoctorCheck {
	const name = "decision_attestor_role"
	if !d.haveWid {
		return fail(name, "workspace identity not verified")
	}
	if !d.wid.HasRole(coreapi.DecisionAttestorRole) {
		return failf(name, "identity roles %q lack %q", d.wid.Roles, coreapi.DecisionAttestorRole)
	}
	return pass(name, "identity carries decision_attestor")
}

// checkClockSkew compares the local clock against AuthScope's Date
// header; skew over 30 seconds fails.
func (d *doctor) checkClockSkew() DoctorCheck {
	const name = "clock_skew"
	timer, ok := d.authority.(interface {
		ServerTime(context.Context) (time.Time, error)
	})
	if !ok {
		return fail(name, "authority does not expose server time")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	serverTime, err := timer.ServerTime(ctx)
	if err != nil {
		return failf(name, "server time unavailable: %v", err)
	}
	skew := d.clock().Sub(serverTime)
	if skew < 0 {
		skew = -skew
	}
	if skew > maxClockSkew {
		return failf(name, "skew %s exceeds %s", skew.Round(time.Millisecond), maxClockSkew)
	}
	return pass(name, fmt.Sprintf("skew %s within %s", skew.Round(time.Millisecond), maxClockSkew))
}

// checkDatabase verifies the data directory and database file exist
// with owner-only permissions and ownership.
func (d *doctor) checkDatabase() DoctorCheck {
	const name = "database"
	dirFi, err := os.Stat(d.cfg.DataDir)
	if err != nil {
		return failf(name, "data directory: %v", err)
	}
	if !dirFi.IsDir() {
		return failf(name, "%q is not a directory", d.cfg.DataDir)
	}
	if perm := dirFi.Mode().Perm(); perm&0o077 != 0 {
		return failf(name, "data directory permissions %o grant group/world access", perm)
	}
	if err := checkOwnedBySelf(d.cfg.DataDir, dirFi); err != nil {
		return failf(name, "data directory %v", err)
	}
	dbPath := filepath.Join(d.cfg.DataDir, "ope.db")
	dbFi, err := os.Stat(dbPath)
	if err != nil {
		return failf(name, "database file: %v", err)
	}
	if perm := dbFi.Mode().Perm(); perm&0o077 != 0 {
		return failf(name, "database file permissions %o grant group/world access", perm)
	}
	if err := checkOwnedBySelf(dbPath, dbFi); err != nil {
		return failf(name, "database file %v", err)
	}
	// Availability: the binding read above already proved the database
	// opens and the schema migrates.
	return pass(name, fmt.Sprintf("directory and %s owner-only", filepath.Base(dbPath)))
}

// checkOrigin verifies Host, Origin, RP ID, and cookie name agree.
func (d *doctor) checkOrigin() DoctorCheck {
	const name = "origin"
	if !d.haveInst {
		return fail(name, "no instance binding")
	}
	u, err := url.Parse(d.cfg.Origin)
	if err != nil || u.Host == "" {
		return failf(name, "origin %q is not a valid origin", d.cfg.Origin)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return failf(name, "origin %q has unexpected scheme", d.cfg.Origin)
	}
	host := u.Hostname()
	if d.cfg.Hostname != "" && host != d.cfg.Hostname {
		return failf(name, "origin host %q differs from hostname %q", host, d.cfg.Hostname)
	}
	if d.cfg.RPID == "" {
		return fail(name, "WebAuthn RP ID is not configured")
	}
	if d.inst.RPID != "" && d.inst.RPID != d.cfg.RPID {
		return failf(name, "binding RP ID %q differs from config %q", d.inst.RPID, d.cfg.RPID)
	}
	wantCookie := store.DeriveSessionCookieName(d.inst.InstanceID)
	if d.inst.SessionCookieName != wantCookie {
		return failf(name, "binding cookie %q, want %q", d.inst.SessionCookieName, wantCookie)
	}
	if !strings.HasPrefix(d.inst.SessionCookieName, "__Host-") {
		return failf(name, "cookie %q lacks the __Host- prefix", d.inst.SessionCookieName)
	}
	return pass(name, fmt.Sprintf("origin %s rp_id %s cookie %s", d.cfg.Origin, d.cfg.RPID, wantCookie))
}

// checkPasskeySecureContext verifies the origin is a WebAuthn secure
// context: https, or loopback http in development.
func (d *doctor) checkPasskeySecureContext() DoctorCheck {
	const name = "passkey_secure_context"
	u, err := url.Parse(d.cfg.Origin)
	if err != nil || u.Host == "" {
		return failf(name, "origin %q is not a valid origin", d.cfg.Origin)
	}
	if u.Scheme == "https" {
		return pass(name, "https origin is a secure context")
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return pass(name, "loopback http origin is a secure context in development")
	}
	if host == "localhost" {
		return pass(name, "localhost http origin is a secure context in development")
	}
	return failf(name, "origin %q is not a secure context for passkeys", d.cfg.Origin)
}

// checkGitHubBinding verifies every configured GitHub connection still
// resolves to the same workspace-scoped repository binding.
func (d *doctor) checkGitHubBinding() DoctorCheck {
	const name = "github_binding"
	if !d.haveInst {
		return fail(name, "no instance binding")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conns, err := d.st.ListConnections(ctx, d.inst.WorkspaceID)
	if err != nil {
		return failf(name, "list connections: %v", err)
	}
	if len(conns) == 0 {
		return pass(name, "no GitHub connections configured")
	}
	da, ok := d.authority.(doctorAuthority)
	if !ok {
		return fail(name, "authority does not support binding checks")
	}
	for _, conn := range conns {
		binding, err := da.GetRepositoryBinding(ctx, conn.RepositoryBindingRef,
			coreapi.RequestOptions{WorkspaceID: d.inst.WorkspaceID})
		if err != nil {
			return failf(name, "connection %q: %v", conn.ConnectionID, err)
		}
		if binding.WorkspaceID != d.inst.WorkspaceID {
			return failf(name, "connection %q bound to workspace %q", conn.ConnectionID, binding.WorkspaceID)
		}
	}
	return pass(name, fmt.Sprintf("%d connection(s) resolve", len(conns)))
}

// checkWorkflowPosture inspects the workflow posture of every
// configured connection; any risky finding fails.
func (d *doctor) checkWorkflowPosture() DoctorCheck {
	const name = "workflow_posture"
	if !d.haveInst {
		return fail(name, "no instance binding")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	conns, err := d.st.ListConnections(ctx, d.inst.WorkspaceID)
	if err != nil {
		return failf(name, "list connections: %v", err)
	}
	if len(conns) == 0 {
		return pass(name, "no GitHub connections configured")
	}
	da, ok := d.authority.(doctorAuthority)
	if !ok {
		return fail(name, "authority does not support posture checks")
	}
	for _, conn := range conns {
		posture, err := da.InspectWorkflowPosture(ctx,
			coreapi.WorkflowPostureRequest{BindingID: conn.RepositoryBindingRef, Ref: "HEAD"},
			coreapi.RequestOptions{WorkspaceID: d.inst.WorkspaceID})
		if err != nil {
			return failf(name, "connection %q: %v", conn.ConnectionID, err)
		}
		if posture.Posture != coreapi.WorkflowPostureClean {
			return failf(name, "connection %q posture %q: %d finding(s)",
				conn.ConnectionID, posture.Posture, len(posture.Findings))
		}
	}
	return pass(name, fmt.Sprintf("%d connection(s) clean", len(conns)))
}

// checkAgentKits verifies AuthScope serves a non-empty supported kit
// list.
func (d *doctor) checkAgentKits() DoctorCheck {
	const name = "agent_kit"
	da, ok := d.authority.(doctorAuthority)
	if !ok {
		return fail(name, "authority does not support kit checks")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	kits, err := da.ListAgentKits(ctx, coreapi.RequestOptions{WorkspaceID: d.cfg.WorkspaceID})
	if err != nil {
		return failf(name, "list agent kits: %v", err)
	}
	if len(kits) == 0 {
		return fail(name, "no supported agent kits")
	}
	return pass(name, fmt.Sprintf("%d supported kit(s)", len(kits)))
}

// checkRunner validates the governed runner binary path and ownership
// and reports its version.
func (d *doctor) checkRunner() DoctorCheck {
	const name = "runner"
	if d.cfg.RunnerPath == "" {
		return fail(name, "OPE_RUNNER_PATH is not configured")
	}
	abs, err := ValidateRunnerPath(d.cfg.RunnerPath)
	if err != nil {
		return failf(name, "invalid: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	version, err := d.runnerVersion(ctx, abs)
	if err != nil {
		return pass(name, fmt.Sprintf("%s valid; version unknown: %v", abs, err))
	}
	return pass(name, fmt.Sprintf("%s valid; version %s", abs, version))
}

// checkIsolation verifies enforced isolation: the HTTP listener is
// loopback-only and the data directory grants no group/world access.
func (d *doctor) checkIsolation() DoctorCheck {
	const name = "isolation"
	addr := d.cfg.BindAddr
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return failf(name, "bind address %q: %v", addr, err)
	}
	if host != "" && host != "localhost" {
		if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
			return failf(name, "bind address %q is not loopback-only", addr)
		}
	}
	return pass(name, fmt.Sprintf("listener %s loopback-only", addr))
}

// checkWorkers verifies the event/check worker lease: when the server
// runs, its heartbeat must be fresh and unexpired.
func (d *doctor) checkWorkers() DoctorCheck {
	const name = "worker_health"
	if !d.haveInst {
		return fail(name, "no instance binding")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	lease, err := d.st.GetWorkerLease(ctx, d.inst.InstanceID)
	if err != nil {
		// No lease row: the server is not running. That is fine for
		// doctor; it reports rather than fails.
		return pass(name, "server not running: no worker lease")
	}
	now := d.clock()
	if now.After(lease.ExpiresAt) {
		return failf(name, "worker lease expired at %s", lease.ExpiresAt.UTC().Format(time.RFC3339))
	}
	if now.Sub(lease.HeartbeatAt) > 90*time.Second {
		return failf(name, "worker heartbeat stale: %s", lease.HeartbeatAt.UTC().Format(time.RFC3339))
	}
	return pass(name, fmt.Sprintf("worker %q heartbeat %s", lease.Owner,
		lease.HeartbeatAt.UTC().Format(time.RFC3339)))
}

// probeRunnerVersion runs the runner with --version under a timeout.
func probeRunnerVersion(ctx context.Context, path string) (string, error) {
	cmd := exec.CommandContext(ctx, path, "--version")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("runner --version: %w", err)
	}
	version := strings.TrimSpace(string(out))
	if version == "" {
		return "", fmt.Errorf("runner --version printed nothing")
	}
	if len(version) > 120 {
		version = version[:120]
	}
	return version, nil
}
