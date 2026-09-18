package missionpass

// Task 7: approve the exact proposal with a passkey and create only the
// mission. Approval binds the full server-side proposal content into the
// WebAuthn challenge, verifies the founder's assertion, signs a decision
// attestation with the workload key, and calls ApproveProposal exactly
// once per idempotency key. It never touches PrepareLaunch, leases,
// runtime policy, launch descriptors, or sealed credentials: the only
// artifact it creates is the mission.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/tauliang/authscope-ope/internal/authn"
	"github.com/tauliang/authscope-ope/internal/coreapi"
	"github.com/tauliang/authscope-ope/internal/github"
	"github.com/tauliang/authscope-ope/internal/identity"
	"github.com/tauliang/authscope-ope/internal/store"
)

var (
	// ErrApprovalReconcilePending reports an approval begin attempted while
	// a previous approval outcome is still ambiguous.
	ErrApprovalReconcilePending = errors.New("missionpass: approval reconciliation pending")
	// ErrApprovalBindingChanged reports a finish attempted after the exact
	// proposal moved under the begun challenge.
	ErrApprovalBindingChanged = errors.New("missionpass: proposal changed after approval began")
	// ErrApprovalDigest reports a stored digest that is not a well-formed
	// algorithm-tagged digest.
	ErrApprovalDigest = errors.New("missionpass: malformed approval digest")
)

// approvalAttestationTTL is the lifetime of the signed approval decision
// attestation: long enough for one upstream call, short enough that a
// leaked attestation is useless.
const approvalAttestationTTL = 2 * time.Minute

// approvalAudience is the decision attestation audience for proposal
// approval. The browser never supplies it.
const approvalAudience = identity.AudienceProposalApproval

// ApprovalBinding is the complete server-side binding for one approval.
// Every field is challenge-bound: the founder's WebAuthn ceremony covers
// the founder, session, purpose, subject, and the SHA-256 of the canonical
// approval bytes, and the canonical bytes cover the exact proposal
// content. The browser supplies none of these fields.
type ApprovalBinding struct {
	WorkspaceID      string
	FounderID        string
	SessionID        string
	PassID           string
	DraftVersion     int64
	ProposalID       string
	ProposalDigest   string
	InvocationDigest string
	SourceDigest     string
	BaseSHA          string
	Purpose          string
	Audience         string
}

// ApprovalResult is the created mission. It carries no RunID and no
// launch artifacts: approval creates only the mission.
type ApprovalResult struct {
	MissionRef              string `json:"mission_ref"`
	MissionHash             string `json:"mission_hash"`
	AuthScopeMissionVersion int64  `json:"authscope_mission_version"`
	ApprovalDecisionRef     string `json:"approval_decision_ref"`
}

// ApprovalConfig wires the approval service.
type ApprovalConfig struct {
	Store           store.Store
	Authority       coreapi.Authority
	Source          *github.Source
	Authn           *authn.Service
	Attestor        *identity.DecisionAttestor
	Clock           func() time.Time
	UpstreamTimeout time.Duration
}

// begunApproval is the server-side state cached between begin and finish.
// It is keyed by the unguessable challenge ID and never leaves the server.
type begunApproval struct {
	challengeID string
	digest      [32]byte
	nonce       [32]byte
	binding     ApprovalBinding
	purpose     authn.DecisionPurpose
	audience    string
	expiresAt   time.Time
}

// ApprovalService approves exact mission-pass proposals.
type ApprovalService struct {
	store           store.Store
	authority       coreapi.Authority
	source          *github.Source
	authn           *authn.Service
	attestor        *identity.DecisionAttestor
	clock           func() time.Time
	upstreamTimeout time.Duration

	mu    sync.Mutex
	begun map[string]*begunApproval
}

// NewApprovalService builds the approval service.
func NewApprovalService(cfg ApprovalConfig) (*ApprovalService, error) {
	if cfg.Store == nil || cfg.Authority == nil || cfg.Source == nil ||
		cfg.Authn == nil || cfg.Attestor == nil {
		return nil, fmt.Errorf("missionpass: store, authority, source, authn, and attestor are required")
	}
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	timeout := cfg.UpstreamTimeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &ApprovalService{
		store:           cfg.Store,
		authority:       cfg.Authority,
		source:          cfg.Source,
		authn:           cfg.Authn,
		attestor:        cfg.Attestor,
		clock:           clock,
		upstreamTimeout: timeout,
		begun:           make(map[string]*begunApproval),
	}, nil
}

func (s *ApprovalService) now() time.Time { return s.clock().UTC() }

// approvalKey returns the deterministic idempotency key for one approval.
func approvalKey(workspaceID, passID string, draftVersion int64) string {
	return fmt.Sprintf("approve:%s:%s:%d", workspaceID, passID, draftVersion)
}

// ApprovalBeginResult carries the challenge the browser must complete.
type ApprovalBeginResult struct {
	ChallengeID string
	OptionsJSON json.RawMessage
}

// loadForApproval loads the pass and requires a draft with settled
// reconciliation.
func (s *ApprovalService) loadForApproval(ctx context.Context, workspaceID, passID string) (persistedPass, error) {
	stored, err := s.store.GetMissionPass(ctx, workspaceID, passID)
	if err != nil {
		return persistedPass{}, err
	}
	full := fromStoreRecord(stored)
	if full.State != PassDraft {
		return persistedPass{}, fmt.Errorf("%w: pass %q is %q", ErrNotDraft, passID, full.State)
	}
	if full.Reconciliation != ReconciliationSettled {
		return persistedPass{}, fmt.Errorf("%w: pass %q", ErrApprovalReconcilePending, passID)
	}
	return full, nil
}

// checkApprovalDigests validates the algorithm-tagged digests the approval
// binds. Stored digests came from AuthScope; a malformed one fails closed
// instead of binding garbage.
func checkApprovalDigests(rec ProposalRecord) error {
	for _, d := range []string{rec.ProposalDigest, rec.InvocationDigest, rec.SourceDigest} {
		if !canonicalDigestPattern.MatchString(d) {
			return fmt.Errorf("%w: %q", ErrApprovalDigest, d)
		}
	}
	if rec.ProposalID == "" {
		return fmt.Errorf("%w: proposal id is empty", ErrApprovalDigest)
	}
	return nil
}

// refreshApprovalSource re-reads the pinned issue and re-inspects workflow
// posture, exactly like revision does. A moved source or an unclean
// posture fails closed.
func (s *ApprovalService) refreshApprovalSource(ctx context.Context, full persistedPass) error {
	conn, err := s.store.GetConnection(ctx, full.WorkspaceID, full.ConnectionID)
	if err != nil {
		return err
	}
	snap, err := s.source.ReadIssue(ctx, full.WorkspaceID, conn, full.IssueNumber, full.SourceRevision, full.BaseSHA)
	if err != nil {
		return mapSourceError(err)
	}
	posture, err := s.source.CheckPosture(ctx, full.WorkspaceID, conn, snap.DefaultBranch, snap.BaseSHA)
	if err != nil {
		return err
	}
	if posture.Outcome != "clean" {
		return fmt.Errorf("%w: outcome %q", ErrUnsafePosture, posture.Outcome)
	}
	return nil
}

// bindingFor builds the complete server-side approval binding.
func bindingFor(p authn.Principal, rec ProposalRecord) ApprovalBinding {
	return ApprovalBinding{
		WorkspaceID:      rec.WorkspaceID,
		FounderID:        p.FounderID,
		SessionID:        p.SessionID,
		PassID:           rec.PassID,
		DraftVersion:     rec.DraftVersion,
		ProposalID:       rec.ProposalID,
		ProposalDigest:   rec.ProposalDigest,
		InvocationDigest: rec.InvocationDigest,
		SourceDigest:     rec.SourceDigest,
		BaseSHA:          rec.BaseSHA,
		Purpose:          string(authn.DecisionPassApproval),
		Audience:         approvalAudience,
	}
}

// Begin starts the approval ceremony: it reloads the pass, requires draft
// with settled reconciliation, refreshes the pinned source and posture,
// validates the stored digests, and binds every binding field into the
// WebAuthn challenge digest. The browser supplies only the challenge
// completion.
func (s *ApprovalService) Begin(ctx context.Context, p authn.Principal, passID string) (*ApprovalBeginResult, error) {
	full, err := s.loadForApproval(ctx, p.WorkspaceID, passID)
	if err != nil {
		return nil, err
	}
	rec := full.ProposalRecord
	if err := s.refreshApprovalSource(ctx, full); err != nil {
		return nil, err
	}
	if err := checkApprovalDigests(rec); err != nil {
		return nil, err
	}
	binding := bindingFor(p, rec)
	canonical := CanonicalApprovalBytes(rec)
	challenge, optionsJSON, err := s.authn.BeginDecision(ctx, p, authn.DecisionPassApproval, rec.PassID, canonical)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.begun[challenge.ChallengeID] = &begunApproval{
		challengeID: challenge.ChallengeID,
		digest:      challenge.Digest,
		nonce:       challenge.Nonce,
		binding:     binding,
		purpose:     authn.DecisionPassApproval,
		audience:    approvalAudience,
		expiresAt:   challenge.ExpiresAt,
	}
	s.mu.Unlock()
	return &ApprovalBeginResult{ChallengeID: challenge.ChallengeID, OptionsJSON: optionsJSON}, nil
}

// begunForTest exposes begun approval state to in-package tests.
func (s *ApprovalService) begunForTest(challengeID string) *begunApproval {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.begun[challengeID]
}

// ceremonyProof is the verified local WebAuthn ceremony record bound into
// the decision attestation. It carries the authentication method, the
// consumed challenge identity and nonce, and the session that performed
// the ceremony. It never embeds the credential ID, the assertion, or any
// secret.
type ceremonyProof struct {
	Method       string `json:"method"`
	ChallengeID  string `json:"challenge_id"`
	Nonce        string `json:"nonce"`
	WorkspaceID  string `json:"workspace_id"`
	SessionID    string `json:"session_id"`
	FounderID    string `json:"founder_id"`
	SubjectID    string `json:"subject_id"`
	Purpose      string `json:"purpose"`
	UserVerified bool   `json:"user_verified"`
}

// ceremonyProofDigest binds the verified local ceremony record into the
// decision attestation without embedding credential material. The struct
// has fixed JSON field order, so the digest is deterministic.
func ceremonyProofDigest(proof ceremonyProof) (string, error) {
	raw, err := json.Marshal(proof)
	if err != nil {
		return "", fmt.Errorf("missionpass: encode ceremony proof: %w", err)
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// attestationDigest covers the signed decision attestation bytes.
func attestationDigest(att identity.SignedDecisionAttestation) (string, error) {
	raw, err := json.Marshal(att)
	if err != nil {
		return "", fmt.Errorf("missionpass: encode attestation: %w", err)
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// derivedMissionHash derives the local mission hash when AuthScope omits
// it: the algorithm-tagged digest of the canonical approval bytes.
func derivedMissionHash(rec ProposalRecord) string {
	sum := sha256.Sum256(CanonicalApprovalBytes(rec))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// approvalDecisionRef is the non-empty local reference for the signed
// approval decision.
func approvalDecisionRef(binding ApprovalBinding) string {
	return fmt.Sprintf("approval-decision:%s:%s:%d", binding.WorkspaceID, binding.PassID, binding.DraftVersion)
}

// dropBegun forgets begun approval state for a challenge.
func (s *ApprovalService) dropBegun(challengeID string) {
	s.mu.Lock()
	delete(s.begun, challengeID)
	s.mu.Unlock()
}

// Finish completes the approval ceremony: it reloads the pass, rebuilds
// the exact binding, verifies the passkey assertion, signs the decision
// attestation, and creates only the mission. A stale proposal fails closed
// before any upstream call.
func (s *ApprovalService) Finish(ctx context.Context, p authn.Principal, passID, challengeID string, assertion []byte) (*ApprovalResult, error) {
	s.mu.Lock()
	begun, ok := s.begun[challengeID]
	s.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("%w: unknown approval challenge", authn.ErrCeremonyNotFound)
	}
	full, err := s.loadForApproval(ctx, p.WorkspaceID, passID)
	if err != nil {
		s.dropBegun(challengeID)
		return nil, err
	}
	rec := full.ProposalRecord
	binding := bindingFor(p, rec)
	canonical := CanonicalApprovalBytes(rec)
	// The proposal must be byte-identical to the one the challenge bound.
	// This check runs before the challenge is consumed so a stale proposal
	// fails closed without burning the ceremony; FinishDecision rechecks
	// the digest as the second line of defense.
	if digest := sha256.Sum256(canonical); digest != begun.digest {
		s.dropBegun(challengeID)
		return nil, fmt.Errorf("%w: proposal changed after approval began", ErrApprovalBindingChanged)
	}
	verified, err := s.authn.FinishDecision(ctx, p, challengeID, authn.DecisionPassApproval, rec.PassID, canonical, assertion)
	s.dropBegun(challengeID)
	if err != nil {
		return nil, err
	}
	proofDigest, err := ceremonyProofDigest(ceremonyProof{
		Method:       verified.Method,
		ChallengeID:  verified.ChallengeID,
		Nonce:        hex.EncodeToString(verified.Nonce[:]),
		WorkspaceID:  verified.WorkspaceID,
		SessionID:    verified.SessionID,
		FounderID:    verified.FounderID,
		SubjectID:    verified.SubjectID,
		Purpose:      string(verified.Purpose),
		UserVerified: verified.UserVerified,
	})
	if err != nil {
		return nil, err
	}
	issuedAt := s.now()
	att, err := s.attestor.Attest(ctx, identity.DecisionClaims{
		WorkspaceID:               binding.WorkspaceID,
		FounderID:                 binding.FounderID,
		Audience:                  approvalAudience,
		Purpose:                   identity.PurposePassApproval,
		SubjectID:                 binding.ProposalID,
		DecisionDigest:            "sha256:" + hex.EncodeToString(mustDigest(canonical)),
		InvocationDigest:          binding.InvocationDigest,
		AuthenticationMethod:      verified.Method,
		AuthenticationProofDigest: proofDigest,
		Nonce:                     verified.Nonce,
		IssuedAt:                  issuedAt,
		ExpiresAt:                 issuedAt.Add(approvalAttestationTTL),
	})
	if err != nil {
		return nil, fmt.Errorf("missionpass: sign approval decision: %w", err)
	}
	attDigest, err := attestationDigest(att)
	if err != nil {
		return nil, err
	}
	return s.approveOnce(ctx, full, binding, att, attDigest)
}

func mustDigest(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

// approveOnce performs one approval attempt under the deterministic
// idempotency key. It persists the local intent before the upstream call
// so an ambiguous outcome can be reconciled without re-issuing the
// approval, and settles the pass on success.
func (s *ApprovalService) approveOnce(ctx context.Context, full persistedPass, binding ApprovalBinding, att identity.SignedDecisionAttestation, attDigest string) (*ApprovalResult, error) {
	rec := full.ProposalRecord
	key := approvalKey(binding.WorkspaceID, binding.PassID, binding.DraftVersion)
	canonicalDigest := "sha256:" + hex.EncodeToString(mustDigest(CanonicalApprovalBytes(rec)))

	var beginRes store.IdempotencyResult
	if err := s.store.WithTx(ctx, func(tx store.Tx) error {
		var err error
		beginRes, err = tx.BeginIdempotency(ctx, store.IdempotencyRecord{
			WorkspaceID:     binding.WorkspaceID,
			Key:             key,
			CanonicalDigest: canonicalDigest,
		})
		return err
	}); err != nil {
		return nil, err
	}
	if beginRes.Completed {
		// A previous attempt completed: return its stored result instead
		// of re-issuing the approval.
		var res ApprovalResult
		if err := json.Unmarshal(beginRes.Result, &res); err != nil {
			return nil, fmt.Errorf("missionpass: decode completed approval: %w", err)
		}
		return &res, nil
	}
	attJSON, err := json.Marshal(att)
	if err != nil {
		return nil, fmt.Errorf("missionpass: encode attestation: %w", err)
	}
	// Persist the local intent before the upstream mutation: a crash or an
	// ambiguous outcome from here on reconciles against this intent.
	if err := s.store.WithTx(ctx, func(tx store.Tx) error {
		return tx.PutApprovalIntent(ctx, store.ApprovalIntentRecord{
			WorkspaceID:       binding.WorkspaceID,
			PassID:            binding.PassID,
			IdempotencyKey:    key,
			State:             store.ApprovalIntentInFlight,
			AttestationDigest: attDigest,
			AttestationJSON:   string(attJSON),
		})
	}); err != nil {
		return nil, err
	}

	upstreamCtx, cancel := context.WithTimeout(ctx, s.upstreamTimeout)
	defer cancel()
	mission, err := s.authority.ApproveProposal(upstreamCtx, binding.ProposalID,
		coreapi.ApproveProposalInput{
			ProposalDigest:   binding.ProposalDigest,
			InvocationDigest: binding.InvocationDigest,
		}, att, coreapi.RequestOptions{
			WorkspaceID:    binding.WorkspaceID,
			ActorID:        "founder:" + binding.FounderID,
			IdempotencyKey: key,
		})
	if err != nil {
		if isAmbiguousUpstream(err) {
			// The outcome is unknown: the intent stays in flight for
			// reconciliation. Never retry ApproveProposal blindly.
			_ = s.markApprovalPending(ctx, full, key)
			return nil, fmt.Errorf("%w: approve proposal", ErrPendingReconciliation)
		}
		return nil, err
	}
	return s.settleApproval(ctx, full, binding, key, attDigest, mission)
}

// markApprovalPending records the ambiguous outcome on the pass: the draft
// stays a draft with pending reconciliation.
func (s *ApprovalService) markApprovalPending(ctx context.Context, full persistedPass, key string) error {
	rec := full.ProposalRecord
	return s.store.WithTx(ctx, func(tx store.Tx) error {
		pending := full
		pending.ProposalRecord.State = PassDraft
		pending.ProposalRecord.Reconciliation = ReconciliationPending
		if err := tx.PutMissionPass(ctx, toStoreRecord(pending), rec.StoreRevision); err != nil {
			return err
		}
		return nil
	})
}

// settleApproval persists the approved pass atomically: the pass moves to
// approved with the created mission, and the idempotency record completes
// with the result.
func (s *ApprovalService) settleApproval(ctx context.Context, full persistedPass, binding ApprovalBinding, key, attDigest string, mission coreapi.Mission) (*ApprovalResult, error) {
	rec := full.ProposalRecord
	if mission.MissionRef == "" {
		return nil, fmt.Errorf("missionpass: upstream approval returned no mission ref")
	}
	missionHash := mission.MissionHash
	if !canonicalDigestPattern.MatchString(missionHash) {
		missionHash = derivedMissionHash(rec)
	}
	res := &ApprovalResult{
		MissionRef:              mission.MissionRef,
		MissionHash:             missionHash,
		AuthScopeMissionVersion: mission.Version,
		ApprovalDecisionRef:     approvalDecisionRef(binding),
	}
	if res.AuthScopeMissionVersion == 0 {
		return nil, fmt.Errorf("missionpass: upstream approval returned no mission version")
	}
	resultJSON, err := json.Marshal(res)
	if err != nil {
		return nil, fmt.Errorf("missionpass: encode approval result: %w", err)
	}
	approved := full
	approved.ProposalRecord.State = PassApproved
	approved.ProposalRecord.Reconciliation = ReconciliationSettled
	approved.ProposalRecord.ApprovedProposalDigest = rec.ProposalDigest
	approved.ProposalRecord.AuthScopeMissionVersion = mission.Version
	approved.ProposalRecord.MissionRef = mission.MissionRef
	approved.ProposalRecord.MissionHash = missionHash
	approved.ProposalRecord.ApprovalDecisionRef = res.ApprovalDecisionRef
	approved.ProposalRecord.AttestationDigest = attDigest
	approved.ProposalRecord.RunID = ""
	if err := s.store.WithTx(ctx, func(tx store.Tx) error {
		if err := tx.PutMissionPass(ctx, toStoreRecord(approved), rec.StoreRevision); err != nil {
			return err
		}
		if err := tx.CompleteIdempotency(ctx, binding.WorkspaceID, key, resultJSON); err != nil {
			return err
		}
		return tx.CompleteApprovalIntent(ctx, binding.WorkspaceID, binding.PassID, mission.MissionRef)
	}); err != nil {
		return nil, err
	}
	return res, nil
}

// ReconcileApproval settles an ambiguous approval without ever re-issuing
// ApproveProposal. It is a no-op when nothing is pending. On a settled
// upstream outcome it replays the original idempotent call and persists
// the approval; while the operation is still in flight it returns nil.
func (s *ApprovalService) ReconcileApproval(ctx context.Context, workspaceID, passID string) (*ApprovalResult, error) {
	stored, err := s.store.GetMissionPass(ctx, workspaceID, passID)
	if err != nil {
		return nil, err
	}
	full := fromStoreRecord(stored)
	rec := full.ProposalRecord
	if rec.State == PassApproved && rec.Reconciliation == ReconciliationSettled {
		return &ApprovalResult{
			MissionRef:              rec.MissionRef,
			MissionHash:             rec.MissionHash,
			AuthScopeMissionVersion: rec.AuthScopeMissionVersion,
			ApprovalDecisionRef:     rec.ApprovalDecisionRef,
		}, nil
	}
	if rec.Reconciliation != ReconciliationPending {
		return nil, nil
	}
	var intent store.ApprovalIntentRecord
	if err := s.store.WithTx(ctx, func(tx store.Tx) error {
		var err error
		intent, err = tx.GetApprovalIntent(ctx, workspaceID, passID)
		return err
	}); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	if intent.State == store.ApprovalIntentCompleted {
		return nil, nil
	}
	reconCtx, cancel := context.WithTimeout(ctx, s.upstreamTimeout)
	defer cancel()
	outcome, err := s.authority.ReconcileOperation(reconCtx, intent.IdempotencyKey, intent.OperationRef, coreapi.RequestOptions{
		WorkspaceID: workspaceID,
		ActorID:     "founder:reconcile",
	})
	if err != nil {
		return nil, err
	}
	if outcome.Status != "completed" {
		return nil, nil
	}
	// The operation completed upstream: replay the original idempotent
	// call to recover its result. The upstream dedupes on the idempotency
	// key, so this never creates a second mission.
	replayCtx, cancel := context.WithTimeout(ctx, s.upstreamTimeout)
	defer cancel()
	att, err := replayAttestation(intent)
	if err != nil {
		return nil, err
	}
	mission, err := s.authority.ApproveProposal(replayCtx, rec.ProposalID,
		coreapi.ApproveProposalInput{
			ProposalDigest:   rec.ProposalDigest,
			InvocationDigest: rec.InvocationDigest,
		}, att, coreapi.RequestOptions{
			WorkspaceID:    workspaceID,
			ActorID:        "founder:reconcile",
			IdempotencyKey: intent.IdempotencyKey,
		})
	if err != nil {
		if isAmbiguousUpstream(err) {
			return nil, nil
		}
		return nil, err
	}
	binding := ApprovalBinding{
		WorkspaceID:      rec.WorkspaceID,
		PassID:           rec.PassID,
		DraftVersion:     rec.DraftVersion,
		ProposalID:       rec.ProposalID,
		ProposalDigest:   rec.ProposalDigest,
		InvocationDigest: rec.InvocationDigest,
		SourceDigest:     rec.SourceDigest,
		BaseSHA:          rec.BaseSHA,
	}
	return s.settleApproval(ctx, full, binding, intent.IdempotencyKey, intent.AttestationDigest, mission)
}

// replayAttestation decodes the original signed attestation stored in the
// intent. The idempotent replay carries the exact original call; the
// upstream dedupes on the idempotency key, so the replay never creates a
// second mission.
func replayAttestation(intent store.ApprovalIntentRecord) (identity.SignedDecisionAttestation, error) {
	var att identity.SignedDecisionAttestation
	if intent.AttestationJSON == "" {
		return att, fmt.Errorf("missionpass: approval intent has no attestation")
	}
	if err := json.Unmarshal([]byte(intent.AttestationJSON), &att); err != nil {
		return att, fmt.Errorf("missionpass: decode approval attestation: %w", err)
	}
	return att, nil
}
