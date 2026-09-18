// Package reconcile runs the leased background worker that keeps local
// state settled against the authority: it projects authoritative event
// pages into the safe local timeline, reconciles ambiguous revocation
// intents by their original idempotency keys without ever re-issuing a
// revocation, and drives passes to their terminal receipt states. One
// worker holds the instance lease at a time; the lease heartbeat keeps
// it alive and graceful shutdown releases it.
package reconcile

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/tauliang/authscope-ope/internal/coreapi"
	"github.com/tauliang/authscope-ope/internal/missionpass"
	"github.com/tauliang/authscope-ope/internal/store"
)

// reconcileOwner is the worker lease owner name.
const reconcileOwner = "reconcile"

// Tunables for the poll loop.
const (
	// defaultPollInterval paces full reconciliation sweeps.
	defaultPollInterval = 15 * time.Second
	// defaultLeaseTTL bounds how long a dead worker's lease blocks a
	// successor.
	defaultLeaseTTL = 60 * time.Second
	// maxPagesPerPass caps event paging per pass per sweep so one
	// chatty mission cannot starve the rest.
	maxPagesPerPass = 10
	// baseBackoff and maxBackoff bound the per-pass retry delay after a
	// failed poll.
	baseBackoff = 30 * time.Second
	maxBackoff  = 10 * time.Minute
)

// RevocationReconciler settles ambiguous revocation intents.
// *missionpass.RevocationService satisfies it.
type RevocationReconciler interface {
	ReconcileRevocation(ctx context.Context, workspaceID, passID string) (*missionpass.RevocationResult, error)
}

// Config wires the worker.
type Config struct {
	Store       store.Store
	Authority   coreapi.Authority
	Projector   *missionpass.EventProjector
	Revocation  RevocationReconciler
	InstanceID  string
	WorkspaceID string
	PollInterval time.Duration
	LeaseTTL    time.Duration
	Clock       func() time.Time
	Log         func(format string, args ...any)
}

// Worker is the leased reconciliation worker.
type Worker struct {
	store       store.Store
	authority   coreapi.Authority
	projector   *missionpass.EventProjector
	revocation  RevocationReconciler
	instanceID  string
	owner       string
	workspaceID string
	pollInterval time.Duration
	leaseTTL    time.Duration
	clock       func() time.Time
	log         func(format string, args ...any)

	mu           sync.Mutex
	backoffUntil map[string]time.Time
	backoffCount map[string]int
	incompatible map[string]bool
}

// newOwnerID mints a unique owner identity per worker process so two
// workers never believe they hold the same lease: the store only hands
// the lease to another owner after expiry.
func newOwnerID() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return reconcileOwner + "-" + hex.EncodeToString(b[:]), nil
}

// NewWorker builds the worker.
func NewWorker(cfg Config) (*Worker, error) {
	if cfg.Store == nil || cfg.Authority == nil || cfg.Projector == nil || cfg.Revocation == nil {
		return nil, fmt.Errorf("reconcile: worker requires store, authority, projector, and revocation service")
	}
	if cfg.InstanceID == "" || cfg.WorkspaceID == "" {
		return nil, fmt.Errorf("reconcile: worker requires instance and workspace IDs")
	}
	poll := cfg.PollInterval
	if poll <= 0 {
		poll = defaultPollInterval
	}
	ttl := cfg.LeaseTTL
	if ttl <= 0 {
		ttl = defaultLeaseTTL
	}
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	logger := cfg.Log
	if logger == nil {
		logger = log.Printf
	}
	owner, err := newOwnerID()
	if err != nil {
		return nil, fmt.Errorf("reconcile: owner ID: %w", err)
	}
	return &Worker{
		store:        cfg.Store,
		authority:    cfg.Authority,
		projector:    cfg.Projector,
		revocation:   cfg.Revocation,
		instanceID:   cfg.InstanceID,
		owner:        owner,
		workspaceID:  cfg.WorkspaceID,
		pollInterval: poll,
		leaseTTL:     ttl,
		clock:        clock,
		log:          logger,
		backoffUntil: map[string]time.Time{},
		backoffCount: map[string]int{},
		incompatible: map[string]bool{},
	}, nil
}

// Run holds the worker lease and reconciles until ctx is cancelled. It
// returns nil on graceful shutdown: the lease is released before Run
// returns.
func (w *Worker) Run(ctx context.Context) error {
	if err := w.acquireLease(ctx); err != nil {
		return err
	}
	w.log("reconcile: worker lease acquired (instance %s)", w.instanceID)
	defer w.releaseLease()

	pollTicker := time.NewTicker(w.pollInterval)
	defer pollTicker.Stop()
	heartbeatTicker := time.NewTicker(w.leaseTTL / 3)
	defer heartbeatTicker.Stop()

	w.poll(ctx)
	for {
		select {
		case <-ctx.Done():
			w.log("reconcile: shutting down")
			return nil
		case <-heartbeatTicker.C:
			if !w.heartbeat(ctx) {
				w.log("reconcile: lease heartbeat lost; re-acquiring")
				if err := w.acquireLease(ctx); err != nil {
					return err
				}
			}
		case <-pollTicker.C:
			w.poll(ctx)
		}
	}
}

// acquireLease takes the instance worker lease, waiting while another
// owner holds it. It returns ctx.Err() when the context is cancelled.
func (w *Worker) acquireLease(ctx context.Context) error {
	for {
		var acquired bool
		err := w.store.WithTx(ctx, func(tx store.Tx) error {
			var err error
			acquired, err = tx.AcquireWorkerLease(ctx, w.instanceID, w.owner, w.leaseTTL)
			return err
		})
		if err != nil {
			return fmt.Errorf("reconcile: acquire lease: %w", err)
		}
		if acquired {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(w.pollInterval):
		}
	}
}

// heartbeat renews the lease. A false return means the lease was lost.
func (w *Worker) heartbeat(ctx context.Context) bool {
	var ok bool
	err := w.store.WithTx(ctx, func(tx store.Tx) error {
		var err error
		ok, err = tx.HeartbeatWorkerLease(ctx, w.instanceID, w.owner, w.leaseTTL)
		return err
	})
	if err != nil {
		w.log("reconcile: lease heartbeat error: %v", err)
		return false
	}
	return ok
}

// releaseLease drops the worker lease. It is a no-op when the worker no
// longer holds it.
func (w *Worker) releaseLease() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := w.store.WithTx(ctx, func(tx store.Tx) error {
		return tx.ReleaseWorkerLease(ctx, w.instanceID, w.owner)
	}); err != nil {
		w.log("reconcile: release lease: %v", err)
		return
	}
	w.log("reconcile: worker lease released")
}

// poll runs one reconciliation sweep: event projection for every active
// pass, then ambiguous revocation intent reconciliation.
func (w *Worker) poll(ctx context.Context) {
	passes, err := w.store.ListMissionPasses(ctx, w.workspaceID)
	if err != nil {
		w.log("reconcile: list passes: %v", err)
		return
	}
	for i := range passes {
		pass := passes[i]
		if !reconcilableState(pass.State) {
			continue
		}
		if w.inBackoff(pass.PassID) || w.isIncompatible(pass.PassID) {
			continue
		}
		if err := w.projectPass(ctx, pass); err != nil {
			if errors.Is(err, missionpass.ErrProjectionIncompatible) {
				w.markIncompatible(pass.PassID)
				w.log("reconcile: pass %s projection incompatible; polling suspended for this pass", pass.PassID)
				continue
			}
			w.noteFailure(pass.PassID)
			w.log("reconcile: pass %s: %v", pass.PassID, err)
			continue
		}
		w.clearFailure(pass.PassID)
	}
	w.reconcileRevocations(ctx)
}

// reconcilableState reports the pass states the worker polls: missions
// in flight or awaiting their final receipt.
func reconcilableState(state string) bool {
	switch missionpass.PassState(state) {
	case missionpass.PassRunning,
		missionpass.PassAwaitingExpansion,
		missionpass.PassOutcomePending:
		return true
	}
	return false
}

// projectPass pages authoritative events for one pass and projects them
// into the safe local timeline. Receipt events carry their resource
// digest, and the projector verifies it locally against the latest run
// outcome before moving the pass to completed or failed: only a locally
// verified receipt settles the final state.
func (w *Worker) projectPass(ctx context.Context, pass store.MissionPassRecord) error {
	if pass.MissionRef == "" {
		return nil
	}
	for page := 0; page < maxPagesPerPass; page++ {
		var cursor string
		proj, err := w.store.GetMissionProjection(ctx, w.workspaceID, pass.PassID)
		if err != nil {
			if !errors.Is(err, store.ErrNotFound) {
				return fmt.Errorf("read projection: %w", err)
			}
		} else {
			cursor = proj.Cursor
		}
		pageCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		events, err := w.authority.ReadEvents(pageCtx, pass.MissionRef, cursor, coreapi.RequestOptions{
			WorkspaceID: w.workspaceID,
			ActorID:     "worker:" + w.owner,
		})
		cancel()
		if err != nil {
			return fmt.Errorf("read events: %w", err)
		}
		if _, err := w.projector.ApplyPage(ctx, w.workspaceID, pass.PassID, events); err != nil {
			return err
		}
		if events.NextCursor == "" || events.NextCursor == cursor {
			return nil
		}
	}
	return nil
}

// reconcileRevocations settles ambiguous revocation intents by their
// original idempotency keys. Settling replays the original idempotent
// call to recover the result; a still-unknown outcome stays in flight
// for the next sweep.
func (w *Worker) reconcileRevocations(ctx context.Context) {
	intents, err := w.store.ListRevocationIntents(ctx, w.workspaceID, store.RevocationIntentInFlight)
	if err != nil {
		w.log("reconcile: list revocation intents: %v", err)
		return
	}
	for i := range intents {
		intent := intents[i]
		if _, err := w.revocation.ReconcileRevocation(ctx, intent.WorkspaceID, intent.PassID); err != nil {
			w.log("reconcile: revocation intent %s: %v", intent.PassID, err)
		}
	}
}

func (w *Worker) inBackoff(passID string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	until, ok := w.backoffUntil[passID]
	return ok && w.clock().Before(until)
}

func (w *Worker) noteFailure(passID string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := w.backoffCount[passID] + 1
	w.backoffCount[passID] = n
	delay := baseBackoff << (n - 1)
	if delay > maxBackoff || delay <= 0 {
		delay = maxBackoff
	}
	w.backoffUntil[passID] = w.clock().Add(delay)
}

func (w *Worker) clearFailure(passID string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	delete(w.backoffCount, passID)
	delete(w.backoffUntil, passID)
}

func (w *Worker) isIncompatible(passID string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.incompatible[passID]
}

func (w *Worker) markIncompatible(passID string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.incompatible[passID] = true
}
