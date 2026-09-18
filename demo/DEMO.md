# AuthScope OPE Edition: Demo Walkthrough

A guided tour of the founder-focused product layer for governing AI agents with the AuthScope mission-authority service. The whole product is three screens, and every path resolves to one of them.

## The story

You are a solo founder. You have one GitHub issue you want an AI coding agent to fix. You want the agent to act, but only inside a boundary you define, with you resolving only the meaningful exceptions, and with verifiable evidence of the outcome. That is what OPE Edition does.

One GitHub issue becomes one expiring Mission Pass, one governed coding-agent run, one pull request, and one verified receipt. AuthScope remains the authority and enforcement engine; OPE owns local founder authentication, exact signed decision attestations, onboarding, presentation, and workflow.

## Screen 1: Connect

**What you see:** The Connect screen is the front door. It shows:

- **Founder enrollment.** A first-run terminal code pairs this browser with the instance. You then enroll a passkey, which becomes your signing identity for every decision that follows.
- **Instance workspace binding.** The instance is bound to exactly one AuthScope workspace (for example `ws-demo` on `demo.local`). The binding is immutable: this OPE instance governs missions for one workspace, never more.
- **AuthScope compatibility.** The screen reports the pinned upstream release (`ope-v1.0.0`) and whether the local instance is compatible with it before anything else can proceed.
- **GitHub repository binding.** You connect a GitHub repository through the AuthScope-hosted installation. The OAuth handoff never exposes codes or tokens to OPE; AuthScope completes it and hands back only the connection record.
- **Issue picker.** With the repo bound, you pick the mission issue. The picker shows open issues from the connected repository; selecting one stages the mission proposal.

**What it demonstrates:** Trust is established before any agent acts. The founder is authenticated (passkey), the instance is bound (one workspace), the upstream is pinned (one release), and the repo is connected without leaking credentials.

## Screen 2: Authorize

**What you see:** The Authorize screen presents the shaped proposal for the selected issue:

- **Trusted issue snapshot.** The exact issue title, body, and repository state the proposal was shaped from, so you can see what the agent will work from.
- **The exact plan.** The fixed agent kit and runner arguments, shown verbatim. Nothing about the plan is editable here; it is either approved as-is or not at all.
- **Invocation digest.** A digest binding the fixed agent kit and runner arguments, so the approval covers precisely what will run.
- **Approval card.** You review the proposal and approve with your passkey. Approval mints an exact signed decision attestation and creates the mission. Approval creates the mission and nothing else: no agent has run yet.

**What it demonstrates:** Consent is explicit, scoped, and cryptographically bound. The founder sees exactly what the agent will do, and the passkey signature attests to that exact proposal. There is no blanket permission; every mission starts from a signed decision.

## Screen 3: Mission

**What you see:** The Mission screen follows the governed run for one Mission Pass:

- **Run timeline.** A live timeline of the governed run: proposal approved, runner launched, execution grants consumed, and completion or revocation.
- **Expansion requests.** When the agent needs to go beyond its boundary (for example, touching files outside the approved scope), it raises an expansion request. Each request shows the exact requested scope delta, and you approve or deny it with your passkey. Each decision is its own exact signed decision attestation.
- **Revoke.** At any point you can revoke the mission with a reason. Revocation is enforced by AuthScope; the runner loses its execution grants immediately.
- **Verified receipt.** When the run completes, the screen shows the locally verified receipt: the mission outcome, the historical enforcement status, and a receipt digest. The automatically published GitHub check carries only the outcome, the enforcement status, and a receipt-digest prefix; the full evidence stays in the private founder view.

**What it demonstrates:** Governance continues during the run, not just before it. Exceptions are resolved by the founder with signed decisions, revocation is always available, and the outcome is verifiable evidence rather than a claim.

## The guarantees, in one pass

| Guarantee | Where you see it |
|---|---|
| One workspace per instance | Connect: immutable workspace binding |
| No credential exposure | Connect: AuthScope-hosted GitHub handoff |
| Exact signed consent | Authorize: passkey approval of the exact proposal |
| Bounded execution | Mission: expansion requests for scope changes |
| Always revocable | Mission: revoke with reason, enforced upstream |
| Verifiable outcome | Mission: locally verified receipt, minimal public check |

## Running the demo

The demo runs as a single self-contained container: the image embeds
the web UI, runs in development mode, and uses the same fake-backend
posture as the e2e suite, so the three screens are fully navigable
without real AuthScope or GitHub credentials.

```sh
docker compose -f demo/compose.yaml up -d --build
```

Then open http://localhost:8080 and walk the three screens: Connect,
Authorize, Mission.

The one-time bootstrap code is printed to the container log at
startup; enter it in the browser to begin founder enrollment:

```sh
docker compose -f demo/compose.yaml logs ope-demo
```

Useful commands:

```sh
docker compose -f demo/compose.yaml logs -f ope-demo   # follow the log
docker compose -f demo/compose.yaml down                # stop, keep data
docker compose -f demo/compose.yaml down -v             # stop and wipe for a fresh bootstrap
```

For a real deployment (release mode, real AuthScope, HSM-backed
signer), see [deploy/README.md](../deploy/README.md) instead.

## Demo video

`demo-video.mp4` is a two-minute narrated walkthrough of the three screens above, recorded against this demo setup.
