// Privacy filters for receipt publication. The GitHub check is public,
// so its content is a fixed minimal triple: the outcome, the signed
// historical enforcement statuses, and a receipt-digest prefix. Nothing
// else from the receipt may appear in the check. The authenticated
// private view may carry richer verified evidence, but it never renders
// the raw envelope, issue bodies, logs, patches, transcripts, private
// detail URLs, or secrets.
package receipt

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/tauliang/authscope-ope/internal/coreapi"
	"github.com/tauliang/authscope-ope/internal/store"
)

// receiptDigestPrefixLen is how much of the receipt digest the public
// check exposes: enough to correlate, not enough to matter.
const receiptDigestPrefixLen = 12

// checkNamePrefix is the fixed check name prefix. The full name carries
// the minimal public triple; the prefix keeps every receipt check from
// one workspace grouped under one stable name root.
const checkNamePrefix = "authscope/receipt"

// PublicationIDKey derives the publication idempotency key from the
// workspace, the receipt digest, and the repository binding triple, so
// retries and duplicate deliveries never create a second check run.
func PublicationIDKey(workspaceID, receiptDigest string, repositoryID, pullRequestNumber int64, headSHA string) string {
	raw := fmt.Sprintf("%s|%s|%d|%d|%s", workspaceID, receiptDigest, repositoryID, pullRequestNumber, headSHA)
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// enforcementStatus renders the signed historical enforcement statuses
// as a compact scope:level list. An empty history renders as "none".
func enforcementStatus(view *ReceiptView) string {
	if view == nil || len(view.HistoricalEnforcement) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(view.HistoricalEnforcement))
	for _, e := range view.HistoricalEnforcement {
		parts = append(parts, e.Scope+":"+e.Level)
	}
	return strings.Join(parts, ",")
}

// MinimalCheckRequest renders the privacy-safe public GitHub check for
// a verified receipt. Only three facts cross the trust boundary: the
// outcome, the signed historical enforcement statuses, and the
// receipt-digest prefix. It refuses to render a check for anything but
// a verified view.
func MinimalCheckRequest(view *ReceiptView, bindingID, idempotencyKey string) coreapi.GitHubCheckRequest {
	if view == nil || view.Verification != store.ReceiptVerified || view.ReceiptDigest == "" {
		return coreapi.GitHubCheckRequest{}
	}
	var conclusion coreapi.CheckConclusion
	switch view.Outcome {
	case OutcomeSuccess:
		conclusion = coreapi.CheckConclusionSuccess
	case OutcomeFailure:
		conclusion = coreapi.CheckConclusionFailure
	default:
		return coreapi.GitHubCheckRequest{}
	}
	prefix := view.ReceiptDigest
	if len(prefix) > receiptDigestPrefixLen {
		prefix = prefix[:receiptDigestPrefixLen]
	}
	name := fmt.Sprintf("%s %s %s sha256:%s", checkNamePrefix, view.Outcome, enforcementStatus(view), prefix)
	return coreapi.GitHubCheckRequest{
		BindingID:      bindingID,
		HeadSHA:        view.HeadSHA,
		Name:           name,
		Status:         coreapi.CheckStatusCompleted,
		Conclusion:     conclusion,
		IdempotencyKey: idempotencyKey,
	}
}
