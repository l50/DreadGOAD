package scoreboard

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"

	awsclient "github.com/dreadnode/dreadgoad/internal/aws"

	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

// AresTransport sources findings from a running ares operation by invoking
// `ares ops loot --latest --json` on the target instance via SSM, then
// translating the structured loot snapshot into synthetic JSONL findings the
// existing parser understands.
type AresTransport struct {
	InstanceID string
	Region     string
	BinaryPath string
	Client     *awsclient.Client

	mu    sync.Mutex
	drift []string
}

// NewAresTransport constructs an AresTransport. binaryPath defaults to
// /usr/local/bin/ares when empty.
func NewAresTransport(ctx context.Context, instanceID, binaryPath, region, profile string) (*AresTransport, error) {
	if instanceID == "" {
		return nil, fmt.Errorf("instance ID is required")
	}
	c, err := awsclient.NewClient(ctx, region, profile)
	if err != nil {
		return nil, err
	}
	if binaryPath == "" {
		binaryPath = "/usr/local/bin/ares"
	}
	return &AresTransport{
		InstanceID: instanceID,
		Region:     region,
		BinaryPath: binaryPath,
		Client:     c,
	}, nil
}

type aresLoot struct {
	OperationID      string                     `json:"operation_id"`
	StartedAt        string                     `json:"started_at"`
	Credentials      []aresCredEntry            `json:"credentials"`
	Hashes           []aresHashEntry            `json:"hashes"`
	DomainCompromise []aresDomainCompromise     `json:"domain_compromise"`
	TokenCoverage    map[string]aresTokenBucket `json:"token_coverage"`
}

// aresTokenBucket is one entry in the ares loot JSON's `token_coverage` map,
// keyed by ares's own scoreboard-category name. We deliberately do not credit
// objectives from it (see detectTokenCoverageDrift) and only read Exploited.
type aresTokenBucket struct {
	Discovered int    `json:"discovered"`
	Exploited  int    `json:"exploited"`
	Status     string `json:"status"`
}

type aresCredEntry struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Domain   string `json:"domain"`
	IsAdmin  bool   `json:"is_admin"`
}

type aresHashEntry struct {
	Username  string `json:"username"`
	Domain    string `json:"domain"`
	HashValue string `json:"hash_value"`
	HashType  string `json:"hash_type"`
	Source    string `json:"source"`
}

// aresDomainCompromise mirrors entries in the ares loot JSON's
// `domain_compromise[]` array. Ares filters krbtgt rows out of `hashes[]` by
// design (see ares-cli `report_filter.rs`: krbtgt is "consumed internally by
// Golden Ticket detection rather than tracked as a cred objective"), and some
// DA paths use built-in users that are not answer-key credential objectives.
// This metadata is therefore the authoritative report-boundary signal for
// domain ownership.
type aresDomainCompromise struct {
	Domain          string   `json:"domain"`
	HasDomainAdmin  bool     `json:"has_domain_admin"`
	HasGoldenTicket bool     `json:"has_golden_ticket"`
	AdminUsers      []string `json:"admin_users"`
	KrbtgtHashTypes []string `json:"krbtgt_hash_types"`
}

// FetchReport runs `ares ops loot --latest --json` on the remote instance and,
// if successful, also fetches the proven subset of the `ares:op:<id>:exploited`
// Redis set so technique objectives can be credited directly. Both payloads are
// gzip+base64-encoded to sidestep SSM's 24KB stdout cap. Returns ErrNoReport
// when the operation hasn't produced any state yet.
func (t *AresTransport) FetchReport(ctx context.Context) (string, error) {
	const jqFilter = `{operation_id, started_at,` +
		` credentials: [.credentials[] | {username, password, domain, is_admin}],` +
		` hashes: [.hashes[] | {username, domain, hash_value, hash_type, source}],` +
		` domain_compromise: [.domain_compromise[] | {domain, has_domain_admin, has_golden_ticket, admin_users, krbtgt_hash_types}],` +
		` token_coverage: (.token_coverage // {})}`
	cmd := fmt.Sprintf("%s ops loot --latest --json | jq -c %s | gzip -c | base64 -w0",
		shellQuote(t.BinaryPath), shellQuote(jqFilter))
	out, status, stderr, err := runSSMShell(ctx, t.Client, t.InstanceID, cmd)
	if err != nil {
		return "", err
	}
	if status != ssmtypes.CommandInvocationStatusSuccess {
		if strings.Contains(stderr, "No state found") || strings.Contains(stderr, "No operations") {
			return "", ErrNoReport
		}
		return "", fmt.Errorf("ares ops loot: %s: %s", status, strings.TrimSpace(stderr))
	}
	out = strings.TrimSpace(out)
	if out == "" {
		return "", ErrNoReport
	}
	raw, err := decodeGzipBase64(out)
	if err != nil {
		return "", fmt.Errorf("decode ares loot: %w", err)
	}
	var loot aresLoot
	if err := json.Unmarshal(raw, &loot); err != nil {
		return "", fmt.Errorf("parse ares loot json: %w", err)
	}

	proven, allExploited := t.fetchExploited(ctx, loot.OperationID)

	drift := detectTokenCoverageDrift(&loot, allExploited)
	t.mu.Lock()
	t.drift = drift
	t.mu.Unlock()

	return synthesizeJSONL(&loot, proven), nil
}

// Drift returns the ares token_coverage categories that reported at least one
// exploit which this transport's prefix table credited to nothing, as of the
// last FetchReport. Empty means the two mappings agree.
func (t *AresTransport) Drift() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string(nil), t.drift...)
}

// driftExemptCategories are ares categories that are expected to produce no
// direct technique credit, so their presence is not evidence of a mapping bug.
//
//   - "other" is ares's catch-all, a mix of ids DreadGOAD scores and ids it
//     has no objective for, so the bucket is not actionable either way.
//   - "printnightmare" and "zerologon" are deliberately never credited:
//     ares's evidence gate fires on markers that precede success
//     (printnightmare accepts "Stub loaded" / "[+] Triggering"; zerologon only
//     ever runs the nxc check module, never the reset), so a credit there
//     would score an attempt as an exploit. ares categorized both as "other"
//     until l50/ares#366 gave them their own categories; without an explicit
//     exemption they would warn on every poll once that lands.
//   - "golden_ticket" is flat in ares but per-domain in the answer key
//     (golden_ticket-<domain>). That credit comes from domain_compromise[]
//     instead, so a flat category with no matching credit is expected.
var driftExemptCategories = map[string]bool{
	"other":          true,
	"golden_ticket":  true,
	"printnightmare": true,
	"zerologon":      true,
}

// driftCategoryAliases translates ares category names that differ from the
// answer-key technique ID for the same thing. ares returns the matched prefix
// verbatim unless it has an explicit alias, so `forest_trust_escalation_*`
// becomes category "forest_trust" while the objective is "cross_forest_trust".
// Every other category ares emits already matches its technique ID.
var driftCategoryAliases = map[string]string{
	"forest_trust": "cross_forest_trust",
}

// detectTokenCoverageDrift cross-checks ares's own category mapping against
// aresExploitedToTechniqueIDs. ares computes `token_coverage` with
// `token_category` (ares-cli `ops/loot/format/display.rs`), whose comment
// claims it is kept in lock-step with the Go table below; nothing enforces
// that, and it has silently diverged before (acl_*, gpo_*, and adcs_esc8 were
// all uncreditable for months). A category ares scores as exploited that maps
// to no technique here is the signature of that drift.
//
// This is a detector, not a credit source. token_coverage counts from the raw
// `:exploited` set (ares-core `state/reader.rs` does a plain SMEMBERS with no
// `:superseded` subtraction), so its exploited counts include back-credits for
// techniques ares never actually walked. Scoring off it would undo the
// superseded filtering in fetchExploited.
//
// allExploited must therefore be the raw set, not the proven subset: this asks
// "can the table below name every id ares has?", which is a mapping question.
// Passing the filtered set would report the superseded filter as drift.
func detectTokenCoverageDrift(l *aresLoot, allExploited []string) []string {
	if len(l.TokenCoverage) == 0 {
		return nil
	}
	credited := map[string]bool{}
	for _, entry := range allExploited {
		for _, id := range aresExploitedToTechniqueIDs(entry) {
			credited[id] = true
		}
	}
	var drifted []string
	for category, bucket := range l.TokenCoverage {
		if bucket.Exploited == 0 || driftExemptCategories[category] {
			continue
		}
		techID := category
		if alias, ok := driftCategoryAliases[category]; ok {
			techID = alias
		}
		if !credited[techID] {
			drifted = append(drifted, category)
		}
	}
	sort.Strings(drifted)
	return drifted
}

// exploitedSetMarker separates the two SMEMBERS payloads in the combined
// Redis fetch. No ares vuln_id can collide with it: ids are built from
// hostnames, IPs, usernames and rights, all sanitized to alphanumerics, dots
// and underscores at the construction sites.
const exploitedSetMarker = "---SUPERSEDED---"

// fetchExploited reads both `ares:op:<op>:exploited` and
// `ares:op:<op>:superseded` in a single SSM round trip. It returns the proven
// subset (exploited minus superseded) for scoring, and the raw exploited set
// for drift detection. Failures are non-fatal (just means no technique
// findings get emitted this poll).
//
// ares credits a vuln as exploited when a *different* path already reached the
// same goal, so the technique itself was never proven: an mssql_impersonation
// win back-credits the host's mssql_access, and a dc_secretsdump_<domain>
// back-credits child_to_parent for that domain (ares-cli
// `orchestrator/state/dedup.rs`). Those ids are mirrored into `:superseded`,
// which ares documents as "subset of KEY_EXPLOITED; the technique itself was
// never proven to work", so only the proven subset is scored.
//
// Both sets are returned because drift detection must not see the filtering:
// token_coverage counts superseded ids too, so comparing it against the proven
// subset would flag the filter doing its job as a mapping bug.
func (t *AresTransport) fetchExploited(ctx context.Context, opID string) (proven, all []string) {
	if opID == "" {
		return nil, nil
	}
	cmd := fmt.Sprintf("redis-cli SMEMBERS %s; echo %s; redis-cli SMEMBERS %s",
		shellQuote(fmt.Sprintf("ares:op:%s:exploited", opID)),
		shellQuote(exploitedSetMarker),
		shellQuote(fmt.Sprintf("ares:op:%s:superseded", opID)))
	out, status, _, err := runSSMShell(ctx, t.Client, t.InstanceID, cmd)
	if err != nil || status != ssmtypes.CommandInvocationStatusSuccess {
		return nil, nil
	}
	return splitExploitedSets(out)
}

// splitExploitedSets parses the combined SMEMBERS output into the proven
// subset and the raw exploited set.
func splitExploitedSets(out string) (proven, all []string) {
	superseded := map[string]bool{}
	seenMarker := false
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if line == exploitedSetMarker {
			seenMarker = true
			continue
		}
		if seenMarker {
			superseded[line] = true
			continue
		}
		all = append(all, line)
	}
	for _, entry := range all {
		if !superseded[entry] {
			proven = append(proven, entry)
		}
	}
	return proven, all
}

func decodeGzipBase64(s string) ([]byte, error) {
	gz, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("base64: %w", err)
	}
	gr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return nil, fmt.Errorf("gzip: %w", err)
	}
	body, readErr := io.ReadAll(gr)
	closeErr := gr.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close gzip reader: %w", closeErr)
	}
	return body, nil
}

// DeleteReport is a no-op: ares state lives in Redis, not a file the
// scoreboard should clobber. Restarting an ares operation is a separate
// workflow (`task ec2:launch ...`).
func (t *AresTransport) DeleteReport(_ context.Context) (bool, error) {
	return false, nil
}

// aresExploitedToTechniqueIDs maps an entry from `ares:op:<id>:exploited` to
// the answer-key technique IDs it represents. Returns nil for entries that
// don't correspond to any answer-key technique. The exploited set uses prefix
// names like `mssql_linked_server_<ip>_<svc>` or bare names like
// `constrained_delegation_<user>`; we match on the prefix.
func aresExploitedToTechniqueIDs(entry string) []string {
	prefixes := []struct {
		prefix string
		ids    []string
	}{
		{"mssql_linked_server_", []string{"mssql_linked_server"}},
		{"mssql_impersonation_", []string{"mssql_exploit"}},
		{"mssql_", []string{"mssql_exploit"}},
		{"constrained_delegation_", []string{"constrained_delegation"}},
		{"unconstrained_delegation_", []string{"unconstrained_delegation"}},
		{"forest_trust_", []string{"cross_forest_trust"}},
		{"child_to_parent_", []string{"child_to_parent"}},
		// ares emits the granted right in the id (acl_genericall_*,
		// acl_writeproperty_*, ...); they all collapse to one objective.
		{"acl_", []string{"acl_abuse"}},
		{"asrep_roast_", []string{"asrep_roast"}},
		{"kerberoast_", []string{"kerberoast"}},
		{"llmnr_", []string{"llmnr_nbtns_poisoning"}},
		{"ntlm_relay_", []string{"ntlm_relay"}},
		{"ntlmv1_", []string{"ntlmv1_downgrade"}},
		{"seimpersonate_", []string{"seimpersonate"}},
		{"nopac_", []string{"nopac"}},
		{"adcs_esc1_", []string{"adcs_esc1"}},
		{"adcs_esc2_", []string{"adcs_esc2"}},
		{"adcs_esc3_", []string{"adcs_esc3"}}, // collapses ESC3 + ESC3-CRA
		{"adcs_esc4_", []string{"adcs_esc4"}},
		{"adcs_esc6_", []string{"adcs_esc6"}},
		{"adcs_esc7_", []string{"adcs_esc7"}},
		{"adcs_esc8_", []string{"adcs_esc8"}},
		{"adcs_esc9_", []string{"adcs_esc9"}},
		{"adcs_esc10_case1_", []string{"adcs_esc10_case1"}},
		{"adcs_esc10_case2_", []string{"adcs_esc10_case2"}},
		{"adcs_esc11_", []string{"adcs_esc11"}},
		{"adcs_esc13_", []string{"adcs_esc13"}},
		{"adcs_esc15_", []string{"adcs_esc15"}},
		// Same shape as acl_: ares emits gpo_<right>_<source>_<gpo-slug>.
		{"gpo_", []string{"gpo_abuse"}},
		{"gmsa_", []string{"gmsa_password_read"}},
		{"laps_", []string{"laps_password_read"}},
		{"sid_history_", []string{"sid_history_abuse"}},
		{"rbcd_", []string{"rbcd"}},
		{"shadow_credentials_", []string{"shadow_credentials"}},
	}
	// Per-domain golden ticket: `golden_ticket_<domain>` → `golden_ticket-<domain>`.
	// One scoreboard objective per domain because forging requires that domain's
	// krbtgt hash; a multi-domain forest can have a separate GT per domain.
	if strings.HasPrefix(entry, "golden_ticket_") {
		domain := strings.ToLower(strings.TrimPrefix(entry, "golden_ticket_"))
		if domain != "" {
			return []string{"golden_ticket-" + domain}
		}
	}
	for _, p := range prefixes {
		if strings.HasPrefix(entry, p.prefix) || entry == strings.TrimSuffix(p.prefix, "_") {
			return p.ids
		}
	}
	return nil
}

func synthesizeJSONL(l *aresLoot, exploited []string) string {
	var b strings.Builder
	writeJSONLEntry(&b, map[string]string{
		"agent_id":   "ares:" + l.OperationID,
		"start_time": l.StartedAt,
	})
	for _, c := range l.Credentials {
		writeCredentialEntry(&b, c)
	}
	for _, h := range l.Hashes {
		writeHashEntry(&b, h)
	}
	emitted := map[string]bool{}
	writeExploitedEntries(&b, exploited, emitted)
	writeDomainCompromiseEntries(&b, l.DomainCompromise, emitted)
	return b.String()
}

func writeJSONLEntry(b *strings.Builder, entry map[string]string) {
	eb, _ := json.Marshal(entry)
	b.Write(eb)
	b.WriteByte('\n')
}

func writeCredentialEntry(b *strings.Builder, c aresCredEntry) {
	if c.Username == "" || c.Password == "" {
		return
	}
	target := c.Username
	if c.Domain != "" {
		target = c.Username + "@" + c.Domain
	}
	desc := "ares loot"
	if c.IsAdmin {
		desc = "ares loot (admin)"
	}
	writeJSONLEntry(b, map[string]string{
		"target":      target,
		"evidence":    c.Password,
		"description": desc,
	})
}

func writeHashEntry(b *strings.Builder, h aresHashEntry) {
	if h.Username == "" || h.HashValue == "" {
		return
	}
	target := h.Username
	if h.Domain != "" {
		target = h.Username + "@" + strings.ToLower(h.Domain)
	}
	htype := h.HashType
	if htype == "" {
		htype = "hash"
	}
	writeJSONLEntry(b, map[string]string{
		"target":      target,
		"evidence":    h.HashValue,
		"description": "ares: " + strings.ToLower(htype) + " (" + h.Source + ")",
	})
}

func writeExploitedEntries(b *strings.Builder, exploited []string, emitted map[string]bool) {
	for _, ex := range exploited {
		for _, techID := range aresExploitedToTechniqueIDs(ex) {
			if emitted[techID] {
				continue
			}
			emitted[techID] = true
			writeJSONLEntry(b, map[string]string{
				"target":      "tech:" + techID,
				"evidence":    "ares: " + ex,
				"description": "exploited",
			})
		}
	}
}

// writeDomainCompromiseEntries synthesizes findings from domain_compromise[]
// metadata. The explicit domain_admin signal credits real DA-level compromise
// even when the DA account is built-in (for example ESSOS\administrator) and
// therefore absent from the answer-key credential objectives. The krbtgt
// compatibility signal remains for older inference paths that key off an
// NT-hash-shaped krbtgt finding.
func writeDomainCompromiseEntries(b *strings.Builder, entries []aresDomainCompromise, emitted map[string]bool) {
	const krbtgtSyntheticEvidence = "00000000000000000000000000000000"
	for _, dc := range entries {
		domain := strings.ToLower(strings.TrimSpace(dc.Domain))
		if domain == "" {
			continue
		}
		if dc.HasDomainAdmin {
			signalID := "domain_admin:" + domain
			if !emitted[signalID] {
				emitted[signalID] = true
				writeJSONLEntry(b, map[string]string{
					"target":      signalID,
					"evidence":    domainAdminEvidence(dc),
					"description": "ares: domain_compromise has_domain_admin",
				})
			}
		}
		if dc.HasDomainAdmin && len(dc.KrbtgtHashTypes) > 0 {
			writeJSONLEntry(b, map[string]string{
				"target":      "krbtgt@" + domain,
				"evidence":    krbtgtSyntheticEvidence,
				"description": "ares: synthetic krbtgt from domain_compromise (" + strings.Join(dc.KrbtgtHashTypes, ",") + ")",
			})
		}
		if dc.HasGoldenTicket {
			techID := "golden_ticket-" + domain
			if !emitted[techID] {
				emitted[techID] = true
				writeJSONLEntry(b, map[string]string{
					"target":      "tech:" + techID,
					"evidence":    "ares: domain_compromise has_golden_ticket",
					"description": "exploited",
				})
			}
		}
	}
}

func domainAdminEvidence(dc aresDomainCompromise) string {
	var admins []string
	for _, admin := range dc.AdminUsers {
		admin = strings.TrimSpace(admin)
		if admin != "" {
			admins = append(admins, admin)
		}
	}
	if len(admins) == 0 {
		return "ares: domain_compromise has_domain_admin"
	}
	return "ares: domain_compromise has_domain_admin via " + strings.Join(admins, ",")
}
