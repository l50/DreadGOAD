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
// keyed by ares's own scoreboard-category name. Exploited counts only proven
// techniques as of ares-cli #366, which made it the technique credit source
// (see writeTokenCoverageEntries).
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

// FetchReport runs `ares ops loot --latest --json` on the remote instance and
// translates the snapshot into synthetic findings. Technique credit comes from
// the loot JSON's own `token_coverage`, so this is a single round trip: no
// Redis read is needed. The payload is gzip+base64-encoded to sidestep SSM's
// 24KB stdout cap. Returns ErrNoReport when the operation hasn't produced any
// state yet.
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

	drift := detectTokenCoverageDrift(&loot)
	t.mu.Lock()
	t.drift = drift
	t.mu.Unlock()

	return synthesizeJSONL(&loot), nil
}

// Drift returns the ares token_coverage categories that reported at least one
// proven exploit but are neither creditable nor deliberately refused, as of the
// last FetchReport. Empty means we can classify everything ares scored.
func (t *AresTransport) Drift() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string(nil), t.drift...)
}

// creditableCategories joins ares token_coverage category names to answer-key
// technique IDs. Most are identity — ares normalises its own aliases already
// (gpo_* to gpo_abuse, mssql_* to mssql_exploit, ntlmv1 to ntlmv1_downgrade)
// — but the join has to be written out because the two vocabularies are
// maintained in different repos and only this table is checked against the
// generated answer key (TestAresCreditedTechniquesExistInAnswerKey).
//
// This is deliberately not the old prefix table. That one re-derived the
// category from a raw vuln_id, duplicating ares's token_category, and drifted
// from it silently for months (acl_*, gpo_* and adcs_esc8 credited nothing).
// ares now does that derivation and we consume the result.
var creditableCategories = map[string]string{
	"acl_abuse":                "acl_abuse",
	"gpo_abuse":                "gpo_abuse",
	"adcs_esc1":                "adcs_esc1",
	"adcs_esc2":                "adcs_esc2",
	"adcs_esc3":                "adcs_esc3",
	"adcs_esc4":                "adcs_esc4",
	"adcs_esc6":                "adcs_esc6",
	"adcs_esc7":                "adcs_esc7",
	"adcs_esc8":                "adcs_esc8",
	"adcs_esc9":                "adcs_esc9",
	"adcs_esc10_case1":         "adcs_esc10_case1",
	"adcs_esc10_case2":         "adcs_esc10_case2",
	"adcs_esc11":               "adcs_esc11",
	"adcs_esc13":               "adcs_esc13",
	"adcs_esc15":               "adcs_esc15",
	"mssql_linked_server":      "mssql_linked_server",
	"mssql_exploit":            "mssql_exploit",
	"constrained_delegation":   "constrained_delegation",
	"unconstrained_delegation": "unconstrained_delegation",
	"shadow_credentials":       "shadow_credentials",
	"ntlm_relay":               "ntlm_relay",
	"child_to_parent":          "child_to_parent",
	"forest_trust":             "cross_forest_trust",
	"sid_history_abuse":        "sid_history_abuse",
	"asrep_roast":              "asrep_roast",
	"seimpersonate":            "seimpersonate",
	"kerberoast":               "kerberoast",
	"ntlmv1_downgrade":         "ntlmv1_downgrade",
	"llmnr_nbtns_poisoning":    "llmnr_nbtns_poisoning",
	"gmsa_password_read":       "gmsa_password_read",
	"laps_password_read":       "laps_password_read",
	"rbcd":                     "rbcd",
	"nopac":                    "nopac",
}

// uncreditableCategories are ares categories that must never produce technique
// credit. They are refusals, not gaps, so they are also exempt from drift.
//
//   - "other" is ares's catch-all: discovery-only ids (smb_signing, spooler,
//     dc_secretsdump) land here with no technique name attached.
//   - "golden_ticket" is flat in ares but per-domain in the answer key
//     (golden_ticket-<domain>). That credit comes from domain_compromise[],
//     which carries the domain the flat category drops.
//   - "printnightmare" and "zerologon" are uncreditable by design: ares mints
//     both on evidence that precedes success (printnightmare accepts "Stub
//     loaded"/"[+] Triggering"; zerologon only runs the nxc check module,
//     never the reset). ares-cli #366 promoted them out of "other", so without
//     an explicit refusal they would start crediting attempts as exploits.
var uncreditableCategories = map[string]bool{
	"other":          true,
	"golden_ticket":  true,
	"printnightmare": true,
	"zerologon":      true,
}

// aresCategoryToTechniqueID returns the answer-key technique ID for an ares
// token_coverage category, or "" when the category must not be credited.
func aresCategoryToTechniqueID(category string) string {
	return creditableCategories[category]
}

// detectTokenCoverageDrift reports ares categories we can neither credit nor
// explain. Since ares owns the vuln_id-to-category derivation, the surviving
// failure mode is vocabulary drift: ares adds or renames a category and this
// repo keeps scoring without it. Such a category credits nothing and would
// otherwise be invisible, so it is surfaced rather than silently dropped.
//
// Categories are matched against creditableCategories and uncreditableCategories
// only. An unknown category never credits — failing closed here means a new ares
// technique shows up as a warning to classify, not as a silent dead credit.
func detectTokenCoverageDrift(l *aresLoot) []string {
	var drifted []string
	for category, bucket := range l.TokenCoverage {
		if bucket.Exploited == 0 || uncreditableCategories[category] {
			continue
		}
		if aresCategoryToTechniqueID(category) == "" {
			drifted = append(drifted, category)
		}
	}
	sort.Strings(drifted)
	return drifted
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

func synthesizeJSONL(l *aresLoot) string {
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
	writeTokenCoverageEntries(&b, l.TokenCoverage, emitted)
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

// writeTokenCoverageEntries credits one finding per creditable ares category
// that reported at least one proven exploit. Categories are walked in sorted
// order so the synthesized JSONL is deterministic across polls.
//
// The evidence string names the category and its proven count rather than a
// vuln_id, because token_coverage is aggregated: ares no longer hands us the
// individual ids. That is the cost of sourcing credit from ares's own
// categorisation instead of re-deriving it here.
func writeTokenCoverageEntries(b *strings.Builder, coverage map[string]aresTokenBucket, emitted map[string]bool) {
	categories := make([]string, 0, len(coverage))
	for category := range coverage {
		categories = append(categories, category)
	}
	sort.Strings(categories)

	for _, category := range categories {
		bucket := coverage[category]
		if bucket.Exploited == 0 {
			continue
		}
		techID := aresCategoryToTechniqueID(category)
		if techID == "" || emitted[techID] {
			continue
		}
		emitted[techID] = true
		writeJSONLEntry(b, map[string]string{
			"target":      "tech:" + techID,
			"evidence":    fmt.Sprintf("ares token_coverage: %s (%d proven)", category, bucket.Exploited),
			"description": "exploited",
		})
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
