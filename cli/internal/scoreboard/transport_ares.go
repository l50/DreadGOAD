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
	OperationID      string                       `json:"operation_id"`
	StartedAt        string                       `json:"started_at"`
	Credentials      []aresCredEntry              `json:"credentials"`
	Hashes           []aresHashEntry              `json:"hashes"`
	DomainCompromise []aresDomainCompromise       `json:"domain_compromise"`
	TokenCoverage    map[string]aresTokenCoverage `json:"token_coverage"`
}

// aresTokenCoverage mirrors one entry of the ares loot JSON's `token_coverage`
// map, which ares emits keyed by scoreboard category (`ares-cli`
// `ops/loot/format/json.rs`, `build_token_coverage_json`). Its doc comment
// names the dreadgoad scoreboard verifier as an intended consumer, precisely so
// downstream stops re-deriving category mapping from raw `vuln_id` strings.
//
// `Exploited` is proven-only: ares subtracts its superseded set before
// counting, so back-credited techniques (a goal another path already reached)
// do not inflate it. That subtraction is what lets DreadGOAD drop its own
// `SDIFF exploited superseded` round-trip against Redis.
type aresTokenCoverage struct {
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
// translates the result into synthetic JSONL findings. The payload is
// gzip+base64-encoded to sidestep SSM's 24KB stdout cap. Returns ErrNoReport
// when the operation hasn't produced any state yet.
//
// Technique credit comes from `token_coverage`, which ares computes with its
// own category mapping and its own superseded subtraction. Reading it replaces
// both the second Redis round-trip and the hand-maintained prefix table that
// used to translate raw `vuln_id` strings here, so the two sides can no longer
// drift apart on category naming.
func (t *AresTransport) FetchReport(ctx context.Context) (string, error) {
	const jqFilter = `{operation_id, started_at, token_coverage,` +
		` credentials: [.credentials[] | {username, password, domain, is_admin}],` +
		` hashes: [.hashes[] | {username, domain, hash_value, hash_type, source}],` +
		` domain_compromise: [.domain_compromise[] | {domain, has_domain_admin, has_golden_ticket, admin_users, krbtgt_hash_types}]}`
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

	return synthesizeJSONL(&loot), nil
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

// aresCategoryToTechniqueID translates an ares `token_coverage` category key to
// the answer-key technique ID it credits, or "" for categories the scoreboard
// deliberately does not credit.
//
// ares already normalises most aliases to the scoreboard's own names in
// `token_category` (`gpo`→`gpo_abuse`, `mssql_impersonation`→`mssql_exploit`,
// `ntlmv1`→`ntlmv1_downgrade`, `llmnr`→`llmnr_nbtns_poisoning`,
// `sid_history`→`sid_history_abuse`, `gmsa`/`laps`→`*_password_read`), so the
// vast majority pass through untouched. Only the exceptions below need stating,
// and each one is a real disagreement rather than a naming preference.
func aresCategoryToTechniqueID(category string) string {
	switch category {
	case "forest_trust":
		// ares has no normalisation arm for this one, so it emits the bare
		// prefix while the answer key declares `cross_forest_trust`. Passing it
		// through unchanged silently drops the objective.
		return "cross_forest_trust"
	case "zerologon":
		// ares mints a zerologon id from the nxc *check* module and never runs
		// the password reset, so the id records a detection rather than an
		// exploit. Crediting it would flip an objective nothing exercised.
		return ""
	case "golden_ticket":
		// ares collapses `golden_ticket_<domain>` to a single bare category,
		// discarding the domain. The answer key declares one objective per
		// domain because forging needs that domain's krbtgt hash, so these are
		// credited from `domain_compromise[]` instead, which keeps the domain.
		return ""
	case "other":
		// token_category's catch-all for ids it does not recognise.
		return ""
	default:
		return category
	}
}

// writeTokenCoverageEntries credits one technique objective per ares category
// with at least one proven exploit. Categories are walked in sorted order so
// the synthesized JSONL is byte-stable across polls of unchanged state.
func writeTokenCoverageEntries(b *strings.Builder, coverage map[string]aresTokenCoverage, emitted map[string]bool) {
	categories := make([]string, 0, len(coverage))
	for c := range coverage {
		categories = append(categories, c)
	}
	sort.Strings(categories)

	for _, category := range categories {
		cov := coverage[category]
		if cov.Exploited <= 0 {
			continue
		}
		techID := aresCategoryToTechniqueID(category)
		if techID == "" || emitted[techID] {
			continue
		}
		emitted[techID] = true
		writeJSONLEntry(b, map[string]string{
			"target":      "tech:" + techID,
			"evidence":    fmt.Sprintf("ares: token_coverage %s exploited=%d discovered=%d", category, cov.Exploited, cov.Discovered),
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
