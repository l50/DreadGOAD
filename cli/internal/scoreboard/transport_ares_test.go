package scoreboard

import (
	"strings"
	"testing"
)

// TestAresCategoryToTechniqueID pins the residual translation between ares's
// `token_coverage` category keys and answer-key technique IDs.
//
// ares normalises most aliases to the scoreboard's own names in
// `token_category` (`ares-cli/src/ops/loot/format/display.rs`), so the table
// here is deliberately tiny: every case below is either a real disagreement or
// a category the scoreboard refuses on purpose. If this test grows, the two
// sides have started drifting again and the fix belongs in ares, not here.
func TestAresCategoryToTechniqueID(t *testing.T) {
	tests := []struct {
		name     string
		category string
		want     string
	}{
		// ares emits the bare prefix; the answer key says cross_forest_trust.
		// Passing this through unchanged silently drops a real objective.
		{"forest trust is renamed", "forest_trust", "cross_forest_trust"},

		// ares only ever runs the nxc zerologon *check* module, never the
		// password reset, so its id is a detection and not an exploit.
		{"zerologon is refused", "zerologon", ""},

		// ares discards the domain; the answer key needs one objective per
		// domain, so these come from domain_compromise[] instead.
		{"golden ticket is refused", "golden_ticket", ""},

		// token_category's catch-all for ids it does not recognise.
		{"other is refused", "other", ""},

		// Everything ares already normalises passes through untouched.
		{"acl abuse", "acl_abuse", "acl_abuse"},
		{"gpo abuse", "gpo_abuse", "gpo_abuse"},
		{"mssql exploit", "mssql_exploit", "mssql_exploit"},
		{"mssql linked server", "mssql_linked_server", "mssql_linked_server"},
		{"ntlmv1 downgrade", "ntlmv1_downgrade", "ntlmv1_downgrade"},
		{"llmnr", "llmnr_nbtns_poisoning", "llmnr_nbtns_poisoning"},
		{"sid history", "sid_history_abuse", "sid_history_abuse"},
		{"gmsa", "gmsa_password_read", "gmsa_password_read"},
		{"laps", "laps_password_read", "laps_password_read"},
		{"child to parent", "child_to_parent", "child_to_parent"},
		{"kerberoast", "kerberoast", "kerberoast"},
		{"asrep roast", "asrep_roast", "asrep_roast"},
		{"nopac", "nopac", "nopac"},
		{"printnightmare", "printnightmare", "printnightmare"},
		{"adcs esc8", "adcs_esc8", "adcs_esc8"},
		{"adcs esc10 case1", "adcs_esc10_case1", "adcs_esc10_case1"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := aresCategoryToTechniqueID(tc.category); got != tc.want {
				t.Errorf("aresCategoryToTechniqueID(%q) = %q, want %q", tc.category, got, tc.want)
			}
		})
	}
}

// Only categories with a proven exploit may credit an objective. A category
// ares discovered but never exploited must stay dark, which is the whole point
// of reading `exploited` rather than `discovered`.
func TestWriteTokenCoverageEntries(t *testing.T) {
	coverage := map[string]aresTokenCoverage{
		"acl_abuse":     {Discovered: 12, Exploited: 3, Status: "partial"},
		"adcs_esc1":     {Discovered: 2, Exploited: 2, Status: "ok"},
		"kerberoast":    {Discovered: 4, Exploited: 0, Status: "missing"},
		"forest_trust":  {Discovered: 1, Exploited: 1, Status: "ok"},
		"zerologon":     {Discovered: 1, Exploited: 1, Status: "ok"},
		"golden_ticket": {Discovered: 0, Exploited: 1, Status: "ok"},
		"other":         {Discovered: 9, Exploited: 5, Status: "partial"},
	}

	var b strings.Builder
	writeTokenCoverageEntries(&b, coverage, map[string]bool{})
	got := b.String()

	for _, want := range []string{"tech:acl_abuse", "tech:adcs_esc1", "tech:cross_forest_trust"} {
		if !strings.Contains(got, want) {
			t.Errorf("expected %q in output:\n%s", want, got)
		}
	}
	for _, notWant := range []string{
		"tech:kerberoast",    // discovered but never exploited
		"tech:zerologon",     // check-only, refused
		"tech:golden_ticket", // credited from domain_compromise instead
		"tech:other",         // catch-all, refused
		"tech:forest_trust",  // must appear only under its renamed ID
	} {
		if strings.Contains(got, notWant) {
			t.Errorf("did not expect %q in output:\n%s", notWant, got)
		}
	}
}

// A technique already credited by an earlier writer must not be emitted twice;
// synthesizeJSONL shares one `emitted` map across all writers so the scoreboard
// sees a single finding per objective.
func TestWriteTokenCoverageEntries_RespectsEmitted(t *testing.T) {
	coverage := map[string]aresTokenCoverage{
		"acl_abuse": {Discovered: 1, Exploited: 1, Status: "ok"},
	}
	emitted := map[string]bool{"acl_abuse": true}

	var b strings.Builder
	writeTokenCoverageEntries(&b, coverage, emitted)

	if got := b.String(); got != "" {
		t.Errorf("expected no output for an already-emitted technique, got:\n%s", got)
	}
}

// Output order must not depend on Go's randomised map iteration, or an
// unchanged operation would synthesize a different report on every poll.
func TestWriteTokenCoverageEntries_DeterministicOrder(t *testing.T) {
	coverage := map[string]aresTokenCoverage{
		"acl_abuse":  {Discovered: 1, Exploited: 1},
		"adcs_esc1":  {Discovered: 1, Exploited: 1},
		"kerberoast": {Discovered: 1, Exploited: 1},
		"rbcd":       {Discovered: 1, Exploited: 1},
		"gpo_abuse":  {Discovered: 1, Exploited: 1},
	}

	var first strings.Builder
	writeTokenCoverageEntries(&first, coverage, map[string]bool{})
	want := first.String()

	for i := 0; i < 20; i++ {
		var b strings.Builder
		writeTokenCoverageEntries(&b, coverage, map[string]bool{})
		if got := b.String(); got != want {
			t.Fatalf("output not stable across iterations:\nfirst:\n%s\ngot:\n%s", want, got)
		}
	}
}

// An ares build that predates token_coverage, or an operation with no state
// yet, yields a nil map. That must be a quiet no-op rather than a panic.
func TestWriteTokenCoverageEntries_NilCoverage(t *testing.T) {
	var b strings.Builder
	writeTokenCoverageEntries(&b, nil, map[string]bool{})
	if got := b.String(); got != "" {
		t.Errorf("expected no output for nil coverage, got %q", got)
	}
}

// Golden-ticket objectives are per-domain and must survive the switch to
// token_coverage, which throws the domain away. They ride on domain_compromise[]
// instead, and the shared emitted map must not let the two paths collide.
func TestSynthesizeJSONL_GoldenTicketStillPerDomain(t *testing.T) {
	loot := &aresLoot{
		OperationID: "op1",
		StartedAt:   "2026-07-30T00:00:00Z",
		TokenCoverage: map[string]aresTokenCoverage{
			"golden_ticket": {Discovered: 0, Exploited: 1, Status: "ok"},
			"acl_abuse":     {Discovered: 2, Exploited: 1, Status: "partial"},
		},
		DomainCompromise: []aresDomainCompromise{
			{Domain: "ESSOS.LOCAL", HasDomainAdmin: true, HasGoldenTicket: true},
		},
	}

	got := synthesizeJSONL(loot)

	if !strings.Contains(got, "tech:golden_ticket-essos.local") {
		t.Errorf("expected per-domain golden ticket objective in output:\n%s", got)
	}
	if strings.Contains(got, `"target":"tech:golden_ticket"`) {
		t.Errorf("bare golden_ticket must not be credited:\n%s", got)
	}
	if !strings.Contains(got, "tech:acl_abuse") {
		t.Errorf("expected acl_abuse in output:\n%s", got)
	}
}

// Every technique ID this transport can emit must exist in the generated answer
// key. A category that maps to an ID the answer key never declares is a silently
// dead credit, which is the failure mode that motivated reading token_coverage
// in the first place.
func TestAresCategoriesExistInAnswerKey(t *testing.T) {
	ak, err := GenerateAnswerKey("../../../ad/GOAD/data/config.json")
	if err != nil {
		t.Fatal(err)
	}
	known := map[string]bool{}
	for _, obj := range ak.Objectives {
		if obj.Group == "techniques" {
			known[obj.Technique] = true
		}
	}

	// The categories ares can emit, taken from token_category's ADCS list and
	// CATEGORIES table in ares-cli display.rs.
	categories := []string{
		"acl_abuse", "gpo_abuse", "mssql_exploit", "mssql_linked_server",
		"constrained_delegation", "unconstrained_delegation", "shadow_credentials",
		"ntlm_relay", "child_to_parent", "forest_trust", "sid_history_abuse",
		"asrep_roast", "seimpersonate", "printnightmare", "kerberoast", "nopac",
		"ntlmv1_downgrade", "llmnr_nbtns_poisoning", "gmsa_password_read",
		"laps_password_read", "rbcd",
		"adcs_esc1", "adcs_esc2", "adcs_esc3", "adcs_esc4", "adcs_esc6",
		"adcs_esc7", "adcs_esc8", "adcs_esc9", "adcs_esc10_case1",
		"adcs_esc10_case2", "adcs_esc11", "adcs_esc13", "adcs_esc15",
	}
	for _, category := range categories {
		techID := aresCategoryToTechniqueID(category)
		if techID == "" {
			continue // deliberately refused
		}
		if !known[techID] {
			t.Errorf("category %q maps to %q, which is not an answer-key objective", category, techID)
		}
	}
}
