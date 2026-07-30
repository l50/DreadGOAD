package scoreboard

import (
	"reflect"
	"strings"
	"testing"
)

// aresTokenCategories mirrors every category name ares's token_category can
// return (ares-cli `ops/loot/format/display.rs`). It is the input domain of the
// credit path, so both the credit table and the refusal table are checked
// against it below.
var aresTokenCategories = []string{
	"acl_abuse",
	"gpo_abuse",
	"adcs_esc1",
	"adcs_esc2",
	"adcs_esc3",
	"adcs_esc4",
	"adcs_esc6",
	"adcs_esc7",
	"adcs_esc8",
	"adcs_esc9",
	"adcs_esc10_case1",
	"adcs_esc10_case2",
	"adcs_esc11",
	"adcs_esc13",
	"adcs_esc15",
	"mssql_linked_server",
	"mssql_exploit",
	"constrained_delegation",
	"unconstrained_delegation",
	"shadow_credentials",
	"ntlm_relay",
	"child_to_parent",
	"forest_trust",
	"sid_history_abuse",
	"asrep_roast",
	"seimpersonate",
	"kerberoast",
	"ntlmv1_downgrade",
	"llmnr_nbtns_poisoning",
	"gmsa_password_read",
	"laps_password_read",
	"rbcd",
	"nopac",
	"printnightmare",
	"zerologon",
	"golden_ticket",
	"other",
}

// TestAresCategoryToTechniqueID pins the category join, including the refusals.
// ares owns the vuln_id-to-category derivation now, so the only thing this
// repo decides is which categories become answer-key credit.
func TestAresCategoryToTechniqueID(t *testing.T) {
	tests := []struct {
		name     string
		category string
		want     string
	}{
		{"identity mapping", "acl_abuse", "acl_abuse"},
		{"ares normalises its own alias", "gpo_abuse", "gpo_abuse"},
		{"esc8 credits", "adcs_esc8", "adcs_esc8"},
		{"long esc form is distinct", "adcs_esc10_case1", "adcs_esc10_case1"},
		{"nopac credits after ares #366", "nopac", "nopac"},

		// The one name that differs between the two vocabularies.
		{"forest_trust aliases to cross_forest_trust", "forest_trust", "cross_forest_trust"},

		// Refusals: ares mints these on evidence that precedes success, so
		// crediting them would score an attempt as an exploit.
		{"printnightmare refused", "printnightmare", ""},
		{"zerologon refused", "zerologon", ""},

		// Flat in ares, per-domain in the answer key; credited from
		// domain_compromise[] instead, which still carries the domain.
		{"golden_ticket refused", "golden_ticket", ""},

		// ares's catch-all holds discovery-only ids with no technique name.
		{"other refused", "other", ""},

		{"unknown category never credits", "brand_new_ares_category", ""},
		{"empty", "", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := aresCategoryToTechniqueID(tc.category); got != tc.want {
				t.Errorf("aresCategoryToTechniqueID(%q) = %q, want %q", tc.category, got, tc.want)
			}
		})
	}
}

// TestAresCreditedTechniquesExistInAnswerKey is the guard that keeps the credit
// table honest: a category mapping to a technique ID the generated answer key
// never declares is a credit that can never land. Every creditable category is
// checked, not a sample, so adding one without an objective fails here.
func TestAresCreditedTechniquesExistInAnswerKey(t *testing.T) {
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

	for category, techID := range creditableCategories {
		t.Run(category, func(t *testing.T) {
			if !known[techID] {
				t.Errorf("category %q credits %q, which is not an answer-key technique objective", category, techID)
			}
		})
	}
}

// TestEveryAresCategoryIsClassified asserts each category ares can emit is
// either creditable or an explicit refusal. An unclassified one credits
// nothing and warns forever, which trains operators to ignore the drift signal.
func TestEveryAresCategoryIsClassified(t *testing.T) {
	for _, category := range aresTokenCategories {
		t.Run(category, func(t *testing.T) {
			_, creditable := creditableCategories[category]
			if creditable == uncreditableCategories[category] {
				t.Errorf("category %q must be exactly one of creditable or uncreditable (creditable=%v, uncreditable=%v)",
					category, creditable, uncreditableCategories[category])
			}
		})
	}
}

// TestUncreditableCategoriesAreDeliberate pins the exact refusal set. Widening
// it is how a real technique goes quiet: a category moved here stops crediting
// and stops warning, so every entry has to be justified in the doc comment
// rather than added to silence a failing run.
func TestUncreditableCategoriesAreDeliberate(t *testing.T) {
	want := map[string]bool{
		"other":          true,
		"golden_ticket":  true,
		"printnightmare": true,
		"zerologon":      true,
	}
	if !reflect.DeepEqual(uncreditableCategories, want) {
		t.Errorf("uncreditableCategories = %v, want %v; a new refusal needs its rationale in the doc comment",
			uncreditableCategories, want)
	}
}

// TestDetectTokenCoverageDrift covers the surviving failure mode. ares owns the
// categorisation, so drift is no longer two tables disagreeing — it is ares
// emitting a category name this repo has never classified.
func TestDetectTokenCoverageDrift(t *testing.T) {
	cov := func(pairs ...any) map[string]aresTokenBucket {
		m := map[string]aresTokenBucket{}
		for i := 0; i < len(pairs); i += 2 {
			m[pairs[i].(string)] = aresTokenBucket{Exploited: pairs[i+1].(int)}
		}
		return m
	}

	tests := []struct {
		name     string
		coverage map[string]aresTokenBucket
		want     []string
	}{
		{
			name:     "no drift when every category is classified",
			coverage: cov("acl_abuse", 3, "kerberoast", 1),
			want:     nil,
		},
		{
			// A category ares adds upstream that nobody has classified here.
			name:     "unknown category with proven exploits drifts",
			coverage: cov("acl_abuse", 3, "esc12_of_the_future", 1),
			want:     []string{"esc12_of_the_future"},
		},
		{
			name:     "drifted categories are sorted",
			coverage: cov("zzz_new", 1, "aaa_new", 1),
			want:     []string{"aaa_new", "zzz_new"},
		},
		{
			name:     "discovered-but-not-exploited is not drift",
			coverage: cov("adcs_esc1", 0),
			want:     nil,
		},
		{
			// An unclassified category with no proven exploit says nothing.
			name:     "unknown category without exploits is not drift",
			coverage: cov("esc12_of_the_future", 0),
			want:     nil,
		},
		{
			name:     "deliberate refusals are exempt",
			coverage: cov("other", 5, "golden_ticket", 2, "printnightmare", 1, "zerologon", 1),
			want:     nil,
		},
		{
			name:     "forest_trust alias is classified",
			coverage: cov("forest_trust", 1),
			want:     nil,
		},
		{
			name:     "missing token_coverage disables the check",
			coverage: nil,
			want:     nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := detectTokenCoverageDrift(&aresLoot{TokenCoverage: tc.coverage})
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("detectTokenCoverageDrift() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestNoAresCategoryDrifts runs the real category list through the detector.
// Any category ares can emit must be silent when it reports a proven exploit.
func TestNoAresCategoryDrifts(t *testing.T) {
	for _, category := range aresTokenCategories {
		t.Run(category, func(t *testing.T) {
			drift := detectTokenCoverageDrift(
				&aresLoot{TokenCoverage: map[string]aresTokenBucket{category: {Exploited: 1}}},
			)
			if len(drift) != 0 {
				t.Errorf("category %q reports drift %v; it needs a credit entry or an explicit refusal", category, drift)
			}
		})
	}
}

// TestWriteTokenCoverageEntries covers what reaches the scoreboard: only
// categories with a proven exploit, only creditable ones, deduped against
// findings already emitted, and in a stable order.
func TestWriteTokenCoverageEntries(t *testing.T) {
	tests := []struct {
		name     string
		coverage map[string]aresTokenBucket
		emitted  map[string]bool
		want     []string
		absent   []string
	}{
		{
			name: "credits proven categories only",
			coverage: map[string]aresTokenBucket{
				"acl_abuse": {Discovered: 4, Exploited: 2, Status: "partial"},
				"adcs_esc1": {Discovered: 1, Exploited: 0, Status: "missing"},
			},
			want:   []string{"tech:acl_abuse"},
			absent: []string{"tech:adcs_esc1"},
		},
		{
			// ares subtracts superseded ids upstream, so a category credited
			// only by another path arrives as exploited=0 and must not score.
			name: "fully superseded category does not credit",
			coverage: map[string]aresTokenBucket{
				"child_to_parent": {Discovered: 1, Exploited: 0, Status: "missing"},
			},
			absent: []string{"tech:child_to_parent"},
		},
		{
			name: "refusals never credit",
			coverage: map[string]aresTokenBucket{
				"printnightmare": {Exploited: 3},
				"zerologon":      {Exploited: 1},
				"golden_ticket":  {Exploited: 2},
				"other":          {Exploited: 9},
			},
			absent: []string{"tech:printnightmare", "tech:zerologon", "tech:golden_ticket", "tech:other"},
		},
		{
			name:     "alias is credited under the answer-key id",
			coverage: map[string]aresTokenBucket{"forest_trust": {Exploited: 1}},
			want:     []string{"tech:cross_forest_trust"},
			absent:   []string{"tech:forest_trust"},
		},
		{
			name:     "already-emitted technique is not duplicated",
			coverage: map[string]aresTokenBucket{"kerberoast": {Exploited: 2}},
			emitted:  map[string]bool{"kerberoast": true},
			absent:   []string{"tech:kerberoast"},
		},
		{
			name:     "unknown category is dropped, not credited",
			coverage: map[string]aresTokenBucket{"esc12_of_the_future": {Exploited: 4}},
			absent:   []string{"tech:esc12_of_the_future"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var b strings.Builder
			emitted := tc.emitted
			if emitted == nil {
				emitted = map[string]bool{}
			}
			writeTokenCoverageEntries(&b, tc.coverage, emitted)
			out := b.String()

			for _, want := range tc.want {
				if !strings.Contains(out, want) {
					t.Errorf("missing %q in output:\n%s", want, out)
				}
			}
			for _, absent := range tc.absent {
				if strings.Contains(out, absent) {
					t.Errorf("unexpected %q in output:\n%s", absent, out)
				}
			}
		})
	}
}

// TestWriteTokenCoverageEntriesIsDeterministic guards the sort: Go map order is
// randomised per run, and an unstable synthesized report would churn the
// scoreboard between otherwise identical polls.
func TestWriteTokenCoverageEntriesIsDeterministic(t *testing.T) {
	coverage := map[string]aresTokenBucket{
		"rbcd":       {Exploited: 1},
		"acl_abuse":  {Exploited: 1},
		"kerberoast": {Exploited: 1},
		"nopac":      {Exploited: 1},
	}

	var first string
	for i := 0; i < 20; i++ {
		var b strings.Builder
		writeTokenCoverageEntries(&b, coverage, map[string]bool{})
		got := b.String()
		if i == 0 {
			first = got
			continue
		}
		if got != first {
			t.Fatalf("output is not deterministic:\nfirst:\n%s\ngot:\n%s", first, got)
		}
	}
}

// TestTokenCoverageEvidenceNamesTheCategory documents the auditability tradeoff
// this credit source makes: the evidence string carries the category and its
// proven count, because token_coverage is aggregated and ares no longer hands
// over the individual vuln_ids.
func TestTokenCoverageEvidenceNamesTheCategory(t *testing.T) {
	var b strings.Builder
	writeTokenCoverageEntries(&b, map[string]aresTokenBucket{
		"acl_abuse": {Discovered: 7, Exploited: 3, Status: "partial"},
	}, map[string]bool{})

	out := b.String()
	if !strings.Contains(out, "ares token_coverage: acl_abuse (3 proven)") {
		t.Errorf("evidence should name the category and proven count, got:\n%s", out)
	}
}
