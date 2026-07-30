package scoreboard

import (
	"reflect"
	"testing"
)

// TestAresExploitedToTechniqueIDs pins the mapping against the vuln_id shapes
// ares actually SADDs into `ares:op:<id>:exploited`. The literals below are
// taken from the ares construction sites, not invented: acl_* from
// `orchestrator/result_processing/acl_grants.rs`, gpo_* from
// `ares-tools/src/parsers/ntsd.rs`, and the rest from
// `orchestrator/result_processing/mod.rs` and `orchestrator/automation/*`.
// ares mirrors this table in `ops/loot/format/display.rs` (token_category);
// the two must agree or the loot view and the status board disagree.
func TestAresExploitedToTechniqueIDs(t *testing.T) {
	tests := []struct {
		name  string
		entry string
		want  []string
	}{
		// ares emits the granted right in the id, never the literal
		// "acl_abuse". Matching on "acl_abuse_" credited nothing.
		{"acl generic all", "acl_genericall_tywin.lannister_kingsguard", []string{"acl_abuse"}},
		{"acl write property", "acl_writeproperty_stannis.baratheon_dragonstone", []string{"acl_abuse"}},
		{"acl write dacl", "acl_writedacl_alice_dc01", []string{"acl_abuse"}},
		{"acl all extended rights", "acl_allextendedrights_bob_carol", []string{"acl_abuse"}},

		// Same shape: gpo_<right>_<source>_<gpo-slug>.
		{"gpo write property", "gpo_writeproperty_alice__31b2f340_016d_11d2_945f_00c04fb984f9_", []string{"gpo_abuse"}},
		{"gpo generic all", "gpo_genericall_bob_default_domain_policy", []string{"gpo_abuse"}},

		// ESC8 is an answer-key objective and is in ares's
		// EXPLOITABLE_ESC_TYPES, but had no entry in the prefix table.
		{"adcs esc8", "adcs_esc8_192.168.58.50_ca01", []string{"adcs_esc8"}},

		// ESC1 must not swallow the longer ESC10/ESC11/ESC13/ESC15 forms.
		{"adcs esc1", "adcs_esc1_192.168.58.50_ESC1", []string{"adcs_esc1"}},
		{"adcs esc10 case1", "adcs_esc10_case1_192.168.58.50", []string{"adcs_esc10_case1"}},
		{"adcs esc10 case2", "adcs_esc10_case2_192.168.58.50", []string{"adcs_esc10_case2"}},
		{"adcs esc11", "adcs_esc11_192.168.58.50", []string{"adcs_esc11"}},
		{"adcs esc13", "adcs_esc13_192.168.58.50_group", []string{"adcs_esc13"}},
		{"adcs esc15", "adcs_esc15_192.168.58.50", []string{"adcs_esc15"}},

		// mssql_ is a prefix of the two longer forms; order decides.
		{"mssql linked server", "mssql_linked_server_192_168_58_22_sql01", []string{"mssql_linked_server"}},
		{"mssql impersonation", "mssql_impersonation_192_168_58_22", []string{"mssql_exploit"}},
		{"mssql bare", "mssql_192_168_58_22", []string{"mssql_exploit"}},

		{"kerberoast", "kerberoast_svc_sql", []string{"kerberoast"}},
		{"asrep roast", "asrep_roast_contoso.local", []string{"asrep_roast"}},
		{"ntlm relay", "ntlm_relay_192_168_58_10", []string{"ntlm_relay"}},
		{"ntlmv1 downgrade", "ntlmv1_192_168_58_12", []string{"ntlmv1_downgrade"}},
		{"seimpersonate", "seimpersonate_sql01", []string{"seimpersonate"}},
		{"nopac", "nopac_192_168_58_240", []string{"nopac"}},
		{"sid history", "sid_history_alice", []string{"sid_history_abuse"}},
		{"constrained delegation", "constrained_delegation_svc_web", []string{"constrained_delegation"}},
		{"unconstrained delegation", "unconstrained_delegation_dc01", []string{"unconstrained_delegation"}},
		{"shadow credentials", "shadow_credentials_dc01", []string{"shadow_credentials"}},
		{"rbcd", "rbcd_dc01", []string{"rbcd"}},
		{"gmsa", "gmsa_svc_gmsa", []string{"gmsa_password_read"}},
		{"laps", "laps_sql01", []string{"laps_password_read"}},
		{"forest trust", "forest_trust_escalation_fabrikam.local", []string{"cross_forest_trust"}},
		{"child to parent", "child_to_parent_contoso.local", []string{"child_to_parent"}},

		// Per-domain objective, lowercased.
		{"golden ticket", "golden_ticket_CONTOSO.LOCAL", []string{"golden_ticket-contoso.local"}},

		// Deliberately unmapped despite ares minting the prefix: the ares
		// evidence gate credits these on markers that precede success.
		// printnightmare accepts "Stub loaded"/"[+] Triggering" and zerologon
		// only ever runs the nxc check module, never the reset. Mapping them
		// would credit an attempt as an exploit.
		{"printnightmare unproven", "printnightmare_192_168_58_10", nil},
		{"zerologon check only", "zerologon_192_168_58_240", nil},

		// Discovery-only ids ares tracks that are not scoreboard techniques.
		{"smb signing", "smb_signing_192_168_58_10", nil},
		{"webdav", "webdav_enabled_192_168_58_22", nil},
		{"spooler", "spooler_192_168_58_10", nil},
		{"ldap signing", "ldap_signing_192_168_58_10", nil},
		{"dc secretsdump", "dc_secretsdump_contoso.local", nil},
		{"empty", "", nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := aresExploitedToTechniqueIDs(tc.entry)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("aresExploitedToTechniqueIDs(%q) = %v, want %v", tc.entry, got, tc.want)
			}
		})
	}
}

// TestAresExploitedTechniquesExistInAnswerKey guards against the drift that
// motivated this file: a prefix that maps to a technique ID the generated
// answer key never declares is a silently dead credit.
func TestAresExploitedTechniquesExistInAnswerKey(t *testing.T) {
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

	entries := []string{
		"acl_genericall_alice_bob",
		"gpo_writeproperty_alice_policy",
		"adcs_esc8_192.168.58.50_ca01",
		"kerberoast_svc_sql",
		"mssql_linked_server_192_168_58_22_sql01",
		"nopac_192_168_58_240",
	}
	for _, entry := range entries {
		ids := aresExploitedToTechniqueIDs(entry)
		if len(ids) == 0 {
			t.Errorf("%q maps to no technique", entry)
			continue
		}
		for _, id := range ids {
			if !known[id] {
				t.Errorf("%q maps to %q, which is not an answer-key objective", entry, id)
			}
		}
	}
}

// TestSplitExploitedSets covers the combined SMEMBERS parse: the proven subset
// drops superseded ids, while the raw set keeps them for drift detection.
func TestSplitExploitedSets(t *testing.T) {
	tests := []struct {
		name       string
		out        string
		wantProven []string
		wantAll    []string
	}{
		{
			name:       "superseded removed from proven only",
			out:        "kerberoast_svc_sql\nmssql_access_sql01\n" + exploitedSetMarker + "\nmssql_access_sql01\n",
			wantProven: []string{"kerberoast_svc_sql"},
			wantAll:    []string{"kerberoast_svc_sql", "mssql_access_sql01"},
		},
		{
			// ares only writes :superseded when something was superseded, so
			// the second SMEMBERS is routinely empty.
			name:       "absent superseded key",
			out:        "kerberoast_svc_sql\nrbcd_dc01\n" + exploitedSetMarker + "\n",
			wantProven: []string{"kerberoast_svc_sql", "rbcd_dc01"},
			wantAll:    []string{"kerberoast_svc_sql", "rbcd_dc01"},
		},
		{
			name:       "everything superseded",
			out:        "child_to_parent_contoso.local\n" + exploitedSetMarker + "\nchild_to_parent_contoso.local\n",
			wantProven: nil,
			wantAll:    []string{"child_to_parent_contoso.local"},
		},
		{
			name:       "both empty",
			out:        exploitedSetMarker + "\n",
			wantProven: nil,
			wantAll:    nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			proven, all := splitExploitedSets(tc.out)
			if !reflect.DeepEqual(proven, tc.wantProven) {
				t.Errorf("proven = %v, want %v", proven, tc.wantProven)
			}
			if !reflect.DeepEqual(all, tc.wantAll) {
				t.Errorf("all = %v, want %v", all, tc.wantAll)
			}
		})
	}
}

// TestDetectTokenCoverageDrift pins the cross-check against ares's own
// category mapping. The regression it exists to catch is the acl_/gpo_/esc8
// class: ares scores a category as exploited, our prefix table credits nothing.
func TestDetectTokenCoverageDrift(t *testing.T) {
	cov := func(pairs ...any) map[string]aresTokenBucket {
		m := map[string]aresTokenBucket{}
		for i := 0; i < len(pairs); i += 2 {
			m[pairs[i].(string)] = aresTokenBucket{Exploited: pairs[i+1].(int)}
		}
		return m
	}

	tests := []struct {
		name      string
		coverage  map[string]aresTokenBucket
		exploited []string
		want      []string
	}{
		{
			name:      "no drift when the table credits the category",
			coverage:  cov("acl_abuse", 3, "kerberoast", 1),
			exploited: []string{"acl_genericall_alice_bob", "kerberoast_svc_sql"},
			want:      nil,
		},
		{
			// The exact shape of the bug this detector exists for: before the
			// prefix fix, acl_* and gpo_* ids credited nothing at all.
			name:      "drift when a category credits nothing",
			coverage:  cov("acl_abuse", 3, "gpo_abuse", 1, "kerberoast", 1),
			exploited: []string{"kerberoast_svc_sql"},
			want:      []string{"acl_abuse", "gpo_abuse"},
		},
		{
			name:      "discovered-but-not-exploited is not drift",
			coverage:  cov("adcs_esc1", 0),
			exploited: nil,
			want:      nil,
		},
		{
			// nopac/printnightmare/zerologon all land in ares's catch-all, so
			// the bucket says nothing about our mapping either way.
			name:      "other bucket is exempt",
			coverage:  cov("other", 5),
			exploited: nil,
			want:      nil,
		},
		{
			// ares collapses golden_ticket_<domain> to one flat category; the
			// per-domain credit comes from domain_compromise[] instead.
			name:      "flat golden_ticket is exempt",
			coverage:  cov("golden_ticket", 2),
			exploited: nil,
			want:      nil,
		},
		{
			// ares category name differs from the answer-key technique ID.
			name:      "forest_trust alias resolves to cross_forest_trust",
			coverage:  cov("forest_trust", 1),
			exploited: []string{"forest_trust_escalation_fabrikam.local"},
			want:      nil,
		},
		{
			// The superseded filter must not read as drift: the raw set still
			// contains the id, so the mapping question answers "yes".
			name:      "superseded id still counts as mapped",
			coverage:  cov("child_to_parent", 1),
			exploited: []string{"child_to_parent_contoso.local"},
			want:      nil,
		},
		{
			name:      "missing token_coverage disables the check",
			coverage:  nil,
			exploited: nil,
			want:      nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := detectTokenCoverageDrift(&aresLoot{TokenCoverage: tc.coverage}, tc.exploited)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("detectTokenCoverageDrift() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestDriftCategoriesCoverAresTokenCategory asserts that every category name
// ares's token_category can return is either creditable by our prefix table,
// explicitly exempt, or explicitly aliased. A new ares category that is none
// of those would warn forever, which trains operators to ignore the signal.
func TestDriftCategoriesCoverAresTokenCategory(t *testing.T) {
	// Mirrors the return values of token_category in ares-cli
	// `ops/loot/format/display.rs`, paired with a representative vuln_id.
	aresCategories := map[string]string{
		"acl_abuse":                "acl_genericall_alice_bob",
		"gpo_abuse":                "gpo_writeproperty_alice_policy",
		"adcs_esc1":                "adcs_esc1_192.168.58.50_t",
		"adcs_esc2":                "adcs_esc2_192.168.58.50_t",
		"adcs_esc3":                "adcs_esc3_192.168.58.50_t",
		"adcs_esc4":                "adcs_esc4_192.168.58.50_t",
		"adcs_esc6":                "adcs_esc6_192.168.58.50_t",
		"adcs_esc7":                "adcs_esc7_192.168.58.50_t",
		"adcs_esc8":                "adcs_esc8_192.168.58.50_t",
		"adcs_esc9":                "adcs_esc9_192.168.58.50_t",
		"adcs_esc10_case1":         "adcs_esc10_case1_192.168.58.50",
		"adcs_esc10_case2":         "adcs_esc10_case2_192.168.58.50",
		"adcs_esc11":               "adcs_esc11_192.168.58.50",
		"adcs_esc13":               "adcs_esc13_192.168.58.50",
		"adcs_esc15":               "adcs_esc15_192.168.58.50",
		"mssql_linked_server":      "mssql_linked_server_sql01",
		"mssql_exploit":            "mssql_impersonation_sql01",
		"constrained_delegation":   "constrained_delegation_svc",
		"unconstrained_delegation": "unconstrained_delegation_dc01",
		"shadow_credentials":       "shadow_credentials_dc01",
		"ntlm_relay":               "ntlm_relay_192_168_58_10",
		"child_to_parent":          "child_to_parent_contoso.local",
		"forest_trust":             "forest_trust_escalation_fabrikam.local",
		"sid_history_abuse":        "sid_history_alice",
		"asrep_roast":              "asrep_roast_contoso.local",
		"seimpersonate":            "seimpersonate_sql01",
		"kerberoast":               "kerberoast_svc_sql",
		"ntlmv1_downgrade":         "ntlmv1_192_168_58_12",
		"llmnr_nbtns_poisoning":    "llmnr_192_168_58_11",
		"gmsa_password_read":       "gmsa_svc",
		"laps_password_read":       "laps_sql01",
		"rbcd":                     "rbcd_dc01",
	}

	for category, vulnID := range aresCategories {
		t.Run(category, func(t *testing.T) {
			drift := detectTokenCoverageDrift(
				&aresLoot{TokenCoverage: map[string]aresTokenBucket{category: {Exploited: 1}}},
				[]string{vulnID},
			)
			if len(drift) != 0 {
				t.Errorf("category %q with vuln_id %q reports drift %v; it needs a prefix entry, an alias, or an exemption",
					category, vulnID, drift)
			}
		})
	}
}
