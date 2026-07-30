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
