package scoreboard

import (
	"path/filepath"
	"testing"
)

// techniqueSet generates the answer key for a lab and returns its technique IDs.
func techniqueSet(t *testing.T, lab string) map[string]bool {
	t.Helper()
	ak, err := GenerateAnswerKey(filepath.Join("../../../ad", lab, "data", "config.json"))
	if err != nil {
		t.Fatalf("%s: %v", lab, err)
	}
	out := map[string]bool{}
	for _, o := range ak.Objectives {
		if o.Group == "techniques" {
			out[o.Technique] = true
		}
	}
	return out
}

// TestTopologyGatedTechniques pins the techniques that must not be credited to
// labs that cannot host them. These were previously added unconditionally, which
// put uncompletable objectives on the answer key: ADCS techniques on labs with no
// CA, and child-to-parent escalation on labs with no child domain.
func TestTopologyGatedTechniques(t *testing.T) {
	// Labs with no ADCS provisioning at all. MINILAB, SCCM, and DRACARYS have an
	// empty `adcs` inventory group; TEMPLATE is a scaffold that plants no ADCS.
	for _, lab := range []string{"MINILAB", "SCCM", "DRACARYS", "TEMPLATE"} {
		t.Run("no_adcs/"+lab, func(t *testing.T) {
			techs := techniqueSet(t, lab)
			for _, id := range []string{"certifried", "adcs_esc8"} {
				if techs[id] {
					t.Errorf("%s has no CA but was credited %q", lab, id)
				}
			}
		})
	}

	// Single-domain labs, and NHA whose two domains are separate forest roots
	// (ninja.hack and academy.ninja.lan), so neither is a child of the other.
	for _, lab := range []string{"GOAD-Mini", "MINILAB", "SCCM", "DRACARYS", "TEMPLATE", "NHA"} {
		t.Run("no_child_domain/"+lab, func(t *testing.T) {
			if techniqueSet(t, lab)["child_to_parent"] {
				t.Errorf("%s has no parent/child domain pair but was credited child_to_parent", lab)
			}
		})
	}

	// NHA installs a CA, so Certifried stands, but its CA-bearing domain sets
	// ca_web_enrollment=false, so ESC8 must not be credited.
	t.Run("nha_web_enrollment_disabled", func(t *testing.T) {
		techs := techniqueSet(t, "NHA")
		if !techs["certifried"] {
			t.Error("NHA installs a CA and should still be credited certifried")
		}
		if techs["adcs_esc8"] {
			t.Error("NHA disables ca_web_enrollment and must not be credited adcs_esc8")
		}
	})

	// Labs that do provision a CA keep their ADCS techniques. GOAD-Light and
	// GOAD-Mini install one via the `adcs` inventory group without setting the
	// domain-level ca_server key, so gating on ca_server alone would regress them.
	for _, lab := range []string{"GOAD", "GOAD-Light", "GOAD-Mini", "GOAD-variant-1"} {
		t.Run("has_adcs/"+lab, func(t *testing.T) {
			techs := techniqueSet(t, lab)
			for _, id := range []string{"certifried", "adcs_esc8"} {
				if !techs[id] {
					t.Errorf("%s provisions a CA but lost %q", lab, id)
				}
			}
		})
	}

	// GOAD-variant-1 is generated from GOAD and publishes the same certificate
	// templates, so it must credit the same per-template ESC techniques.
	t.Run("variant_matches_goad_templates", func(t *testing.T) {
		goad := techniqueSet(t, "GOAD")
		variant := techniqueSet(t, "GOAD-variant-1")
		for _, id := range []string{"adcs_esc1", "adcs_esc2", "adcs_esc3", "adcs_esc4", "adcs_esc9"} {
			if goad[id] && !variant[id] {
				t.Errorf("GOAD credits %q but GOAD-variant-1 does not", id)
			}
		}
	})
}
