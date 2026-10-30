package server

import (
	"fmt"
	"strings"

	"github.com/Autumn-27/jingwei/db"
	"github.com/Autumn-27/jingwei/scanner"
	"github.com/Autumn-27/jingwei/verdict"
)

// assessNucleiHit applies the anti-false-positive rules to one nuclei hit. The
// matcher profile comes from the template, the rest from the live result.
func assessNucleiHit(res scanner.NucleiResult, tpl db.POCTemplate) verdict.Decision {
	status, _ := intFromRaw(res.Raw, "response-code")
	return verdict.Assess(verdict.Observation{
		TemplateID: displayOr(res.TemplateID, tpl.TemplateID),
		Name:       displayOr(res.Name, tpl.Name),
		Tags:       tpl.Tags,
		Type:       res.Type,
		StatusCode: status,
		Response:   stringFromRaw(res.Raw, "response"),
		Extracted:  res.Extracted,
		MatchedAt:  displayOr(res.MatchedAt, res.Host),
		Matcher:    verdict.ParseMatcherProfile(tpl.Content),
	})
}

// verdictEvidence renders the decision into the exploit record evidence so the
// UI, reports and LLM tools all see the same reasoning.
func verdictEvidence(d verdict.Decision) string {
	var b strings.Builder
	fmt.Fprintf(&b, "判定: %s（类别 %s）", d.Verdict, d.Class)
	for _, reason := range d.Reasons {
		fmt.Fprintf(&b, "\n- %s", reason)
	}
	if len(d.Checks) > 0 {
		b.WriteString("\n复核清单:")
		for i, check := range d.Checks {
			fmt.Fprintf(&b, "\n%d. %s", i+1, check)
		}
	}
	return b.String()
}
