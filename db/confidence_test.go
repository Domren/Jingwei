package db

// P10：置信度归一化的默认值兼容（老 finding / 未知值一律 observed）。

import "testing"

func TestNormalizeFindingConfidence(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", FindingConfidenceObserved},
		{"  ", FindingConfidenceObserved},
		{"legacy_unknown", FindingConfidenceObserved},
		{"OBSERVED", FindingConfidenceObserved},
		{"observed", FindingConfidenceObserved},
		{"inferred", FindingConfidenceInferred},
		{" INFERRED ", FindingConfidenceInferred},
		{"failed", FindingConfidenceFailed},
	}
	for _, tc := range cases {
		if got := NormalizeFindingConfidence(tc.in); got != tc.want {
			t.Fatalf("NormalizeFindingConfidence(%q) = %q，期望 %q", tc.in, got, tc.want)
		}
	}
}
