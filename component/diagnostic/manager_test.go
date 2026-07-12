package diagnostic

import "testing"

func TestPercentile(t *testing.T) {
	if got := percentile([]float64{4, 1, 3, 2}, .5); got != 2.5 {
		t.Fatalf("p50=%v", got)
	}
}

func TestValidateRejectsUnsafeRequest(t *testing.T) {
	r := defaults(StartRequest{Proxy: "DIRECT", Profile: ProfileGame, Target: "example.com", Token: "secret"})
	if validate(r) == nil {
		t.Fatal("expected hostname to be rejected")
	}
}
