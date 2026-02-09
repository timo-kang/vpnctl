package stunutil

import "testing"

func TestClassify(t *testing.T) {
	t.Parallel()

	if got := Classify([]string{"1.2.3.4:1"}); got != NATTypeUnknown {
		t.Fatalf("got=%q", got)
	}
	if got := Classify([]string{"1.2.3.4:1", "1.2.3.4:1"}); got != NATTypeConeOrRestricted {
		t.Fatalf("got=%q", got)
	}
	if got := Classify([]string{"1.2.3.4:1", "1.2.3.4:2"}); got != NATTypeSymmetric {
		t.Fatalf("got=%q", got)
	}
}
