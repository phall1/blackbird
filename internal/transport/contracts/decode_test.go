package contracts

import (
	"strings"
	"testing"
)

func TestJSONNestingDepthBoundary(t *testing.T) {
	t.Parallel()

	atLimit := strings.Repeat("[", maxJSONNestingDepth) + "0" +
		strings.Repeat("]", maxJSONNestingDepth)
	if err := validateNoDuplicateJSONKeys([]byte(atLimit)); err != nil {
		t.Fatalf("depth %d error = %v", maxJSONNestingDepth, err)
	}

	overLimit := strings.Repeat("[", maxJSONNestingDepth+1) + "0" +
		strings.Repeat("]", maxJSONNestingDepth+1)
	if err := validateNoDuplicateJSONKeys([]byte(overLimit)); err == nil {
		t.Fatalf("depth %d error = nil", maxJSONNestingDepth+1)
	}
}
