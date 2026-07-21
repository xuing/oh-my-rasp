package control

import (
	"encoding/json"
	"testing"
)

func TestIntAttributeClampsToPortableRange(t *testing.T) {
	attributes := map[string]any{
		"high": json.Number("9223372036854775807"),
		"low":  json.Number("-9223372036854775808"),
	}
	if got := intAttribute(attributes, "high"); got != 2147483647 {
		t.Fatalf("high value = %d, want 2147483647", got)
	}
	if got := intAttribute(attributes, "low"); got != -2147483648 {
		t.Fatalf("low value = %d, want -2147483648", got)
	}
}
