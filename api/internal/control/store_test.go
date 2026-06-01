package control

import (
	"strings"
	"testing"
)

func TestValidateRulesParsesSupportedExpressions(t *testing.T) {
	validation := ValidateRules([]Rule{
		{
			Name:       "Block command",
			Hook:       "command",
			Algorithm:  "command_common",
			Action:     "block",
			Severity:   "high",
			Expression: `message contains "Runtime.exec" && attributes.source == "policy-console"`,
		},
	})
	if !validation.Valid {
		t.Fatalf("expected valid rule, got %#v", validation.Errors)
	}
}

func TestValidateRulesRejectsUnsupportedRules(t *testing.T) {
	validation := ValidateRules([]Rule{
		{Name: "Bad hook", Hook: "unknown", Action: "block", Expression: "message contains test"},
		{Name: "Bad regex", Hook: "command", Action: "block", Expression: "message matches ["},
		{Name: "Bad algorithm", Hook: "command", Algorithm: "sql_regex", Action: "block", Expression: "test"},
	})
	if validation.Valid {
		t.Fatal("expected invalid rules")
	}
	joined := strings.Join(validation.Errors, "\n")
	for _, want := range []string{"hook is not supported", "regex is invalid", "algorithm is not supported"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected %q in errors: %#v", want, validation.Errors)
		}
	}
}

func TestRuleTestEvaluatesStructuredConditions(t *testing.T) {
	result := TestRule(
		Rule{
			Name:       "Command detector",
			Hook:       "command",
			Algorithm:  "command_common",
			Action:     "block",
			Expression: `message contains "Runtime.exec" && attributes.source == "policy-console"`,
		},
		SecurityEvent{
			Hook:      "command",
			Algorithm: "command_common",
			Severity:  "high",
			Message:   "java.lang.Runtime.exec invoked",
			Attributes: map[string]any{
				"source": "policy-console",
			},
		},
	)
	if !result.Matched || result.Confidence != 95 || result.Action != "block" {
		t.Fatalf("unexpected rule test result: %#v", result)
	}
}

func TestRuleTestRequiresAllConditions(t *testing.T) {
	result := TestRule(
		Rule{Hook: "command", Action: "block", Expression: `message contains "Runtime.exec" && severity == "critical"`},
		SecurityEvent{Hook: "command", Severity: "low", Message: "java.lang.Runtime.exec invoked", Attributes: map[string]any{}},
	)
	if result.Matched || result.Confidence != 0 {
		t.Fatalf("expected no match, got %#v", result)
	}
}
