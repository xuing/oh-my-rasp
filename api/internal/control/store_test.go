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

func TestDefaultPolicyRulesCoverSupportedAlgorithms(t *testing.T) {
	catalog := SupportedPolicyAlgorithmCatalog()
	rules := DefaultPolicyRules()
	validation := ValidateRules(rules)
	if !validation.Valid {
		t.Fatalf("expected default rules to validate, got %#v", validation.Errors)
	}
	expected := 0
	seen := map[string]bool{}
	for _, item := range catalog.Items {
		if len(item.Algorithms) == 0 {
			t.Fatalf("expected algorithms for hook %s", item.Hook)
		}
		expected += len(item.Algorithms)
		for _, algorithm := range item.Algorithms {
			seen[item.Hook+"|"+algorithm] = false
		}
	}
	if len(rules) != expected {
		t.Fatalf("expected %d default rules, got %d", expected, len(rules))
	}
	for _, rule := range rules {
		key := rule.Hook + "|" + rule.Algorithm
		if _, ok := seen[key]; !ok {
			t.Fatalf("unexpected default rule %#v", rule)
		}
		seen[key] = true
	}
	for key, ok := range seen {
		if !ok {
			t.Fatalf("missing default rule for %s", key)
		}
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
