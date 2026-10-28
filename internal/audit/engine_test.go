package audit_test

import (
	"testing"

	"github.com/iluha481/config-audit/internal/audit"
	"github.com/iluha481/config-audit/internal/config"
	"github.com/iluha481/config-audit/internal/rule"
)

func TestAudit_DebugLogging_JSON(t *testing.T) {
	// Пример из технического задания:
	// {"version": "0.1", "log":{"output":"stdout", "level": "debug"}}
	rawJSON := `{"version": "0.1", "log":{"output":"stdout", "level": "debug"}}`

	parser := config.NewParser()
	doc, err := parser.Parse([]byte(rawJSON), ".json")
	if err != nil {
		t.Fatalf("failed to parse json: %v", err)
	}

	rules := &rule.Rules{
		Version: 1,
		Rules: []rule.Rule{
			{
				ID:             "log.debug",
				Name:           "Debug logging",
				Severity:       rule.SeverityLow,
				Message:        "логирование в debug-режиме",
				Recommendation: "Поменяйте режим на более избирательный (info+).",
				MatchMode:      rule.MatchModeAny,
				Match: []rule.Match{
					{
						Keys:       []string{"level", "log-level"},
						Context:    []string{"log"},
						Operator:   rule.OpIn,
						Values:     []string{"debug", "trace"},
						IgnoreCase: true,
					},
				},
			},
		},
	}

	report, err := audit.Audit(doc, rules)
	if err != nil {
		t.Fatalf("audit error: %v", err)
	}

	if len(report.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(report.Findings))
	}

	f := report.Findings[0]
	if f.Severity != rule.SeverityLow {
		t.Errorf("expected LOW severity, got %v", f.Severity)
	}
	if f.Path != "log.level" {
		t.Errorf("expected path 'log.level', got %q", f.Path)
	}
}

func TestAudit_WeakAlgorithm_YAML(t *testing.T) {
	// Пример из технического задания:
	// version: 2.2
	// storage:
	//   digest-algorithm: MD5
	rawYAML := `
    version: 2.2
    storage:
      digest-algorithm: MD5
    `

	parser := config.NewParser()
	doc, err := parser.Parse([]byte(rawYAML), ".yaml")
	if err != nil {
		t.Fatalf("failed to parse yaml: %v", err)
	}

	rules := &rule.Rules{
		Version: 1,
		Rules: []rule.Rule{
			{
				ID:             "crypto.weak_hash",
				Name:           "Weak Hash",
				Severity:       rule.SeverityHigh,
				Message:        "слишком слабый алгоритм - {{value}}",
				Recommendation: "Замените его на более безопасный.",
				Match: []rule.Match{
					{
						Keys:       []string{"digest-algorithm", "algorithm"},
						Operator:   rule.OpIn,
						Values:     []string{"MD5", "SHA1"},
						IgnoreCase: true,
					},
				},
			},
		},
	}

	report, err := audit.Audit(doc, rules)
	if err != nil {
		t.Fatalf("audit error: %v", err)
	}

	if len(report.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(report.Findings))
	}

	f := report.Findings[0]
	if f.Severity != rule.SeverityHigh {
		t.Errorf("expected HIGH severity, got %v", f.Severity)
	}
	if f.Message != "слишком слабый алгоритм - MD5" {
		t.Errorf("unexpected message: %q", f.Message)
	}
	if f.Line != 4 {
		t.Errorf("expected line 4 for YAML node, got %d", f.Line)
	}
}

func TestAudit_IgnoreReferences(t *testing.T) {
	rawJSON := `{"db": {"password": "${DB_PASSWORD}"}}`

	parser := config.NewParser()
	doc, err := parser.Parse([]byte(rawJSON), ".json")
	if err != nil {
		t.Fatalf("failed to parse json: %v", err)
	}

	rules := &rule.Rules{
		Version: 1,
		Rules: []rule.Rule{
			{
				ID:             "cred.plaintext",
				Name:           "Plaintext Password",
				Severity:       rule.SeverityHigh,
				Message:        "Plaintext password found",
				Recommendation: "Use environment variables",
				Match: []rule.Match{
					{
						Keys:             []string{"password"},
						Operator:         rule.OpExists,
						IgnoreReferences: true,
					},
				},
			},
		},
	}

	report, err := audit.Audit(doc, rules)
	if err != nil {
		t.Fatalf("audit error: %v", err)
	}

	// Так как пароль передан как ссылка ${DB_PASSWORD}, находки быть не должно.
	if len(report.Findings) != 0 {
		t.Fatalf("expected 0 findings for reference value, got %d", len(report.Findings))
	}
}
