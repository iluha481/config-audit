package service_test

import (
	"errors"
	"testing"

	"github.com/iluha481/config-audit/internal/audit"
	"github.com/iluha481/config-audit/internal/config"
	"github.com/iluha481/config-audit/internal/rule"
	"github.com/iluha481/config-audit/internal/service"
)

func newService(t *testing.T, defaults *rule.Rules) *service.AuditService {
	t.Helper()

	svc, err := service.New(config.NewParser(), audit.NewEngine(), defaults)
	if err != nil {
		t.Fatalf("service.New: %v", err)
	}
	return svc
}

func defaultRules(t *testing.T) *rule.Rules {
	t.Helper()

	rules, err := rule.DefaultRules()
	if err != nil {
		t.Fatalf("rule.DefaultRules: %v", err)
	}
	return rules
}

func TestAudit_UsesProvidedDefaults(t *testing.T) {
	defaults := &rule.Rules{
		Version: 1,
		Rules: []rule.Rule{
			{
				ID:             "custom.default",
				Name:           "Custom default",
				Severity:       rule.SeverityHigh,
				Message:        "custom default rule",
				Recommendation: "fix custom default",
				Match: []rule.Match{
					{
						Keys:     []string{"custom"},
						Operator: rule.OpEquals,
						Values:   []string{"bad"},
					},
				},
			},
		},
	}

	svc := newService(t, defaults)
	report, err := svc.Audit(service.Input{
		Config: []byte(`{"custom":"bad","log":{"level":"debug"}}`),
	})
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}

	if len(report.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(report.Findings))
	}
	if report.Findings[0].RuleID != "custom.default" {
		t.Fatalf("rule ID = %q, want custom.default", report.Findings[0].RuleID)
	}
}

func TestAudit_UsesCustomRules(t *testing.T) {
	svc := newService(t, nil)

	customRules := []byte(`{
		"version": 1,
		"rules": [
			{
				"id": "custom.rule",
				"name": "Custom rule",
				"severity": "HIGH",
				"message": "custom hit",
				"recommendation": "fix custom",
				"match": [
					{
						"keys": ["custom"],
						"operator": "equals",
						"values": ["bad"]
					}
				]
			}
		]
	}`)

	report, err := svc.Audit(service.Input{
		Config: []byte(`{"custom":"bad","log":{"level":"debug"}}`),
		Rules:  customRules,
	})
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}

	if len(report.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(report.Findings))
	}
	if report.Findings[0].RuleID != "custom.rule" {
		t.Fatalf("rule ID = %q, want custom.rule", report.Findings[0].RuleID)
	}
}

func TestAudit_EmptyRulesUseDefaults(t *testing.T) {
	tests := []struct {
		name  string
		rules []byte
	}{
		{name: "nil", rules: nil},
		{name: "empty", rules: []byte("")},
		{name: "whitespace", rules: []byte(" \n\t ")},
		{name: "empty object", rules: []byte(`{}`)},
		{name: "empty rule list", rules: []byte(`{"version":1,"rules":[]}`)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := newService(t, defaultRules(t))
			report, err := svc.Audit(service.Input{
				Config: []byte(`{"log":{"level":"debug"}}`),
				Rules:  tt.rules,
			})
			if err != nil {
				t.Fatalf("Audit: %v", err)
			}

			if len(report.Findings) != 1 {
				t.Fatalf("findings = %d, want 1", len(report.Findings))
			}
			if report.Findings[0].RuleID != "log.debug" {
				t.Fatalf("rule ID = %q, want log.debug", report.Findings[0].RuleID)
			}
		})
	}
}

func TestAudit_InvalidRules(t *testing.T) {
	tests := []struct {
		name  string
		rules []byte
	}{
		{name: "malformed", rules: []byte(`{invalid`)},
		{
			name:  "invalid schema",
			rules: []byte(`{"version":1,"rules":[{"id":"custom.rule"}]}`),
		},
		{
			name: "invalid regex",
			rules: []byte(`{
				"version": 1,
				"rules": [
					{
						"id": "custom.regex",
						"name": "Custom regex",
						"severity": "LOW",
						"message": "regex hit",
						"recommendation": "fix regex",
						"match": [
							{
								"keys": ["custom"],
								"operator": "regex",
								"values": ["["]
							}
						]
					}
				]
			}`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := newService(t, defaultRules(t))
			_, err := svc.Audit(service.Input{
				Config: []byte(`{"custom":"bad"}`),
				Rules:  tt.rules,
			})
			if !errors.Is(err, service.ErrInvalidRules) {
				t.Fatalf("error = %v, want ErrInvalidRules", err)
			}
		})
	}
}

func TestAudit_Formats(t *testing.T) {
	tests := []struct {
		name    string
		config  []byte
		format  config.Format
		wantErr bool
	}{
		{
			name:   "yaml explicit",
			config: []byte("log:\n  level: debug\n"),
			format: config.FormatYAML,
		},
		{
			name:   "yaml auto",
			config: []byte("log:\n  level: debug\n"),
		},
		{
			name:   "json explicit",
			config: []byte(`{"log":{"level":"debug"}}`),
			format: config.FormatJSON,
		},
		{
			name:   "json as yaml",
			config: []byte(`{"log":{"level":"debug"}}`),
			format: config.FormatYAML,
		},
		{
			name:    "yaml as json",
			config:  []byte("log:\n  level: debug\n"),
			format:  config.FormatJSON,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := newService(t, defaultRules(t))
			report, err := svc.Audit(service.Input{
				Config: tt.config,
				Format: tt.format,
			})

			if tt.wantErr {
				if !errors.Is(err, service.ErrInvalidConfig) {
					t.Fatalf("error = %v, want ErrInvalidConfig", err)
				}
				return
			}

			if err != nil {
				t.Fatalf("Audit: %v", err)
			}
			if len(report.Findings) != 1 {
				t.Fatalf("findings = %d, want 1", len(report.Findings))
			}
		})
	}
}

func TestAudit_EmptyConfig(t *testing.T) {
	svc := newService(t, defaultRules(t))

	for _, input := range [][]byte{nil, []byte(""), []byte(" \n\t ")} {
		_, err := svc.Audit(service.Input{Config: input})
		if !errors.Is(err, service.ErrInvalidConfig) {
			t.Fatalf("error = %v, want ErrInvalidConfig", err)
		}
	}
}

func TestAudit_SourceNameAndEmptyFindings(t *testing.T) {
	svc := newService(t, defaultRules(t))

	report, err := svc.Audit(service.Input{
		Config:     []byte(`{"log":{"level":"info"}}`),
		SourceName: "<http>",
	})
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}

	if report.SourceName != "<http>" {
		t.Fatalf("source name = %q, want <http>", report.SourceName)
	}
	if report.Findings == nil {
		t.Fatal("findings is nil, want empty slice")
	}
	if len(report.Findings) != 0 {
		t.Fatalf("findings = %d, want 0", len(report.Findings))
	}
}

func TestNew_NilDefaultsLoadsBuiltInRules(t *testing.T) {
	svc, err := service.New(config.NewParser(), audit.NewEngine(), nil)
	if err != nil {
		t.Fatalf("service.New: %v", err)
	}

	report, err := svc.Audit(service.Input{
		Config: []byte(`{"log":{"level":"debug"}}`),
	})
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(report.Findings))
	}
}

func TestNew_RequiresParserAndEngine(t *testing.T) {
	if _, err := service.New(nil, audit.NewEngine(), defaultRules(t)); err == nil {
		t.Fatal("service.New(nil, engine, rules) returned nil error")
	}
	if _, err := service.New(config.NewParser(), nil, defaultRules(t)); err == nil {
		t.Fatal("service.New(parser, nil, rules) returned nil error")
	}
}
