// Package service выполняет аудит конфигураций и управляет набором правил.
package service

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/iluha481/config-audit/internal/audit"
	"github.com/iluha481/config-audit/internal/config"
	"github.com/iluha481/config-audit/internal/rule"
)

var (
	// ErrInvalidConfig сообщает об ошибке разбора или проверки конфигурации.
	ErrInvalidConfig = errors.New("service: invalid config")

	// ErrInvalidRules сообщает об ошибке разбора или проверки правил.
	ErrInvalidRules = errors.New("service: invalid rules")
)

// Input содержит данные для одной проверки конфигурации.
type Input struct {
	// Config содержит исходную конфигурацию в формате JSON или YAML.
	Config []byte
	// Format задает формат конфигурации. FormatUnknown включает автоопределение.
	Format config.Format
	// Rules содержит пользовательские правила. Пустое значение включает правила по умолчанию.
	Rules []byte
	// SourceName задает имя источника для отчета. Если пусто, имя не меняется.
	SourceName string
}

// AuditService выполняет аудит конфигураций по пользовательским или стандартным правилам.
type AuditService struct {
	parser   *config.Parser
	engine   *audit.Engine
	loader   *rule.Loader
	defaults *rule.Rules
}

// New создает AuditService. Если defaults равен nil, загружается встроенный набор правил.
func New(parser *config.Parser, engine *audit.Engine, defaults *rule.Rules) (*AuditService, error) {
	if parser == nil || engine == nil {
		return nil, errors.New("service: parser and engine are required")
	}

	if defaults == nil {
		var err error
		defaults, err = rule.DefaultRules()
		if err != nil {
			return nil, fmt.Errorf("service: load default rules: %w", err)
		}
	}

	if err := defaults.Validate(); err != nil {
		return nil, fmt.Errorf("service: validate default rules: %w", err)
	}

	return &AuditService{
		parser:   parser,
		engine:   engine,
		loader:   rule.NewLoader(),
		defaults: defaults,
	}, nil
}

// Audit выполняет аудит конфигурации и возвращает отчет с найденными проблемами.
func (s *AuditService) Audit(in Input) (*audit.Report, error) {
	rules, err := s.resolveRules(in.Rules)
	if err != nil {
		return nil, err
	}

	format := in.Format
	if format == config.FormatUnknown {
		format = config.DetectFormat("inline", in.Config)
	}

	doc, err := s.parser.Parse(in.Config, format.Extension())
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	if in.SourceName != "" {
		doc.Source.Name = in.SourceName
	}

	report, err := s.engine.Audit(doc, rules)
	if err != nil {
		return nil, fmt.Errorf("service: audit config: %w", err)
	}
	if report == nil {
		report = &audit.Report{}
	}
	if report.Findings == nil {
		report.Findings = []audit.Finding{}
	}

	return report, nil
}

// resolveRules возвращает пользовательские правила или набор по умолчанию.
func (s *AuditService) resolveRules(raw []byte) (*rule.Rules, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return s.defaults, nil
	}

	if int64(len(trimmed)) > rule.DefaultMaxRuleFileSize {
		return nil, fmt.Errorf("%w: rules exceed %d bytes", ErrInvalidRules, rule.DefaultMaxRuleFileSize)
	}

	format := config.DetectFormat("rules", trimmed)
	rules, err := s.loader.Parse(trimmed, format.Extension())
	if err != nil {
		return nil, fmt.Errorf("%w: parse rules: %w", ErrInvalidRules, err)
	}

	if err := rules.Validate(); err != nil {
		return nil, fmt.Errorf("%w: validate rules: %w", ErrInvalidRules, err)
	}

	if len(rules.Rules) == 0 {
		return s.defaults, nil
	}

	return rules, nil
}
