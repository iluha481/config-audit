// Package audit проверяет документы конфигурации по правилам и формирует отчет.
package audit

import (
	"github.com/iluha481/config-audit/internal/config"
	"github.com/iluha481/config-audit/internal/rule"
)

// Engine координирует проверку документов конфигурации по правилам безопасности.
type Engine struct {
	matcher *Matcher
}

// NewEngine создает новый Engine.
func NewEngine() *Engine {
	return &Engine{
		matcher: NewMatcher(),
	}
}

// Audit выполняет аудит документа по переданным правилам с помощью Engine по умолчанию.
func Audit(doc *config.Document, rules *rule.Rules) (*Report, error) {
	return NewEngine().Audit(doc, rules)
}

// Audit обходит дерево документа и находит нарушения правил.
func (e *Engine) Audit(doc *config.Document, rules *rule.Rules) (*Report, error) {
	if doc == nil || doc.Root == nil {
		return &Report{}, nil
	}
	if rules == nil {
		return &Report{}, nil
	}

	report := &Report{
		SourceName: doc.Source.Name,
	}

	enabled := rules.EnabledRules()
	if len(enabled) == 0 {
		return report, nil
	}

	seen := make(map[string]struct{}) // Дедупликация по ключу Rule.ID + ":" + Node.PathString.

	doc.Root.Walk(func(node *config.Node) {
		for _, r := range enabled {
			dedupKey := r.ID + ":" + node.PathString()
			if _, exists := seen[dedupKey]; exists {
				continue
			}

			if e.matchesRule(node, &r) {
				seen[dedupKey] = struct{}{}
				finding := e.createFinding(node, &r)
				report.Findings = append(report.Findings, finding)
			}
		}
	})

	report.Sort()
	return report, nil
}

// matchesRule сообщает, удовлетворяет ли узел всем условиям правила.
func (e *Engine) matchesRule(node *config.Node, r *rule.Rule) bool {
	if len(r.Match) == 0 {
		return false
	}

	mode := rule.NormalizeMatchMode(r.MatchMode)
	if mode == rule.MatchModeAll {
		for i := range r.Match {
			if !e.matcher.MatchNode(node, &r.Match[i]) {
				return false
			}
		}
		return true
	}

	// MatchModeAny (по умолчанию) требует совпадения хотя бы одного условия.
	for i := range r.Match {
		if e.matcher.MatchNode(node, &r.Match[i]) {
			return true
		}
	}
	return false
}

// createFinding создает находку для узла и правила.
func (e *Engine) createFinding(node *config.Node, r *rule.Rule) Finding {
	val := ""
	if r.IncludeValue {
		val = node.Value
	}

	return Finding{
		RuleID:         r.ID,
		RuleName:       r.Name,
		Severity:       r.Severity,
		Message:        renderTemplate(r.Message, node, r),
		Recommendation: renderTemplate(r.Recommendation, node, r),
		Path:           node.PathString(),
		Line:           node.Line,
		Column:         node.Column,
		Value:          val,
	}
}
