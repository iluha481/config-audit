package audit

import (
	"fmt"
	"sort"
	"strings"

	"github.com/iluha481/config-audit/internal/rule"
)

// Finding описывает одну обнаруженную проблему в конфигурационном файле.
type Finding struct {
	RuleID         string        `json:"rule_id"`
	RuleName       string        `json:"rule_name"`
	Severity       rule.Severity `json:"severity"`
	Message        string        `json:"message"`
	Recommendation string        `json:"recommendation"`
	Path           string        `json:"path"`
	Line           int           `json:"line,omitempty"`
	Column         int           `json:"column,omitempty"`
	Value          string        `json:"value,omitempty"`
}

// String форматирует проблему в соответствии с примерами из технического задания.
func (f Finding) String() string {
	loc := ""
	if f.Path != "" {
		if f.Line > 0 {
			loc = fmt.Sprintf(" [%s:%d:%d]", f.Path, f.Line, f.Column)
		} else {
			loc = fmt.Sprintf(" [%s]", f.Path)
		}
	}

	return fmt.Sprintf("%s: %s%s\n     Рекомендация: %s",
		f.Severity, f.Message, loc, f.Recommendation)
}

// Report содержит результаты аудита конфигурации.
type Report struct {
	SourceName string    `json:"source_name"`
	Findings   []Finding `json:"findings"`
}

// HasIssues сообщает, были ли найдены нарушения.
func (r *Report) HasIssues() bool {
	return r != nil && len(r.Findings) > 0
}

// Count возвращает общее количество находок.
func (r *Report) Count() int {
	if r == nil {
		return 0
	}
	return len(r.Findings)
}

// CountBySeverity возвращает количество находок заданного уровня критичности.
func (r *Report) CountBySeverity(s rule.Severity) int {
	if r == nil {
		return 0
	}
	total := 0
	for _, f := range r.Findings {
		if f.Severity == s {
			total++
		}
	}
	return total
}

// MaxSeverity вычисляет максимальный уровень критичности среди находок.
func (r *Report) MaxSeverity() rule.Severity {
	if r == nil || len(r.Findings) == 0 {
		return rule.SeverityUnknown
	}
	max := rule.SeverityLow
	for _, f := range r.Findings {
		if f.Severity > max {
			max = f.Severity
		}
	}
	return max
}

// Sort сортирует находки: сначала по критичности (HIGH -> MEDIUM -> LOW),
// затем по номеру строки и пути.
func (r *Report) Sort() {
	if r == nil || len(r.Findings) == 0 {
		return
	}
	sort.SliceStable(r.Findings, func(i, j int) bool {
		fi, fj := r.Findings[i], r.Findings[j]
		if fi.Severity != fj.Severity {
			return fi.Severity > fj.Severity
		}
		if fi.Line != fj.Line {
			return fi.Line < fj.Line
		}
		return fi.Path < fj.Path
	})
}

// String формирует текстовый отчет со всеми находками.
func (r *Report) String() string {
	if !r.HasIssues() {
		return "Проблем не обнаружено."
	}
	var sb strings.Builder
	for i, f := range r.Findings {
		if i > 0 {
			sb.WriteString("\n\n")
		}
		sb.WriteString(f.String())
	}
	return sb.String()
}
