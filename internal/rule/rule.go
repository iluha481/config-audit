// Package rule загружает, проверяет и представляет правила аудита безопасности.
package rule

import (
	"fmt"
	"strings"
)

// MatchMode определяет режим объединения условий правила: все условия или хотя бы одно.
type MatchMode string

const (
	// MatchModeAny означает, что достаточно совпадения хотя бы одного условия.
	MatchModeAny MatchMode = "any"
	// MatchModeAll означает, что должны совпасть все условия.
	MatchModeAll MatchMode = "all"
)

// NormalizeMatchMode приводит режим к каноническому виду и по умолчанию
// возвращает MatchModeAny.
func NormalizeMatchMode(m MatchMode) MatchMode {
	if strings.EqualFold(string(m), string(MatchModeAll)) {
		return MatchModeAll
	}
	return MatchModeAny
}

// Operator определяет тип проверки условия.
type Operator string

const (
	// OpIn проверяет, входит ли значение в заданный список.
	OpIn Operator = "in"
	// OpEquals проверяет точное равенство значению.
	OpEquals Operator = "equals"
	// OpContains проверяет наличие подстроки.
	OpContains Operator = "contains"
	// OpPrefix проверяет префикс значения.
	OpPrefix Operator = "has_prefix"
	// OpSuffix проверяет суффикс значения.
	OpSuffix Operator = "has_suffix"
	// OpRegex проверяет соответствие регулярному выражению.
	OpRegex Operator = "regex"
	// OpExists проверяет, что значение задано и не пусто.
	OpExists Operator = "exists"
	// OpPermTooWide проверяет, что права доступа слишком широки.
	OpPermTooWide Operator = "perm_too_wide"
)

// Match описывает отдельное условие проверки.
type Match struct {
	Keys             []string `json:"keys,omitempty" yaml:"keys,omitempty"`
	KeySuffixes      []string `json:"key_suffixes,omitempty" yaml:"key_suffixes,omitempty"`
	Path             string   `json:"path,omitempty" yaml:"path,omitempty"`
	Context          []string `json:"context,omitempty" yaml:"context,omitempty"`
	Operator         Operator `json:"operator" yaml:"operator"`
	Values           []string `json:"values,omitempty" yaml:"values,omitempty"`
	IgnoreCase       bool     `json:"ignore_case,omitempty" yaml:"ignore_case,omitempty"`
	Normalize        bool     `json:"normalize,omitempty" yaml:"normalize,omitempty"`
	IgnoreReferences bool     `json:"ignore_references,omitempty" yaml:"ignore_references,omitempty"`
	Negate           bool     `json:"negate,omitempty" yaml:"negate,omitempty"`
}

// Validate проверяет корректность условия Match и приводит оператор к нижнему регистру.
func (m *Match) Validate() error {
	op := strings.ToLower(strings.TrimSpace(string(m.Operator)))
	if op == "" {
		return fmt.Errorf("%w: operator is required", ErrInvalidOperator)
	}
	m.Operator = Operator(op)

	if len(m.Keys) == 0 && len(m.KeySuffixes) == 0 && m.Path == "" && len(m.Context) == 0 {
		return fmt.Errorf("%w: match condition must specify keys, key_suffixes, path, or context",
			ErrInvalidRules)
	}
	return nil
}

// Rule описывает одно правило аудита безопасности.
type Rule struct {
	ID             string    `json:"id" yaml:"id"`
	Name           string    `json:"name" yaml:"name"`
	Severity       Severity  `json:"severity" yaml:"severity"`
	Message        string    `json:"message" yaml:"message"`
	Recommendation string    `json:"recommendation" yaml:"recommendation"`
	Enabled        *bool     `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	Target         string    `json:"target,omitempty" yaml:"target,omitempty"`
	IncludeValue   bool      `json:"include_value,omitempty" yaml:"include_value,omitempty"`
	Tags           []string  `json:"tags,omitempty" yaml:"tags,omitempty"`
	MatchMode      MatchMode `json:"match_mode,omitempty" yaml:"match_mode,omitempty"`
	Match          []Match   `json:"match" yaml:"match"`
}

// IsEnabled сообщает, включено ли правило. Если поле Enabled не задано,
// правило считается включенным.
func (r *Rule) IsEnabled() bool {
	if r.Enabled == nil {
		return true
	}
	return *r.Enabled
}

// Validate проверяет структуру правила и его условий.
func (r *Rule) Validate() error {
	if strings.TrimSpace(r.ID) == "" {
		return ErrEmptyRuleID
	}
	if strings.TrimSpace(r.Name) == "" {
		return fmt.Errorf("rule %q: %w", r.ID, ErrEmptyRuleName)
	}
	if !r.Severity.IsValid() {
		return fmt.Errorf("rule %q: %w", r.ID, ErrInvalidSeverity)
	}
	if strings.TrimSpace(r.Message) == "" {
		return fmt.Errorf("rule %q: %w", r.ID, ErrEmptyRuleMessage)
	}
	if strings.TrimSpace(r.Recommendation) == "" {
		return fmt.Errorf("rule %q: %w", r.ID, ErrEmptyRuleRecommendation)
	}
	if len(r.Match) == 0 {
		return fmt.Errorf("rule %q: %w", r.ID, ErrEmptyMatches)
	}

	r.MatchMode = NormalizeMatchMode(r.MatchMode)

	for i := range r.Match {
		if err := r.Match[i].Validate(); err != nil {
			return fmt.Errorf("rule %q match[%d]: %w", r.ID, i, err)
		}
	}
	return nil
}

// Rules представляет набор загруженных правил.
type Rules struct {
	Version int    `json:"version" yaml:"version"`
	Rules   []Rule `json:"rules" yaml:"rules"`
}

// Validate проверяет все правила набора и уникальность их ID.
func (rs *Rules) Validate() error {
	if rs == nil {
		return ErrInvalidRules
	}
	seen := make(map[string]struct{}, len(rs.Rules))
	for i := range rs.Rules {
		r := &rs.Rules[i]
		if err := r.Validate(); err != nil {
			return err
		}
		if _, exists := seen[r.ID]; exists {
			return fmt.Errorf("%w: %q", ErrDuplicateRuleID, r.ID)
		}
		seen[r.ID] = struct{}{}
	}
	return nil
}

// EnabledRules возвращает только включенные правила.
func (rs *Rules) EnabledRules() []Rule {
	if rs == nil {
		return nil
	}
	out := make([]Rule, 0, len(rs.Rules))
	for _, r := range rs.Rules {
		if r.IsEnabled() {
			out = append(out, r)
		}
	}
	return out
}
