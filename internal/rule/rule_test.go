package rule_test

import (
	"errors"
	"testing"

	"github.com/iluha481/config-audit/internal/rule"
)

func TestMatchValidate_Regex(t *testing.T) {
	valid := rule.Match{
		Keys:     []string{"custom"},
		Operator: rule.OpRegex,
		Values:   []string{"^a+$"},
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("Validate valid regex: %v", err)
	}

	tests := []struct {
		name  string
		match rule.Match
	}{
		{
			name: "missing values",
			match: rule.Match{
				Keys:     []string{"custom"},
				Operator: rule.OpRegex,
			},
		},
		{
			name: "invalid expression",
			match: rule.Match{
				Keys:     []string{"custom"},
				Operator: rule.OpRegex,
				Values:   []string{"["},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.match.Validate()
			if !errors.Is(err, rule.ErrInvalidRules) {
				t.Fatalf("error = %v, want ErrInvalidRules", err)
			}
		})
	}
}
