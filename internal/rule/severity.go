package rule

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Severity определяет уровень критичности найденной проблемы.
type Severity uint8

const (
	// SeverityUnknown обозначает неизвестный уровень критичности.
	SeverityUnknown Severity = iota
	// SeverityLow соответствует низкому уровню критичности.
	SeverityLow
	// SeverityMedium соответствует среднему уровню критичности.
	SeverityMedium
	// SeverityHigh соответствует высокому уровню критичности.
	SeverityHigh
)

// String возвращает строковое представление уровня критичности.
func (s Severity) String() string {
	switch s {
	case SeverityLow:
		return "LOW"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityHigh:
		return "HIGH"
	default:
		return "UNKNOWN"
	}
}

// ParseSeverity разбирает строку в Severity без учета регистра.
func ParseSeverity(s string) (Severity, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "LOW":
		return SeverityLow, nil
	case "MEDIUM":
		return SeverityMedium, nil
	case "HIGH":
		return SeverityHigh, nil
	default:
		return SeverityUnknown, fmt.Errorf("%w: %q", ErrInvalidSeverity, s)
	}
}

// IsValid сообщает, является ли значение допустимым уровнем критичности.
func (s Severity) IsValid() bool {
	return s >= SeverityLow && s <= SeverityHigh
}

// MarshalText реализует encoding.TextMarshaler для YAML и текстового вывода.
func (s Severity) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

// UnmarshalText реализует encoding.TextUnmarshaler.
func (s *Severity) UnmarshalText(text []byte) error {
	parsed, err := ParseSeverity(string(text))
	if err != nil {
		return err
	}
	*s = parsed
	return nil
}

// MarshalJSON реализует json.Marshaler.
func (s Severity) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// UnmarshalJSON реализует json.Unmarshaler.
func (s *Severity) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return fmt.Errorf("severity must be a string: %w", err)
	}
	return s.UnmarshalText([]byte(str))
}
