package config

import "errors"

const (
	// DefaultMaxBytes задает предельный размер входных данных по умолчанию.
	DefaultMaxBytes int64 = 8 << 20

	// DefaultMaxDepth задает предельную глубину вложенности по умолчанию.
	DefaultMaxDepth = 200

	// DefaultMaxNodes задает предельное количество узлов по умолчанию.
	DefaultMaxNodes = 200_000
)

var (
	// ErrEmpty означает, что входные данные не содержат значения конфигурации.
	ErrEmpty = errors.New("config: empty document")

	// ErrTooLarge означает, что размер входных данных превышает установленный предел.
	ErrTooLarge = errors.New("config: input too large")

	// ErrTooDeep означает, что глубина вложенности превышает установленный предел.
	ErrTooDeep = errors.New("config: nesting too deep")

	// ErrTooManyNodes означает, что дерево содержит больше узлов, чем разрешено.
	ErrTooManyNodes = errors.New("config: too many nodes")

	// ErrUnsupportedExt означает, что для расширения не зарегистрирован декодер.
	ErrUnsupportedExt = errors.New("config: unsupported document extension")
)

// Limits содержит ограничения безопасности для недоверенных входных данных.
type Limits struct {
	MaxBytes int64
	MaxDepth int
	MaxNodes int
}

// withDefaults заменяет неположительные ограничения значениями пакета по умолчанию.
func (l Limits) withDefaults() Limits {
	if l.MaxBytes <= 0 {
		l.MaxBytes = DefaultMaxBytes
	}
	if l.MaxDepth <= 0 {
		l.MaxDepth = DefaultMaxDepth
	}
	if l.MaxNodes <= 0 {
		l.MaxNodes = DefaultMaxNodes
	}
	return l
}
