// Package config разбирает конфигурации JSON и YAML в единое дерево узлов.
package config

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"path/filepath"
	"strings"
)

// Format определяет поддерживаемый формат конфигурации.
type Format uint8

const (
	// FormatUnknown обозначает неизвестный или неподдерживаемый формат.
	FormatUnknown Format = iota
	// FormatYAML обозначает формат YAML.
	FormatYAML
	// FormatJSON обозначает формат JSON.
	FormatJSON
)

// String возвращает читаемое имя формата.
func (f Format) String() string {
	switch f {
	case FormatYAML:
		return "yaml"
	case FormatJSON:
		return "json"
	default:
		return "unknown"
	}
}

// Extension возвращает каноническое расширение файла для формата.
func (f Format) Extension() string {
	switch f {
	case FormatYAML:
		return ".yaml"
	case FormatJSON:
		return ".json"
	default:
		return ""
	}
}

// DetectFormat определяет формат сначала по расширению файла, затем по содержимому.
func DetectFormat(name string, data []byte) Format {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".yaml", ".yml":
		return FormatYAML
	case ".json":
		return FormatJSON
	}

	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[') && json.Valid(trimmed) {
		return FormatJSON
	}
	return FormatYAML
}

// Source содержит метаданные разобранной конфигурации.
type Source struct {
	Name     string      // имя источника: путь к файлу или "<stdin>"
	Format   Format      // формат источника
	Mode     fs.FileMode // права доступа к файлу; 0, если они неизвестны
	DocIndex int         // индекс документа в многодокументном файле
}

// Document представляет разобранное дерево конфигурации вместе с метаданными.
//
// Правила получают весь Document, а не только корневой Node, поэтому могут
// использовать имя файла, формат и права доступа к файлу.
type Document struct {
	Source Source
	Root   *Node
}
