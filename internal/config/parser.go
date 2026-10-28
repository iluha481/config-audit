package config

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Decoder реализуется каждым поддерживаемым форматом конфигурации.
type Decoder interface {
	Extensions() []string
	Format() Format
	Decode(data []byte) (*Node, error)
}

// Parser направляет входные данные декодеру, выбранному по расширению файла.
type Parser struct {
	limits   Limits
	decoders map[string]Decoder
}

// NewParser возвращает парсер со встроенными декодерами JSON и YAML.
func NewParser() *Parser {
	return NewParserWithLimits(Limits{})
}

// NewParserWithLimits возвращает парсер с пользовательскими ограничениями безопасности.
func NewParserWithLimits(limits Limits) *Parser {
	limits = limits.withDefaults()

	p := &Parser{
		limits:   limits,
		decoders: make(map[string]Decoder),
	}
	p.mustRegister(JSONDecoder{limits: limits})
	p.mustRegister(YAMLDecoder{limits: limits})

	return p
}

// Register добавляет декодер для всех поддерживаемых им расширений.
func (p *Parser) Register(d Decoder) error {
	for _, ext := range d.Extensions() {
		ext = normalizeExt(ext)
		if ext == "" {
			return fmt.Errorf("config: decoder returned empty extension")
		}
		if _, ok := p.decoders[ext]; ok {
			return fmt.Errorf("config: duplicate decoder for %q", ext)
		}
		p.decoders[ext] = d
	}
	return nil
}

// mustRegister регистрирует декодер и паникует при ошибке.
func (p *Parser) mustRegister(d Decoder) {
	if err := p.Register(d); err != nil {
		panic(err)
	}
}

// ParseFile открывает файл, читает его и разбирает в Document.
func (p *Parser) ParseFile(path string) (*Document, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat config: %w", err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("read config: %s is a directory", path)
	}

	data, err := io.ReadAll(io.LimitReader(f, p.limits.MaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	doc, err := p.Parse(data, filepath.Ext(path))
	if err != nil {
		return nil, err
	}

	doc.Source.Name = path
	doc.Source.Mode = info.Mode().Perm()

	return doc, nil
}

// Parse декодирует байты в формате, соответствующем ext.
func (p *Parser) Parse(data []byte, ext string) (*Document, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, ErrEmpty
	}
	if int64(len(data)) > p.limits.MaxBytes {
		return nil, fmt.Errorf("%w: limit %d bytes", ErrTooLarge, p.limits.MaxBytes)
	}

	d, ok := p.decoders[normalizeExt(ext)]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedExt, ext)
	}

	node, err := d.Decode(data)
	if err != nil {
		return nil, err
	}

	return &Document{
		Source: Source{Format: d.Format()},
		Root:   node,
	}, nil
}

// normalizeExt приводит расширение к нижнему регистру и добавляет ведущую точку.
func normalizeExt(ext string) string {
	ext = strings.ToLower(strings.TrimSpace(ext))
	if ext != "" && !strings.HasPrefix(ext, ".") {
		ext = "." + ext
	}
	return ext
}

var defaultParser = NewParser()

// ParseFile разбирает файл с помощью парсера по умолчанию.
func ParseFile(path string) (*Document, error) {
	return defaultParser.ParseFile(path)
}

// Parse разбирает байты с помощью парсера по умолчанию.
func Parse(data []byte, ext string) (*Document, error) {
	return defaultParser.Parse(data, ext)
}
