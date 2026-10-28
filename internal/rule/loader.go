package rule

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	// DefaultMaxRuleFileSize задает предельный размер файла правил (4 МБ).
	DefaultMaxRuleFileSize int64 = 4 << 20
)

// LoaderOptions задает параметры загрузчика правил.
type LoaderOptions struct {
	// MaxFileSize задает предельный размер файла правил в байтах.
	MaxFileSize int64
}

// Loader отвечает за чтение, разбор и проверку правил из файлов и директорий.
type Loader struct {
	maxFileSize int64
}

// NewLoader создает Loader с необязательными параметрами.
func NewLoader(opts ...func(*LoaderOptions)) *Loader {
	options := LoaderOptions{
		MaxFileSize: DefaultMaxRuleFileSize,
	}
	for _, opt := range opts {
		opt(&options)
	}
	return &Loader{
		maxFileSize: options.MaxFileSize,
	}
}

// LoadRules загружает и объединяет правила по путям к файлам или директориям.
func LoadRules(paths []string) (*Rules, error) {
	return NewLoader().LoadPaths(paths)
}

// LoadPaths загружает и объединяет правила из списка путей.
func (l *Loader) LoadPaths(paths []string) (*Rules, error) {
	merged := &Rules{Version: 1}
	seenIDs := make(map[string]string)

	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return nil, fmt.Errorf("%w: stat %s: %w", ErrRulesLoad, p, err)
		}

		var rs *Rules
		if info.IsDir() {
			rs, err = l.LoadDir(p, true)
		} else {
			rs, err = l.LoadFile(p)
		}
		if err != nil {
			return nil, err
		}

		for _, r := range rs.Rules {
			if prevPath, exists := seenIDs[r.ID]; exists {
				return nil, fmt.Errorf("%w: %q defined in %s and %s", ErrDuplicateRuleID, r.ID, prevPath, p)
			}
			seenIDs[r.ID] = p
			merged.Rules = append(merged.Rules, r)
		}
	}

	if err := merged.Validate(); err != nil {
		return nil, err
	}
	return merged, nil
}

// LoadFile читает и проверяет один файл правил в формате JSON или YAML.
func (l *Loader) LoadFile(path string) (*Rules, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%w: open %s: %w", ErrRulesLoad, path, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("%w: stat %s: %w", ErrRulesLoad, path, err)
	}

	if info.Size() > l.maxFileSize {
		return nil, fmt.Errorf("%w: %s (%d bytes)", ErrFileTooLarge, path, info.Size())
	}

	data, err := io.ReadAll(io.LimitReader(f, l.maxFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("%w: read %s: %w", ErrRulesLoad, path, err)
	}
	if int64(len(data)) > l.maxFileSize {
		return nil, fmt.Errorf("%w: %s (%d bytes)", ErrFileTooLarge, path, len(data))
	}

	rs, err := l.Parse(data, filepath.Ext(path))
	if err != nil {
		return nil, fmt.Errorf("%w: file %s: %w", ErrBadRuleFile, path, err)
	}

	if err := rs.Validate(); err != nil {
		return nil, fmt.Errorf("%w in %s: %w", ErrInvalidRules, path, err)
	}

	return rs, nil
}

// LoadDir ищет файлы правил (.json, .yaml, .yml) в директории. Если recursive
// равен true, вложенные директории также обходятся.
func (l *Loader) LoadDir(dirPath string, recursive bool) (*Rules, error) {
	merged := &Rules{Version: 1}
	seenIDs := make(map[string]string)

	walkFn := func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if !recursive && path != dirPath {
				return fs.SkipDir
			}
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".json" && ext != ".yaml" && ext != ".yml" {
			return nil
		}

		fileRules, err := l.LoadFile(path)
		if err != nil {
			return err
		}

		for _, r := range fileRules.Rules {
			if prevPath, exists := seenIDs[r.ID]; exists {
				return fmt.Errorf("%w: %q in %s and %s", ErrDuplicateRuleID, r.ID, prevPath, path)
			}
			seenIDs[r.ID] = path
			merged.Rules = append(merged.Rules, r)
		}
		return nil
	}

	if err := filepath.WalkDir(dirPath, walkFn); err != nil {
		return nil, fmt.Errorf("%w: walk %s: %w", ErrRulesLoad, dirPath, err)
	}

	return merged, nil
}

// Parse декодирует исходные байты в Rules в зависимости от расширения.
func (l *Loader) Parse(data []byte, ext string) (*Rules, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("%w: empty rule content", ErrBadRuleFile)
	}

	var rs Rules
	switch strings.ToLower(ext) {
	case ".json":
		dec := json.NewDecoder(bytes.NewReader(trimmed))
		if err := dec.Decode(&rs); err != nil {
			return nil, err
		}
		var extra any
		if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("extra data after JSON rule document")
		}
	case ".yaml", ".yml":
		dec := yaml.NewDecoder(bytes.NewReader(trimmed))
		if err := dec.Decode(&rs); err != nil {
			return nil, err
		}
		var extra any
		if err := dec.Decode(&extra); err == nil {
			return nil, fmt.Errorf("multiple YAML documents in rule file not supported")
		} else if !errors.Is(err, io.EOF) {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedFormat, ext)
	}

	return &rs, nil
}
