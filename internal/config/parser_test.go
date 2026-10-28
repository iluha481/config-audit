package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestParseFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	if err := os.WriteFile(path, []byte(`{"log":{"level":"debug"}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	doc, err := ParseFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if doc.Source.Name != path {
		t.Fatalf("source name = %q, want %q", doc.Source.Name, path)
	}
	if doc.Source.Format != FormatJSON {
		t.Fatalf("source format = %v, want json", doc.Source.Format)
	}

	level := doc.Root.Child("log").Child("level")
	if level == nil || level.Value != "debug" {
		t.Fatalf("log.level = %v, want debug", level)
	}
}

func TestParseEmpty(t *testing.T) {
	_, err := Parse(nil, ".yaml")
	if !errors.Is(err, ErrEmpty) {
		t.Fatalf("err = %v, want ErrEmpty", err)
	}
}

func TestParseUnsupportedExtension(t *testing.T) {
	_, err := Parse([]byte(`{"a":1}`), ".toml")
	if !errors.Is(err, ErrUnsupportedExt) {
		t.Fatalf("err = %v, want ErrUnsupportedExt", err)
	}
}

func TestParserRegisterDuplicate(t *testing.T) {
	p := NewParser()
	if err := p.Register(JSONDecoder{}); err == nil {
		t.Fatal("expected duplicate decoder error")
	}
}

func TestParserMaxBytes(t *testing.T) {
	p := NewParserWithLimits(Limits{MaxBytes: 5})

	_, err := p.Parse([]byte(`{"a":1}`), ".json")
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
}

func TestDetectFormat(t *testing.T) {
	tests := []struct {
		name string
		data string
		want Format
	}{
		{name: "config.json", data: `{}`, want: FormatJSON},
		{name: "config.yaml", data: `{}`, want: FormatYAML},
		{name: "stdin", data: `{"a":1}`, want: FormatJSON},
		{name: "stdin", data: `a: 1`, want: FormatYAML},
		{name: "stdin", data: `{a: 1}`, want: FormatYAML},
	}

	for _, tt := range tests {
		if got := DetectFormat(tt.name, []byte(tt.data)); got != tt.want {
			t.Errorf("DetectFormat(%q, %q) = %v, want %v", tt.name, tt.data, got, tt.want)
		}
	}
}
