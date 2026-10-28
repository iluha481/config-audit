package config

import (
	"errors"
	"testing"
)

func TestJSONDecoder(t *testing.T) {
	data := []byte(`{
		"server": {"host": "0.0.0.0"},
		"servers": [{"port": 8080}]
	}`)

	doc, err := Parse(data, ".json")
	if err != nil {
		t.Fatal(err)
	}

	root := doc.Root
	if root.Kind != KindMap {
		t.Fatalf("root kind = %v, want map", root.Kind)
	}

	host := root.Child("server").Child("host")
	if host == nil {
		t.Fatal("server.host not found")
	}
	if host.Value != "0.0.0.0" {
		t.Fatalf("host = %q, want 0.0.0.0", host.Value)
	}
	if got := host.PathString(); got != "server.host" {
		t.Fatalf("path = %q, want server.host", got)
	}

	port := root.Child("servers").Children[0].Child("port")
	if port == nil {
		t.Fatal("servers[0].port not found")
	}
	if port.ScalarType != ScalarNumber {
		t.Fatalf("port type = %v, want number", port.ScalarType)
	}
	if port.Value != "8080" {
		t.Fatalf("port = %q, want 8080", port.Value)
	}
	if got := port.PathString(); got != "servers[0].port" {
		t.Fatalf("path = %q, want servers[0].port", got)
	}
}

func TestJSONTrailingData(t *testing.T) {
	_, err := Parse([]byte(`{"a":1} {"b":2}`), ".json")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestJSONDepthLimit(t *testing.T) {
	p := NewParserWithLimits(Limits{MaxDepth: 2})

	_, err := p.Parse([]byte(`{"a":{"b":{"c":1}}}`), ".json")
	if !errors.Is(err, ErrTooDeep) {
		t.Fatalf("err = %v, want ErrTooDeep", err)
	}
}
