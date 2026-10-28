package config

import (
	"strings"
	"testing"
)

func TestYAMLDecoder(t *testing.T) {
	data := []byte("server:\n  host: 0.0.0.0\n  tls:\n    insecure_skip_verify: true\n")

	doc, err := Parse(data, ".yaml")
	if err != nil {
		t.Fatal(err)
	}

	root := doc.Root
	verify := root.Child("server").Child("tls").Child("insecure_skip_verify")
	if verify == nil {
		t.Fatal("server.tls.insecure_skip_verify not found")
	}
	if ok, _ := verify.Bool(); !ok {
		t.Fatalf("value = %q, want true", verify.Value)
	}
	if verify.Line != 4 {
		t.Fatalf("line = %d, want 4", verify.Line)
	}
	if got := verify.PathString(); got != "server.tls.insecure_skip_verify" {
		t.Fatalf("path = %q", got)
	}
}

func TestYAMLDuplicateKey(t *testing.T) {
	_, err := Parse([]byte("a: 1\na: 2\n"), ".yaml")
	if err == nil || !strings.Contains(err.Error(), "duplicate key") {
		t.Fatalf("err = %v, want duplicate key", err)
	}
}

func TestYAMLMultipleDocuments(t *testing.T) {
	_, err := Parse([]byte("a: 1\n---\nb: 2\n"), ".yaml")
	if err == nil || !strings.Contains(err.Error(), "multiple documents") {
		t.Fatalf("err = %v, want multiple documents", err)
	}
}

func TestYAMLAlias(t *testing.T) {
	data := []byte("defaults: &d\n  host: 0.0.0.0\nserver: *d\n")

	doc, err := Parse(data, ".yaml")
	if err != nil {
		t.Fatal(err)
	}

	host := doc.Root.Child("server").Child("host")
	if host == nil || host.Value != "0.0.0.0" {
		t.Fatalf("server.host = %v, want 0.0.0.0", host)
	}
}
