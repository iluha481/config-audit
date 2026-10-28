package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

// YAMLDecoder преобразует документ YAML в дерево Node.
type YAMLDecoder struct {
	limits Limits
}

// Extensions возвращает расширения файлов, поддерживаемые декодером.
func (YAMLDecoder) Extensions() []string {
	return []string{".yaml", ".yml"}
}

// Format возвращает имя формата.
func (YAMLDecoder) Format() Format {
	return FormatYAML
}

// Decode разбирает один документ YAML и отклоняет несколько документов.
func (d YAMLDecoder) Decode(data []byte) (*Node, error) {
	limits := d.limits.withDefaults()

	dec := yaml.NewDecoder(bytes.NewReader(data))

	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, ErrEmpty
		}
		return nil, fmt.Errorf("parse YAML: %w", err)
	}

	var extra yaml.Node
	err := dec.Decode(&extra)
	switch {
	case errors.Is(err, io.EOF):
	case err == nil:
		return nil, errors.New("parse YAML: multiple documents")
	default:
		return nil, fmt.Errorf("parse YAML: %w", err)
	}

	if len(doc.Content) == 0 {
		return nil, ErrEmpty
	}

	root := doc.Content[0]
	if root.Kind == yaml.ScalarNode && root.Tag == "!!null" {
		return nil, ErrEmpty
	}

	b := &yamlBuilder{
		limits:  limits,
		aliases: make(map[*yaml.Node]bool),
	}
	return b.build(root, "", nil, nil, 0)
}

// yamlBuilder строит дерево Node из документа YAML.
type yamlBuilder struct {
	limits  Limits
	nodes   int
	aliases map[*yaml.Node]bool
}

// build рекурсивно создает узел дерева из узла YAML.
func (b *yamlBuilder) build(n *yaml.Node, key string, path []string, parent *Node, depth int) (*Node, error) {
	if n == nil {
		return nil, fmt.Errorf("nil YAML node at %s", pathOrRoot(path))
	}
	if depth > b.limits.MaxDepth {
		return nil, fmt.Errorf("%w: %s", ErrTooDeep, pathOrRoot(path))
	}

	b.nodes++
	if b.nodes > b.limits.MaxNodes {
		return nil, ErrTooManyNodes
	}

	switch n.Kind {
	case yaml.AliasNode:
		if n.Alias == nil {
			return nil, fmt.Errorf("alias without target at %s", pathOrRoot(path))
		}
		if b.aliases[n.Alias] {
			return nil, fmt.Errorf("recursive alias at %s", pathOrRoot(path))
		}

		b.aliases[n.Alias] = true
		defer delete(b.aliases, n.Alias)

		return b.build(n.Alias, key, path, parent, depth+1)

	case yaml.MappingNode:
		node := &Node{
			Kind:   KindMap,
			Key:    key,
			Path:   path,
			Parent: parent,
			Line:   n.Line,
			Column: n.Column,
		}

		seen := make(map[string]int, len(n.Content)/2)
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]

			if k.Kind != yaml.ScalarNode {
				return nil, fmt.Errorf("line %d: mapping key must be a scalar at %s", k.Line, pathOrRoot(path))
			}

			name := k.Value
			if prev, ok := seen[name]; ok {
				return nil, fmt.Errorf(
					"line %d: duplicate key %q (first defined at line %d)",
					k.Line, name, prev,
				)
			}
			seen[name] = k.Line

			child, err := b.build(v, name, appendPath(path, name), node, depth+1)
			if err != nil {
				return nil, err
			}
			node.Children = append(node.Children, child)
		}
		return node, nil

	case yaml.SequenceNode:
		node := &Node{
			Kind:   KindSeq,
			Key:    key,
			Path:   path,
			Parent: parent,
			Line:   n.Line,
			Column: n.Column,
		}

		for i, item := range n.Content {
			seg := fmt.Sprintf("[%d]", i)
			child, err := b.build(item, "", appendPath(path, seg), node, depth+1)
			if err != nil {
				return nil, err
			}
			node.Children = append(node.Children, child)
		}
		return node, nil

	case yaml.ScalarNode:
		node := &Node{
			Kind:       KindScalar,
			Key:        key,
			Value:      n.Value,
			ScalarType: yamlScalarType(n.Tag),
			Path:       path,
			Parent:     parent,
			Line:       n.Line,
			Column:     n.Column,
		}
		if node.ScalarType == ScalarNull {
			node.Value = ""
		}
		return node, nil

	default:
		return nil, fmt.Errorf("line %d: unsupported YAML node kind %d", n.Line, n.Kind)
	}
}

// yamlScalarType сопоставляет тег YAML скалярному типу.
func yamlScalarType(tag string) ScalarType {
	switch tag {
	case "!!bool":
		return ScalarBool
	case "!!int", "!!float":
		return ScalarNumber
	case "!!null":
		return ScalarNull
	default:
		return ScalarString
	}
}
