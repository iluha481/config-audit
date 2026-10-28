package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
)

// JSONDecoder преобразует документ JSON в дерево Node.
type JSONDecoder struct {
	limits Limits
}

// Extensions возвращает расширения файлов, поддерживаемые декодером.
func (JSONDecoder) Extensions() []string {
	return []string{".json"}
}

// Format возвращает имя формата.
func (JSONDecoder) Format() Format {
	return FormatJSON
}

// Decode разбирает одно значение JSON и отклоняет данные после него.
func (d JSONDecoder) Decode(data []byte) (*Node, error) {
	limits := d.limits.withDefaults()

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()

	var raw any
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("parse JSON: %w", err)
	}
	if err := ensureJSONEOF(dec); err != nil {
		return nil, err
	}

	b := &jsonBuilder{limits: limits}
	return b.build(raw, "", nil, nil, 0)
}

// ensureJSONEOF проверяет, что после документа JSON нет других значений.
func ensureJSONEOF(dec *json.Decoder) error {
	var extra any
	err := dec.Decode(&extra)

	switch {
	case errors.Is(err, io.EOF):
		return nil
	case err == nil:
		return errors.New("parse JSON: multiple values")
	default:
		return fmt.Errorf("parse JSON: %w", err)
	}
}

// jsonBuilder строит дерево Node из декодированного JSON.
type jsonBuilder struct {
	limits Limits
	nodes  int
}

// build рекурсивно создает узел дерева из значения JSON.
func (b *jsonBuilder) build(v any, key string, path []string, parent *Node, depth int) (*Node, error) {
	if depth > b.limits.MaxDepth {
		return nil, fmt.Errorf("%w: %s", ErrTooDeep, pathOrRoot(path))
	}

	b.nodes++
	if b.nodes > b.limits.MaxNodes {
		return nil, ErrTooManyNodes
	}

	switch x := v.(type) {
	case map[string]any:
		n := &Node{
			Kind:   KindMap,
			Key:    key,
			Path:   path,
			Parent: parent,
		}

		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		slices.Sort(keys)

		for _, k := range keys {
			child, err := b.build(x[k], k, appendPath(path, k), n, depth+1)
			if err != nil {
				return nil, err
			}
			n.Children = append(n.Children, child)
		}
		return n, nil

	case []any:
		n := &Node{
			Kind:   KindSeq,
			Key:    key,
			Path:   path,
			Parent: parent,
		}

		for i, item := range x {
			seg := fmt.Sprintf("[%d]", i)
			child, err := b.build(item, "", appendPath(path, seg), n, depth+1)
			if err != nil {
				return nil, err
			}
			n.Children = append(n.Children, child)
		}
		return n, nil

	case string:
		return &Node{
			Kind:       KindScalar,
			Key:        key,
			Value:      x,
			ScalarType: ScalarString,
			Path:       path,
			Parent:     parent,
		}, nil

	case bool:
		return &Node{
			Kind:       KindScalar,
			Key:        key,
			Value:      strconv.FormatBool(x),
			ScalarType: ScalarBool,
			Path:       path,
			Parent:     parent,
		}, nil

	case json.Number:
		return &Node{
			Kind:       KindScalar,
			Key:        key,
			Value:      x.String(),
			ScalarType: ScalarNumber,
			Path:       path,
			Parent:     parent,
		}, nil

	case nil:
		return &Node{
			Kind:       KindScalar,
			Key:        key,
			ScalarType: ScalarNull,
			Path:       path,
			Parent:     parent,
		}, nil

	default:
		return nil, fmt.Errorf("unsupported JSON value %T at %s", v, pathOrRoot(path))
	}
}
