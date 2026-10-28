package config

import (
	"strconv"
	"strings"
)

// Kind определяет тип узла дерева конфигурации.
type Kind uint8

const (
	// KindInvalid — нулевое значение неинициализированного узла.
	KindInvalid Kind = iota
	// KindMap — объект JSON или отображение YAML.
	KindMap
	// KindSeq — массив JSON или последовательность YAML.
	KindSeq
	// KindScalar — строка, число, логическое значение или null.
	KindScalar
)

// String возвращает читаемое имя типа узла.
func (k Kind) String() string {
	switch k {
	case KindMap:
		return "map"
	case KindSeq:
		return "seq"
	case KindScalar:
		return "scalar"
	default:
		return "invalid"
	}
}

// ScalarType уточняет тип KindScalar.
type ScalarType uint8

const (
	// ScalarString — текстовое значение.
	ScalarString ScalarType = iota
	// ScalarBool — логическое значение.
	ScalarBool
	// ScalarNumber — целое или число с плавающей запятой.
	ScalarNumber
	// ScalarNull — значение null.
	ScalarNull
)

// String возвращает читаемое имя скалярного типа.
func (t ScalarType) String() string {
	switch t {
	case ScalarString:
		return "string"
	case ScalarBool:
		return "bool"
	case ScalarNumber:
		return "number"
	case ScalarNull:
		return "null"
	default:
		return "unknown"
	}
}

// Node представляет одно значение в дереве конфигурации.
//
// Отображения и последовательности хранят потомков в Children. Скаляры хранят
// значение в Value в виде строки, а ScalarType сохраняет исходный тип: строку,
// число, логическое значение или null.
type Node struct {
	Kind       Kind
	Key        string
	Value      string
	ScalarType ScalarType
	Path       []string
	Line       int
	Column     int
	Parent     *Node
	Children   []*Node
}

// IsMap сообщает, является ли узел отображением.
func (n *Node) IsMap() bool { return n != nil && n.Kind == KindMap }

// IsSeq сообщает, является ли узел последовательностью.
func (n *Node) IsSeq() bool { return n != nil && n.Kind == KindSeq }

// IsScalar сообщает, является ли узел скаляром.
func (n *Node) IsScalar() bool { return n != nil && n.Kind == KindScalar }

// IsNull сообщает, является ли узел скаляром null.
func (n *Node) IsNull() bool {
	return n != nil && n.Kind == KindScalar && n.ScalarType == ScalarNull
}

// PathString возвращает путь в виде "server.tls.enabled".
func (n *Node) PathString() string {
	if n == nil {
		return ""
	}
	return JoinPath(n.Path)
}

// CanonicalKey возвращает нормализованный ключ узла.
func (n *Node) CanonicalKey() string {
	if n == nil {
		return ""
	}
	return Canonical(n.Key)
}

// Bool разбирает скаляр как логическое значение. Второй результат равен false,
// если значение не похоже на логическое.
func (n *Node) Bool() (bool, bool) {
	if n == nil || n.Kind != KindScalar {
		return false, false
	}

	switch strings.ToLower(strings.TrimSpace(n.Value)) {
	case "true", "yes", "on", "1":
		return true, true
	case "false", "no", "off", "0":
		return false, true
	default:
		return false, false
	}
}

// Int разбирает скаляр как целое число с основанием 0, поэтому принимаются
// "10", "0777" и "0x10". Второй результат равен false, если разбор не удался.
func (n *Node) Int() (int64, bool) {
	if n == nil || n.Kind != KindScalar {
		return 0, false
	}

	s := strings.TrimSpace(n.Value)
	if s == "" {
		return 0, false
	}

	if v, err := strconv.ParseInt(s, 0, 64); err == nil {
		return v, true
	}
	if v, err := strconv.ParseInt(s, 10, 64); err == nil {
		return v, true
	}
	return 0, false
}

// Child возвращает первого потомка, канонический ключ которого совпадает с key.
func (n *Node) Child(key string) *Node {
	if n == nil {
		return nil
	}

	ck := Canonical(key)
	for _, c := range n.Children {
		if c.CanonicalKey() == ck {
			return c
		}
	}
	return nil
}

// Walk обходит узел и всех потомков в порядке обхода в глубину.
func (n *Node) Walk(fn func(*Node)) {
	if n == nil {
		return
	}

	fn(n)
	for _, c := range n.Children {
		c.Walk(fn)
	}
}

// WalkScalars обходит только скалярные узлы.
func (n *Node) WalkScalars(fn func(*Node)) {
	n.Walk(func(current *Node) {
		if current.Kind == KindScalar {
			fn(current)
		}
	})
}
