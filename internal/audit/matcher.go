package audit

import (
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/iluha481/config-audit/internal/config"
	"github.com/iluha481/config-audit/internal/rule"
)

// Matcher проверяет узлы дерева конфигурации на соответствие условиям Match.
type Matcher struct {
	regexCache sync.Map
}

// NewMatcher создает Matcher с кэшированием регулярных выражений.
func NewMatcher() *Matcher {
	return &Matcher{}
}

// MatchNode проверяет один узел Node по заданному условию Match.
func (m *Matcher) MatchNode(n *config.Node, cond *rule.Match) bool {
	if n == nil || cond == nil {
		return false
	}

	// 1. Проверяет путь, если он задан.
	if cond.Path != "" {
		if !matchPath(n.PathString(), cond.Path) {
			return false
		}
	}

	// 2. Проверяет ключи, если они заданы.
	if len(cond.Keys) > 0 {
		if !matchKeys(n, cond.Keys, cond.IgnoreCase, cond.Normalize) {
			return false
		}
	}

	// 3. Проверяет суффиксы ключа, если они заданы.
	if len(cond.KeySuffixes) > 0 {
		if !matchKeySuffixes(n, cond.KeySuffixes, cond.IgnoreCase, cond.Normalize) {
			return false
		}
	}

	// 4. Проверяет контекст родительских секций.
	if len(cond.Context) > 0 {
		if !matchContext(n, cond.Context, cond.IgnoreCase, cond.Normalize) {
			return false
		}
	}

	// 5. Игнорирует ссылки на секреты (${ENV}, {{ secret }}, vault:...).
	if cond.IgnoreReferences && isReference(n.Value) {
		return false
	}

	// Для строковых и числовых операторов узел должен быть скаляром (кроме OpExists).
	if !n.IsScalar() && cond.Operator != rule.OpExists {
		return false
	}

	// 6. Применяет оператор к значению узла.
	matched := m.matchValue(n, cond)
	if cond.Negate {
		matched = !matched
	}

	return matched
}

// matchValue применяет оператор условия к значению узла.
func (m *Matcher) matchValue(n *config.Node, cond *rule.Match) bool {
	val := n.Value

	switch cond.Operator {
	case rule.OpIn:
		for _, v := range cond.Values {
			if cond.IgnoreCase {
				if strings.EqualFold(val, v) {
					return true
				}
			} else if val == v {
				return true
			}
		}
		return false

	case rule.OpEquals:
		if len(cond.Values) == 0 {
			return false
		}
		for _, target := range cond.Values {
			if cond.IgnoreCase {
				if strings.EqualFold(val, target) {
					return true
				}
			} else if val == target {
				return true
			}
		}
		return false

	case rule.OpContains:
		for _, sub := range cond.Values {
			if cond.IgnoreCase {
				if strings.Contains(strings.ToLower(val), strings.ToLower(sub)) {
					return true
				}
			} else if strings.Contains(val, sub) {
				return true
			}
		}
		return false

	case rule.OpPrefix:
		for _, p := range cond.Values {
			if cond.IgnoreCase {
				if strings.HasPrefix(strings.ToLower(val), strings.ToLower(p)) {
					return true
				}
			} else if strings.HasPrefix(val, p) {
				return true
			}
		}
		return false

	case rule.OpSuffix:
		for _, s := range cond.Values {
			if cond.IgnoreCase {
				if strings.HasSuffix(strings.ToLower(val), strings.ToLower(s)) {
					return true
				}
			} else if strings.HasSuffix(val, s) {
				return true
			}
		}
		return false

	case rule.OpRegex:
		for _, pattern := range cond.Values {
			re, err := m.getOrCompileRegex(pattern)
			if err != nil {
				continue
			}
			if re.MatchString(val) {
				return true
			}
		}
		return false

	case rule.OpExists:
		return !n.IsNull() && strings.TrimSpace(n.Value) != ""

	case rule.OpPermTooWide:
		return isPermTooWide(n, cond.Values)

	default:
		return false
	}
}

// getOrCompileRegex возвращает скомпилированное выражение из кэша или компилирует его.
func (m *Matcher) getOrCompileRegex(pattern string) (*regexp.Regexp, error) {
	if cached, ok := m.regexCache.Load(pattern); ok {
		return cached.(*regexp.Regexp), nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	m.regexCache.Store(pattern, re)
	return re, nil
}

// effectiveKey возвращает ключ узла или ключ родительского массива, если узел
// является элементом списка.
func effectiveKey(n *config.Node) string {
	if n == nil {
		return ""
	}
	if n.Key != "" {
		return n.Key
	}
	if n.Parent != nil && n.Parent.Kind == config.KindSeq {
		return n.Parent.Key
	}
	return ""
}

// matchKeys проверяет, совпадает ли ключ узла с одним из заданных ключей.
func matchKeys(n *config.Node, keys []string, ignoreCase, normalize bool) bool {
	k := effectiveKey(n)
	if k == "" {
		return false
	}
	for _, target := range keys {
		if normalize || config.Canonical(k) == config.Canonical(target) {
			return true
		}
		if ignoreCase && strings.EqualFold(k, target) {
			return true
		}
		if k == target {
			return true
		}
	}
	return false
}

// matchKeySuffixes проверяет, оканчивается ли ключ узла одним из заданных суффиксов.
func matchKeySuffixes(n *config.Node, suffixes []string, ignoreCase, normalize bool) bool {
	k := effectiveKey(n)
	if k == "" {
		return false
	}
	for _, suff := range suffixes {
		if normalize && strings.HasSuffix(config.Canonical(k), config.Canonical(suff)) {
			return true
		}
		if ignoreCase && strings.HasSuffix(strings.ToLower(k), strings.ToLower(suff)) {
			return true
		}
		if strings.HasSuffix(k, suff) {
			return true
		}
	}
	return false
}

// matchContext проверяет, входит ли узел в одну из заданных родительских секций.
func matchContext(n *config.Node, contexts []string, ignoreCase, normalize bool) bool {
	if n == nil || n.Parent == nil {
		return false
	}
	for curr := n.Parent; curr != nil; curr = curr.Parent {
		ck := curr.Key
		if ck == "" {
			continue
		}
		for _, ctx := range contexts {
			if normalize && config.Canonical(ck) == config.Canonical(ctx) {
				return true
			}
			if ignoreCase && strings.EqualFold(ck, ctx) {
				return true
			}
			if ck == ctx {
				return true
			}
		}
	}
	return false
}

// matchPath сравнивает путь узла с ожидаемым без учета регистра, используя
// канонический вид путей.
func matchPath(actual, expected string) bool {
	return strings.EqualFold(actual, expected) || config.Canonical(actual) == config.Canonical(expected)
}

// isReference проверяет, является ли значение подстановкой переменной окружения
// или ссылкой на хранилище секретов.
func isReference(val string) bool {
	v := strings.TrimSpace(val)
	if strings.HasPrefix(v, "${") && strings.HasSuffix(v, "}") {
		return true
	}
	if strings.HasPrefix(v, "$") && len(v) > 1 && !strings.ContainsAny(v, " \t\n") {
		return true
	}
	if strings.HasPrefix(v, "{{") && strings.HasSuffix(v, "}}") {
		return true
	}
	lower := strings.ToLower(v)
	for _, prefix := range []string{"env:", "vault:", "secret:", "aws:", "sm:", "ref:"} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

// isPermTooWide проверяет, являются ли права доступа слишком широкими: запись
// для всех (0002) или полное отсутствие ограничений (0777/0666).
func isPermTooWide(n *config.Node, values []string) bool {
	raw := strings.TrimSpace(n.Value)
	if len(values) > 0 {
		for _, v := range values {
			if raw == v || strings.TrimPrefix(raw, "0") == strings.TrimPrefix(v, "0") {
				return true
			}
		}
	}

	mode, err := strconv.ParseUint(raw, 8, 32)
	if err == nil {
		return (mode&0002) != 0 || (mode&0777) == 0777 || (mode&0666) == 0666
	}

	if num, ok := n.Int(); ok {
		return (num&0002) != 0 || (num&0777) == 0777 || (num&0666) == 0666
	}

	return false
}

// renderTemplate подставляет значения узла и правила в шаблон сообщения.
func renderTemplate(tmpl string, n *config.Node, r *rule.Rule) string {
	res := tmpl
	if n != nil {
		res = strings.ReplaceAll(res, "{{path}}", n.PathString())
		res = strings.ReplaceAll(res, "{{value}}", n.Value)
		res = strings.ReplaceAll(res, "{{key}}", n.Key)
		res = strings.ReplaceAll(res, "{{line}}", strconv.Itoa(n.Line))
	}
	if r != nil {
		res = strings.ReplaceAll(res, "{{id}}", r.ID)
		res = strings.ReplaceAll(res, "{{name}}", r.Name)
	}
	return res
}
