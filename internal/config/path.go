package config

import "strings"

// Canonical нормализует ключ: приводит его к нижнему регистру и удаляет
// подчеркивания и дефисы, поэтому "insecure_skip_verify" и
// "insecureSkipVerify" считаются равными.
func Canonical(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "_", "")
	s = strings.ReplaceAll(s, "-", "")
	return s
}

// JoinPath строит путь через точку из сегментов. Индексы массивов
// записываются как "[0]" без ведущей точки.
func JoinPath(path []string) string {
	if len(path) == 0 {
		return ""
	}

	var b strings.Builder
	for i, p := range path {
		if i > 0 && !strings.HasPrefix(p, "[") {
			b.WriteByte('.')
		}
		b.WriteString(p)
	}
	return b.String()
}

// appendPath возвращает новый путь с добавленным сегментом seg. Срез
// копируется, чтобы соседние узлы не использовали общий массив.
func appendPath(path []string, seg string) []string {
	out := make([]string, len(path)+1)
	copy(out, path)
	out[len(path)] = seg
	return out
}

// pathOrRoot форматирует путь для сообщений об ошибках.
func pathOrRoot(path []string) string {
	if len(path) == 0 {
		return "<root>"
	}
	return JoinPath(path)
}
