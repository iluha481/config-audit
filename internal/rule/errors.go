package rule

import "errors"

var (
	// ErrRulesLoad сообщает об ошибке чтения файлов или обхода директорий.
	ErrRulesLoad = errors.New("rule: error loading rules")

	// ErrBadRuleFile сообщает о синтаксической ошибке в файле правил JSON или YAML.
	ErrBadRuleFile = errors.New("rule: error parsing rule file")

	// ErrInvalidRules сообщает о нарушении схемы или бизнес-правил.
	ErrInvalidRules = errors.New("rule: invalid rule set")

	// ErrDuplicateRuleID возникает, когда два правила имеют одинаковый ID.
	ErrDuplicateRuleID = errors.New("rule: duplicate rule ID")

	// ErrEmptyRuleID сообщает об отсутствии обязательного поля ID.
	ErrEmptyRuleID = errors.New("rule: rule ID cannot be empty")

	// ErrEmptyRuleName сообщает об отсутствии имени правила.
	ErrEmptyRuleName = errors.New("rule: rule name cannot be empty")

	// ErrEmptyRuleMessage сообщает об отсутствии сообщения правила.
	ErrEmptyRuleMessage = errors.New("rule: rule message cannot be empty")

	// ErrEmptyRuleRecommendation сообщает об отсутствии рекомендации.
	ErrEmptyRuleRecommendation = errors.New("rule: rule recommendation cannot be empty")

	// ErrEmptyMatches сообщает об отсутствии условий проверки.
	ErrEmptyMatches = errors.New("rule: rule must have at least one match condition")

	// ErrInvalidSeverity сообщает о неизвестном уровне критичности.
	ErrInvalidSeverity = errors.New("rule: invalid severity level (expected LOW, MEDIUM, HIGH)")

	// ErrInvalidOperator сообщает о неподдерживаемом операторе сравнения.
	ErrInvalidOperator = errors.New("rule: unsupported match operator")

	// ErrUnsupportedFormat сообщает о неподдерживаемом расширении файла правил.
	ErrUnsupportedFormat = errors.New("rule: unsupported rule file format")

	// ErrFileTooLarge сообщает о превышении допустимого размера файла правил.
	ErrFileTooLarge = errors.New("rule: file exceeds size limit")
)
