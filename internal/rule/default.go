package rule

// defaultRulesJSON содержит встроенный набор правил, который используется,
// если файлы правил не найдены.
const defaultRulesJSON = `{
      "version": 1,
      "rules": [
        {
          "id": "log.debug",
          "name": "Debug logging enabled",
          "severity": "LOW",
          "message": "логирование в debug-режиме",
          "recommendation": "Поменяйте режим на более избирательный (info+).",
          "match_mode": "any",
          "match": [
            {
              "keys": ["level", "log-level", "log_level", "verbosity"],
              "context": ["log", "logger", "logging"],
              "operator": "in",
              "values": ["debug", "trace", "all"],
              "ignore_case": true
            },
            {
              "keys": ["debug"],
              "operator": "in",
              "values": ["true", "yes", "1"]
            }
          ]
        },
        {
          "id": "credential.plaintext",
          "name": "Plaintext credentials",
          "severity": "HIGH",
          "message": "пароль или секретный ключ указан в открытом виде",
          "recommendation": "Вынесите секретные данные в переменную окружения (${ENV_VAR}) или внешнее хранилище секретов (Vault).",
          "match_mode": "any",
          "match": [
            {
              "keys": ["password", "passwd", "secret", "api_key", "apikey", "token", "auth_token", "private_key", "secret_key"],
              "operator": "exists",
              "ignore_references": true
            },
            {
              "key_suffixes": ["password", "passwd", "secret", "token", "apikey"],
              "operator": "exists",
              "ignore_references": true
            }
          ]
        },
        {
          "id": "network.bind_all",
          "name": "Unrestricted 0.0.0.0 bind",
          "severity": "MEDIUM",
          "message": "использование 0.0.0.0 без ограничений",
          "recommendation": "Ограничьте сетевую привязку доверенным интерфейсом (например, 127.0.0.1) либо настройте сетевой экран (firewall).",
          "match": [
            {
              "keys": ["host", "bind", "listen", "address", "bind_address", "listen_address"],
              "operator": "in",
              "values": ["0.0.0.0", "::", "0.0.0.0:0", "*"]
            }
          ]
        },
        {
          "id": "tls.insecure",
          "name": "Disabled TLS or TLS verification",
          "severity": "HIGH",
          "message": "отключена проверка TLS-сертификатов или шифрование",
          "recommendation": "Включите обязательное шифрование TLS и валидацию сертификатов (установите false для insecure_skip_verify или true для tls_enabled).",
          "match_mode": "any",
          "match": [
            {
              "keys": ["insecure", "insecure_skip_verify", "insecureSkipVerify", "skip_verify", "disable_tls", "disable_ssl"],
              "operator": "in",
              "values": ["true", "yes", "1"]
            },
            {
              "keys": ["tls", "ssl", "tls_enabled", "ssl_enabled", "enable_tls", "verify_tls"],
              "operator": "in",
              "values": ["false", "no", "0"]
            }
          ]
        },
        {
          "id": "crypto.weak_algorithm",
          "name": "Weak cryptographic algorithm",
          "severity": "HIGH",
          "message": "слишком слабый алгоритм - {{value}}",
          "recommendation": "Замените его на более безопасный (например, SHA-256, AES-256-GCM, TLS 1.3).",
          "match": [
            {
              "keys": ["digest-algorithm", "digest_algorithm", "algorithm", "hash", "cipher", "crypto", "digest"],
              "operator": "in",
              "values": ["MD5", "SHA1", "SHA-1", "DES", "3DES", "RC4", "MD4", "Blowfish", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"],
              "ignore_case": true
            }
          ]
        },
        {
          "id": "perm.too_wide",
          "name": "Overly permissive file permissions",
          "severity": "HIGH",
          "message": "слишком широкие права доступа ({{value}})",
          "recommendation": "Ограничьте права доступа до минимально необходимых (например, 0600 для файлов с секретами, 0640 для конфигов, 0750 для директорий).",
          "match": [
            {
              "keys": ["mode", "permissions", "perms", "file_mode", "chmod"],
              "operator": "perm_too_wide",
              "values": ["0777", "777", "0666", "666"]
            }
          ]
        }
      ]
    }`

// DefaultRules загружает правила из встроенного набора по умолчанию.
func DefaultRules() (*Rules, error) {
	loader := NewLoader()

	rules, err := loader.Parse([]byte(defaultRulesJSON), ".json")
	if err != nil {
		return nil, err
	}
	if err := rules.Validate(); err != nil {
		return nil, err
	}

	return rules, nil
}
