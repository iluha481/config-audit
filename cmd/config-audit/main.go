// Command config-audit анализирует конфигурационные файлы и сообщает об опасных настройках.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/iluha481/config-audit/internal/audit"
	"github.com/iluha481/config-audit/internal/config"
	"github.com/iluha481/config-audit/internal/rule"
)

const (
	exitOK    = 0
	exitAudit = 1
	exitError = 2
)

// cliConfig содержит разобранные параметры командной строки.
type cliConfig struct {
	silent    bool
	fromStdin bool
	rulesPath string
	target    string
}

func main() {
	os.Exit(run(os.Args[:1]))
}

// run выполняет команду и возвращает код завершения.
func run(args []string) int {
	cfg, err := parseCLIArgs(args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		printUsage()
		return exitError
	}

	rules, err := loadRules(cfg.rulesPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading rules: %v\n", err)
		return exitError
	}

	parser := config.NewParser()
	engine := audit.NewEngine()
	report := &audit.Report{}

	if cfg.fromStdin {
		data, err := io.ReadAll(io.LimitReader(os.Stdin, config.DefaultMaxBytes+1))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading stdin: %v\n", err)
			return exitError
		}
		if len(strings.TrimSpace(string(data))) == 0 {
			fmt.Fprintln(os.Stderr, "Error empty stdin")
			return exitError
		}

		format := config.DetectFormat("stdin", data)
		doc, err := parser.Parse(data, format.Extension())
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing config: %v\n", err)
			return exitError
		}
		doc.Source.Name = "<stdin>"

		stdinReport, err := engine.Audit(doc, rules)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Ошибка аудита: %v\n", err)
			return exitError
		}
		report.Findings = append(report.Findings, stdinReport.Findings...)
	} else {
		targetInfo, err := os.Stat(cfg.target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Ошибка доступа к файлу: %v\n", err)
			return exitError
		}

		if targetInfo.IsDir() {
			if err := auditDirectory(cfg.target, parser, rules, engine, report); err != nil {
				fmt.Fprintf(os.Stderr, "Ошибка анализа директории: %v\n", err)
				return exitError
			}
		} else {
			doc, err := parser.ParseFile(cfg.target)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Ошибка парсинга файла: %v\n", err)
				return exitError
			}
			checkFilePermissions(doc, report)

			fileReport, err := engine.Audit(doc, rules)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Ошибка аудита: %v\n", err)
				return exitError
			}
			report.Findings = append(report.Findings, fileReport.Findings...)
		}
	}

	report.Sort()

	if report.HasIssues() {
		fmt.Println(report.String())
		if cfg.silent {
			return exitOK
		}
		return exitAudit
	}

	fmt.Println("Проблем не обнаружено.")
	return exitOK
}

// parseCLIArgs разбирает аргументы командной строки.
func parseCLIArgs(args []string) (cliConfig, error) {
	var cfg cliConfig

	fs := flag.NewFlagSet("config-audit", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	fs.BoolVar(&cfg.silent, "s", false, "не выходить с ошибкой при наличии проблем")
	fs.BoolVar(&cfg.silent, "silent", false, "не выходить с ошибкой при наличии проблем")
	fs.BoolVar(&cfg.fromStdin, "stdin", false, "прочитать конфигурацию из стандартного потока ввода")
	fs.StringVar(&cfg.rulesPath, "r", "", "путь к файлу или папке правил")
	fs.StringVar(&cfg.rulesPath, "rules", "", "путь к файлу или папке правил")

	normalized := normalizeArgs(args)
	if err := fs.Parse(normalized); err != nil {
		return cfg, err
	}

	posArgs := fs.Args()
	if !cfg.fromStdin {
		if len(posArgs) == 0 {
			return cfg, errors.New("не указан путь к файлу конфигурации")
		}
		cfg.target = posArgs[0]
	}

	return cfg, nil
}

// normalizeArgs переставляет флаги перед позиционными аргументами, чтобы путь
// к файлу мог стоять в любом месте.
func normalizeArgs(args []string) []string {
	var flags []string
	var positional []string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "-r" || arg == "--rules" || arg == "-rules" {
			flags = append(flags, arg)
			if i+1 < len(args) {
				flags = append(flags, args[i+1])
				i++
			}
			continue
		}
		if strings.HasPrefix(arg, "-") {
			flags = append(flags, arg)
		} else {
			positional = append(positional, arg)
		}
	}
	return append(flags, positional...)
}

// loadRules загружает правила из указанного пути или встроенного набора по умолчанию.
func loadRules(customPath string) (*rule.Rules, error) {
	loader := rule.NewLoader()

	if customPath != "" {
		return loader.LoadPaths([]string{customPath})
	}

	candidates := []string{
		"rules/rule.json",
		"rules",
		"../rules/rule.json",
		"../rules",
	}

	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return loader.LoadPaths([]string{p})
		}
	}

	return loader.Parse([]byte(defaultRulesJSON), ".json")
}

// auditDirectory рекурсивно проверяет конфигурационные файлы в директории.
func auditDirectory(dir string, parser *config.Parser, rules *rule.Rules, engine *audit.Engine, report *audit.Report) error {
	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" && ext != ".json" {
			return nil
		}

		doc, err := parser.ParseFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Предупреждение: не удалось распарсить %s: %v\n", path, err)
			return nil
		}

		checkFilePermissions(doc, report)

		fileReport, err := engine.Audit(doc, rules)
		if err != nil {
			return err
		}
		report.Findings = append(report.Findings, fileReport.Findings...)
		return nil
	})
}

// checkFilePermissions добавляет находку, если файл доступен на запись всем.
func checkFilePermissions(doc *config.Document, report *audit.Report) {
	if doc == nil || doc.Source.Name == "<stdin>" || doc.Source.Mode == 0 {
		return
	}
	perm := doc.Source.Mode.Perm()
	if perm&0002 != 0 {
		report.Findings = append(report.Findings, audit.Finding{
			RuleID:         "perm.file_too_wide",
			RuleName:       "Insecure file permissions",
			Severity:       rule.SeverityHigh,
			Message:        fmt.Sprintf("Файл конфигурации имеет опасные права доступа (%04o)", perm),
			Recommendation: "Ограничьте права доступа к файлу: chmod 0600 или chmod 0640.",
			Path:           doc.Source.Name,
		})
	}
}

// printUsage выводит справку по использованию.
func printUsage() {
	fmt.Fprintf(os.Stderr, `Использование:
      config-audit [параметры] <путь-к-файлу-или-папке>
      config-audit --stdin [параметры]

    Параметры:
      -s, --silent   Не завершаться с кодом ошибки при найденных замечаниях
      --stdin        Читать конфигурацию из стандартного потока ввода
      -r, --rules    Путь к файлу или директории с правилами (по умолчанию rules/rule.json)
      -h, --help     Показать справку
    `)
}
