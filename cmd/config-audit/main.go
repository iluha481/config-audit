// Command config-audit анализирует конфигурационные файлы и сообщает об опасных настройках.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/iluha481/config-audit/internal/audit"
	"github.com/iluha481/config-audit/internal/config"
	v1 "github.com/iluha481/config-audit/internal/controller/restapi/v1"
	"github.com/iluha481/config-audit/internal/rule"
	"github.com/iluha481/config-audit/internal/service"
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
	server    bool
	rulesPath string
	addr      string
	target    string
}

func main() {
	os.Exit(run(os.Args[1:]))
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

	if cfg.server {
		return runServer(cfg)
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
	fs.BoolVar(&cfg.server, "server", false, "запустить HTTP-сервер")
	fs.StringVar(&cfg.rulesPath, "r", "", "путь к файлу или папке правил")
	fs.StringVar(&cfg.rulesPath, "rules", "", "путь к файлу или папке правил")
	fs.StringVar(&cfg.addr, "addr", "127.0.0.1:8080", "адрес HTTP-сервера")

	normalized := normalizeArgs(args)
	if err := fs.Parse(normalized); err != nil {
		return cfg, err
	}

	posArgs := fs.Args()
	if cfg.server {
		if cfg.fromStdin {
			return cfg, errors.New("флаг --stdin несовместим с --server")
		}
		if len(posArgs) > 0 {
			return cfg, errors.New("в режиме сервера путь к конфигурации не указывается")
		}
		return cfg, nil
	}

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
		if takesValue(arg) {
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

// takesValue сообщает, что флаг принимает значение отдельным аргументом.
func takesValue(arg string) bool {
	switch arg {
	case "-r", "--rules", "-rules", "-addr", "--addr":
		return true
	default:
		return false
	}
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

	return rule.DefaultRules()
}

// runServer запускает HTTP-сервер аудита конфигураций.
func runServer(cfg cliConfig) int {
	rules, err := loadRules(cfg.rulesPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading rules: %v\n", err)
		return exitError
	}

	auditService, err := service.New(config.NewParser(), audit.NewEngine(), rules)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating service: %v\n", err)
		return exitError
	}

	mux := http.NewServeMux()
	v1.New(auditService).RegisterRoutes(mux)

	server := &http.Server{
		Addr:              cfg.addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.ListenAndServe()
	}()

	log.Printf("HTTP-сервер слушает %s", server.Addr)

	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(os.Stderr, "HTTP server error: %v\n", err)
			return exitError
		}
	case <-ctx.Done():
		log.Println("Останавливаем HTTP-сервер")

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			_ = server.Close()
			fmt.Fprintf(os.Stderr, "HTTP shutdown error: %v\n", err)
			return exitError
		}
		if err := <-errCh; err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(os.Stderr, "HTTP server error: %v\n", err)
			return exitError
		}
	}

	return exitOK
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
      config-audit --server [параметры]

    Параметры:
      -s, --silent   Не завершаться с кодом ошибки при найденных замечаниях
      --stdin        Читать конфигурацию из стандартного потока ввода
      --server       Запустить HTTP-сервер вместо проверки файла
      --addr         Адрес HTTP-сервера (по умолчанию 127.0.0.1:8080)
      -r, --rules    Путь к файлу или директории с правилами (по умолчанию rules/rule.json)
      -h, --help     Показать справку
    `)
}
