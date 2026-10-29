// Package v1 реализует HTTP API версии 1.
package v1

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"strings"

	"github.com/iluha481/config-audit/internal/config"
	"github.com/iluha481/config-audit/internal/service"
)

const (
	// maxBodyBytes ограничивает размер тела HTTP-запроса (16 МиБ).
	maxBodyBytes int64 = 16 << 20
	// contentTypeJSON задает поддерживаемый тип содержимого запроса.
	contentTypeJSON = "application/json"
)

// Controller обрабатывает HTTP-запросы аудита конфигураций.
type Controller struct {
	service *service.AuditService
}

// New создает контроллер с переданным сервисом аудита.
func New(auditService *service.AuditService) *Controller {
	return &Controller{service: auditService}
}

// RegisterRoutes регистрирует маршруты контроллера в переданном мультиплексоре.
func (c *Controller) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/v1/audit", c.audit)
}

// auditRequest описывает тело запроса аудита.
type auditRequest struct {
	Config json.RawMessage `json:"config"`
	Format string          `json:"format,omitempty"`
	Rules  json.RawMessage `json:"rules,omitempty"`
}

// errorResponse описывает тело ответа с ошибкой.
type errorResponse struct {
	Error apiError `json:"error"`
}

// apiError содержит машиночитаемый код и описание ошибки.
type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// audit обрабатывает запрос POST /v1/audit.
func (c *Controller) audit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "используйте метод POST")
		return
	}

	if !isJSONContentType(r.Header.Get("Content-Type")) {
		writeError(w, http.StatusUnsupportedMediaType, "unsupported_media_type",
			"ожидается Content-Type: application/json")
		return
	}

	if r.ContentLength > maxBodyBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "payload_too_large", "тело запроса слишком большое")
		return
	}

	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))

	var req auditRequest
	if err := decoder.Decode(&req); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeError(w, http.StatusRequestEntityTooLarge, "payload_too_large", "тело запроса слишком большое")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid_request", "некорректный JSON запроса")
		return
	}

	if err := ensureEOF(decoder); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "после JSON обнаружены лишние данные")
		return
	}

	configData, err := decodeContent(req.Config, false)
	if err != nil || len(bytes.TrimSpace(configData)) == 0 {
		writeError(w, http.StatusBadRequest, "invalid_request", "поле config обязательно и не должно быть пустым")
		return
	}

	rulesData, err := decodeContent(req.Rules, true)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "поле rules должно быть JSON-значением или строкой")
		return
	}

	format, err := parseFormat(req.Format)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	report, err := c.service.Audit(service.Input{
		Config:     configData,
		Format:     format,
		Rules:      rulesData,
		SourceName: "<http>",
	})
	if err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidRules):
			writeError(w, http.StatusBadRequest, "invalid_rules", "не удалось разобрать или проверить правила")
		case errors.Is(err, service.ErrInvalidConfig):
			writeError(w, http.StatusBadRequest, "invalid_config", "не удалось разобрать конфигурацию")
		default:
			log.Printf("http audit: %v", err)
			writeError(w, http.StatusInternalServerError, "internal_error", "внутренняя ошибка")
		}
		return
	}

	writeJSON(w, http.StatusOK, report)
}

// decodeContent преобразует JSON-значение или строку в исходные байты.
func decodeContent(raw json.RawMessage, optional bool) ([]byte, error) {
	if len(raw) == 0 {
		if optional {
			return nil, nil
		}
		return nil, errors.New("missing value")
	}

	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		if optional {
			return nil, nil
		}
		return nil, errors.New("empty value")
	}

	if bytes.Equal(trimmed, []byte("null")) {
		if optional {
			return nil, nil
		}
		return nil, errors.New("null value")
	}

	if trimmed[0] == '"' {
		var value string
		if err := json.Unmarshal(trimmed, &value); err != nil {
			return nil, err
		}
		return []byte(value), nil
	}

	return trimmed, nil
}

// parseFormat преобразует строку формата в значение config.Format.
func parseFormat(value string) (config.Format, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "auto":
		return config.FormatUnknown, nil
	case "json":
		return config.FormatJSON, nil
	case "yaml", "yml":
		return config.FormatYAML, nil
	default:
		return config.FormatUnknown, fmt.Errorf("неподдерживаемый формат %q", value)
	}
}

// isJSONContentType сообщает, что запрос имеет тип application/json.
func isJSONContentType(value string) bool {
	mediaType, _, err := mime.ParseMediaType(value)
	return err == nil && mediaType == contentTypeJSON
}

// ensureEOF проверяет, что после первого JSON-значения нет других данных.
func ensureEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("unexpected data after JSON")
		}
		return err
	}
	return nil
}

// writeJSON отправляет значение в формате JSON с указанным статусом.
func writeJSON(w http.ResponseWriter, status int, value any) {
	var buf bytes.Buffer

	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

// writeError отправляет ответ с ошибкой в формате JSON.
func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errorResponse{Error: apiError{Code: code, Message: message}})
}
