package v1

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/iluha481/config-audit/internal/audit"
	"github.com/iluha481/config-audit/internal/config"
	"github.com/iluha481/config-audit/internal/rule"
	"github.com/iluha481/config-audit/internal/service"
)

func newTestHandler(t *testing.T) http.Handler {
	t.Helper()

	defaults, err := rule.DefaultRules()
	if err != nil {
		t.Fatalf("rule.DefaultRules: %v", err)
	}

	svc, err := service.New(config.NewParser(), audit.NewEngine(), defaults)
	if err != nil {
		t.Fatalf("service.New: %v", err)
	}

	mux := http.NewServeMux()
	New(svc).RegisterRoutes(mux)
	return mux
}

func performRequest(t *testing.T, handler http.Handler, method, contentType, body string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(method, "/v1/audit", strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decodeErrorCode(t *testing.T, body []byte) string {
	t.Helper()

	var resp errorResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	return resp.Error.Code
}

func TestAudit_Success(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        string
		ruleID      string
	}{
		{
			name:        "json object",
			contentType: "application/json",
			body:        `{"config":{"log":{"level":"debug"}}}`,
			ruleID:      "log.debug",
		},
		{
			name:        "yaml string",
			contentType: "application/json; charset=utf-8",
			body:        `{"config":"log:\n  level: debug\n","format":"yaml"}`,
			ruleID:      "log.debug",
		},
		{
			name:        "yaml auto detect",
			contentType: "application/json",
			body:        `{"config":"log:\n  level: debug\n"}`,
			ruleID:      "log.debug",
		},
		{
			name:        "empty rules use defaults",
			contentType: "application/json",
			body:        `{"config":{"log":{"level":"debug"}},"rules":{}}`,
			ruleID:      "log.debug",
		},
		{
			name:        "custom rules",
			contentType: "application/json",
			body: `{
				"config": {"custom": "bad", "log": {"level": "debug"}},
				"rules": {
					"version": 1,
					"rules": [
						{
							"id": "custom.rule",
							"name": "Custom rule",
							"severity": "HIGH",
							"message": "custom hit",
							"recommendation": "fix custom",
							"match": [
								{
									"keys": ["custom"],
									"operator": "equals",
									"values": ["bad"]
								}
							]
						}
					]
				}
			}`,
			ruleID: "custom.rule",
		},
	}

	handler := newTestHandler(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := performRequest(t, handler, http.MethodPost, tt.contentType, tt.body)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
			}

			var report audit.Report
			if err := json.Unmarshal(rec.Body.Bytes(), &report); err != nil {
				t.Fatalf("decode report: %v", err)
			}

			if report.SourceName != "<http>" {
				t.Fatalf("source name = %q, want <http>", report.SourceName)
			}
			if len(report.Findings) != 1 {
				t.Fatalf("findings = %d, want 1", len(report.Findings))
			}
			if report.Findings[0].RuleID != tt.ruleID {
				t.Fatalf("rule ID = %q, want %q", report.Findings[0].RuleID, tt.ruleID)
			}
		})
	}
}

func TestAudit_EmptyFindingsSerializedAsArray(t *testing.T) {
	handler := newTestHandler(t)

	rec := performRequest(t, handler, http.MethodPost, "application/json",
		`{"config":{"log":{"level":"info"}}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"findings":[]`) {
		t.Fatalf("body = %s, want findings array", rec.Body.String())
	}
}

func TestAudit_RequestErrors(t *testing.T) {
	tests := []struct {
		name        string
		method      string
		contentType string
		body        string
		wantStatus  int
		wantCode    string
	}{
		{
			name:        "missing config",
			method:      http.MethodPost,
			contentType: "application/json",
			body:        `{}`,
			wantStatus:  http.StatusBadRequest,
			wantCode:    "invalid_request",
		},
		{
			name:        "null config",
			method:      http.MethodPost,
			contentType: "application/json",
			body:        `{"config":null}`,
			wantStatus:  http.StatusBadRequest,
			wantCode:    "invalid_request",
		},
		{
			name:        "malformed json",
			method:      http.MethodPost,
			contentType: "application/json",
			body:        `{"config":`,
			wantStatus:  http.StatusBadRequest,
			wantCode:    "invalid_request",
		},
		{
			name:        "trailing json",
			method:      http.MethodPost,
			contentType: "application/json",
			body:        `{"config":{}}{}`,
			wantStatus:  http.StatusBadRequest,
			wantCode:    "invalid_request",
		},
		{
			name:        "unsupported format",
			method:      http.MethodPost,
			contentType: "application/json",
			body:        `{"config":{},"format":"xml"}`,
			wantStatus:  http.StatusBadRequest,
			wantCode:    "invalid_request",
		},
		{
			name:        "invalid config",
			method:      http.MethodPost,
			contentType: "application/json",
			body:        `{"config":"log: [","format":"yaml"}`,
			wantStatus:  http.StatusBadRequest,
			wantCode:    "invalid_config",
		},
		{
			name:        "invalid rules",
			method:      http.MethodPost,
			contentType: "application/json",
			body:        `{"config":{},"rules":{"version":1,"rules":[{"id":"custom.rule"}]}}`,
			wantStatus:  http.StatusBadRequest,
			wantCode:    "invalid_rules",
		},
		{
			name:        "unsupported media type",
			method:      http.MethodPost,
			contentType: "text/plain",
			body:        `{}`,
			wantStatus:  http.StatusUnsupportedMediaType,
			wantCode:    "unsupported_media_type",
		},
		{
			name:        "method not allowed",
			method:      http.MethodGet,
			contentType: "application/json",
			body:        "",
			wantStatus:  http.StatusMethodNotAllowed,
			wantCode:    "method_not_allowed",
		},
	}

	handler := newTestHandler(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := performRequest(t, handler, tt.method, tt.contentType, tt.body)
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body = %s", rec.Code, tt.wantStatus, rec.Body.String())
			}
			if code := decodeErrorCode(t, rec.Body.Bytes()); code != tt.wantCode {
				t.Fatalf("error code = %q, want %q", code, tt.wantCode)
			}

			if tt.wantStatus == http.StatusMethodNotAllowed && rec.Header().Get("Allow") != http.MethodPost {
				t.Fatalf("Allow = %q, want POST", rec.Header().Get("Allow"))
			}
		})
	}
}

func TestAudit_BodyTooLarge(t *testing.T) {
	handler := newTestHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/v1/audit", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = maxBodyBytes + 1

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413; body = %s", rec.Code, rec.Body.String())
	}
	if code := decodeErrorCode(t, rec.Body.Bytes()); code != "payload_too_large" {
		t.Fatalf("error code = %q, want payload_too_large", code)
	}
}
