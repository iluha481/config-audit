package rule_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/iluha481/config-audit/internal/rule"
)

func TestLoader_LoadFile_JSON(t *testing.T) {
	content := `{
            "version": 1,                                                                                               
            "rules": [                                                                                                  
                {                                                                                                       
                    "id": "tls.disabled",                                                                               
                    "name": "TLS is disabled",                                                                          
                    "severity": "HIGH",                                                                                 
                    "message": "TLS is turned off at {{path}}",                                                         
                    "recommendation": "Enable TLS encryption",                                                          
                    "match_mode": "any",                                                                                
                    "match": [                                                                                          
                        {                                                                                               
                            "keys": ["tls_enabled"],                                                                    
                            "operator": "equals",                                                                       
                            "values": ["false"]                                                                         
                        }                                                                                               
                    ]                                                                                                   
                }                                                                                                       
            ]                                                                                                           
        }`

	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "rule.json")
	if err := os.WriteFile(filePath, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	loader := rule.NewLoader()
	rs, err := loader.LoadFile(filePath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(rs.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rs.Rules))
	}

	r := rs.Rules[0]
	if r.ID != "tls.disabled" {
		t.Errorf("expected ID 'tls.disabled', got %q", r.ID)
	}
	if r.Severity != rule.SeverityHigh {
		t.Errorf("expected HIGH severity, got %v", r.Severity)
	}
	if !r.IsEnabled() {
		t.Errorf("rule should be enabled by default")
	}
}

func TestLoader_DuplicateID(t *testing.T) {
	content := `{
            "version": 1,                                                                                               
            "rules": [                                                                                                  
                {                                                                                                       
                    "id": "dup.id",                                                                                     
                    "name": "Rule 1",                                                                                   
                    "severity": "LOW",                                                                                  
                    "message": "msg",                                                                                   
                    "recommendation": "rec",                                                                            
                    "match": [{"keys": ["a"], "operator": "equals"}]                                                    
                },                                                                                                      
                {                                                                                                       
                    "id": "dup.id",                                                                                     
                    "name": "Rule 2",                                                                                   
                    "severity": "LOW",                                                                                  
                    "message": "msg",                                                                                   
                    "recommendation": "rec",                                                                            
                    "match": [{"keys": ["b"], "operator": "equals"}]                                                    
                }
            ]
        }`

	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "dup.json")
	if err := os.WriteFile(filePath, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	loader := rule.NewLoader()
	_, err := loader.LoadFile(filePath)
	if err == nil {
		t.Fatal("expected error on duplicate ID, got nil")
	}
}
