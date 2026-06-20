package gcpauth

import (
	"testing"

	"github.com/pucora/lura/v2/config"
)

func TestConfigGetterRequiresAudience(t *testing.T) {
	cfg := &config.Backend{
		ExtraConfig: config.ExtraConfig{
			Namespace: map[string]interface{}{
				"service": "run",
			},
		},
	}
	if _, ok := configGetter(cfg.ExtraConfig); ok {
		t.Fatal("expected missing audience to disable config")
	}
}

func TestConfigGetterParsesFields(t *testing.T) {
	cfg := &config.Backend{
		ExtraConfig: config.ExtraConfig{
			Namespace: map[string]interface{}{
				"audience":        "https://api.example.com",
				"credentials_file": "/etc/gcp/sa.json",
				"s2s_auth_header": "X-Serverless-Authorization",
				"custom_claims": map[string]interface{}{
					"target": "backend",
				},
			},
		},
	}
	got, ok := configGetter(cfg.ExtraConfig)
	if !ok {
		t.Fatal("expected valid config")
	}
	if got.Audience != "https://api.example.com" {
		t.Fatalf("unexpected audience: %q", got.Audience)
	}
	if got.S2SAuthHeader != "X-Serverless-Authorization" {
		t.Fatalf("unexpected header: %q", got.S2SAuthHeader)
	}
	if got.CustomClaims["target"] != "backend" {
		t.Fatalf("unexpected custom claims: %+v", got.CustomClaims)
	}
}
