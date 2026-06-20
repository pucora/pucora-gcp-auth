package gcpauth

import (
	"encoding/json"

	"github.com/pucora/lura/v2/config"
	"golang.org/x/oauth2"
	"google.golang.org/api/idtoken"
	"google.golang.org/api/option"
)

// Namespace is the key to use to store and access the custom config data.
const Namespace = "github.com/pucora/pucora-gcp-auth"

// Config holds GCP service-to-service authentication settings.
type Config struct {
	Audience        string
	CredentialsFile string
	CredentialsJSON map[string]interface{}
	CustomClaims    map[string]interface{}
	S2SAuthHeader   string
}

func configGetter(e config.ExtraConfig) (Config, bool) {
	v, ok := e[Namespace]
	if !ok {
		return Config{}, false
	}
	tmp, ok := v.(map[string]interface{})
	if !ok {
		return Config{}, false
	}
	cfg := Config{}
	if v, ok := tmp["audience"]; ok {
		cfg.Audience, _ = v.(string)
	}
	if v, ok := tmp["credentials_file"]; ok {
		cfg.CredentialsFile, _ = v.(string)
	}
	if v, ok := tmp["credentials_json"]; ok {
		if m, ok := v.(map[string]interface{}); ok {
			cfg.CredentialsJSON = m
		}
	}
	if v, ok := tmp["custom_claims"]; ok {
		if m, ok := v.(map[string]interface{}); ok {
			cfg.CustomClaims = m
		}
	}
	if v, ok := tmp["s2s_auth_header"]; ok {
		cfg.S2SAuthHeader, _ = v.(string)
	}
	if cfg.Audience == "" {
		return Config{}, false
	}
	return cfg, true
}

type tokenSourceFactory func(cfg Config) (oauth2.TokenSource, error)

var newTokenSourceFn tokenSourceFactory = newTokenSource

func newTokenSource(cfg Config) (oauth2.TokenSource, error) {
	ctx := oauth2.NoContext
	hasCustom := len(cfg.CustomClaims) > 0
	if cfg.CredentialsFile != "" {
		if hasCustom {
			return idtoken.NewTokenSource(ctx, cfg.Audience, idtoken.WithCustomClaims(cfg.CustomClaims), option.WithCredentialsFile(cfg.CredentialsFile))
		}
		return idtoken.NewTokenSource(ctx, cfg.Audience, option.WithCredentialsFile(cfg.CredentialsFile))
	}
	if len(cfg.CredentialsJSON) > 0 {
		data, err := json.Marshal(cfg.CredentialsJSON)
		if err != nil {
			return nil, err
		}
		if hasCustom {
			return idtoken.NewTokenSource(ctx, cfg.Audience, idtoken.WithCustomClaims(cfg.CustomClaims), option.WithCredentialsJSON(data))
		}
		return idtoken.NewTokenSource(ctx, cfg.Audience, option.WithCredentialsJSON(data))
	}
	if hasCustom {
		return idtoken.NewTokenSource(ctx, cfg.Audience, idtoken.WithCustomClaims(cfg.CustomClaims))
	}
	return idtoken.NewTokenSource(ctx, cfg.Audience)
}
