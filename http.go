package gcpauth

import (
	"context"
	"fmt"
	"net/http"

	"github.com/pucora/lura/v2/config"
	"github.com/pucora/lura/v2/transport/http/client"
)

// WrapRequestExecutor injects a GCP ID token into outbound backend requests.
func WrapRequestExecutor(cfg *config.Backend, next client.HTTPRequestExecutor) client.HTTPRequestExecutor {
	gcpCfg, ok := configGetter(cfg.ExtraConfig)
	if !ok {
		return next
	}
	ts, err := newTokenSourceFn(gcpCfg)
	if err != nil {
		return func(_ context.Context, _ *http.Request) (*http.Response, error) {
			return nil, fmt.Errorf("gcp auth: %w", err)
		}
	}
	headerName := gcpCfg.S2SAuthHeader
	if headerName == "" {
		headerName = "Authorization"
	}
	return func(ctx context.Context, req *http.Request) (*http.Response, error) {
		token, err := ts.Token()
		if err != nil {
			return nil, fmt.Errorf("gcp auth token: %w", err)
		}
		req.Header.Set(headerName, "Bearer "+token.AccessToken)
		return next(ctx, req)
	}
}
