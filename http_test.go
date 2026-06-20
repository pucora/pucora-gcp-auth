package gcpauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pucora/lura/v2/config"
	"github.com/pucora/lura/v2/transport/http/client"
	"golang.org/x/oauth2"
)

type staticTokenSource struct {
	token string
}

func (s staticTokenSource) Token() (*oauth2.Token, error) {
	return &oauth2.Token{AccessToken: s.token}, nil
}

func TestWrapRequestExecutorInjectsToken(t *testing.T) {
	orig := newTokenSourceFn
	defer func() { newTokenSourceFn = orig }()
	newTokenSourceFn = func(_ Config) (oauth2.TokenSource, error) {
		return staticTokenSource{token: "gcp-test-token"}, nil
	}

	var gotAuth string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := &config.Backend{
		ExtraConfig: config.ExtraConfig{
			Namespace: map[string]interface{}{
				"audience": backend.URL,
			},
		},
	}
	next := func(_ context.Context, req *http.Request) (*http.Response, error) {
		return http.DefaultClient.Do(req)
	}
	exec := WrapRequestExecutor(cfg, next)
	req, _ := http.NewRequest(http.MethodGet, backend.URL, nil)
	if _, err := exec(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer gcp-test-token" {
		t.Fatalf("expected bearer token injection, got %q", gotAuth)
	}
}

func TestWrapRequestExecutorPassthroughWithoutConfig(t *testing.T) {
	called := false
	cfg := &config.Backend{ExtraConfig: config.ExtraConfig{}}
	next := client.HTTPRequestExecutor(func(_ context.Context, _ *http.Request) (*http.Response, error) {
		called = true
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
	})
	exec := WrapRequestExecutor(cfg, next)
	if _, err := exec(context.Background(), &http.Request{}); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("expected passthrough executor")
	}
}
