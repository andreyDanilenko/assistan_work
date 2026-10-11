package integration_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"loki-analyzer/internal/app"
	"loki-analyzer/internal/cli"
	"loki-analyzer/internal/config"
	"loki-analyzer/internal/loki"
)

func TestHelpAndMissingTokenNeedNoNetwork(t *testing.T) {
	var out, diagnostic bytes.Buffer
	if runCLI(context.Background(), []string{"--help"}, &out, &diagnostic) != 0 || !strings.Contains(out.String(), "lokictl") {
		t.Fatal("help failed")
	}
	for _, key := range []string{"GRAFANA_URL", "GRAFANA_DATASOURCE_UID", "GRAFANA_ORG_ID", "GRAFANA_TOKEN", "LOKI_PROJECT", "LOKI_PROJECT_LABEL"} {
		t.Setenv(key, "")
		if err := os.Unsetenv(key); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("GRAFANA_TOKEN", "")
	path := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(path, []byte("GRAFANA_TOKEN=file-token-must-not-be-used\n"), 0600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	code := runCLI(context.Background(), []string{"check", "--env-file", path}, &out, &diagnostic)
	if code != 1 || out.Len() > 0 || !strings.Contains(diagnostic.String(), "GRAFANA_TOKEN") || strings.Contains(diagnostic.String(), "file-token-must-not-be-used") {
		t.Fatal("missing token was not rejected safely")
	}
}

type httpFunc func(*http.Request) (*http.Response, error)

func (f httpFunc) Do(request *http.Request) (*http.Response, error) { return f(request) }

func TestWiringConnectsCLIServiceAndInjectedHTTP(t *testing.T) {
	settings := config.Config{
		Grafana: config.Grafana{URL: "https://grafana.example.test/subpath/", DataSourceUID: "test-source", OrgID: "1", Token: "test-token"},
		Logs:    config.Logs{Project: "sds-orders", ProjectLabel: "app"},
	}
	calls := 0
	transport := httpFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		if request.Method != http.MethodGet || request.URL.Path != "/subpath/api/datasources/proxy/uid/test-source/loki/api/v1/query_range" {
			t.Fatal("wrong proxy route")
		}
		if request.Header.Get("Authorization") != "Bearer test-token" || request.Header.Get("X-Grafana-Org-Id") != "1" {
			t.Fatal("missing authentication settings")
		}
		if request.URL.Query().Get("query") != `{app="sds-orders"}` || request.URL.Query().Get("limit") != "5" {
			t.Fatal("scenario settings not forwarded")
		}
		body := `{"status":"success","data":{"resultType":"streams","result":[]}}`
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}, nil
	})
	if err := settings.ValidateLoki(); err != nil {
		t.Fatal(err)
	}
	clientConfig := loki.DefaultConfig()
	clientConfig.URL = strings.TrimRight(settings.Grafana.URL, "/") + "/api/datasources/proxy/uid/" + settings.Grafana.DataSourceUID
	clientConfig.Token, clientConfig.OrgID = settings.Grafana.Token, settings.Grafana.OrgID
	clientConfig.ProjectLabel, clientConfig.Timeout = settings.Logs.ProjectLabel, time.Second
	source, err := loki.New(clientConfig, transport)
	if err != nil {
		t.Fatal(err)
	}
	service := app.New(app.Config{DefaultProject: settings.Logs.Project, ProjectLabel: settings.Logs.ProjectLabel}, source)
	options, err := cli.Parse([]string{"logs", "--limit", "5"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var out, diagnostic bytes.Buffer
	code := cli.Run(context.Background(), service, options, &out, &diagnostic)
	if code != 0 || calls != 1 || diagnostic.Len() > 0 || !strings.Contains(out.String(), "Записей в ответе: 0") {
		t.Fatal("layered execution failed")
	}
}
