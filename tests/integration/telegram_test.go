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

	"loki-analyzer/internal/cli"
	"loki-analyzer/internal/telegram"
)

func TestTelegramInitializationUsesInjectedHTTP(t *testing.T) {
	const token = "123:Test_Token"
	calls := 0
	httpClient := httpFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		if request.Method != http.MethodGet || request.URL.String() != "https://api.telegram.org/bot"+token+"/getMe" {
			t.Fatal("initialization must only call getMe")
		}
		if deadline, ok := request.Context().Deadline(); !ok || time.Until(deadline) > 3*time.Second {
			t.Fatal("initialization must have a deadline")
		}
		body := `{"ok":true,"result":{"id":9000000001,"is_bot":true,"username":"orders_bot","first_name":"Orders"}}`
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}, nil
	})
	var out, diagnostic bytes.Buffer
	bot, err := telegram.New(telegram.Config{Token: token}, httpClient)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	info, err := bot.GetMe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := cli.PrintBotInfo(&out, info); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || diagnostic.Len() != 0 || !strings.Contains(out.String(), "orders_bot") || !strings.Contains(out.String(), "9000000001") {
		t.Fatal("Telegram initialization failed")
	}
	if strings.Contains(out.String()+diagnostic.String(), token) {
		t.Fatal("Telegram token leaked")
	}
}

func TestTelegramMissingTokenNeedsNoGrafana(t *testing.T) {
	t.Setenv("TELEGRAM_BOT_TOKEN", "")
	t.Setenv("GRAFANA_TOKEN", "")
	t.Setenv("GRAFANA_URL", "invalid-grafana-url")
	path := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	var out, diagnostic bytes.Buffer
	code := runCLI(context.Background(), []string{"telegram-check", "--env-file", path}, &out, &diagnostic)
	if code != 1 || out.Len() != 0 || !strings.Contains(diagnostic.String(), "TELEGRAM_BOT_TOKEN") || strings.Contains(diagnostic.String(), "GRAFANA") {
		t.Fatal("Telegram initialization must validate only its own settings")
	}
}
