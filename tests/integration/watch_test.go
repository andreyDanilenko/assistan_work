package integration_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Проверяем настоящий бинарник, но неправильная локальная настройка должна
// остановить запуск раньше сети и не раскрыть значения токенов.
func TestWatchValidatesDestinationBeforeNetwork(t *testing.T) {
	t.Setenv("GRAFANA_TOKEN", "local-test-secret")
	t.Setenv("TELEGRAM_BOT_TOKEN", "123:local_test_secret")
	t.Setenv("TELEGRAM_CHAT_ID", "")
	file := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(file, nil, 0600); err != nil {
		t.Fatal(err)
	}
	var output, diagnostic bytes.Buffer
	code := runCLI(context.Background(), []string{"watch", "--once", "--env-file", file}, &output, &diagnostic)
	if code != 1 || !strings.Contains(diagnostic.String(), "TELEGRAM_CHAT_ID") {
		t.Fatalf("destination validation: code=%d diagnostic=%s", code, diagnostic.String())
	}
	if strings.Contains(diagnostic.String(), "local-test-secret") {
		t.Fatal("secret in error")
	}
}

func TestWatchDryRunDoesNotRequireTelegram(t *testing.T) {
	t.Setenv("GRAFANA_TOKEN", "local-test-secret")
	t.Setenv("TELEGRAM_BOT_TOKEN", "")
	t.Setenv("TELEGRAM_CHAT_ID", "")
	t.Setenv("WATCH_INCLUDE_REGEX", "[")
	file := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(file, nil, 0600); err != nil {
		t.Fatal(err)
	}
	var output, diagnostic bytes.Buffer
	code := runCLI(context.Background(), []string{"watch", "--once", "--dry-run", "--env-file", file}, &output, &diagnostic)
	if code != 1 || !strings.Contains(diagnostic.String(), "регулярное выражение") || strings.Contains(diagnostic.String(), "TELEGRAM") {
		t.Fatalf("dry-run must reach monitor validation without Telegram: %s", diagnostic.String())
	}
}
