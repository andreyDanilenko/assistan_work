package integration_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOfflineAnalysisDoesNotLoadEnvironment(t *testing.T) {
	// An invalid .env would fail config.Load. Offline analysis must not read it.
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, ".env"), []byte("INVALID_SETTING=private-value\n"), 0600); err != nil {
		t.Fatal(err)
	}
	fixture, err := filepath.Abs("../../examples/loki-query-response.txt")
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(directory)
	t.Setenv("GRAFANA_TOKEN", "")
	t.Setenv("GRAFANA_URL", "invalid-url")
	t.Setenv("TELEGRAM_BOT_TOKEN", "invalid-token")
	var out, diagnostic bytes.Buffer
	code := runCLI(context.Background(), []string{"analyze", "--file", fixture}, &out, &diagnostic)
	if code != 0 || diagnostic.Len() != 0 {
		t.Fatal("offline analysis unexpectedly depends on external configuration")
	}
	for _, text := range []string{"Прочитано записей: 5", "Найдено заказов: 1", "Есть шаги создания или обработки", "490a7b2f-2797-47be-ab24-b63dbc03edf8"} {
		if !strings.Contains(out.String(), text) {
			t.Fatalf("expected result missing: %s", text)
		}
	}
}
