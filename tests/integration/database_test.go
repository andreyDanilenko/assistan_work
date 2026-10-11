package integration_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Проверяем настоящий запуск: локальная база обслуживается раньше создания
// сетевых клиентов и не требует даже корректных настроек Grafana или Telegram.
func TestDatabaseCommandsCreateAndCleanLocalDatabaseWithoutTokens(t *testing.T) {
	directory := t.TempDir()
	database := filepath.Join(directory, "events.db")
	state := filepath.Join(directory, "watch.json")
	envFile := filepath.Join(directory, "test.env")
	if err := os.WriteFile(envFile, nil, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GRAFANA_TOKEN", "")
	t.Setenv("TELEGRAM_BOT_TOKEN", "")
	t.Setenv("TELEGRAM_CHAT_ID", "")
	t.Setenv("GRAFANA_URL", "invalid-for-network-commands")
	t.Setenv("WATCH_DB_FILE", database)
	t.Setenv("WATCH_STATE_FILE", state)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, command := range []string{"db-status", "db-cleanup"} {
		var output, diagnostic bytes.Buffer
		code := runCLI(ctx, []string{command, "--env-file", envFile, "--timeout", "5s"}, &output, &diagnostic)
		if code != 0 || diagnostic.Len() != 0 {
			t.Fatalf("%s failed without tokens: code=%d diagnostic=%s", command, code, diagnostic.String())
		}
		for _, wanted := range []string{database, "Хранение: 48 часов", "Удалено старых строк: 0", "Строк в базе: 0", "Событий с учетом повторов: 0"} {
			if !strings.Contains(output.String(), wanted) {
				t.Fatalf("%s missing %q in output: %s", command, wanted, output.String())
			}
		}
	}
	file, err := os.Open(database)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	header := make([]byte, 16)
	if _, err := file.Read(header); err != nil || string(header) != "SQLite format 3\x00" {
		t.Fatal("command did not create a real SQLite database")
	}
	info, err := file.Stat()
	if err != nil || info.Mode().Perm()&0077 != 0 {
		t.Fatal("database permissions allow other users")
	}
	if _, err := os.Stat(state); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("database maintenance changed notification state")
	}
}
