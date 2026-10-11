package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"loki-analyzer/internal/config"
)

func writeTestEnv(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "settings.env")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func noEnvironment(string) (string, bool) { return "", false }

func TestLoadDefaults(t *testing.T) {
	opts := config.Options{EnvFile: writeTestEnv(t, "GRAFANA_TOKEN=test-token\n")}
	cfg, err := config.Load(opts, noEnvironment)
	if err != nil {
		t.Fatal(err)
	}
	want := config.Config{
		Grafana: config.Grafana{
			URL: "https://grafana.dev.armlab.pro", DataSourceUID: "ddxh9oc39r6rka",
			OrgID: "1", Token: "test-token",
		},
		Logs: config.Logs{Project: "sds-orders", ProjectLabel: "app", ResellerFile: "examples/data.json"},
		Watch: config.Watch{
			Interval: "2m", Window: "15m", ReportInterval: "15m", ReportOnly: "true", Cooldown: "30m",
			NoLogsAfter: "10m", StateFile: "local/watch-state.json", DBFile: "local/loki.db",
			ErrorThreshold: "3",
		},
	}
	if cfg != want {
		t.Fatal("loaded configuration does not match documented defaults")
	}
}

func TestLoadKeepsGrafanaBaseURL(t *testing.T) {
	opts := config.Options{EnvFile: writeTestEnv(t,
		"GRAFANA_TOKEN=test-token\nGRAFANA_URL=https://example.test:8443/grafana/\nGRAFANA_DATASOURCE_UID=test-UID_12\n")}
	cfg, err := config.Load(opts, noEnvironment)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Grafana.URL != "https://example.test:8443/grafana/" || cfg.Grafana.DataSourceUID != "test-UID_12" {
		t.Fatal("config must retain the base URL and UID without building HTTP routes")
	}
}

func TestReportOnlyCanBeChangedExplicitly(t *testing.T) {
	opts := config.Options{EnvFile: writeTestEnv(t, "WATCH_REPORT_ONLY=false\nWATCH_REPORT_INTERVAL=15m\n")}
	cfg, err := config.Load(opts, noEnvironment)
	if err != nil || cfg.Watch.ReportOnly != "false" || cfg.Watch.ReportInterval != "15m" {
		t.Fatalf("file report mode was not loaded: %v", err)
	}
	cfg, err = config.Load(opts, func(key string) (string, bool) {
		return "true", key == "WATCH_REPORT_ONLY"
	})
	if err != nil || cfg.Watch.ReportOnly != "true" {
		t.Fatalf("environment report mode must override file: %v", err)
	}
}

func TestLoadEnvironmentPrecedenceIncludingExplicitEmpty(t *testing.T) {
	opts := config.Options{EnvFile: writeTestEnv(t, "GRAFANA_TOKEN=file-token\nLOKI_PROJECT=file-project\nGRAFANA_ORG_ID=9\n")}
	environment := map[string]string{
		"GRAFANA_TOKEN":  "environment-token",
		"LOKI_PROJECT":   "environment-project",
		"GRAFANA_ORG_ID": "",
	}
	lookup := func(key string) (string, bool) {
		value, ok := environment[key]
		return value, ok
	}
	cfg, err := config.Load(opts, lookup)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Grafana.Token != "environment-token" || cfg.Logs.Project != "environment-project" || cfg.Grafana.OrgID != "" {
		t.Fatal("environment must override file values, including empty values")
	}
	environment["GRAFANA_TOKEN"] = ""
	cfg, err = config.Load(opts, lookup)
	if err != nil || cfg.Grafana.Token != "" {
		t.Fatal("explicitly empty token must not fall back to the file")
	}
	if err := cfg.ValidateLoki(); err == nil {
		t.Fatal("Loki must reject an explicitly empty token")
	}
}

func TestValidateLokiRejectsInvalidSettingsWithoutLeakingValues(t *testing.T) {
	cases := map[string]string{
		"http":          "GRAFANA_URL=http://example.test\n",
		"userinfo":      "GRAFANA_URL=https://user:private-secret@example.test\n",
		"fragment":      "GRAFANA_URL=https://example.test/#private-secret\n",
		"query":         "GRAFANA_URL=https://example.test/?token=private-secret\n",
		"empty query":   "GRAFANA_URL=https://example.test/?\n",
		"relative URL":  "GRAFANA_URL=/grafana\n",
		"missing host":  "GRAFANA_URL=https:///grafana\n",
		"invalid port":  "GRAFANA_URL=https://example.test:65536\n",
		"zero port":     "GRAFANA_URL=https://example.test:0\n",
		"invalid UID":   "GRAFANA_DATASOURCE_UID=../../private-secret\n",
		"empty UID":     "GRAFANA_DATASOURCE_UID=\n",
		"negative org":  "GRAFANA_ORG_ID=-1\n",
		"zero org":      "GRAFANA_ORG_ID=0\n",
		"ambiguous org": "GRAFANA_ORG_ID=01\n",
		"invalid org":   "GRAFANA_ORG_ID=private-secret\n",
		"invalid label": "LOKI_PROJECT_LABEL=app-name\n",
		"empty label":   "LOKI_PROJECT_LABEL=\n",
		"empty project": "LOKI_PROJECT=\n",
		"blank project": "LOKI_PROJECT='  '\n",
		"large project": "LOKI_PROJECT=" + strings.Repeat("x", 4097) + "\n",
	}
	for name, extra := range cases {
		t.Run(name, func(t *testing.T) {
			opts := config.Options{EnvFile: writeTestEnv(t, "GRAFANA_TOKEN=test-token\n"+extra)}
			cfg, err := config.Load(opts, noEnvironment)
			if err != nil {
				t.Fatal(err)
			}
			if err := cfg.ValidateLoki(); err == nil {
				t.Fatal("invalid settings accepted")
			} else if strings.Contains(err.Error(), "private-secret") {
				t.Fatal("configuration error echoed a sensitive value")
			}
		})
	}
}

func TestValidateLokiRejectsMissingOrUnsafeToken(t *testing.T) {
	for _, token := range []string{"", "private-secret extra", "private-secret\n", "private-secret\x00", "private-secret\u00a0"} {
		opts := config.Options{EnvFile: writeTestEnv(t, "")}
		lookup := func(key string) (string, bool) { return token, key == "GRAFANA_TOKEN" }
		cfg, err := config.Load(opts, lookup)
		if err != nil {
			t.Fatal(err)
		}
		err = cfg.ValidateLoki()
		if err == nil || !strings.Contains(err.Error(), "GRAFANA_TOKEN") {
			t.Fatal("invalid token needs an actionable error naming GRAFANA_TOKEN")
		}
		if strings.Contains(err.Error(), "private-secret") {
			t.Fatal("configuration error echoed the token")
		}
	}
}

func TestLoadTelegramDoesNotRequireGrafana(t *testing.T) {
	opts := config.Options{EnvFile: writeTestEnv(t, "TELEGRAM_BOT_TOKEN=123:FileToken\n")}
	cfg, err := config.Load(opts, noEnvironment)
	if err != nil || cfg.Telegram.Token != "123:FileToken" || cfg.Grafana.Token != "" {
		t.Fatal("Telegram settings must load independently of Grafana credentials")
	}
	for _, value := range []string{"456:EnvironmentToken", ""} {
		lookup := func(key string) (string, bool) { return value, key == "TELEGRAM_BOT_TOKEN" }
		cfg, err := config.Load(opts, lookup)
		if err != nil || cfg.Telegram.Token != value {
			t.Fatal("environment must override the Telegram token, including an empty value")
		}
	}
}

func TestLoadWatchSettingsAndChatUseEnvironmentPrecedence(t *testing.T) {
	path := writeTestEnv(t, `TELEGRAM_CHAT_ID=-100123
WATCH_INTERVAL=5m
WATCH_WINDOW=20m
WATCH_REPORT_INTERVAL=2h
WATCH_COOLDOWN=40m
WATCH_NO_LOGS_AFTER=15m
WATCH_STATE_FILE='local/custom state.json'
WATCH_DB_FILE='local/from-file.db'
WATCH_INCLUDE_REGEX='(?i)order (created|provisioned)'
WATCH_EXCLUDE_REGEX=healthcheck
WATCH_CRITICAL_REGEX=(?i)\bpanic\b
WATCH_ERROR_THRESHOLD=7
`)
	environment := map[string]string{
		"TELEGRAM_CHAT_ID": "-100456", "WATCH_INTERVAL": "3m", "WATCH_EXCLUDE_REGEX": "", "WATCH_DB_FILE": "local/from-env.db",
	}
	lookup := func(key string) (string, bool) {
		value, exists := environment[key]
		return value, exists
	}
	cfg, err := config.Load(config.Options{EnvFile: path}, lookup)
	if err != nil {
		t.Fatal(err)
	}
	want := config.Watch{
		Interval: "3m", Window: "20m", ReportInterval: "2h", ReportOnly: "true", Cooldown: "40m",
		NoLogsAfter: "15m", StateFile: "local/custom state.json", DBFile: "local/from-env.db",
		Include: `(?i)order (created|provisioned)`, Exclude: "",
		CriticalPattern: `(?i)\bpanic\b`, ErrorThreshold: "7",
	}
	if cfg.Watch != want || cfg.Telegram.ChatID != "-100456" {
		t.Fatal("watch settings must retain literal regex and prefer environment, including empty values")
	}
	environment["TELEGRAM_CHAT_ID"] = ""
	cfg, err = config.Load(config.Options{EnvFile: path}, lookup)
	if err != nil || cfg.Telegram.ChatID != "" {
		t.Fatal("an explicitly empty recipient must not fall back to the env file chat")
	}
}

func TestWatchSettingsDoNotInvalidateUnrelatedConnections(t *testing.T) {
	path := writeTestEnv(t, `GRAFANA_TOKEN=test-token
TELEGRAM_BOT_TOKEN=123:TestToken
TELEGRAM_CHAT_ID=invalid-chat
WATCH_INTERVAL=not-a-duration
WATCH_CRITICAL_REGEX=[
WATCH_ERROR_THRESHOLD=not-a-number
`)
	cfg, err := config.Load(config.Options{EnvFile: path}, noEnvironment)
	if err != nil {
		t.Fatal("loading must defer watch-specific validation to watch")
	}
	if err := cfg.ValidateLoki(); err != nil || cfg.Telegram.Token != "123:TestToken" {
		t.Fatal("manual Loki and Telegram checks must not depend on watch settings")
	}
	if cfg.Watch.Interval != "not-a-duration" || cfg.Watch.CriticalPattern != "[" || cfg.Watch.ErrorThreshold != "not-a-number" {
		t.Fatal("loading must preserve values so watch can validate them explicitly")
	}
}

func TestExampleEnvironmentLoadsWithoutSecrets(t *testing.T) {
	cfg, err := config.Load(config.Options{EnvFile: "../../.env.example", ExplicitEnv: true}, noEnvironment)
	if err != nil {
		t.Fatalf("distributed env example must be readable: %v", err)
	}
	if cfg.Grafana.Token != "" || cfg.Telegram.Token != "" || cfg.Telegram.ChatID != "" {
		t.Fatal("distributed env example must not contain credentials or a real recipient")
	}
	if cfg.Watch.CriticalPattern != "" {
		t.Fatal("env example must default to semantic critical matching")
	}
}
