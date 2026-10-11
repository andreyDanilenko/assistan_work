package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"loki-analyzer/internal/config"
)

func TestLoadEnvFileLiteralValuesNeverExecute(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "must-not-exist")
	literal := "$(touch " + marker + ") ${HOME} `whoami` \\n"
	path := writeTestEnv(t, "# comments are allowed\n\nGRAFANA_TOKEN='"+literal+"'\nLOKI_PROJECT=orders\nGRAFANA_ORG_ID=\"1\"\n")
	got, err := config.Load(config.Options{EnvFile: path, ExplicitEnv: true}, noEnvironment)
	if err != nil {
		t.Fatal(err)
	}
	if got.Grafana.Token != literal || got.Logs.Project != "orders" || got.Grafana.OrgID != "1" {
		t.Fatal("values were changed instead of treated as literals")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("shell-like text must not execute: %v", err)
	}
}

func TestLoadEnvFileErrorsDoNotEchoSecrets(t *testing.T) {
	const secret = "private-token-that-must-not-appear"
	cases := map[string]string{
		"unknown key":       "UNKNOWN_" + secret + "=value\n",
		"unknown watch key": "WATCH_INTERVALL=" + secret + "\n",
		"duplicate key":     "GRAFANA_TOKEN=" + secret + "\nGRAFANA_TOKEN=other\n",
		"shell export":      "export GRAFANA_TOKEN=" + secret + "\n",
		"missing equals":    "GRAFANA_TOKEN " + secret + "\n",
		"unquoted spaces":   "GRAFANA_TOKEN=" + secret + " extra\n",
		"unclosed quote":    "GRAFANA_TOKEN=\"" + secret + "\n",
		"unmatched quotes":  "GRAFANA_TOKEN='" + secret + "\"\n",
		"oversize file":     "GRAFANA_TOKEN=" + strings.Repeat(secret, 3000),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := config.Load(config.Options{EnvFile: writeTestEnv(t, body), ExplicitEnv: true}, noEnvironment)
			if err == nil {
				t.Fatal("invalid file was accepted")
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatal("error leaked the secret")
			}
		})
	}
}

func TestLoadEnvFileMissingAndNonRegularFiles(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "private-secret.env")
	want := config.Config{
		Grafana: config.Grafana{URL: "https://grafana.dev.armlab.pro", DataSourceUID: "ddxh9oc39r6rka", OrgID: "1"},
		Logs:    config.Logs{Project: "sds-orders", ProjectLabel: "app", ResellerFile: "examples/data.json"},
		Watch: config.Watch{
			Interval: "2m", Window: "15m", ReportInterval: "15m", ReportOnly: "true", Cooldown: "30m",
			NoLogsAfter: "10m", StateFile: "local/watch-state.json", DBFile: "local/loki.db",
			ErrorThreshold: "3",
		},
	}
	if got, err := config.Load(config.Options{EnvFile: missing}, noEnvironment); err != nil || got != want {
		t.Fatalf("optional missing file: %v", err)
	}
	if _, err := config.Load(config.Options{EnvFile: missing, ExplicitEnv: true}, noEnvironment); err == nil || strings.Contains(err.Error(), "private-secret") {
		t.Fatalf("required missing file: %v", err)
	}
	if _, err := config.Load(config.Options{EnvFile: t.TempDir(), ExplicitEnv: true}, noEnvironment); err == nil {
		t.Fatal("directory must not be read as an env file")
	}
}
