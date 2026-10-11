package config_test

import (
	"loki-analyzer/internal/config"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResellerCatalogLoadAndValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "names.json")
	for _, body := range []string{`{"r-a":" TBank ","r-b":"TBank"}`, `{"r-a":23}`, `{"r-a":""}`, `{"r-a":"name\nforged"}`, `null`, `{"bad id":"name"}`} {
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		names, err := config.LoadResellers(path)
		if strings.Contains(body, " TBank ") {
			if err != nil || len(names) != 2 || names["r-a"] != "TBank" || names["r-b"] != "TBank" {
				t.Fatalf("wrong mapping: %v %v", names, err)
			}
		} else if err == nil || names != nil {
			t.Fatal("invalid mapping was accepted or partially loaded")
		}
	}
	names, err := config.LoadResellers(filepath.Join(t.TempDir(), "missing.json"))
	if err != nil || len(names) != 0 {
		t.Fatal("optional mapping should retain original IDs")
	}
}

func TestResellerCatalogPathUsesConfigurationPrecedence(t *testing.T) {
	path := writeTestEnv(t, "RESELLER_MAP_FILE=examples/custom.json\n")
	cfg, err := config.Load(config.Options{EnvFile: path}, noEnvironment)
	if err != nil || cfg.Logs.ResellerFile != "examples/custom.json" {
		t.Fatalf("env file mapping path: %v %v", cfg, err)
	}
	cfg, err = config.Load(config.Options{EnvFile: path}, func(key string) (string, bool) { return "", key == "RESELLER_MAP_FILE" })
	if err != nil || cfg.Logs.ResellerFile != "" {
		t.Fatal("explicitly empty environment must disable mapping")
	}
}
