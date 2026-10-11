// Пакет config загружает настройки. Остальные компоненты получают их через конструкторы.
package config

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// Config объединяет настройки приложения; каждый компонент получает только свою часть.
type Config struct {
	Grafana  Grafana
	Logs     Logs
	Telegram Telegram
	Watch    Watch
}

type Telegram struct {
	Token  string
	ChatID string
}

// Watch хранит буквальные настройки: преобразование и проверка нужны только команде watch.
type Watch struct {
	Interval        string
	Window          string
	ReportInterval  string
	ReportOnly      string
	Cooldown        string
	NoLogsAfter     string
	StateFile       string
	DBFile          string
	Include         string
	Exclude         string
	CriticalPattern string
	ErrorThreshold  string
}

type Grafana struct {
	URL           string
	DataSourceUID string
	OrgID         string
	Token         string
}

type Logs struct {
	Project      string
	ProjectLabel string
	ResellerFile string
}

// Options отличает обычный .env от файла, явно запрошенного через --env-file.
type Options struct {
	EnvFile     string
	ExplicitEnv bool
}

// defaults задает адреса и проект для текущего окружения; секреты значений по умолчанию не имеют.
func defaults() Config {
	return Config{
		Grafana: Grafana{
			URL:           "https://grafana.dev.armlab.pro",
			DataSourceUID: "ddxh9oc39r6rka",
			OrgID:         "1",
		},
		Logs: Logs{Project: "sds-orders", ProjectLabel: "app", ResellerFile: "examples/data.json"},
		Watch: Watch{
			Interval: "2m", Window: "15m", ReportInterval: "15m", ReportOnly: "true",
			Cooldown: "30m", NoLogsAfter: "10m", StateFile: "local/watch-state.json",
			DBFile:         "local/loki.db",
			ErrorThreshold: "3",
		},
	}
}

// Load выбирает значения в порядке приоритета: окружение → .env → defaults.
// Даже пустое значение окружения перекрывает файл. Функцию чтения окружения передает main.
// Настройки подключения проверяются при создании нужного компонента, а не всех сразу.
func Load(opts Options, lookup func(string) (string, bool)) (Config, error) {
	values, err := readEnvFile(opts.EnvFile, opts.ExplicitEnv)
	if err != nil {
		return Config{}, err
	}
	get := func(key, fallback string) string {
		if value, ok := lookup(key); ok {
			return value
		}
		if value, ok := values[key]; ok {
			return value
		}
		return fallback
	}

	cfg := defaults()
	cfg.Grafana.URL = get("GRAFANA_URL", cfg.Grafana.URL)
	cfg.Grafana.DataSourceUID = get("GRAFANA_DATASOURCE_UID", cfg.Grafana.DataSourceUID)
	cfg.Grafana.OrgID = get("GRAFANA_ORG_ID", cfg.Grafana.OrgID)
	cfg.Grafana.Token = get("GRAFANA_TOKEN", cfg.Grafana.Token)
	cfg.Logs.Project = get("LOKI_PROJECT", cfg.Logs.Project)
	cfg.Logs.ProjectLabel = get("LOKI_PROJECT_LABEL", cfg.Logs.ProjectLabel)
	cfg.Logs.ResellerFile = get("RESELLER_MAP_FILE", cfg.Logs.ResellerFile)
	cfg.Telegram.Token = get("TELEGRAM_BOT_TOKEN", "")
	cfg.Telegram.ChatID = get("TELEGRAM_CHAT_ID", "")
	cfg.Watch.Interval = get("WATCH_INTERVAL", cfg.Watch.Interval)
	cfg.Watch.Window = get("WATCH_WINDOW", cfg.Watch.Window)
	cfg.Watch.ReportInterval = get("WATCH_REPORT_INTERVAL", cfg.Watch.ReportInterval)
	cfg.Watch.ReportOnly = get("WATCH_REPORT_ONLY", cfg.Watch.ReportOnly)
	cfg.Watch.Cooldown = get("WATCH_COOLDOWN", cfg.Watch.Cooldown)
	cfg.Watch.NoLogsAfter = get("WATCH_NO_LOGS_AFTER", cfg.Watch.NoLogsAfter)
	cfg.Watch.StateFile = get("WATCH_STATE_FILE", cfg.Watch.StateFile)
	cfg.Watch.DBFile = get("WATCH_DB_FILE", cfg.Watch.DBFile)
	cfg.Watch.Include = get("WATCH_INCLUDE_REGEX", cfg.Watch.Include)
	cfg.Watch.Exclude = get("WATCH_EXCLUDE_REGEX", cfg.Watch.Exclude)
	cfg.Watch.CriticalPattern = get("WATCH_CRITICAL_REGEX", cfg.Watch.CriticalPattern)
	cfg.Watch.ErrorThreshold = get("WATCH_ERROR_THRESHOLD", cfg.Watch.ErrorThreshold)
	return cfg, nil
}

const maxEnvBytes = 64 * 1024

// readEnvFile читает KEY=value буквально: shell-команды и подстановки не выполняются.
func readEnvFile(path string, required bool) (map[string]string, error) {
	values := make(map[string]string)
	file, err := os.Open(path)
	// Отсутствующий обычный .env допустим; явно указанный файл должен существовать.
	if errors.Is(err, os.ErrNotExist) && !required {
		return values, nil
	}
	if err != nil {
		return nil, errors.New("не удалось открыть файл настроек")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxEnvBytes {
		return nil, errors.New("файл настроек должен быть обычным файлом размером не более 64 КиБ")
	}

	// Ограничиваем чтение и сообщаем номер ошибочной строки, не раскрывая ее содержимое.
	scanner := bufio.NewScanner(io.LimitReader(file, maxEnvBytes+1))
	for line := 1; scanner.Scan(); line++ {
		text := strings.TrimSpace(scanner.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		key, value, err := parseAssignment(text)
		if err != nil {
			return nil, fmt.Errorf("%w в строке %d", err, line)
		}
		// Не выбираем молча одно из двух противоречащих значений настройки.
		if _, duplicate := values[key]; duplicate {
			return nil, fmt.Errorf("повторная настройка в строке %d", line)
		}
		values[key] = value
	}
	if scanner.Err() != nil {
		return nil, errors.New("не удалось прочитать файл настроек")
	}
	return values, nil
}

// parseAssignment проверяет имя настройки и снимает внешние кавычки; значение не преобразует.
func parseAssignment(text string) (string, string, error) {
	key, value, ok := strings.Cut(text, "=")
	key, value = strings.TrimSpace(key), strings.TrimSpace(value)
	if !ok || !knownKey(key) {
		return "", "", errors.New("неверная настройка")
	}
	if strings.HasPrefix(value, "\"") || strings.HasPrefix(value, "'") {
		if len(value) < 2 || value[0] != value[len(value)-1] {
			return "", "", errors.New("незакрытые кавычки")
		}
		return key, value[1 : len(value)-1], nil
	}
	if strings.ContainsAny(value, " \t\"'") {
		return "", "", errors.New("значение с пробелами требует кавычек")
	}
	return key, value, nil
}

// knownKey отклоняет неизвестные имена, чтобы опечатка в .env не осталась незамеченной.
func knownKey(key string) bool {
	switch key {
	case "GRAFANA_URL", "GRAFANA_DATASOURCE_UID", "GRAFANA_ORG_ID", "GRAFANA_TOKEN":
		return true
	case "LOKI_PROJECT", "LOKI_PROJECT_LABEL", "TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID":
		return true
	case "WATCH_INTERVAL", "WATCH_WINDOW", "WATCH_REPORT_INTERVAL", "WATCH_REPORT_ONLY", "WATCH_COOLDOWN", "WATCH_NO_LOGS_AFTER":
		return true
	case "WATCH_STATE_FILE", "WATCH_INCLUDE_REGEX", "WATCH_EXCLUDE_REGEX", "WATCH_CRITICAL_REGEX", "WATCH_ERROR_THRESHOLD":
		return true
	case "WATCH_DB_FILE", "RESELLER_MAP_FILE":
		return true
	default:
		return false
	}
}

// ValidateLoki проверяет только настройки Loki: командам Telegram они не требуются.
func (cfg Config) ValidateLoki() error {
	if err := validateURL(cfg.Grafana.URL); err != nil {
		return err
	}
	if !regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`).MatchString(cfg.Grafana.DataSourceUID) {
		return errors.New("некорректный GRAFANA_DATASOURCE_UID")
	}
	if cfg.Grafana.Token == "" {
		return errors.New("добавьте токен сервисной учетной записи в GRAFANA_TOKEN в .env или окружении")
	}
	if strings.ContainsFunc(cfg.Grafana.Token, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	}) {
		return errors.New("GRAFANA_TOKEN не должен содержать пробелы или управляющие символы")
	}
	if cfg.Grafana.OrgID != "" {
		org, err := strconv.ParseUint(cfg.Grafana.OrgID, 10, 64)
		if err != nil || org == 0 || strconv.FormatUint(org, 10) != cfg.Grafana.OrgID {
			return errors.New("GRAFANA_ORG_ID должен быть положительным целым числом или пустым")
		}
	}
	if !regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`).MatchString(cfg.Logs.ProjectLabel) {
		return errors.New("некорректный LOKI_PROJECT_LABEL")
	}
	if strings.TrimSpace(cfg.Logs.Project) == "" || len(cfg.Logs.Project) > 4096 {
		return errors.New("LOKI_PROJECT должен быть непустым и не длиннее 4096 байт")
	}
	return nil
}

// validateURL допускает базовый HTTPS-адрес, к которому main добавит путь прокси Grafana.
// Логин, query и фрагмент запрещены, чтобы в адресе не оказалось лишних данных авторизации.
func validateURL(raw string) error {
	base, err := url.Parse(raw)
	if err != nil || base.Scheme != "https" || base.Hostname() == "" {
		return errors.New("GRAFANA_URL должен быть абсолютным HTTPS-адресом Grafana")
	}
	if base.User != nil || base.RawQuery != "" || base.ForceQuery {
		return errors.New("GRAFANA_URL не должен содержать логин или query-параметры")
	}
	if base.Fragment != "" || base.Opaque != "" {
		return errors.New("GRAFANA_URL не должен содержать фрагмент или непрозрачную часть")
	}
	if port := base.Port(); port != "" {
		if number, err := strconv.ParseUint(port, 10, 16); err != nil || number == 0 {
			return errors.New("некорректный порт GRAFANA_URL")
		}
	}
	return nil
}
