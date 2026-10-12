// Пакет monitor периодически проверяет свежие логи и готовит ограниченную сводку.
// Это локальный монитор, а не постоянное хранилище всей истории заказов.
package monitor

import (
	"context"
	"errors"
	"io"
	"regexp"
	"time"

	"loki-analyzer/internal/loki"
	"loki-analyzer/internal/model"
)

type Source interface {
	FetchLogs(context.Context, loki.Query) (model.FetchResult, error)
}

type Sender interface {
	SendMessage(context.Context, int64, string) error
}

// ReportSender добавляет кнопку подробностей к сводке с известным периодом.
// Обычный Sender остаётся достаточным для консольных заглушек и других адаптеров.
type ReportSender interface {
	SendMessageWithReport(context.Context, int64, string, string, time.Time, time.Time) error
}

// Archive хранит исходные записи до фильтрации. Реальную SQLite передает main.
type Archive interface {
	SaveRange(context.Context, model.LogRange, []model.LogRecord, time.Time) error
	Latest(context.Context, string, string, time.Time) (time.Time, error)
	Coverage(context.Context, model.LogRange) (model.Coverage, error)
	Prune(context.Context, time.Time) (int64, error)
}

// Config передается из main: пакет не читает окружение и не создает HTTP-клиентов.
type Config struct {
	Project, SourceID, StateFile string
	ChatID                       int64
	Interval, Window             time.Duration
	SessionStart                 time.Time // Нижняя граница текущего процесса; ноль фиксируется один раз в New.
	ReportInterval, Cooldown     time.Duration
	NoLogsAfter, Timeout         time.Duration
	Include, Exclude, Critical   string
	ErrorThreshold               int
	DryRun                       bool
	ReportOnly                   bool                                                                   // Сбор идёт чаще, чем сводки; отдельные ошибки не запускают сообщения.
	BuildSnapshot                func(context.Context, time.Time, time.Time) (Snapshot, error)          // Читает весь заданный период из хранилища.
	ReadWindow                   func(context.Context, time.Time, time.Time) ([]model.LogRecord, error) // Сохранённое окно для немедленных уведомлений.
	ResellerNames                map[string]string                                                      // Только для вывода; ключи ошибок и счётчики используют ID.
}

// Message хранит только готовый безопасный текст, без исходных строк и токенов.
type Message struct {
	Kind        string    `json:"kind"`
	Text        string    `json:"text"`
	Attempts    int       `json:"attempts"`
	NextTry     time.Time `json:"next_try"`
	ReportStart time.Time `json:"report_start,omitempty"`
	ReportEnd   time.Time `json:"report_end,omitempty"`
}

// State нужен для пауз между сообщениями и продолжения недоставленной очереди.
// Сырые логи и полная история заказов сюда не записываются.
type State struct {
	Version         int                  `json:"version"`
	Binding         string               `json:"binding"`
	LastReport      time.Time            `json:"last_report"`
	LastReportEnd   time.Time            `json:"last_report_end,omitempty"`
	NextReportStart time.Time            `json:"next_report_start,omitempty"`
	LastAlert       time.Time            `json:"last_alert"`
	LastHealth      time.Time            `json:"last_health"`
	TelegramAfter   time.Time            `json:"telegram_after"`
	LastComplete    time.Time            `json:"last_complete"`
	SourceFailed    bool                 `json:"source_failed"`
	NoLogs          bool                 `json:"no_logs"`
	Pending         []Message            `json:"pending"`
	AlertIssues     []Issue              `json:"alert_issues,omitempty"`
	Alerted         map[string]time.Time `json:"alerted,omitempty"`
	AlertDropped    int                  `json:"alert_dropped"`
	CooldownEvicted int                  `json:"cooldown_evicted"`
}

type Monitor struct {
	config       Config
	filter       Filter
	source       Source
	sender       Sender
	archive      Archive
	output       io.Writer
	diagnostic   io.Writer
	state        State
	reportFailed bool
}

func New(cfg Config, source Source, sender Sender, archive Archive, output, diagnostic io.Writer) (*Monitor, error) {
	if cfg.SessionStart.IsZero() {
		cfg.SessionStart = time.Now().UTC()
	}
	if source == nil || output == nil || diagnostic == nil || (!cfg.DryRun && sender == nil) {
		return nil, errors.New("монитору нужны источник, вывод и отправитель для Telegram")
	}
	if !cfg.DryRun && archive == nil {
		return nil, errors.New("монитору нужно хранилище исходных логов")
	}
	if cfg.ReportOnly && !cfg.DryRun && cfg.BuildSnapshot == nil {
		return nil, errors.New("для периодической сводки нужен сборщик данных из сохранённых логов")
	}
	if !cfg.ReportOnly && !cfg.DryRun && cfg.ReadWindow == nil {
		return nil, errors.New("для немедленных уведомлений нужно чтение сохранённого окна")
	}
	if cfg.Project == "" || cfg.SourceID == "" || cfg.StateFile == "" || (!cfg.DryRun && cfg.ChatID == 0) {
		return nil, errors.New("укажите проект, файл состояния и TELEGRAM_CHAT_ID для отправки")
	}
	if cfg.Interval < 10*time.Second || cfg.Interval > time.Hour || cfg.Window < time.Minute || cfg.Window > time.Hour {
		return nil, errors.New("WATCH_INTERVAL: от 10s до 1h; WATCH_WINDOW: от 1m до 1h")
	}
	if cfg.ReportInterval < cfg.Interval || cfg.ReportInterval > 24*time.Hour || cfg.Cooldown < cfg.Interval || cfg.Cooldown > 24*time.Hour {
		return nil, errors.New("интервал отчета и пауза уведомлений: от интервала сбора до 24h")
	}
	if cfg.NoLogsAfter < time.Minute || cfg.NoLogsAfter > time.Hour || cfg.Timeout <= 0 || cfg.Timeout > 10*time.Minute {
		return nil, errors.New("WATCH_NO_LOGS_AFTER: от 1m до 1h; timeout: от 0 до 10m")
	}
	if cfg.ErrorThreshold < 1 || cfg.ErrorThreshold > 100000 {
		return nil, errors.New("WATCH_ERROR_THRESHOLD должен быть от 1 до 100000")
	}
	var filter Filter
	for _, field := range []struct {
		text   string
		target **regexp.Regexp
	}{
		{cfg.Include, &filter.Include}, {cfg.Exclude, &filter.Exclude}, {cfg.Critical, &filter.Critical},
	} {
		if len(field.text) > 2048 {
			return nil, errors.New("регулярное выражение WATCH ограничено 2048 байтами")
		}
		if field.text == "" {
			continue
		}
		pattern, err := regexp.Compile(field.text)
		if err != nil {
			return nil, errors.New("некорректное регулярное выражение WATCH")
		}
		*field.target = pattern
	}
	return &Monitor{config: cfg, filter: filter, source: source, sender: sender, archive: archive, output: output, diagnostic: diagnostic}, nil
}
