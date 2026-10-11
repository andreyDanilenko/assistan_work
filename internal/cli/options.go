package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"loki-analyzer/internal/app"
)

// ErrHelp отделяет запрос справки от ошибки аргументов: справка завершается с кодом 0.
var ErrHelp = errors.New("help requested")

// Mode определяет, какие параметры и зависимости нужны выбранной команде.
type Mode int

const (
	LokiMode Mode = iota
	TelegramMode
	AnalyzeMode
	WatchMode
	TelegramChatsMode
	DBStatusMode
	DBCleanupMode
)

// Options хранит запрос сервиса отдельно от настроек запуска и консольного вывода.
type Options struct {
	Request     app.Request
	EnvFile     string
	ExplicitEnv bool
	Timeout     time.Duration
	Raw         bool
	Mode        Mode
	File        string
	AllOrders   bool
	Once        bool
	DryRun      bool
}

// Parse превращает аргументы в проверенные параметры без чтения окружения и сети.
// Текущее время передается снаружи, чтобы относительный период был воспроизводим в тестах.
func Parse(args []string, now time.Time) (Options, error) {
	var options Options
	var flags []string
	// Отдельные сценарии не создают запрос одной страницы Loki с фиксированным периодом.
	if len(args) > 0 {
		switch args[0] {
		case "telegram-check":
			options.Mode = TelegramMode
		case "telegram-chats":
			options.Mode = TelegramChatsMode
		case "analyze":
			options.Mode = AnalyzeMode
		case "watch":
			options.Mode = WatchMode
		case "db-status":
			options.Mode = DBStatusMode
		case "db-cleanup":
			options.Mode = DBCleanupMode
		}
	}
	if options.Mode != LokiMode {
		flags = args[1:]
	} else {
		request, remaining, err := parseCommand(args)
		if err != nil {
			return options, err
		}
		options.Request = request
		flags = remaining
	}
	var period periodFlags
	seen, err := parseFlags(flags, &options, &period)
	if err != nil {
		return options, err
	}
	// Явно указанный файл настроек обязателен; отсутствие стандартного .env допустимо.
	options.ExplicitEnv = seen["env-file"]
	if err := validateFlags(options, seen); err != nil {
		return options, err
	}
	if options.Mode != LokiMode {
		return options, nil
	}
	// Сначала вычисляем границы, затем проверяем готовый запрос общими правилами app.
	options.Request.Start, options.Request.End, err = period.resolve(now, seen)
	if err != nil {
		return options, err
	}
	return options, options.Request.Validate()
}

// parseCommand отделяет имя команды и обязательную метку values от остальных флагов.
func parseCommand(args []string) (app.Request, []string, error) {
	var request app.Request
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		return request, nil, ErrHelp
	}
	request.Command = app.Command(args[0])
	args = args[1:]
	switch request.Command {
	case app.Check, app.Labels, app.Projects, app.Logs, app.Query:
	case app.Values:
		if len(args) > 0 && (args[0] == "--help" || args[0] == "-h") {
			return request, nil, ErrHelp
		}
		if len(args) == 0 || strings.HasPrefix(args[0], "-") {
			return request, nil, errors.New("укажите метку: lokictl values app")
		}
		request.Label, args = args[0], args[1:]
	default:
		return request, nil, errors.New("неизвестная команда; используйте lokictl --help")
	}
	return request, args, nil
}

// parseFlags регистрирует только флаги выбранного режима: чужие параметры будут отклонены.
func parseFlags(args []string, options *Options, period *periodFlags) (map[string]bool, error) {
	flags := flag.NewFlagSet("lokictl", flag.ContinueOnError)
	// Стандартный парсер может напечатать значения аргументов; наружу даем свою диагностику.
	flags.SetOutput(io.Discard)
	flags.DurationVar(&options.Timeout, "timeout", 30*time.Second, "")
	if options.Mode == AnalyzeMode {
		flags.StringVar(&options.File, "file", "", "")
		flags.BoolVar(&options.AllOrders, "all-orders", false, "")
	} else {
		flags.StringVar(&options.EnvFile, "env-file", ".env", "")
	}
	if options.Mode == WatchMode {
		flags.BoolVar(&options.Once, "once", false, "")
		flags.BoolVar(&options.DryRun, "dry-run", false, "")
		flags.StringVar(&options.Request.Project, "project", "", "")
	}
	if options.Mode == LokiMode {
		flags.DurationVar(&period.since, "since", 15*time.Minute, "")
		flags.StringVar(&period.start, "start", "", "")
		flags.StringVar(&period.end, "end", "", "")
		flags.IntVar(&options.Request.Limit, "limit", 20, "")
		flags.StringVar(&options.Request.Project, "project", "", "")
		flags.StringVar(&options.Request.Expression, "query", "", "")
		flags.BoolVar(&options.Raw, "raw", false, "")
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil, ErrHelp
		}
		return nil, errors.New("неверные параметры; используйте lokictl --help")
	}
	if flags.NArg() != 0 {
		return nil, errors.New("лишние аргументы; параметры передаются после команды")
	}
	// Сохраняем факт передачи флага: значение по умолчанию не означает явный выбор пользователя.
	seen := make(map[string]bool)
	flags.Visit(func(f *flag.Flag) { seen[f.Name] = true })
	return seen, nil
}

// validateFlags проверяет сочетания флагов; содержимое запроса отдельно проверяет app.Request.
func validateFlags(options Options, seen map[string]bool) error {
	if options.Mode != AnalyzeMode && options.EnvFile == "" {
		return errors.New("путь --env-file не должен быть пустым")
	}
	if options.Timeout <= 0 || options.Timeout > 10*time.Minute {
		return errors.New("--timeout должен быть больше 0 и не более 10m")
	}
	if options.Mode == AnalyzeMode {
		if strings.TrimSpace(options.File) == "" {
			return errors.New("укажите файл: lokictl analyze --file examples/orders-analysis.txt")
		}
		return nil
	}
	if options.Mode == TelegramMode || options.Mode == TelegramChatsMode || options.Mode == DBStatusMode || options.Mode == DBCleanupMode {
		return nil
	}
	request := options.Request
	if options.Mode == WatchMode {
		if seen["project"] && (strings.TrimSpace(request.Project) == "" || len(request.Project) > 4096) {
			return errors.New("--project должен быть непустым и не длиннее 4096 байт")
		}
		return nil
	}
	if seen["limit"] && request.Command != app.Logs && request.Command != app.Query {
		return errors.New("--limit применяется только к logs/query")
	}
	if seen["project"] && (request.Command != app.Logs || strings.TrimSpace(request.Project) == "") {
		return errors.New("непустой --project применяется только к logs")
	}
	if seen["query"] && request.Command != app.Query {
		return errors.New("--query применяется только к команде query")
	}
	return nil
}

// periodFlags хранит исходный выбор периода до преобразования в две даты UTC.
type periodFlags struct {
	since time.Duration
	start string
	end   string
}

// resolve принимает либо длительность до now, либо полную пару дат с часовым поясом.
func (p periodFlags) resolve(now time.Time, seen map[string]bool) (time.Time, time.Time, error) {
	if !seen["start"] && !seen["end"] {
		if p.since <= 0 || p.since > 24*time.Hour {
			return time.Time{}, time.Time{}, errors.New("--since должен быть больше 0 и не более 24h")
		}
		return now.Add(-p.since).UTC(), now.UTC(), nil
	}
	// Нельзя смешивать способы задания периода или угадывать одну отсутствующую границу.
	if !seen["start"] || !seen["end"] || seen["since"] {
		return time.Time{}, time.Time{}, errors.New("используйте --since либо пару --start и --end")
	}
	start, err := time.Parse(time.RFC3339Nano, p.start)
	if err != nil {
		return time.Time{}, time.Time{}, errors.New("--start должен быть датой RFC3339 с часовым поясом")
	}
	end, err := time.Parse(time.RFC3339Nano, p.end)
	if err != nil {
		return time.Time{}, time.Time{}, errors.New("--end должен быть датой RFC3339 с часовым поясом")
	}
	return start.UTC(), end.UTC(), nil
}

const helpText = `lokictl — получение логов, анализ заказов и проверка Telegram

Команды:
  lokictl check                    Проверить токен и доступ к Loki
  lokictl labels                   Получить названия меток
  lokictl values app               Получить значения выбранной метки
  lokictl projects                 Получить проекты (метка app по умолчанию)
  lokictl logs                     Получить страницу логов sds-orders
  lokictl query --query '{app="sds-orders"}'   Выполнить свой запрос LogQL
  lokictl telegram-check           Проверить токен бота и показать его имя и ID
  lokictl telegram-chats           Найти ID чатов в обновлениях бота
  lokictl analyze --file PATH      Разобрать сохраненный ответ Loki без сети
  lokictl watch                    Следить за логами и отправлять сводки в Telegram
  lokictl db-status                Очистить старые записи и показать статистику SQLite
  lokictl db-cleanup               Выполнить очистку SQLite вручную

Параметры после команды:
  --since 15m                     Период до текущего момента, максимум 24h
  --start RFC3339 --end RFC3339    Явный период с часовым поясом вместо --since
  --limit 20                      Записей на страницу для logs/query (1..100000)
  --project sds-orders            Проект для logs или watch
  --query EXPRESSION              Выражение только для команды query
  --raw                           Исходный JSON, включая чувствительные данные
  --file PATH                     Ответ Loki JSON или экспорт Grafana TXT для analyze
  --all-orders                    Показать все заказы; по умолчанию до 10 подробных историй
  --once                          Только watch: один цикл и завершение
  --dry-run                       Только watch: показать сообщения без отправки в Telegram
  --timeout 30s                   Тайм-аут операции; для watch — одного цикла
  --env-file .env                 Файл настроек; переменные окружения приоритетнее
  --help                          Эта справка

Для команд Loki добавьте GRAFANA_TOKEN в .env или окружение.
Для telegram-check и telegram-chats нужен TELEGRAM_BOT_TOKEN от @BotFather.
telegram-check принимает --env-file и --timeout; выполняет один getMe и завершается.
telegram-chats принимает --env-file и --timeout; чаты видны после сообщения боту.
watch использует WATCH_* из .env; для отправки нужны TELEGRAM_BOT_TOKEN и TELEGRAM_CHAT_ID.
watch --once --dry-run проверяет один цикл без отправки сообщений.
watch сохраняет исходные логи в WATCH_DB_FILE (local/loki.db) за последние 48 часов.
Состояние уведомлений хранится отдельно в JSON. При выключенной программе очистка не работает.
db-status и db-cleanup создают базу при отсутствии и удаляют записи старше 48 часов.
Обе команды принимают --env-file и --timeout; токены не нужны.
analyze принимает --file, --timeout и --all-orders; не читает .env и не требует токенов.
Файл ограничен 10 МиБ и 100000 записями; сводка всегда учитывает все записи файла.
analyze показывает только имеющиеся события; полнота периода файла неизвестна.
Токен передается Grafana по HTTPS. Пароль и браузерная сессия не используются.
Без --raw команды logs/query показывают только количество и время событий.
Коды завершения: 0 — успех; 1 — ошибка; 2 — достигнут лимит страницы.
`

// PrintHelp пишет справку в переданный поток, поэтому запуск и тесты управляют выводом сами.
func PrintHelp(output io.Writer) { fmt.Fprint(output, helpText) }
