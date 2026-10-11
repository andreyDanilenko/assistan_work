// Точка входа: здесь создаются компоненты и передаются их зависимости.
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"loki-analyzer/internal/analyzer"
	"loki-analyzer/internal/app"
	"loki-analyzer/internal/cli"
	"loki-analyzer/internal/config"
	"loki-analyzer/internal/input"
	"loki-analyzer/internal/loki"
	"loki-analyzer/internal/model"
	"loki-analyzer/internal/monitor"
	"loki-analyzer/internal/report"
	"loki-analyzer/internal/storage"
	"loki-analyzer/internal/telegram"
	"loki-analyzer/internal/utils"
)

func main() {
	// Ctrl+C отменяет общий контекст; выполняемый запрос получает ту же отмену.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	// os.Exit не вызывает defer, поэтому освобождаем обработчик сигнала заранее.
	stop()
	os.Exit(code)
}

// run выбирает сценарий и соединяет его компоненты. Код возврата получает оболочка.
func run(ctx context.Context, args []string, output, diagnostic io.Writer) int {
	// 1. Разбираем команду до чтения настроек: справка должна работать без токенов.
	options, err := cli.Parse(args, time.Now())
	if errors.Is(err, cli.ErrHelp) {
		cli.PrintHelp(output)
		return 0
	}
	if err != nil {
		cli.WriteError(diagnostic, "Ошибка", err)
		return 1
	}
	if options.Mode == cli.AnalyzeMode {
		// 2. Передаем сервису источник записей и анализатор.
		// Этот сценарий завершается здесь: сеть и .env ему не нужны.
		service := app.NewAnalysisService(input.NewLokiFileSource(), analyzer.New())
		return cli.RunAnalysis(ctx, service, options, output, diagnostic)
	}
	// 3. Читаем настройки один раз и дальше передаем их явно.
	settings, err := config.Load(config.Options{
		EnvFile: options.EnvFile, ExplicitEnv: options.ExplicitEnv,
	}, os.LookupEnv)
	if err != nil {
		cli.WriteError(diagnostic, "Ошибка", err)
		return 1
	}
	if options.Mode == cli.DBStatusMode || options.Mode == cli.DBCleanupMode {
		return runDatabase(ctx, settings.Watch.DBFile, options.Timeout, output, diagnostic)
	}
	// 4. Loki и Telegram получают готовый HTTP-клиент с едиными правилами безопасности.
	httpClient := utils.NewHTTPClient(options.Timeout)
	if options.Mode == cli.TelegramMode {
		return initializeTelegram(ctx, settings.Telegram, httpClient, options.Timeout, output, diagnostic)
	}
	if options.Mode == cli.TelegramChatsMode {
		return discoverTelegramChats(ctx, settings.Telegram, httpClient, options.Timeout, output, diagnostic)
	}
	// 5. Создаем источник Loki. Сервису передаем источник и настройки проекта, без токена.
	source, err := newSource(settings, options.Timeout, httpClient)
	if err != nil {
		cli.WriteError(diagnostic, "Ошибка настройки", err)
		return 1
	}
	if options.Mode == cli.WatchMode {
		return runMonitor(ctx, settings, options, source, httpClient, output, diagnostic)
	}
	service := app.New(app.Config{
		DefaultProject: settings.Logs.Project,
		ProjectLabel:   settings.Logs.ProjectLabel,
	}, source)
	// 6. CLI вызывает готовый сервис и преобразует его ответ в текст и код завершения.
	return cli.Run(ctx, service, options, output, diagnostic)
}

// runMonitor соединяет получение логов, правила мониторинга и отправку сообщений.
// --dry-run не создает Telegram-клиент и не изменяет состояние реальных отправок.
func runMonitor(ctx context.Context, settings config.Config, options cli.Options, source monitor.Source, httpClient telegram.HTTPClient, output, diagnostic io.Writer) int {
	diagnostic = &lockedWriter{Writer: diagnostic}
	cfg, err := monitorConfig(settings, options)
	if err != nil {
		cli.WriteError(diagnostic, "Ошибка настроек watch", err)
		return 1
	}
	// Названия передаются компонентам явно; анализ и хранение по-прежнему опираются на ID.
	cfg.ResellerNames, err = config.LoadResellers(settings.Logs.ResellerFile)
	if err != nil {
		cli.WriteError(diagnostic, "Ошибка справочника реселлеров", err)
		return 1
	}
	var sender monitor.Sender
	var bot *telegram.Client
	var archive monitor.Archive
	if !cfg.DryRun {
		bot, err = telegram.New(telegram.Config{Token: settings.Telegram.Token}, httpClient)
		if err != nil {
			cli.WriteError(diagnostic, "Ошибка Telegram", err)
			return 1
		}
		sender = bot
		// База и состояние уведомлений — разные файлы; dry-run не открывает ни один.
		dbPath, dbErr := filepath.Abs(settings.Watch.DBFile)
		statePath, stateErr := filepath.Abs(cfg.StateFile)
		if dbErr != nil || stateErr != nil || sameFilePath(dbPath, statePath) || sameFilePath(dbPath, statePath+".commands.json") {
			fmt.Fprintln(diagnostic, "WATCH_DB_FILE, WATCH_STATE_FILE и файл .commands.json должны указывать на разные файлы.")
			return 1
		}
		openCtx, cancel := context.WithTimeout(ctx, options.Timeout)
		database, err := storage.Open(openCtx, settings.Watch.DBFile)
		cancel()
		if err != nil {
			cli.WriteError(diagnostic, "Ошибка SQLite", err)
			return 1
		}
		defer database.Close()
		archive = database
	}
	// Пользовательское правило критичности одинаково для сводки и подробного отчёта.
	// Include/Exclude влияют только на повод отправки, а не на содержимое отчёта.
	var reportFilter monitor.Filter
	if cfg.Critical != "" {
		reportFilter.Critical, err = regexp.Compile(cfg.Critical)
		if err != nil {
			cli.WriteError(diagnostic, "Ошибка правила критичности", err)
			return 1
		}
	}
	// Один расчёт периода используют и автоматическая сводка, и скачивание TXT.
	// Немедленные уведомления используют локальное окно для своих фильтров.
	cfg.ReadWindow = func(ctx context.Context, start, end time.Time) ([]model.LogRecord, error) {
		records, _, err := storage.ReadRange(ctx, settings.Watch.DBFile, storage.Query{
			SourceID: cfg.SourceID, Project: cfg.Project, Start: start, End: end,
		})
		return records, err
	}
	cfg.BuildSnapshot = func(ctx context.Context, start, end time.Time) (monitor.Snapshot, error) {
		return databaseSnapshot(ctx, settings.Watch.DBFile, storage.Query{
			SourceID: cfg.SourceID, Project: cfg.Project, Start: start, End: end,
		}, reportFilter)
	}
	worker, err := monitor.New(cfg, source, sender, archive, output, diagnostic)
	if err != nil {
		cli.WriteError(diagnostic, "Ошибка настроек watch", err)
		return 1
	}
	if len(cfg.ResellerNames) > 0 {
		fmt.Fprintf(output, "Справочник реселлеров: %d названий.\n", len(cfg.ResellerNames))
	}
	fmt.Fprintf(output, "Мониторинг %q: сбор каждые %s, начальная история %s, отчет %s. Остановка: Ctrl+C.\n", cfg.Project, cfg.Interval, cfg.Window, cfg.ReportInterval)
	if cfg.ReportOnly {
		fmt.Fprintln(output, "Telegram: только периодические сводки заказов; новые ошибки между сводками отдельными сообщениями не отправляются.")
	}
	if cfg.DryRun {
		fmt.Fprintln(output, "Предпросмотр: сообщения не отправляются, база и состояние не изменяются.")
	} else {
		fmt.Fprintf(output, "SQLite: %q. Храним логи за последние 48 часов; старые удаляются каждый цикл.\n", settings.Watch.DBFile)
	}
	if cfg.DryRun || options.Once {
		err = worker.Run(ctx, options.Once)
	} else {
		// По сохранённым записям считаем текущие ошибки и готовим сгруппированный отчёт.
		buildReport := func(ctx context.Context, start, end time.Time) ([]byte, error) {
			snapshot, err := cfg.BuildSnapshot(ctx, start, end)
			if err != nil {
				return nil, err
			}
			var text bytes.Buffer
			if err := report.WriteDatabase(&text, snapshot, cfg.Project, start, end, cfg.ResellerNames); err != nil {
				return nil, err
			}
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return text.Bytes(), nil
		}
		fmt.Fprintln(output, "Telegram: кнопки TXT за период, 1 час и 2 часа; /report [1h|2h|24h] — отчёт до текущего момента.")
		err = worker.RunWithCommands(ctx, func(ctx context.Context) {
			telegram.RunReports(ctx, telegram.ReportConfig{
				ChatID: cfg.ChatID, CursorFile: cfg.StateFile + ".commands.json", Timeout: cfg.Timeout,
				Scope: cfg.SourceID + "|" + cfg.Project,
			}, bot, buildReport, diagnostic)
		})
	}
	if err != nil && !errors.Is(err, context.Canceled) {
		cli.WriteError(diagnostic, "Монитор остановлен", err)
		return 1
	}
	return 0
}

// databaseSnapshot читает период отдельно от истории реселлеров: прошлые ошибки
// помогают установить принадлежность, но не увеличивают текущие счётчики.
func databaseSnapshot(ctx context.Context, path string, query storage.Query, filter monitor.Filter) (monitor.Snapshot, error) {
	records, coverage, err := storage.ReadRange(ctx, path, query)
	if err != nil {
		return monitor.Snapshot{}, err
	}
	snapshot := monitor.Analyze(records, filter)
	snapshot.Coverage = coverage
	orderIDs := make([]string, 0, len(snapshot.Issues))
	for _, issue := range snapshot.Issues {
		if issue.OrderID != "" && !snapshot.IsResolved(issue) {
			orderIDs = append(orderIDs, issue.OrderID)
		}
	}
	history, err := storage.LookupResellers(ctx, path, query, orderIDs)
	if err != nil {
		return monitor.Snapshot{}, err
	}
	monitor.EnrichResellers(&snapshot, history)
	return snapshot, ctx.Err()
}

// Обслуживание базы работает без Loki и Telegram: сначала удаляем старое, затем считаем остаток.
func runDatabase(ctx context.Context, path string, timeout time.Duration, output, diagnostic io.Writer) int {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	database, err := storage.Open(ctx, path)
	if err != nil {
		cli.WriteError(diagnostic, "Ошибка SQLite", err)
		return 1
	}
	defer database.Close()
	deleted, err := database.Prune(ctx, time.Now().UTC())
	if err != nil {
		cli.WriteError(diagnostic, "Ошибка очистки SQLite", err)
		return 1
	}
	stats, err := database.Stats(ctx)
	if err != nil {
		cli.WriteError(diagnostic, "Ошибка статистики SQLite", err)
		return 1
	}
	fmt.Fprintf(output, "SQLite: %q\nХранение: 48 часов. Удалено старых строк: %d.\nСтрок в базе: %d | Событий с учетом повторов: %d\n", path, deleted, stats.Rows, stats.Records)
	if stats.Rows > 0 {
		fmt.Fprintf(output, "Первое: %s\nПоследнее: %s\n", stats.Oldest.Format(time.RFC3339Nano), stats.Newest.Format(time.RFC3339Nano))
	}
	return 0
}

func monitorConfig(settings config.Config, options cli.Options) (monitor.Config, error) {
	w := settings.Watch
	cfg := monitor.Config{
		Project: settings.Logs.Project, StateFile: w.StateFile, Timeout: options.Timeout,
		SourceID: settings.Grafana.URL + "|" + settings.Grafana.DataSourceUID + "|" + settings.Grafana.OrgID,
		Include:  w.Include, Exclude: w.Exclude, Critical: w.CriticalPattern, DryRun: options.DryRun,
	}
	if options.Request.Project != "" {
		cfg.Project = options.Request.Project
	}
	for _, field := range []struct {
		name, value string
		target      *time.Duration
	}{
		{"WATCH_INTERVAL", w.Interval, &cfg.Interval},
		{"WATCH_WINDOW", w.Window, &cfg.Window},
		{"WATCH_REPORT_INTERVAL", w.ReportInterval, &cfg.ReportInterval},
		{"WATCH_COOLDOWN", w.Cooldown, &cfg.Cooldown},
		{"WATCH_NO_LOGS_AFTER", w.NoLogsAfter, &cfg.NoLogsAfter},
	} {
		value, err := time.ParseDuration(field.value)
		if err != nil {
			return cfg, fmt.Errorf("%s должен быть длительностью, например 2m или 1h", field.name)
		}
		*field.target = value
	}
	var err error
	cfg.ReportOnly, err = strconv.ParseBool(w.ReportOnly)
	if err != nil {
		return cfg, errors.New("WATCH_REPORT_ONLY должен быть true или false")
	}
	cfg.ErrorThreshold, err = strconv.Atoi(w.ErrorThreshold)
	if err != nil {
		return cfg, errors.New("WATCH_ERROR_THRESHOLD должен быть целым числом")
	}
	if !cfg.DryRun {
		cfg.ChatID, err = strconv.ParseInt(settings.Telegram.ChatID, 10, 64)
		if err != nil || cfg.ChatID == 0 {
			return cfg, errors.New("укажите числовой TELEGRAM_CHAT_ID; получить его можно командой telegram-chats")
		}
	}
	return cfg, nil
}

func discoverTelegramChats(ctx context.Context, settings config.Telegram, httpClient telegram.HTTPClient, timeout time.Duration, output, diagnostic io.Writer) int {
	bot, err := telegram.New(telegram.Config{Token: settings.Token}, httpClient)
	if err != nil {
		cli.WriteError(diagnostic, "Ошибка Telegram", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	chats, err := bot.DiscoverChats(ctx)
	if err != nil {
		cli.WriteError(diagnostic, "Не удалось получить чаты", err)
		return 1
	}
	if len(chats) == 0 {
		fmt.Fprintln(output, "Чаты не найдены. Добавьте бота в группу и отправьте /start@имя_бота либо /start в личном чате, затем повторите команду. Другой получатель обновлений мог уже забрать сообщение.")
		return 0
	}
	for _, chat := range chats {
		fmt.Fprintf(output, "chat_id: %d | Тип: %q | Название: %q | user_id: %d\n", chat.ID, chat.Type, chat.Title, chat.UserID)
	}
	fmt.Fprintln(output, "Добавьте ID нужной группы в TELEGRAM_CHAT_ID. Обновления не подтверждены; сообщения не отправлялись.")
	return 0
}

// newSource выбирает настройки подключения из общего конфига; сетевых запросов здесь нет.
func newSource(settings config.Config, timeout time.Duration, httpClient loki.HTTPClient) (*loki.Client, error) {
	if err := settings.ValidateLoki(); err != nil {
		return nil, err
	}
	clientConfig := loki.DefaultConfig()
	// Токен выдан Grafana, поэтому обращаемся к Loki через прокси выбранного источника.
	clientConfig.URL = strings.TrimRight(settings.Grafana.URL, "/") +
		"/api/datasources/proxy/uid/" + settings.Grafana.DataSourceUID
	clientConfig.Token = settings.Grafana.Token
	clientConfig.OrgID = settings.Grafana.OrgID
	clientConfig.ProjectLabel = settings.Logs.ProjectLabel
	clientConfig.Timeout = timeout
	return loki.New(clientConfig, httpClient)
}

// initializeTelegram проверяет доступ через getMe и выводит данные бота.
// Один проверочный запрос пока не требует отдельного сервиса приложения.
func initializeTelegram(
	ctx context.Context, settings config.Telegram, httpClient telegram.HTTPClient,
	timeout time.Duration, output, diagnostic io.Writer,
) int {
	// Конструктор проверяет токен локально; запрос выполняет только GetMe ниже.
	bot, err := telegram.New(telegram.Config{Token: settings.Token}, httpClient)
	if err != nil {
		cli.WriteError(diagnostic, "Ошибка настройки Telegram", err)
		return 1
	}
	// Проверка ограничена тайм-аутом и может быть отменена общим контекстом.
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	info, err := bot.GetMe(ctx)
	if err != nil {
		cli.WriteError(diagnostic, "Не удалось подключиться к Telegram", err)
		return 1
	}
	if err := cli.PrintBotInfo(output, info); err != nil {
		fmt.Fprintln(diagnostic, "Не удалось вывести информацию о Telegram-боте.")
		return 1
	}
	return 0
}

// Монитор и обработчик команд могут одновременно писать диагностику в один поток.
type lockedWriter struct {
	io.Writer
	mu sync.Mutex
}

func (w *lockedWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.Writer.Write(data)
}

func sameFilePath(left, right string) bool {
	if left == right {
		return true
	}
	leftInfo, leftErr := os.Stat(left)
	rightInfo, rightErr := os.Stat(right)
	return leftErr == nil && rightErr == nil && os.SameFile(leftInfo, rightInfo)
}
