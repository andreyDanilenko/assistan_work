package telegram

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"loki-analyzer/internal/model"
)

// ReportBuilder получает только период: путь базы и анализатор передаёт main.
type ReportBuilder func(context.Context, time.Time, time.Time) ([]byte, error)

type ReportBot interface {
	GetMe(context.Context) (model.BotInfo, error)
	GetUpdates(context.Context, int64) ([]model.TelegramUpdate, error)
	SendMessage(context.Context, int64, string) error
	SendDocument(context.Context, int64, string, []byte) error
}

type ReportConfig struct {
	ChatID     int64
	Scope      string
	CursorFile string
	Timeout    time.Duration
}

// reportCursor содержит только позицию очереди и ограничение частоты, без текстов и токенов.
type reportCursor struct {
	BotID       int64     `json:"bot_id"`
	ChatID      int64     `json:"chat_id"`
	Offset      int64     `json:"offset"`
	LastRequest time.Time `json:"last_request"`
}

// RunReports обслуживает команды, пока работает watch. Ошибка Telegram не останавливает сбор логов.
// getUpdates подтверждает сообщения бота: параллельный получатель обновлений недопустим.
func RunReports(ctx context.Context, cfg ReportConfig, bot ReportBot, build ReportBuilder, diagnostic io.Writer) {
	var identity model.BotInfo
	var cursor reportCursor
	ready := false
	warned := false
	for ctx.Err() == nil {
		delay := 2 * time.Second
		requestCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
		var err error
		if !ready {
			identity, err = bot.GetMe(requestCtx)
			if err == nil {
				cursor, err = readReportCursor(cfg.CursorFile, identity.ID, cfg.ChatID)
				ready = err == nil
			}
		}
		var updates []model.TelegramUpdate
		if err == nil {
			updates, err = bot.GetUpdates(requestCtx, cursor.Offset)
		}
		cancel()
		if err != nil {
			if !warned && ctx.Err() == nil {
				fmt.Fprintln(diagnostic, "Telegram /report: приём команд недоступен. Проверьте токен, отсутствие webhook и другого получателя обновлений.")
				warned = true
			}
			delay = 10 * time.Second
			var apiErr *APIError
			if errors.As(err, &apiErr) && apiErr.RetryAfter > delay {
				delay = apiErr.RetryAfter
			}
		} else {
			warned = false
			for _, update := range updates {
				if ctx.Err() != nil {
					return
				}
				if update.ID < cursor.Offset {
					continue
				}
				// Позицию сохраняем до отправки: при сбое не рассылаем повторно тот же файл.
				cursor.Offset = update.ID + 1
				now := time.Now().UTC()
				command := reportCommand(update, identity.Username, cfg.ChatID, now)
				start, end, callbackValid := callbackPeriod(update.Callback, identity.ID, cfg, now)
				allowed := (command != nil || callbackValid) && now.Sub(cursor.LastRequest) >= time.Minute
				if allowed {
					cursor.LastRequest = now
				}
				if err = writeReportCursor(cfg.CursorFile, cursor); err != nil {
					fmt.Fprintln(diagnostic, "Telegram /report: не удалось сохранить позицию команд; отчёт не отправлен.")
					answerReportButton(ctx, cfg, bot, update.Callback, "Не удалось сохранить запрос. Попробуйте позже.", diagnostic)
					ready = false
					break
				}
				if update.Callback != nil {
					status := "Кнопка недоступна: период устарел или относится к другому источнику."
					if callbackValid {
						status = "Отчёт уже запрошен. Повторите через минуту."
						if allowed {
							status = "Готовлю TXT с ошибками за выбранный период."
						}
					}
					answerReportButton(ctx, cfg, bot, update.Callback, status, diagnostic)
					if allowed && callbackValid {
						sendPeriodReport(ctx, cfg, bot, build, start, end, diagnostic)
					}
				} else if allowed {
					sendReport(ctx, cfg, bot, build, command, diagnostic)
				}
			}
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// Команды других чатов, других ботов, старые сообщения и ответы ботов игнорируются.
func reportCommand(update model.TelegramUpdate, username string, chatID int64, now time.Time) []string {
	message := update.Message
	if update.Callback != nil || message == nil || message.Chat.ID != chatID || message.From.IsBot || message.Date < now.Add(-5*time.Minute).Unix() || message.Date > now.Add(time.Minute).Unix() {
		return nil
	}
	fields := strings.Fields(message.Text)
	if len(fields) == 0 {
		return nil
	}
	command := strings.SplitN(fields[0], "@", 2)
	if command[0] != "/report" || len(command) == 2 && !strings.EqualFold(command[1], username) {
		return nil
	}
	return fields
}

// reportCallbackData хранит только границы периода и короткую привязку к источнику.
// Никаких токенов, ID заказов или логов в Telegram callback_data нет.
func reportCallbackData(scope string, start, end time.Time) (string, error) {
	if scope == "" || start.UnixNano() <= 0 || end.UnixNano() <= start.UnixNano() || !end.After(start) || end.Sub(start) > 48*time.Hour {
		return "", errors.New("report button requires a source and a valid period up to 48h")
	}
	sum := sha256.Sum256([]byte(scope))
	data := fmt.Sprintf("r:%x:%d:%d", sum[:4], start.UnixNano(), end.UnixNano())
	if len(data) > 64 {
		return "", errors.New("report button data exceeds Telegram limit")
	}
	return data, nil
}

func callbackPeriod(query *model.TelegramCallbackQuery, botID int64, cfg ReportConfig, now time.Time) (time.Time, time.Time, bool) {
	invalid := func() (time.Time, time.Time, bool) { return time.Time{}, time.Time{}, false }
	if query == nil || query.ID == "" || len(query.ID) > 256 || query.From.ID <= 0 || query.From.IsBot || query.Message == nil {
		return invalid()
	}
	message := query.Message
	// Пересланное, недоступное или чужое сообщение не даёт доступа к локальной базе.
	if message.Chat.ID != cfg.ChatID || message.ID <= 0 || message.Date <= 0 || !message.From.IsBot || message.From.ID != botID || message.Date < now.Add(-48*time.Hour).Unix() || message.Date > now.Add(time.Minute).Unix() {
		return invalid()
	}
	parts := strings.Split(query.Data, ":")
	if len(parts) != 4 || len(query.Data) > 64 || parts[0] != "r" {
		return invalid()
	}
	startNS, startErr := strconv.ParseInt(parts[2], 10, 64)
	endNS, endErr := strconv.ParseInt(parts[3], 10, 64)
	start, end := time.Unix(0, startNS).UTC(), time.Unix(0, endNS).UTC()
	if startErr != nil || endErr != nil || start.Before(now.Add(-48*time.Hour)) || end.After(now) {
		return invalid()
	}
	expected, err := reportCallbackData(cfg.Scope, start, end)
	if err != nil || expected != query.Data {
		return invalid()
	}
	return start, end, true
}

func answerReportButton(ctx context.Context, cfg ReportConfig, bot ReportBot, query *model.TelegramCallbackQuery, text string, diagnostic io.Writer) {
	if query == nil || query.ID == "" || len(query.ID) > 256 {
		return
	}
	callbackBot, ok := bot.(interface {
		AnswerCallbackQuery(context.Context, string, string) error
	})
	if !ok {
		return
	}
	requestCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	if callbackBot.AnswerCallbackQuery(requestCtx, query.ID, text) != nil && ctx.Err() == nil {
		fmt.Fprintln(diagnostic, "Telegram /report: статус нажатия не подтверждён.")
	}
}

func sendReport(ctx context.Context, cfg ReportConfig, bot ReportBot, build ReportBuilder, command []string, diagnostic io.Writer) {
	period := time.Hour
	var err error
	if len(command) == 2 {
		period, err = time.ParseDuration(command[1])
	}
	if len(command) > 2 || err != nil || period < time.Minute || period > 48*time.Hour {
		sendReportReply(ctx, cfg, bot, "Отчёт по ошибкам: /report — за час; /report 1h или /report 2h. Можно указать другой период от 1m до 48h, например /report 15m.", diagnostic)
		return
	}
	end := time.Now().UTC()
	sendPeriodReport(ctx, cfg, bot, build, end.Add(-period), end, diagnostic)
}

func sendPeriodReport(ctx context.Context, cfg ReportConfig, bot ReportBot, build ReportBuilder, start, end time.Time, diagnostic io.Writer) {
	requestCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	// Границы кнопки неизменны; поздно сохранённые логи этого периода попадут в расчёт.
	document, err := build(requestCtx, start, end)
	if err != nil {
		fmt.Fprintln(diagnostic, "Telegram /report: чтение или анализ базы не завершены; проверьте файл базы, тайм-аут и объём периода.")
		sendReportReply(ctx, cfg, bot, "Не удалось собрать отчёт из локальной базы. Попробуйте меньший период: /report 15m. Подробности проверки — в терминале компьютера.", diagnostic)
		return
	}
	filename := "errors-report-" + start.Format("20060102-150405") + "--" + end.Format("20060102-150405") + ".txt"
	if bot.SendDocument(requestCtx, cfg.ChatID, filename, document) != nil && ctx.Err() == nil {
		fmt.Fprintln(diagnostic, "Telegram /report: доставка не подтверждена; автоматического повтора нет. Повторите запрос через минуту.")
	}
}

func sendReportReply(ctx context.Context, cfg ReportConfig, bot ReportBot, reply string, diagnostic io.Writer) {
	// Ошибка сборки могла исчерпать её тайм-аут; ответу выделяем отдельный запрос.
	requestCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	if bot.SendMessage(requestCtx, cfg.ChatID, reply) != nil && ctx.Err() == nil {
		fmt.Fprintln(diagnostic, "Telegram /report: доставка ответа не подтверждена.")
	}
}

func readReportCursor(path string, botID, chatID int64) (reportCursor, error) {
	cursor := reportCursor{BotID: botID, ChatID: chatID}
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return cursor, nil
	}
	if err != nil {
		return cursor, err
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(body) > 4096 {
		return cursor, errors.New("invalid report cursor")
	}
	var saved reportCursor
	if json.Unmarshal(body, &saved) != nil || saved.Offset < 0 {
		return cursor, errors.New("invalid report cursor")
	}
	if saved.BotID == botID && saved.ChatID == chatID {
		cursor = saved
	}
	return cursor, nil
}

func writeReportCursor(path string, cursor reportCursor) error {
	body, err := json.Marshal(cursor)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".report-cursor-*")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if _, err = file.Write(body); err != nil {
		file.Close()
		return err
	}
	if err = file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
