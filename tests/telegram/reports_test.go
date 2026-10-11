package telegram_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"loki-analyzer/internal/model"
	"loki-analyzer/internal/telegram"
)

type reportBot struct {
	updates        []model.TelegramUpdate
	offsets        []int64
	documents      [][]byte
	filenames      []string
	messages       []string
	chats          []int64
	cancel         context.CancelFunc
	answers        []string
	cancelOnAnswer bool
}

func (b *reportBot) GetMe(context.Context) (model.BotInfo, error) {
	return model.BotInfo{ID: 42, IsBot: true, Username: "orders_bot"}, nil
}
func (b *reportBot) GetUpdates(ctx context.Context, offset int64) ([]model.TelegramUpdate, error) {
	b.offsets = append(b.offsets, offset)
	if len(b.offsets) > 1 {
		b.cancel()
		return nil, context.Canceled
	}
	return b.updates, nil
}
func (b *reportBot) SendMessage(ctx context.Context, chat int64, text string) error {
	b.messages = append(b.messages, text)
	b.chats = append(b.chats, chat)
	b.cancel()
	return nil
}
func (b *reportBot) AnswerCallbackQuery(ctx context.Context, id, text string) error {
	b.answers = append(b.answers, id+": "+text)
	if b.cancelOnAnswer {
		b.cancel()
	}
	return nil
}
func (b *reportBot) SendDocument(ctx context.Context, chat int64, name string, data []byte) error {
	if !strings.HasSuffix(name, ".txt") {
		return errors.New("not TXT")
	}
	b.documents = append(b.documents, data)
	b.filenames = append(b.filenames, name)
	b.chats = append(b.chats, chat)
	b.cancel()
	return nil
}
func reportUpdate(id, chat int64, text string) model.TelegramUpdate {
	message := &model.TelegramMessage{ID: id, Date: time.Now().Unix(), Text: text}
	message.Chat.ID = chat
	return model.TelegramUpdate{ID: id, Message: message}
}
func reportConfig(t *testing.T) telegram.ReportConfig {
	return telegram.ReportConfig{ChatID: -42, Scope: "source|orders", CursorFile: filepath.Join(t.TempDir(), "commands.json"), Timeout: time.Second}
}

func TestReportCommandOnlyConfiguredChatAndCorrectMention(t *testing.T) {
	cfg := reportConfig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	old := reportUpdate(3, cfg.ChatID, "/report")
	old.Message.Date = time.Now().Add(-10 * time.Minute).Unix()
	fromBot := reportUpdate(4, cfg.ChatID, "/report")
	fromBot.Message.From.IsBot = true
	bot := &reportBot{cancel: cancel, updates: []model.TelegramUpdate{
		reportUpdate(1, 42, "/report"), reportUpdate(2, cfg.ChatID, "/report@another_bot"), old, fromBot,
		{ID: 5}, reportUpdate(6, cfg.ChatID, "/report@orders_bot 15m"),
	}}
	calls := 0
	build := func(ctx context.Context, start, end time.Time) ([]byte, error) {
		calls++
		if end.Sub(start) != 15*time.Minute {
			t.Fatalf("wrong period %s", end.Sub(start))
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("report lacks timeout")
		}
		return []byte("Отчёт по заказам"), nil
	}
	var diagnostic bytes.Buffer
	telegram.RunReports(ctx, cfg, bot, build, &diagnostic)
	if calls != 1 || len(bot.documents) != 1 || len(bot.messages) != 0 || len(bot.chats) != 1 || bot.chats[0] != cfg.ChatID {
		t.Fatalf("wrong recipient/count: calls=%d bot=%+v diag=%s", calls, bot, diagnostic.String())
	}
	data, err := os.ReadFile(cfg.CursorFile)
	if err != nil {
		t.Fatal(err)
	}
	var cursor struct{ Offset int64 }
	if json.Unmarshal(data, &cursor) != nil || cursor.Offset != 7 {
		t.Fatalf("cursor not committed: %s", data)
	}
	info, _ := os.Stat(cfg.CursorFile)
	if info.Mode().Perm()&0077 != 0 {
		t.Fatal("cursor is not private")
	}
}

func TestReportCursorAndCooldownSurviveRestart(t *testing.T) {
	cfg := reportConfig(t)
	for run := 0; run < 2; run++ {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		bot := &reportBot{cancel: cancel, updates: []model.TelegramUpdate{reportUpdate(10, cfg.ChatID, "/report"), reportUpdate(11, cfg.ChatID, "/report 24h")}}
		build := func(ctx context.Context, start, end time.Time) ([]byte, error) {
			if end.Sub(start) != time.Hour {
				t.Fatal("default period is not one hour")
			}
			return []byte("report"), nil
		}
		telegram.RunReports(ctx, cfg, bot, build, &bytes.Buffer{})
		cancel()
		if run == 0 && len(bot.documents) != 1 {
			t.Fatalf("expected one document, got %d", len(bot.documents))
		}
		if run == 1 && (bot.offsets[0] != 11 || len(bot.documents) != 0) {
			t.Fatalf("old command replayed: %+v", bot)
		}
	}
}

func TestReportInvalidPeriodAndFailedBuildDoNotSendDocument(t *testing.T) {
	for _, command := range []string{"/report 0m", "/report 49h", "/report 15m extra", "/report 24h"} {
		t.Run(command, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			cfg := reportConfig(t)
			bot := &reportBot{cancel: cancel, updates: []model.TelegramUpdate{reportUpdate(1, cfg.ChatID, command)}}
			calls := 0
			build := func(context.Context, time.Time, time.Time) ([]byte, error) {
				calls++
				return nil, errors.New("secret original payload")
			}
			var diagnostic bytes.Buffer
			telegram.RunReports(ctx, cfg, bot, build, &diagnostic)
			if len(bot.documents) != 0 || len(bot.messages) != 1 {
				t.Fatalf("expected one safe error reply: %+v", bot)
			}
			if command == "/report 24h" && calls != 1 || command != "/report 24h" && calls != 0 {
				t.Fatalf("invalid command invoked builder: %d", calls)
			}
			if strings.Contains(bot.messages[0]+diagnostic.String(), "secret") {
				t.Fatal("build error leaked")
			}
		})
	}
}

func TestReportOneAndTwoHourCommands(t *testing.T) {
	for _, period := range []time.Duration{time.Hour, 2 * time.Hour} {
		t.Run(period.String(), func(t *testing.T) {
			cfg := reportConfig(t)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			bot := &reportBot{cancel: cancel, updates: []model.TelegramUpdate{reportUpdate(1, cfg.ChatID, "/report "+period.String())}}
			calls := 0
			telegram.RunReports(ctx, cfg, bot, func(_ context.Context, start, end time.Time) ([]byte, error) {
				calls++
				if end.Sub(start) != period {
					t.Fatalf("expected %s, got %s", period, end.Sub(start))
				}
				return []byte("Отчёт по ошибкам"), nil
			}, &bytes.Buffer{})
			if calls != 1 || len(bot.documents) != 1 {
				t.Fatalf("report not delivered: calls=%d documents=%d", calls, len(bot.documents))
			}
		})
	}
}

func TestReportButtonsStayAnchoredToOriginalSummary(t *testing.T) {
	// Пользователь нажал кнопку через полчаса: конец отчёта остаётся временем сводки.
	end := time.Now().Add(-30 * time.Minute).UTC()
	start := end.Add(-15 * time.Minute)
	scope := "source|orders"
	var payload struct {
		Markup struct {
			Buttons [][]struct {
				Data string `json:"callback_data"`
			} `json:"inline_keyboard"`
		} `json:"reply_markup"`
	}
	client, _ := telegram.New(telegram.Config{Token: testToken}, fakeHTTPClient(func(req *http.Request) (*http.Response, error) {
		if json.NewDecoder(req.Body).Decode(&payload) != nil {
			t.Fatal("invalid message payload")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"ok":true,"result":{"message_id":100,"chat":{"id":-42}}}`))}, nil
	}))
	if err := client.SendMessageWithReport(context.Background(), -42, "Сводка", scope, start, end); err != nil {
		t.Fatal(err)
	}
	if len(payload.Markup.Buttons) != 2 || len(payload.Markup.Buttons[0]) != 1 || len(payload.Markup.Buttons[1]) != 2 {
		t.Fatal("missing period buttons")
	}
	buttons := append(payload.Markup.Buttons[0], payload.Markup.Buttons[1]...)
	for i, duration := range []time.Duration{15 * time.Minute, time.Hour, 2 * time.Hour} {
		t.Run(duration.String(), func(t *testing.T) {
			cfg := reportConfig(t)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			update := reportCallback(1, cfg, start, end)
			update.Callback.Data = buttons[i].Data
			update.Callback.Message.Date = end.Unix()
			bot := &reportBot{cancel: cancel, updates: []model.TelegramUpdate{update}}
			calls := 0
			telegram.RunReports(ctx, cfg, bot, func(_ context.Context, gotStart, gotEnd time.Time) ([]byte, error) {
				calls++
				if !gotStart.Equal(end.Add(-duration)) || !gotEnd.Equal(end) {
					t.Fatalf("clicked period shifted: %v — %v", gotStart, gotEnd)
				}
				return []byte("Отчёт по ошибкам"), nil
			}, &bytes.Buffer{})
			if calls != 1 || len(bot.documents) != 1 {
				t.Fatalf("button not delivered: calls=%d documents=%d", calls, len(bot.documents))
			}
			wantName := "errors-report-" + end.Add(-duration).Format("20060102-150405") + "--" + end.Format("20060102-150405") + ".txt"
			if bot.filenames[0] != wantName {
				t.Fatalf("filename does not identify selected period: %q", bot.filenames[0])
			}
		})
	}
}

func reportCallback(id int64, cfg telegram.ReportConfig, start, end time.Time) model.TelegramUpdate {
	sum := sha256.Sum256([]byte(cfg.Scope))
	message := &model.TelegramMessage{ID: 100, Date: time.Now().Unix()}
	message.Chat.ID = cfg.ChatID
	message.From.ID = 42
	message.From.IsBot = true
	query := &model.TelegramCallbackQuery{ID: "click-123", Data: fmt.Sprintf("r:%x:%d:%d", sum[:4], start.UnixNano(), end.UnixNano()), Message: message}
	query.From.ID = 321
	return model.TelegramUpdate{ID: id, Callback: query}
}

func TestReportCallbackBuildsExactPeriodAndCommitsBeforeDelivery(t *testing.T) {
	cfg := reportConfig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	end := time.Now().Add(-time.Hour).UTC()
	start := end.Add(-10 * time.Minute)
	bot := &reportBot{cancel: cancel, updates: []model.TelegramUpdate{reportCallback(12, cfg, start, end)}}
	calls := 0
	build := func(ctx context.Context, gotStart, gotEnd time.Time) ([]byte, error) {
		calls++
		if !gotStart.Equal(start) || !gotEnd.Equal(end) {
			t.Fatalf("button period changed: %v %v", gotStart, gotEnd)
		}
		data, err := os.ReadFile(cfg.CursorFile)
		var cursor struct {
			Offset      int64
			LastRequest time.Time `json:"last_request"`
		}
		if err != nil || json.Unmarshal(data, &cursor) != nil || cursor.Offset != 13 || cursor.LastRequest.IsZero() {
			t.Fatal("delivery started before durable cursor")
		}
		if len(bot.answers) != 1 || !strings.Contains(bot.answers[0], "Готовлю") {
			t.Fatal("click not acknowledged before building")
		}
		return []byte("Ошибка → реселлер → все ID"), nil
	}
	telegram.RunReports(ctx, cfg, bot, build, &bytes.Buffer{})
	if calls != 1 || len(bot.documents) != 1 || len(bot.chats) != 1 || bot.chats[0] != cfg.ChatID {
		t.Fatalf("wrong report: calls=%d bot=%+v", calls, bot)
	}
}

func TestReportCallbackRejectsUnauthorizedExpiredOrMalformedWithoutDatabase(t *testing.T) {
	cases := map[string]func(*model.TelegramCallbackQuery){
		"other chat":           func(q *model.TelegramCallbackQuery) { q.Message.Chat.ID = 123 },
		"another bot message":  func(q *model.TelegramCallbackQuery) { q.Message.From.ID = 99 },
		"human message":        func(q *model.TelegramCallbackQuery) { q.Message.From.IsBot = false },
		"bot click":            func(q *model.TelegramCallbackQuery) { q.From.IsBot = true },
		"missing sender":       func(q *model.TelegramCallbackQuery) { q.From.ID = 0 },
		"inaccessible message": func(q *model.TelegramCallbackQuery) { q.Message.Date = 0 },
		"no message":           func(q *model.TelegramCallbackQuery) { q.Message = nil },
		"wrong scope":          func(q *model.TelegramCallbackQuery) { q.Data = strings.Replace(q.Data, "r:", "r:12345678", 1) },
		"malformed":            func(q *model.TelegramCallbackQuery) { q.Data = "r:whatever" },
		"oversize":             func(q *model.TelegramCallbackQuery) { q.Data = strings.Repeat("x", 65) },
		"old message":          func(q *model.TelegramCallbackQuery) { q.Message.Date = time.Now().Add(-49 * time.Hour).Unix() },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := reportConfig(t)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			end := time.Now().Add(-time.Minute)
			update := reportCallback(1, cfg, end.Add(-10*time.Minute), end)
			mutate(update.Callback)
			bot := &reportBot{cancel: cancel, cancelOnAnswer: true, updates: []model.TelegramUpdate{update}}
			telegram.RunReports(ctx, cfg, bot, func(context.Context, time.Time, time.Time) ([]byte, error) {
				t.Fatal("invalid callback read database")
				return nil, nil
			}, &bytes.Buffer{})
			if len(bot.answers) != 1 || !strings.Contains(bot.answers[0], "недоступна") || len(bot.documents) != 0 || len(bot.messages) != 0 {
				t.Fatalf("unexpected callback response: %+v", bot)
			}
		})
	}
	for _, period := range []struct{ start, end time.Time }{
		{time.Now().Add(-49 * time.Hour), time.Now().Add(-48 * time.Hour)},
		{time.Now().Add(-time.Minute), time.Now().Add(time.Hour)},
		{time.Now().Add(-time.Minute), time.Now().Add(-2 * time.Minute)},
	} {
		cfg := reportConfig(t)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		bot := &reportBot{cancel: cancel, cancelOnAnswer: true, updates: []model.TelegramUpdate{reportCallback(1, cfg, period.start, period.end)}}
		telegram.RunReports(ctx, cfg, bot, func(context.Context, time.Time, time.Time) ([]byte, error) {
			t.Fatal("invalid period read database")
			return nil, nil
		}, &bytes.Buffer{})
		cancel()
		if len(bot.answers) != 1 || !strings.Contains(bot.answers[0], "недоступна") {
			t.Fatal("invalid period was not acknowledged")
		}
	}
}

func TestReportCallbackCooldownAcknowledgedAcrossRestart(t *testing.T) {
	cfg := reportConfig(t)
	cursor, _ := json.Marshal(map[string]any{"bot_id": 42, "chat_id": cfg.ChatID, "offset": 10, "last_request": time.Now().UTC()})
	if err := os.WriteFile(cfg.CursorFile, cursor, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	end := time.Now().Add(-time.Minute)
	bot := &reportBot{cancel: cancel, cancelOnAnswer: true, updates: []model.TelegramUpdate{reportCallback(10, cfg, end.Add(-time.Hour), end)}}
	telegram.RunReports(ctx, cfg, bot, func(context.Context, time.Time, time.Time) ([]byte, error) {
		t.Fatal("cooldown callback read database")
		return nil, nil
	}, &bytes.Buffer{})
	if len(bot.answers) != 1 || !strings.Contains(bot.answers[0], "через минуту") || bot.offsets[0] != 10 {
		t.Fatal("cooldown click lacks status or cursor")
	}
}
