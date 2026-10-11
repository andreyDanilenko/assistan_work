package monitor_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"loki-analyzer/internal/loki"
	"loki-analyzer/internal/model"
	"loki-analyzer/internal/monitor"
	"loki-analyzer/internal/telegram"
)

type monitorSourceFunc func(context.Context, loki.Query) (model.FetchResult, error)

func (f monitorSourceFunc) FetchLogs(ctx context.Context, q loki.Query) (model.FetchResult, error) {
	return f(ctx, q)
}

type monitorSender struct {
	messages []string
	chatIDs  []int64
	err      error
}

func (s *monitorSender) SendMessage(ctx context.Context, chatID int64, text string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.messages = append(s.messages, text)
	s.chatIDs = append(s.chatIDs, chatID)
	return s.err
}

func monitorConfig(t *testing.T) monitor.Config {
	t.Helper()
	return monitor.Config{
		Project: "orders-test", SourceID: "https://test.invalid/loki", StateFile: filepath.Join(t.TempDir(), "watch.json"),
		ChatID: -1005000000001, Interval: 2 * time.Minute, Window: 10 * time.Minute,
		ReportInterval: time.Hour, Cooldown: 30 * time.Minute, NoLogsAfter: 10 * time.Minute,
		ReadWindow: func(context.Context, time.Time, time.Time) ([]model.LogRecord, error) { return nil, nil },
		Timeout:    time.Second, ErrorThreshold: 3, Critical: `(?i)\b(fatal|critical)\b`,
	}
}

func recordsSource(t *testing.T, lines ...string) monitorSourceFunc {
	t.Helper()
	stamp := time.Now().Add(-10 * time.Second)
	return func(ctx context.Context, q loki.Query) (model.FetchResult, error) {
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("source has no deadline")
		}
		if q.Project != "orders-test" || !q.Start.Before(q.End) || q.End.Sub(q.Start) > 2*time.Minute {
			t.Fatalf("invalid query window: %#v", q)
		}
		result := model.FetchResult{Complete: true}
		for i, line := range lines {
			ts := stamp.Add(-time.Duration(i+1) * time.Second)
			if ts.Before(q.Start) || !ts.Before(q.End) {
				continue
			}
			result.Records = append(result.Records, model.LogRecord{
				Project: q.Project, Timestamp: ts, Line: line,
				Labels: map[string]string{"pod": "orders-pod", "node_name": "node-a"},
			})
		}
		return result, nil
	}
}

func monitorCycle(t *testing.T, ctx context.Context, cfg monitor.Config, source monitor.Source, sender monitor.Sender) (string, string, error) {
	t.Helper()
	var output, diagnostic bytes.Buffer
	archive := &monitorArchive{}
	cfg.ReadWindow = archive.readWindow
	worker, err := monitor.New(cfg, source, sender, archive, &output, &diagnostic)
	if err == nil {
		err = worker.Run(ctx, true)
	}
	return output.String(), diagnostic.String(), err
}

func readMonitorState(t *testing.T, cfg monitor.Config) monitor.State {
	t.Helper()
	body, err := os.ReadFile(cfg.StateFile)
	if err != nil {
		t.Fatal(err)
	}
	var state monitor.State
	if err := json.Unmarshal(body, &state); err != nil {
		t.Fatal(err)
	}
	return state
}

func writeMonitorState(t *testing.T, cfg monitor.Config, state monitor.State) {
	t.Helper()
	body, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.StateFile, body, 0600); err != nil {
		t.Fatal(err)
	}
}

const repeatedOrderError = `{"context":"orders","orderId":"order-a","resellerId":"reseller-a","msg":"order create error order not found"}`

func TestMonitorDryRunNeedsNoChatOrSenderAndWritesNoState(t *testing.T) {
	cfg := monitorConfig(t)
	cfg.DryRun, cfg.ChatID = true, 0
	cfg.StateFile = filepath.Join(filepath.Dir(cfg.StateFile), "not-created", "watch.json")
	output, diagnostic, err := monitorCycle(t, context.Background(), cfg, recordsSource(t, repeatedOrderError), nil)
	if err != nil || diagnostic != "" || !strings.Contains(output, "Предпросмотр Telegram") {
		t.Fatalf("dry run failed: %v, %s, %s", err, output, diagnostic)
	}
	if _, err := os.Stat(filepath.Dir(cfg.StateFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("dry run created state directory or files")
	}
}

func TestMonitorRepeatedOrderErrorsSendOneAlertAndSurviveRestart(t *testing.T) {
	cfg := monitorConfig(t)
	sender := &monitorSender{}
	source := recordsSource(t, repeatedOrderError, repeatedOrderError, repeatedOrderError)
	for run := 0; run < 2; run++ {
		output, _, err := monitorCycle(t, context.Background(), cfg, source, sender)
		if err != nil || !strings.Contains(output, "Ошибок: 3") {
			t.Fatalf("window was counted incorrectly after restart: %v, %s", err, output)
		}
	}
	if len(sender.messages) != 1 || sender.chatIDs[0] != cfg.ChatID || !strings.Contains(sender.messages[0], "Заказ не найден — 1") || strings.Contains(sender.messages[0], "📋") {
		t.Fatalf("expected one alert without duplicate first report: %#v", sender.messages)
	}
	state := readMonitorState(t, cfg)
	if len(state.Pending) != 0 || state.LastAlert.IsZero() || state.LastReport.IsZero() {
		t.Fatal("anti-spam state was not saved")
	}
	info, err := os.Stat(cfg.StateFile)
	if err != nil || info.Mode().Perm()&0077 != 0 {
		t.Fatal("state file is readable by other users")
	}
}

func TestMonitorFatalSendsImmediatelyBelowErrorThreshold(t *testing.T) {
	cfg := monitorConfig(t)
	sender := &monitorSender{}
	_, _, err := monitorCycle(t, context.Background(), cfg, recordsSource(t, `{"msg":"FATAL connection unavailable","orderId":"order-fatal"}`), sender)
	if err != nil || len(sender.messages) != 1 || !strings.HasPrefix(sender.messages[0], "🔴 Заказы с ошибкой") || !strings.Contains(sender.messages[0], "Другие / нераспознанные ошибки — 1") {
		t.Fatalf("single fatal did not trigger immediate alert: %v, %#v", err, sender.messages)
	}
}

func TestMonitorAlertCountsOrderOnceAndListsEveryErrorCategory(t *testing.T) {
	cfg := monitorConfig(t)
	cfg.ErrorThreshold = 1
	sender := &monitorSender{}
	source := recordsSource(t,
		repeatedOrderError,
		repeatedOrderError,
		`{"context":"orders","orderId":"order-a","msg":"error provisioned, timeout exceeded when trying to connect"}`,
		`{"context":"orders","id":"order-b","msg":"creating order"}`,
	)
	_, _, err := monitorCycle(t, context.Background(), cfg, source, sender)
	if err != nil || len(sender.messages) != 1 || !strings.HasPrefix(sender.messages[0], "🔴 Заказы с ошибкой") {
		t.Fatalf("expected one alert: %v, %#v", err, sender.messages)
	}
	message := sender.messages[0]
	if strings.Contains(message, "• Заказ:") {
		t.Fatalf("short message must show categories instead of selected orders: %s", message)
	}
	for _, expected := range []string{
		"📦 Всего заказов: 2\n✅ Успешно: 0\n🔴 С ошибкой: 1\n⏳ Без результата: 1\n",
		"✅ Успешно: 0\n🔴 С ошибкой: 1\n⏳ Без результата: 1\n",
		"Заказ не найден — 1\n",
		"Таймаут подключения — 1\n",
	} {
		if !strings.Contains(message, expected) {
			t.Fatalf("alert lost order counts or a concrete error %q: %s", expected, message)
		}
	}
}

func TestMonitorFullEmptyWindowWarnsOnceAndReports(t *testing.T) {
	cfg := monitorConfig(t)
	sender := &monitorSender{}
	for run := 0; run < 2; run++ {
		if _, _, err := monitorCycle(t, context.Background(), cfg, recordsSource(t), sender); err != nil {
			t.Fatal(err)
		}
	}
	if len(sender.messages) != 2 || !strings.Contains(sender.messages[0], "🟡 Логи не поступают") || !strings.Contains(sender.messages[1], "📋 Сводка") {
		t.Fatalf("absence warnings repeated or report was missing: %#v", sender.messages)
	}
	if !readMonitorState(t, cfg).NoLogs {
		t.Fatal("absence state was not persisted")
	}
}

func TestMonitorErrorsAndPartialResultsDoNotClaimAbsentLogs(t *testing.T) {
	for _, fail := range []bool{true, false} {
		t.Run(map[bool]string{true: "source error", false: "partial response"}[fail], func(t *testing.T) {
			cfg := monitorConfig(t)
			sender := &monitorSender{}
			source := monitorSourceFunc(func(context.Context, loki.Query) (model.FetchResult, error) {
				if fail {
					return model.FetchResult{}, errors.New("secret source body")
				}
				return model.FetchResult{Complete: false, Reason: "secret partial body"}, nil
			})
			for run := 0; run < 2; run++ {
				_, diagnostic, err := monitorCycle(t, context.Background(), cfg, source, sender)
				if err == nil || !strings.Contains(diagnostic, "Отсутствие логов не оценивается") || strings.Contains(diagnostic, "secret") || strings.Contains(err.Error(), "secret") {
					t.Fatalf("unsafe source error handling: %v %s", err, diagnostic)
				}
			}
			state := readMonitorState(t, cfg)
			if len(sender.messages) != 2 || state.NoLogs || !state.LastComplete.IsZero() || !state.SourceFailed {
				t.Fatalf("failure changed completeness/absence state or repeated notifications: %+v", state)
			}
			for _, message := range sender.messages {
				if strings.Contains(message, "🟡 Логи не поступают") || strings.Contains(message, "secret") {
					t.Fatal("source failure falsely reported absence or exposed source details")
				}
			}
		})
	}
}

func TestMonitorDropsObsoleteAlertWhenNextFetchFails(t *testing.T) {
	cfg := monitorConfig(t)
	failed := &monitorSender{err: errors.New("private transport details")}
	_, diagnostic, err := monitorCycle(t, context.Background(), cfg, recordsSource(t, repeatedOrderError, repeatedOrderError, repeatedOrderError), failed)
	if err == nil || len(failed.messages) != 1 || strings.Contains(diagnostic, "private") {
		t.Fatalf("send failure was not retained safely: %v, %s", err, diagnostic)
	}
	state := readMonitorState(t, cfg)
	if len(state.Pending) != 1 || state.Pending[0].Attempts != 1 || !state.Pending[0].NextTry.After(time.Now()) {
		t.Fatalf("missing scheduled retry: %+v", state)
	}
	state.Pending[0].NextTry = time.Now().Add(-time.Minute)
	state.TelegramAfter = state.Pending[0].NextTry
	writeMonitorState(t, cfg, state)
	sender := &monitorSender{}
	source := monitorSourceFunc(func(context.Context, loki.Query) (model.FetchResult, error) {
		return model.FetchResult{}, errors.New("source unavailable")
	})
	_, _, err = monitorCycle(t, context.Background(), cfg, source, sender)
	if err == nil || len(sender.messages) != 1 || !strings.Contains(sender.messages[0], "Нет подтвержденных данных Loki") {
		t.Fatalf("stale period was delivered after failed fetch: %v, %#v", err, sender.messages)
	}
	for _, pending := range readMonitorState(t, cfg).Pending {
		if pending.Kind == "alert" {
			t.Fatal("successful retry remains pending")
		}
	}
}

func TestMonitorRateLimitBlocksNewMessagesAndKeepsQueueBounded(t *testing.T) {
	cfg := monitorConfig(t)
	sender := &monitorSender{err: &telegram.APIError{Code: 429, RetryAfter: 2 * time.Hour}}
	before := time.Now()
	if _, _, err := monitorCycle(t, context.Background(), cfg, recordsSource(t, repeatedOrderError, repeatedOrderError, repeatedOrderError), sender); err == nil {
		t.Fatal("undelivered alert must fail a one-shot check")
	}
	state := readMonitorState(t, cfg)
	if len(state.Pending) != 1 || state.Pending[0].NextTry.Before(before.Add(2*time.Hour)) {
		t.Fatalf("retry_after was not respected: %+v", state)
	}
	unavailable := monitorSourceFunc(func(context.Context, loki.Query) (model.FetchResult, error) {
		return model.FetchResult{Complete: false}, nil
	})
	for run := 0; run < 5; run++ {
		if _, _, err := monitorCycle(t, context.Background(), cfg, unavailable, sender); err == nil {
			t.Fatal("incomplete fetch must fail a one-shot check")
		}
		if len(readMonitorState(t, cfg).Pending) > 4 {
			t.Fatal("failed delivery grew an unbounded queue")
		}
	}
	if len(sender.messages) != 1 {
		t.Fatalf("new message bypassed Telegram retry_after: attempted %d sends", len(sender.messages))
	}
}

func TestMonitorRejectsChangedBindingAndCorruptStateBeforeQuery(t *testing.T) {
	for _, change := range []string{"chat", "source", "project", "invalid JSON", "too many pending"} {
		t.Run(change, func(t *testing.T) {
			cfg := monitorConfig(t)
			if _, _, err := monitorCycle(t, context.Background(), cfg, recordsSource(t, `{"msg":"ordinary event"}`), &monitorSender{}); err != nil {
				t.Fatal(err)
			}
			switch change {
			case "chat":
				cfg.ChatID--
			case "source":
				cfg.SourceID += "/other"
			case "project":
				cfg.Project = "other-project"
			case "invalid JSON":
				if err := os.WriteFile(cfg.StateFile, []byte("private invalid JSON"), 0600); err != nil {
					t.Fatal(err)
				}
			case "too many pending":
				state := readMonitorState(t, cfg)
				state.Pending = make([]monitor.Message, 5)
				writeMonitorState(t, cfg, state)
			}
			source := monitorSourceFunc(func(context.Context, loki.Query) (model.FetchResult, error) {
				t.Fatal("invalid state reached Loki")
				return model.FetchResult{}, nil
			})
			sender := &monitorSender{}
			output, _, err := monitorCycle(t, context.Background(), cfg, source, sender)
			if err == nil || strings.Contains(err.Error(), "private") || output != "" || len(sender.messages) != 0 {
				t.Fatalf("unsafe state was used or exposed: %v", err)
			}
			if _, err := os.Stat(cfg.StateFile + ".lock"); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("failed startup retained the lock")
			}
		})
	}
}

func TestMonitorLockProtectsOneStateFileOnly(t *testing.T) {
	cfg := monitorConfig(t)
	if err := os.WriteFile(cfg.StateFile+".lock", []byte("other process"), 0600); err != nil {
		t.Fatal(err)
	}
	source := monitorSourceFunc(func(context.Context, loki.Query) (model.FetchResult, error) {
		t.Fatal("locked state reached Loki")
		return model.FetchResult{}, nil
	})
	if _, _, err := monitorCycle(t, context.Background(), cfg, source, &monitorSender{}); err == nil {
		t.Fatal("concurrent monitor acquired the same state")
	}
	if _, err := os.Stat(cfg.StateFile + ".lock"); err != nil {
		t.Fatal("foreign lock was removed")
	}
	// Ограничение MVP: другой путь не блокируется по токену или чату глобально.
	cfg.StateFile = filepath.Join(filepath.Dir(cfg.StateFile), "other-state.json")
	if _, _, err := monitorCycle(t, context.Background(), cfg, recordsSource(t, `{"msg":"ordinary event"}`), &monitorSender{}); err != nil {
		t.Fatalf("another state path should remain independent: %v", err)
	}
}

func TestMonitorCanceledContextDoesNotFetchSendOrPrint(t *testing.T) {
	cfg := monitorConfig(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	source := monitorSourceFunc(func(context.Context, loki.Query) (model.FetchResult, error) {
		t.Fatal("canceled context reached Loki")
		return model.FetchResult{}, nil
	})
	sender := &monitorSender{}
	output, diagnostic, err := monitorCycle(t, ctx, cfg, source, sender)
	if !errors.Is(err, context.Canceled) || output != "" || diagnostic != "" || len(sender.messages) != 0 {
		t.Fatalf("cancellation had side effects: %v, %s, %s", err, output, diagnostic)
	}
}

func TestMonitorDoesNotPersistOrSendRawLogSecrets(t *testing.T) {
	cfg := monitorConfig(t)
	sender := &monitorSender{err: errors.New("secret-send-token")}
	source := recordsSource(t, `{"context":"orders","orderId":"order-a","resellerId":"reseller-a","msg":"FATAL private-payload-message","token":"secret-log-token","password":"secret-password","email":"person@example.org"}`)
	output, diagnostic, err := monitorCycle(t, context.Background(), cfg, source, sender)
	if err == nil || len(sender.messages) != 1 {
		t.Fatalf("send failure must fail one-shot check: %v", err)
	}
	body, err := os.ReadFile(cfg.StateFile)
	if err != nil {
		t.Fatal(err)
	}
	all := output + diagnostic + strings.Join(sender.messages, "\n") + string(body)
	for _, forbidden := range []string{"private-payload-message", "secret-log-token", "secret-password", "person@example.org", "secret-send-token"} {
		if strings.Contains(all, forbidden) {
			t.Fatalf("raw secret exposed: %s", forbidden)
		}
	}
	if !strings.Contains(sender.messages[0], "Другие / нераспознанные ошибки — 1") {
		t.Fatal("unrecognized error category was lost")
	}
}

func TestMonitorOnlyUnresolvedOrdersAppearInAlert(t *testing.T) {
	cfg := monitorConfig(t)
	sender := &monitorSender{}
	// recordsSource возвращает сообщения от новых к старым.
	source := recordsSource(t,
		`{"context":"orders","orderId":"recovered","msg":"order provisioned"}`,
		`{"context":"orders","orderId":"recovered","msg":"order create error order not found"}`,
		`{"context":"orders","orderId":"waiting","msg":"order create error order still being provision"}`,
		`{"context":"orders","orderId":"failed","type":"renew","resellerId":"reseller-r","msg":"error provisioned, timeout exceeded when trying to connect"}`,
	)
	_, _, err := monitorCycle(t, context.Background(), cfg, source, sender)
	if err != nil || len(sender.messages) != 1 {
		t.Fatalf("expected one alert: %v, %v", err, sender.messages)
	}
	message := sender.messages[0]
	for _, expected := range []string{"📦 Всего заказов: 3\n✅ Успешно: 1\n🔴 С ошибкой: 1\n⏳ Без результата: 1", "✅ Успешно: 1\n🔴 С ошибкой: 1\n⏳ Без результата: 1", "Таймаут подключения — 1", "renew: 1"} {
		if !strings.Contains(message, expected) {
			t.Fatalf("missing %q: %s", expected, message)
		}
	}
	for _, forbidden := range []string{"Заказ не найден", "Заказ ещё обрабатывается", "Число повторов", "Проверить:"} {
		if strings.Contains(message, forbidden) {
			t.Fatalf("obsolete or recovered error in alert: %s", message)
		}
	}
}

func TestMonitorSuccessCancelsUndeliveredAlertAfterRestart(t *testing.T) {
	cfg := monitorConfig(t)
	sender := &monitorSender{err: errors.New("offline")}
	_, _, err := monitorCycle(t, context.Background(), cfg, recordsSource(t, repeatedOrderError), sender)
	if err == nil || len(readMonitorState(t, cfg).AlertIssues) != 1 {
		t.Fatal("error was not queued")
	}
	// Следующая проверка содержит подтверждение после сохранённой ошибки.
	state := readMonitorState(t, cfg)
	confirmedAt := state.AlertIssues[0].Last.Add(time.Second)
	source := monitorSourceFunc(func(context.Context, loki.Query) (model.FetchResult, error) {
		return model.FetchResult{Complete: true, Records: []model.LogRecord{{Project: cfg.Project, Timestamp: confirmedAt, Line: `{"context":"orders","orderId":"order-a","msg":"order provisioned"}`}}}, nil
	})
	sender.err = nil
	_, _, err = monitorCycle(t, context.Background(), cfg, source, sender)
	if err != nil {
		t.Fatal(err)
	}
	state = readMonitorState(t, cfg)
	if len(state.AlertIssues) != 0 || len(state.Pending) != 0 || len(sender.messages) != 1 {
		t.Fatalf("resolved alert remained queued: %+v; sent %d", state, len(sender.messages))
	}
}

func TestAlertShortMessageLinksDetailsInsteadOfChoosingResellers(t *testing.T) {
	cfg := monitorConfig(t)
	cfg.ResellerNames = map[string]string{"reseller-a": "TBank"}
	sender := &monitorSender{}
	_, _, err := monitorCycle(t, context.Background(), cfg, recordsSource(t,
		repeatedOrderError,
		`{"context":"orders","orderId":"order-b","resellerId":"reseller-unknown","msg":"order create error order not found"}`,
	), sender)
	if err != nil || len(sender.messages) != 1 {
		t.Fatalf("alert failed: %v %v", err, sender.messages)
	}
	message := sender.messages[0]
	for _, expected := range []string{"Заказ не найден — 2", "все ID заказов — в TXT", "За этот период"} {
		if !strings.Contains(message, expected) {
			t.Fatalf("missing %q: %s", expected, message)
		}
	}
	for _, forbidden := range []string{"В этой подборке", "Ещё заказов", "• Заказ:", "Реселлер: не определён"} {
		if strings.Contains(message, forbidden) {
			t.Fatalf("old truncated listing: %s", message)
		}
	}
}
