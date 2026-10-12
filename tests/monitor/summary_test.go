package monitor_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"loki-analyzer/internal/loki"
	"loki-analyzer/internal/model"
	"loki-analyzer/internal/monitor"
)

func TestPeriodSummaryShowsEveryCategoryAndSeparatesMissingIDs(t *testing.T) {
	cfg := monitorConfig(t)
	sender := &monitorSender{}
	lines := []string{
		`{"context":"orders","orderId":"a","type":"new","msg":"order create error order not found"}`,
		`{"context":"orders","orderId":"a","type":"new","msg":"order create error order not found"}`,
		`{"context":"orders","orderId":"a","type":"new","msg":"error provisioned, timeout exceeded when trying to connect"}`,
		`{"context":"orders","orderId":"b","type":"renew","msg":"order create error order item during the renewal block period"}`,
		`{"context":"orders","orderId":"c","type":"cancel","msg":"order create error order item trial lasts"}`,
		`{"orderId":"d","msg":"ERROR unrecognized"}`,
		`{"msg":"ERROR missing id"}`,
		`{"msg":"ERROR missing id"}`,
		`{"context":"orders","msg":"order create error order still being provision"}`,
	}
	_, _, err := monitorCycle(t, context.Background(), cfg, recordsSource(t, lines...), sender)
	if err != nil || len(sender.messages) != 1 {
		t.Fatalf("expected alert: %v, %v", err, sender.messages)
	}
	text := sender.messages[0]
	for _, expected := range []string{
		"📦 Всего заказов: 4\n✅ Успешно: 0\n🔴 С ошибкой: 4\n⏳ Без результата: 0",
		"Заказ не найден — 1",
		"Таймаут подключения — 1",
		"Продление запрещено в период блокировки — 1",
		"Пробный период ещё не завершён — 1",
		"Другие / нераспознанные ошибки — 1",
		"new: 1", "renew: 1", "cancel: 1", "тип не указан: 1",
		"Записей без ID заказа: 2 (не входят в число заказов)",
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("missing %q: %s", expected, text)
		}
	}
	if strings.Contains(text, "Заказ ещё обрабатывается") || strings.Contains(text, "3 записей") {
		t.Fatalf("waiting event counted as an error: %s", text)
	}
	if len([]rune(text)) >= 4000 {
		t.Fatalf("summary is too long: %d", len([]rune(text)))
	}
}

func TestCooldownSelectsWhenToSendButShowsAllOrdersInCurrentWindow(t *testing.T) {
	cfg := monitorConfig(t)
	sender := &monitorSender{}
	if _, _, err := monitorCycle(t, context.Background(), cfg, recordsSource(t, repeatedOrderError), sender); err != nil {
		t.Fatal(err)
	}
	lines := []string{repeatedOrderError}
	for i := 0; i < 9; i++ {
		lines = append(lines, fmt.Sprintf(`{"context":"orders","orderId":"new-%d","type":"cancel","msg":"order create error order not found"}`, i))
	}
	if _, _, err := monitorCycle(t, context.Background(), cfg, recordsSource(t, lines...), sender); err != nil {
		t.Fatal(err)
	}
	if len(sender.messages) != 2 {
		t.Fatalf("unexpected sends: %d", len(sender.messages))
	}
	text := sender.messages[1]
	for _, expected := range []string{"📦 Всего заказов: 10\n✅ Успешно: 0\n🔴 С ошибкой: 10\n⏳ Без результата: 0", "Заказ не найден — 10", "cancel: 9"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("cooldown removed an order from summary %q: %s", expected, text)
		}
	}
	for _, forbidden := range []string{"В этой подборке", "Ещё заказов", "очередь доставки", "• Заказ:"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("obsolete text: %s", text)
		}
	}
}

func TestWindowUsesSameExclusiveEndAsDatabaseReport(t *testing.T) {
	cfg := monitorConfig(t)
	cfg.Window = 2 * time.Minute
	cfg.SessionStart = time.Now().UTC().Add(-2 * time.Minute)
	sender := &monitorSender{}
	source := monitorSourceFunc(func(_ context.Context, q loki.Query) (model.FetchResult, error) {
		return model.FetchResult{Complete: true, Records: []model.LogRecord{
			{Project: q.Project, Timestamp: q.Start, Line: repeatedOrderError},
			{Project: q.Project, Timestamp: q.End, Line: `{"context":"orders","orderId":"boundary","msg":"order create error order not found"}`},
		}}, nil
	})
	_, _, err := monitorCycle(t, context.Background(), cfg, source, sender)
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Join(sender.messages, "\n")
	if !strings.Contains(text, "📦 Всего заказов: 1\n✅ Успешно: 0\n🔴 С ошибкой: 1\n⏳ Без результата: 0") {
		t.Fatalf("end boundary mismatch: %s", text)
	}
}

func TestNotificationFiltersDoNotHideCategoriesFromPeriodSummary(t *testing.T) {
	cfg := monitorConfig(t)
	cfg.Exclude = "timeout"
	sender := &monitorSender{}
	_, _, err := monitorCycle(t, context.Background(), cfg, recordsSource(t,
		repeatedOrderError,
		`{"context":"orders","orderId":"b","msg":"error provisioned, timeout exceeded when trying to connect"}`,
	), sender)
	if err != nil {
		t.Fatal(err)
	}
	if len(sender.messages) != 1 || !strings.Contains(sender.messages[0], "С ошибкой: 2") || !strings.Contains(sender.messages[0], "Таймаут подключения — 1") {
		t.Fatalf("filters cut report content: %v", sender.messages)
	}
	state := readMonitorState(t, cfg)
	if len(state.Alerted) != 1 {
		t.Fatalf("excluded category must not trigger notifications: %+v", state.Alerted)
	}
}

type reportSender struct {
	monitorSender
	starts, ends []time.Time
	scopes       []string
}

func (s *reportSender) SendMessageWithReport(ctx context.Context, chat int64, text, scope string, start, end time.Time) error {
	s.starts = append(s.starts, start)
	s.ends = append(s.ends, end)
	s.scopes = append(s.scopes, scope)
	return s.SendMessage(ctx, chat, text)
}

func TestExactReportPeriodSurvivesPendingStateAndRetry(t *testing.T) {
	cfg := monitorConfig(t)
	sender := &reportSender{monitorSender: monitorSender{err: errors.New("offline")}}
	source := recordsSource(t, `{"context":"orders","id":"ordinary","msg":"creating order"}`)
	_, _, err := monitorCycle(t, context.Background(), cfg, source, sender)
	if err == nil || len(sender.starts) != 1 {
		t.Fatalf("expected queued report with period: %v", err)
	}
	state := readMonitorState(t, cfg)
	pending := state.Pending[0]
	if pending.Kind != "report" || !pending.ReportStart.Equal(sender.starts[0]) || !pending.ReportEnd.Equal(sender.ends[0]) || pending.ReportEnd.Sub(pending.ReportStart) != cfg.Window {
		t.Fatalf("period not persisted with text: %+v", pending)
	}
	state.TelegramAfter = time.Now().Add(-time.Minute)
	state.Pending[0].NextTry = state.TelegramAfter
	writeMonitorState(t, cfg, state)
	sender.err = nil
	if _, _, err = monitorCycle(t, context.Background(), cfg, source, sender); err != nil {
		t.Fatal(err)
	}
	if len(sender.starts) != 2 || !sender.starts[1].Equal(sender.starts[0]) || !sender.ends[1].Equal(sender.ends[0]) || sender.scopes[1] != cfg.SourceID+"|"+cfg.Project {
		t.Fatalf("retry changed fixed period: %+v", sender)
	}
	if sender.messages[0] != sender.messages[1] {
		t.Fatal("retry changed text without changing period")
	}
}

func TestCustomCriticalPatternClassifiesPeriodAndTriggerConsistently(t *testing.T) {
	cfg := monitorConfig(t)
	cfg.Critical = "UPSTREAM_UNAVAILABLE"
	sender := &monitorSender{}
	_, _, err := monitorCycle(t, context.Background(), cfg, recordsSource(t, `{"orderId":"custom-error","level":"INFO","msg":"UPSTREAM_UNAVAILABLE"}`), sender)
	if err != nil {
		t.Fatal(err)
	}
	if len(sender.messages) != 1 || !strings.Contains(sender.messages[0], "📦 Всего заказов: 1\n✅ Успешно: 0\n🔴 С ошибкой: 1\n⏳ Без результата: 0") || !strings.Contains(sender.messages[0], "Другие / нераспознанные ошибки — 1") {
		t.Fatalf("custom trigger missing from full snapshot: %v", sender.messages)
	}
}

func TestLegacyQueuedReportIsRefreshedBeforeDelivery(t *testing.T) {
	cfg := monitorConfig(t)
	source := recordsSource(t, `{"context":"orders","id":"ordinary","msg":"creating order"}`)
	if _, _, err := monitorCycle(t, context.Background(), cfg, source, &monitorSender{}); err != nil {
		t.Fatal(err)
	}
	state := readMonitorState(t, cfg)
	// Предыдущая версия уже ждала отправки, но не сохраняла период для кнопки.
	state.Pending = []monitor.Message{{Kind: "report", Text: "LEGACY_REPORT_WITHOUT_BUTTON", NextTry: time.Now().Add(-time.Minute)}}
	writeMonitorState(t, cfg, state)
	sender := &reportSender{}
	if _, _, err := monitorCycle(t, context.Background(), cfg, source, sender); err != nil {
		t.Fatal(err)
	}
	if len(sender.messages) != 1 || len(sender.starts) != 1 || sender.starts[0].IsZero() || !strings.Contains(sender.messages[0], "Ошибки за период") || strings.Contains(sender.messages[0], "LEGACY_REPORT") {
		t.Fatalf("legacy report was delivered unchanged: %+v", sender)
	}
	if len(readMonitorState(t, cfg).Pending) != 0 {
		t.Fatal("refreshed report remained queued")
	}
}
