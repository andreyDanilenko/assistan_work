package monitor_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"loki-analyzer/internal/monitor"
	"os"
	"strings"
	"testing"
	"time"

	"loki-analyzer/internal/loki"
	"loki-analyzer/internal/model"
	"loki-analyzer/internal/telegram"
)

const reviewFatalA = `{"context":"orders","orderId":"fatal-a","msg":"FATAL secret-original-a","token":"secret-token-a"}`
const reviewFatalB = `{"context":"orders","orderId":"fatal-b","msg":"FATAL secret-original-b"}`

func TestMonitorNewCriticalGroupBypassesOtherGroupsCooldown(t *testing.T) {
	cfg := monitorConfig(t)
	cfg.Critical = "" // Автоматическая проверка msg/level, без regex по произвольным JSON-полям.
	sender := &monitorSender{}
	for _, lines := range [][]string{{reviewFatalA}, {reviewFatalB}, {reviewFatalA, reviewFatalB}} {
		if _, _, err := monitorCycle(t, context.Background(), cfg, recordsSource(t, lines...), sender); err != nil {
			t.Fatal(err)
		}
	}
	if len(sender.messages) != 2 || !strings.Contains(sender.messages[0], "Другие / нераспознанные ошибки — 1") || !strings.Contains(sender.messages[1], "Другие / нераспознанные ошибки — 1") {
		t.Fatalf("new group suppressed or repeated group resent: %#v", sender.messages)
	}
	state := readMonitorState(t, cfg)
	if len(state.Alerted) != 2 || len(state.AlertIssues) != 0 {
		t.Fatalf("group cooldown not saved: %+v", state)
	}
}

func TestMonitorUpdatesCurrentGroupsAndDropsExpiredDelivery(t *testing.T) {
	cfg := monitorConfig(t)
	sender := &monitorSender{err: &telegram.APIError{Code: 429, RetryAfter: time.Hour}}
	for _, lines := range [][]string{{repeatedOrderError, repeatedOrderError, repeatedOrderError}, {repeatedOrderError, repeatedOrderError, repeatedOrderError, reviewFatalB}} {
		if _, _, err := monitorCycle(t, context.Background(), cfg, recordsSource(t, lines...), sender); err == nil {
			t.Fatal("pending delivery must be visible to one-shot caller")
		}
	}
	state := readMonitorState(t, cfg)
	if len(sender.messages) != 1 || len(state.Pending) != 1 || len(state.AlertIssues) != 2 || state.Pending[0].Attempts != 1 {
		t.Fatalf("new groups lost or retry reset: %+v", state)
	}
	for _, issue := range state.AlertIssues {
		if issue.OrderID == "order-a" && issue.Count != 3 {
			t.Fatalf("overlapping windows were summed: %+v", issue)
		}
	}
	body, err := os.ReadFile(cfg.StateFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "secret-original") {
		t.Fatal("raw log leaked into saved buffer")
	}
	state.TelegramAfter = time.Now().Add(-time.Minute)
	state.Pending[0].NextTry = state.TelegramAfter
	writeMonitorState(t, cfg, state)
	sender.err = nil
	if _, _, err := monitorCycle(t, context.Background(), cfg, recordsSource(t, `{"msg":"ordinary event"}`), sender); err != nil {
		t.Fatal(err)
	}
	if len(sender.messages) != 1 {
		t.Fatalf("old groups delivered as current after leaving the period: %#v", sender.messages)
	}
	state = readMonitorState(t, cfg)
	if len(state.AlertIssues) != 0 || len(state.Alerted) != 0 || len(state.Pending) != 0 {
		t.Fatalf("delivered buffer was not acknowledged: %+v", state)
	}
}

type reviewSenderFunc func(context.Context, int64, string) error

func (f reviewSenderFunc) SendMessage(ctx context.Context, chat int64, text string) error {
	return f(ctx, chat, text)
}

func TestMonitorRetryAfterStartsWhenTelegramResponds(t *testing.T) {
	cfg := monitorConfig(t)
	var responded time.Time
	sender := reviewSenderFunc(func(context.Context, int64, string) error {
		time.Sleep(20 * time.Millisecond)
		responded = time.Now().UTC()
		return &telegram.APIError{Code: 429, RetryAfter: 2 * time.Hour}
	})
	if _, _, err := monitorCycle(t, context.Background(), cfg, recordsSource(t, reviewFatalA), sender); err == nil {
		t.Fatal("pending delivery not reported")
	}
	state := readMonitorState(t, cfg)
	if state.TelegramAfter.Before(responded.Add(2*time.Hour)) || state.Pending[0].NextTry.Before(responded.Add(2*time.Hour)) {
		t.Fatal("retry_after counted from the start of the Loki cycle")
	}
}

func TestMonitorAlertBufferLimitDoesNotTruncatePeriodCounts(t *testing.T) {
	cfg := monitorConfig(t)
	source := monitorSourceFunc(func(_ context.Context, q loki.Query) (model.FetchResult, error) {
		result := model.FetchResult{Complete: true}
		for i := 0; i < 520; i++ {
			result.Records = append(result.Records, model.LogRecord{Project: q.Project, Timestamp: q.End.Add(-time.Second), Line: fmt.Sprintf(`{"orderId":"order-%d","msg":"FATAL"}`, i)})
		}
		return result, nil
	})
	sender := &monitorSender{err: &telegram.APIError{Code: 429, RetryAfter: time.Hour}}
	_, diagnostic, err := monitorCycle(t, context.Background(), cfg, source, sender)
	if err == nil || !strings.Contains(diagnostic, "Буфер уведомлений заполнен") {
		t.Fatal("buffer overflow not reported")
	}
	state := readMonitorState(t, cfg)
	if len(state.AlertIssues) != 512 || state.AlertDropped != 8 || len(state.Pending) != 1 || !strings.Contains(state.Pending[0].Text, "Другие / нераспознанные ошибки — 520") {
		t.Fatalf("overflow was silent or unbounded: groups=%d dropped=%d", len(state.AlertIssues), state.AlertDropped)
	}
	encoded, err := json.Marshal(state)
	if err != nil || len(encoded) >= 1<<20 {
		t.Fatal("bounded state is too large")
	}
}

func TestCommandsStartOnlyAfterWatchLockAndStopBeforeRunReturns(t *testing.T) {
	cfg := monitorConfig(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered := make(chan struct{})
	commandsStarted, commandsStopped := make(chan struct{}), make(chan struct{})
	source := monitorSourceFunc(func(ctx context.Context, q loki.Query) (model.FetchResult, error) {
		close(entered)
		<-ctx.Done()
		return model.FetchResult{}, ctx.Err()
	})
	worker, err := monitor.New(cfg, source, &monitorSender{}, &monitorArchive{}, &bytes.Buffer{}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- worker.RunWithCommands(ctx, func(ctx context.Context) {
			close(commandsStarted)
			<-ctx.Done()
			close(commandsStopped)
		})
	}()
	<-entered
	<-commandsStarted
	second, err := monitor.New(cfg, recordsSource(t), &monitorSender{}, &monitorArchive{}, &bytes.Buffer{}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	invoked := false
	if err := second.RunWithCommands(context.Background(), func(context.Context) { invoked = true }); err == nil || invoked {
		t.Fatal("second watcher consumed commands without owning the lock")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("watch did not stop")
	}
	select {
	case <-commandsStopped:
	default:
		t.Fatal("watch returned before commands stopped")
	}
}
