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

func digestSnapshot(project string, end time.Time, ids ...string) monitor.Snapshot {
	var records []model.LogRecord
	for i, id := range ids {
		records = append(records, model.LogRecord{Project: project, Timestamp: end.Add(-time.Duration(i+1) * time.Minute), Line: fmt.Sprintf(`{"context":"orders","orderId":%q,"type":"renew","resellerId":"reseller-a","msg":"order create error order not found"}`, id)})
	}
	return monitor.Analyze(records, monitor.Filter{})
}

func TestDigestUsesSavedPeriodAndNewErrorsDoNotSendBeforeNextReport(t *testing.T) {
	cfg := monitorConfig(t)
	cfg.ReportOnly, cfg.ReportInterval = true, 15*time.Minute
	calls := 0
	var starts, ends []time.Time
	cfg.BuildSnapshot = func(ctx context.Context, start, end time.Time) (monitor.Snapshot, error) {
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("database snapshot has no deadline")
		}
		calls++
		starts, ends = append(starts, start), append(ends, end)
		return digestSnapshot(cfg.Project, end, "earlier-collected-order", "fresh-order"), nil
	}
	sender := &reportSender{}
	if _, _, err := monitorCycle(t, context.Background(), cfg, recordsSource(t, repeatedOrderError), sender); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || len(sender.messages) != 1 || !strings.Contains(sender.messages[0], "📦 Всего заказов: 2\n✅ Успешно: 0\n🔴 С ошибкой: 2\n⏳ Без результата: 0") || !strings.HasPrefix(sender.messages[0], "📋") {
		t.Fatalf("digest must use complete archived snapshot: calls=%d messages=%v", calls, sender.messages)
	}
	state := readMonitorState(t, cfg)
	if !state.LastReportEnd.Equal(ends[0]) || !sender.starts[0].Equal(starts[0]) || !sender.ends[0].Equal(ends[0]) || ends[0].Sub(starts[0]) != cfg.Window {
		t.Fatal("first digest or its button lost period")
	}
	if _, _, err := monitorCycle(t, context.Background(), cfg, recordsSource(t, reviewFatalB), sender); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || len(sender.messages) != 1 {
		t.Fatal("new error bypassed periodic reports")
	}
	state.LastReport, state.LastReportEnd = time.Now().Add(-20*time.Minute), time.Now().Add(-20*time.Minute)
	writeMonitorState(t, cfg, state)
	if _, _, err := monitorCycle(t, context.Background(), cfg, recordsSource(t, repeatedOrderError), sender); err != nil {
		t.Fatal(err)
	}
	if calls != 2 || !starts[1].Equal(state.LastReportEnd) || ends[1].Sub(starts[1]) <= cfg.Window {
		t.Fatal("digest used only last Loki window, leaving a gap")
	}
	if !sender.starts[1].Equal(starts[1]) || !strings.Contains(sender.messages[1], starts[1].UTC().Format("02.01.2006 15:04:05")) {
		t.Fatal("button and visible period disagree")
	}
}

func TestDigestBuilderFailureRetriesSameStartWithoutSendingZeroCounts(t *testing.T) {
	cfg := monitorConfig(t)
	cfg.ReportOnly, cfg.ReportInterval = true, 15*time.Minute
	fail := true
	var starts []time.Time
	cfg.BuildSnapshot = func(_ context.Context, start, end time.Time) (monitor.Snapshot, error) {
		starts = append(starts, start)
		if fail {
			return monitor.Snapshot{}, errors.New("PRIVATE DATABASE DETAILS")
		}
		return digestSnapshot(cfg.Project, end, "order-a"), nil
	}
	sender := &monitorSender{}
	_, diagnostic, err := monitorCycle(t, context.Background(), cfg, recordsSource(t, repeatedOrderError), sender)
	if err == nil || len(sender.messages) != 0 || strings.Contains(diagnostic, "PRIVATE") {
		t.Fatalf("failed builder sent a report or exposed details: %v %s", err, diagnostic)
	}
	state := readMonitorState(t, cfg)
	if !state.LastReport.IsZero() || !state.LastReportEnd.IsZero() || state.NextReportStart.IsZero() {
		t.Fatal("failed report advanced cursor or lost first period start")
	}
	// Имитируем время между попытками: первое начало должно сохраниться.
	state.NextReportStart = state.NextReportStart.Add(-time.Minute)
	writeMonitorState(t, cfg, state)
	fail = false
	if _, _, err := monitorCycle(t, context.Background(), cfg, recordsSource(t, repeatedOrderError), sender); err != nil {
		t.Fatal(err)
	}
	if len(starts) != 2 || !starts[1].Equal(state.NextReportStart) || len(sender.messages) != 1 {
		t.Fatal("retry shifted start or failed to send")
	}
	state = readMonitorState(t, cfg)
	if state.LastReportEnd.IsZero() || !state.NextReportStart.IsZero() {
		t.Fatal("successful digest did not commit cursor")
	}
}

func TestDigestKeepsUndeliveredBeginningWhenReplacingReport(t *testing.T) {
	cfg := monitorConfig(t)
	cfg.ReportOnly, cfg.ReportInterval = true, 15*time.Minute
	cfg.BuildSnapshot = func(_ context.Context, _, end time.Time) (monitor.Snapshot, error) {
		return digestSnapshot(cfg.Project, end, "order-a"), nil
	}
	sender := &reportSender{monitorSender: monitorSender{err: errors.New("offline")}}
	if _, _, err := monitorCycle(t, context.Background(), cfg, recordsSource(t, repeatedOrderError), sender); err == nil {
		t.Fatal("expected pending delivery")
	}
	state := readMonitorState(t, cfg)
	originalStart := state.Pending[0].ReportStart
	state.LastReport = time.Now().Add(-20 * time.Minute)
	state.TelegramAfter = time.Now().Add(-time.Minute)
	state.Pending[0].NextTry = state.TelegramAfter
	writeMonitorState(t, cfg, state)
	sender.err = nil
	if _, _, err := monitorCycle(t, context.Background(), cfg, recordsSource(t, repeatedOrderError), sender); err != nil {
		t.Fatal(err)
	}
	if len(sender.starts) != 2 || !sender.starts[1].Equal(originalStart) || !sender.ends[1].After(sender.ends[0]) {
		t.Fatal("replaced pending report lost part of its period")
	}
}

func TestDigestRemovesLegacyAlertAndLoadsLongSavedPeriod(t *testing.T) {
	cfg := monitorConfig(t)
	if _, _, err := monitorCycle(t, context.Background(), cfg, recordsSource(t, repeatedOrderError), &monitorSender{}); err != nil {
		t.Fatal(err)
	}
	state := readMonitorState(t, cfg)
	state.Pending = []monitor.Message{{Kind: "alert", Text: "OBSOLETE_ALERT", NextTry: time.Now().Add(-time.Minute)}}
	writeMonitorState(t, cfg, state)
	cfg.ReportOnly, cfg.ReportInterval = true, 15*time.Minute
	var gotStart time.Time
	cfg.BuildSnapshot = func(_ context.Context, start, end time.Time) (monitor.Snapshot, error) {
		gotStart = start
		return digestSnapshot(cfg.Project, end, "order-a"), nil
	}
	sender := &reportSender{}
	if _, _, err := monitorCycle(t, context.Background(), cfg, recordsSource(t, repeatedOrderError), sender); err != nil {
		t.Fatal(err)
	}
	state = readMonitorState(t, cfg)
	if len(sender.messages) != 1 || strings.Contains(sender.messages[0], "OBSOLETE") || len(state.Alerted) != 0 || len(state.AlertIssues) != 0 {
		t.Fatal("periodic mode retained legacy individual alerts")
	}
	state.LastReport = time.Now().Add(-3 * time.Hour)
	state.LastReportEnd = state.LastReport
	state.Pending = []monitor.Message{{Kind: "report", Text: "OLD_SAVED_REPORT", ReportStart: time.Now().Add(-5 * time.Hour), ReportEnd: state.LastReportEnd, NextTry: time.Now().Add(-time.Minute)}}
	start := state.Pending[0].ReportStart
	writeMonitorState(t, cfg, state)
	if _, _, err := monitorCycle(t, context.Background(), cfg, recordsSource(t, repeatedOrderError), sender); err != nil {
		t.Fatal(err)
	}
	if !gotStart.Equal(start) {
		t.Fatal("report longer than hour could not resume")
	}
}

func TestDigestCapsLongPauseAndExplainsMissingHistory(t *testing.T) {
	cfg := monitorConfig(t)
	cfg.ReportOnly = true
	var gotStart, gotEnd time.Time
	cfg.BuildSnapshot = func(_ context.Context, start, end time.Time) (monitor.Snapshot, error) {
		gotStart, gotEnd = start, end
		return digestSnapshot(cfg.Project, end, "order-a"), nil
	}
	if _, _, err := monitorCycle(t, context.Background(), cfg, recordsSource(t, repeatedOrderError), &monitorSender{}); err != nil {
		t.Fatal(err)
	}
	state := readMonitorState(t, cfg)
	state.LastReport, state.LastReportEnd = time.Now().Add(-72*time.Hour), time.Now().Add(-72*time.Hour)
	writeMonitorState(t, cfg, state)
	sender := &monitorSender{}
	if _, _, err := monitorCycle(t, context.Background(), cfg, recordsSource(t, repeatedOrderError), sender); err != nil {
		t.Fatal(err)
	}
	if gotEnd.Sub(gotStart) > 48*time.Hour || !strings.Contains(sender.messages[0], "ранние данные уже недоступны") {
		t.Fatal("long pause silently truncated or requested expired history")
	}
}

func TestDigestDryRunDoesNotReadDatabase(t *testing.T) {
	cfg := monitorConfig(t)
	cfg.DryRun, cfg.ReportOnly = true, true
	cfg.BuildSnapshot = func(context.Context, time.Time, time.Time) (monitor.Snapshot, error) {
		t.Fatal("dry-run read database")
		return monitor.Snapshot{}, nil
	}
	out, _, err := monitorCycle(t, context.Background(), cfg, recordsSource(t, repeatedOrderError), nil)
	if err != nil || !strings.Contains(out, "Предпросмотр Telegram: report") || !strings.Contains(out, "С ошибкой: 1") {
		t.Fatalf("invalid digest preview: %v %s", err, out)
	}
}

func TestDigestSourceFailureReportsSavedPeriodWithCoverage(t *testing.T) {
	cfg := monitorConfig(t)
	cfg.ReportOnly = true
	calls := 0
	var reportStart time.Time
	cfg.BuildSnapshot = func(_ context.Context, start, end time.Time) (monitor.Snapshot, error) {
		calls++
		reportStart = start
		return digestSnapshot(cfg.Project, end, "order-a"), nil
	}
	if _, _, err := monitorCycle(t, context.Background(), cfg, recordsSource(t, repeatedOrderError), &monitorSender{}); err != nil {
		t.Fatal(err)
	}
	state := readMonitorState(t, cfg)
	state.LastReport, state.LastReportEnd = time.Now().Add(-2*time.Hour), time.Now().Add(-2*time.Hour)
	writeMonitorState(t, cfg, state)
	sender := &monitorSender{}
	source := monitorSourceFunc(func(context.Context, loki.Query) (model.FetchResult, error) {
		return model.FetchResult{}, errors.New("source unavailable")
	})
	if _, _, err := monitorCycle(t, context.Background(), cfg, source, sender); err == nil {
		t.Fatal("incomplete collection must be reported to once caller")
	}
	failed := readMonitorState(t, cfg)
	if calls != 2 || !failed.LastReport.After(state.LastReport) || !failed.LastReportEnd.After(state.LastReportEnd) || len(sender.messages) != 2 || !strings.Contains(sender.messages[0], "Нет подтвержденных данных Loki") || !strings.Contains(sender.messages[1], "Полнота") {
		t.Fatal("source failure failed to report the saved period with explicit coverage")
	}
	// Уведомление о восстановлении может ещё ожидать паузу между сообщениями о доступе.
	if _, _, err := monitorCycle(t, context.Background(), cfg, recordsSource(t, repeatedOrderError), sender); err != nil && !strings.Contains(err.Error(), "часть сообщений ожидает доставки") {
		t.Fatal(err)
	}
	if calls != 2 || !reportStart.Equal(state.LastReportEnd) {
		t.Fatal("recovery skipped failed collection period")
	}
}

func TestSummaryListsAllSmallResellerSetsAndNoArbitrarySubset(t *testing.T) {
	cfg := monitorConfig(t)
	cfg.ResellerNames = map[string]string{"reseller-a": "Company A", "reseller-b": "Company B"}
	sender := &monitorSender{}
	_, _, err := monitorCycle(t, context.Background(), cfg, recordsSource(t,
		repeatedOrderError,
		`{"context":"orders","orderId":"order-b","resellerId":"reseller-b","msg":"order create error order not found"}`,
	), sender)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"Company A (ID: reseller-a) — 1", "Company B (ID: reseller-b) — 1"} {
		if !strings.Contains(sender.messages[0], expected) {
			t.Fatalf("small complete reseller list missing %s: %s", expected, sender.messages[0])
		}
	}
	cfg = monitorConfig(t)
	sender = &monitorSender{}
	_, _, err = monitorCycle(t, context.Background(), cfg, recordsSource(t,
		repeatedOrderError,
		`{"context":"orders","orderId":"order-b","resellerId":"reseller-b","msg":"order create error order not found"}`,
		`{"context":"orders","orderId":"order-c","resellerId":"reseller-c","msg":"order create error order not found"}`,
	), sender)
	if err != nil || !strings.Contains(sender.messages[0], "Реселлеров: 3 · названия и ID — в TXT") || strings.Contains(sender.messages[0], "reseller-a") {
		t.Fatalf("long reseller list became arbitrary subset: %v %v", err, sender.messages)
	}
}
