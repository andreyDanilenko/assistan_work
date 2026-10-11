package monitor_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"loki-analyzer/internal/loki"
	"loki-analyzer/internal/model"
	"loki-analyzer/internal/monitor"
	"loki-analyzer/internal/storage"
)

func incrementalConfig(t *testing.T) (monitor.Config, string, *storage.Store) {
	t.Helper()
	cfg := monitorConfig(t)
	cfg.ReportOnly, cfg.ReportInterval, cfg.Timeout = true, 15*time.Minute, 10*time.Second
	path := filepath.Join(t.TempDir(), "logs.sqlite")
	store, err := storage.Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	cfg.BuildSnapshot = func(ctx context.Context, start, end time.Time) (monitor.Snapshot, error) {
		records, coverage, err := storage.ReadRange(ctx, path, storage.Query{SourceID: cfg.SourceID, Project: cfg.Project, Start: start, End: end})
		snapshot := monitor.Analyze(records, monitor.Filter{})
		snapshot.Coverage = coverage
		return snapshot, err
	}
	return cfg, path, store
}

func TestIncrementalCommitsEveryPortionAndResumesAfterOutageAndReopen(t *testing.T) {
	cfg, path, store := incrementalConfig(t)
	var initialStart, durableEnd time.Time
	calls := 0
	source := monitorSourceFunc(func(ctx context.Context, q loki.Query) (model.FetchResult, error) {
		calls++
		if q.End.Sub(q.Start) > 2*time.Minute {
			t.Fatal("collector requested more than one portion")
		}
		if calls == 1 {
			initialStart = q.Start
		} else {
			// Чтение отдельным соединением доказывает commit до следующего FetchLogs.
			_, coverage, err := storage.ReadRange(ctx, path, storage.Query{SourceID: cfg.SourceID, Project: cfg.Project, Start: initialStart, End: q.Start})
			if err != nil || !coverage.Known || len(coverage.Gaps) > 0 {
				t.Fatalf("previous portion was not durably committed: %v %+v", err, coverage)
			}
		}
		if calls == 3 {
			durableEnd = q.Start
			return model.FetchResult{}, errors.New("offline")
		}
		return model.FetchResult{Complete: true, Records: []model.LogRecord{{Project: q.Project, Timestamp: q.Start, Line: repeatedOrderError}}}, nil
	})
	sender := &monitorSender{}
	if _, _, err := archiveCycle(t, context.Background(), cfg, source, sender, store); err == nil {
		t.Fatal("outage must fail the one-shot command")
	}
	if calls != 3 || readMonitorState(t, cfg).NoLogs {
		t.Fatal("outage retried within cycle or claimed absent logs")
	}
	_, coverage, err := storage.ReadRange(context.Background(), path, storage.Query{SourceID: cfg.SourceID, Project: cfg.Project, Start: initialStart, End: durableEnd.Add(time.Minute)})
	if err != nil || len(coverage.Gaps) != 1 || !coverage.Gaps[0].Start.Equal(durableEnd) {
		t.Fatalf("failed portion was confirmed: %v %+v", err, coverage)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = storage.Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	calls = 0
	source = monitorSourceFunc(func(_ context.Context, q loki.Query) (model.FetchResult, error) {
		calls++
		if calls == 2 && !q.Start.Equal(durableEnd) {
			t.Fatalf("restart skipped unconfirmed range: %s want %s", q.Start, durableEnd)
		}
		return model.FetchResult{Complete: true}, nil
	})
	_, _, err = archiveCycle(t, context.Background(), cfg, source, &monitorSender{}, store)
	if err != nil && !strings.Contains(err.Error(), "часть сообщений ожидает доставки") {
		t.Fatal(err)
	}
	if readMonitorState(t, cfg).SourceFailed {
		t.Fatal("successful retry retained source failure")
	}
}

func TestIncrementalSplitsPartialResponseAndCommitsChildBeforeSiblingFailure(t *testing.T) {
	cfg, path, store := incrementalConfig(t)
	defer store.Close()
	var firstStart, splitEnd time.Time
	calls := 0
	source := monitorSourceFunc(func(ctx context.Context, q loki.Query) (model.FetchResult, error) {
		calls++
		switch calls {
		case 1:
			firstStart = q.Start
			return model.FetchResult{Complete: false, Records: []model.LogRecord{{Project: q.Project, Timestamp: q.Start, Line: "unconfirmed"}}}, nil
		case 2:
			if !q.Start.Equal(firstStart) || q.End.Sub(q.Start) != time.Minute {
				t.Fatal("partial response was not divided")
			}
			splitEnd = q.End
			return model.FetchResult{Complete: true, Records: []model.LogRecord{{Project: q.Project, Timestamp: q.Start, Line: "confirmed"}}}, nil
		default:
			if !q.Start.Equal(splitEnd) {
				t.Fatal("did not attempt adjacent second half")
			}
			records, coverage, err := storage.ReadRange(ctx, path, storage.Query{SourceID: cfg.SourceID, Project: cfg.Project, Start: firstStart, End: splitEnd})
			if err != nil || len(records) != 1 || records[0].Line != "confirmed" || len(coverage.Gaps) != 0 {
				t.Fatalf("successful child did not commit independently: %v %+v %+v", err, records, coverage)
			}
			return model.FetchResult{}, errors.New("offline sibling")
		}
	})
	if _, _, err := archiveCycle(t, context.Background(), cfg, source, &monitorSender{}, store); err == nil {
		t.Fatal("partial sibling failure should fail once")
	}
	cursor, err := store.Resume(context.Background(), model.LogRange{SourceID: cfg.SourceID, Project: cfg.Project, Start: firstStart, End: splitEnd.Add(time.Minute)}, time.Now())
	if err != nil || !cursor.Equal(splitEnd) || calls != 3 {
		t.Fatalf("partial prefix was lost or sibling skipped: %v %s calls=%d", err, cursor, calls)
	}
}

func TestIncrementalEmptyCatchupIsBoundedAndDoesNotClaimNoRecentLogs(t *testing.T) {
	cfg, _, store := incrementalConfig(t)
	defer store.Close()
	now := time.Now()
	start := now.Add(-6 * time.Hour)
	query := model.LogRange{SourceID: cfg.SourceID, Project: cfg.Project, Start: start, End: now.Add(-time.Minute)}
	if _, err := store.Resume(context.Background(), query, now); err != nil {
		t.Fatal(err)
	}
	calls := 0
	source := monitorSourceFunc(func(_ context.Context, q loki.Query) (model.FetchResult, error) {
		calls++
		return model.FetchResult{Complete: true}, nil
	})
	sender := &monitorSender{}
	output, _, err := archiveCycle(t, context.Background(), cfg, source, sender, store)
	if err != nil || calls != 64 || !strings.Contains(output, "Догрузка: true") {
		t.Fatalf("backlog was unbounded or treated as source failure: %v calls=%d %s", err, calls, output)
	}
	state := readMonitorState(t, cfg)
	if state.SourceFailed || state.NoLogs || !state.LastComplete.IsZero() || len(sender.messages) != 1 || strings.Contains(sender.messages[0], "🟡 Логи не поступают") || !strings.Contains(sender.messages[0], "Не подтверждено") {
		t.Fatalf("historical empty portions reported a healthy recent window: %+v %v", state, sender.messages)
	}
	cursor, err := store.Resume(context.Background(), query, time.Now())
	if err != nil || !cursor.Equal(start.Add(128*time.Minute)) {
		t.Fatalf("empty intervals did not advance durable cursor: %s %v", cursor, err)
	}
	coverage, err := store.Coverage(context.Background(), model.LogRange{SourceID: cfg.SourceID, Project: cfg.Project, Start: start, End: cursor})
	if err != nil || !coverage.Known || len(coverage.Gaps) > 0 {
		t.Fatalf("empty intervals lost confirmed coverage: %+v %v", coverage, err)
	}
}

func TestIncrementalOverlapFindsLateEventWithoutDuplicatingHistory(t *testing.T) {
	cfg, path, store := incrementalConfig(t)
	defer store.Close()
	stamp := time.Now().Add(-40 * time.Second)
	records := []model.LogRecord{{Project: cfg.Project, Timestamp: stamp, Line: repeatedOrderError}}
	var queries []loki.Query
	source := monitorSourceFunc(func(_ context.Context, q loki.Query) (model.FetchResult, error) {
		queries = append(queries, q)
		result := model.FetchResult{Complete: true}
		for _, record := range records {
			if !record.Timestamp.Before(q.Start) && record.Timestamp.Before(q.End) {
				result.Records = append(result.Records, record)
			}
		}
		return result, nil
	})
	if _, _, err := archiveCycle(t, context.Background(), cfg, source, &monitorSender{}, store); err != nil {
		t.Fatal(err)
	}
	firstEnd := readMonitorState(t, cfg).LastComplete
	records = append(records, model.LogRecord{Project: cfg.Project, Timestamp: stamp.Add(time.Second), Line: "late event"})
	queries = nil
	if _, _, err := archiveCycle(t, context.Background(), cfg, source, &monitorSender{}, store); err != nil {
		t.Fatal(err)
	}
	if len(queries) != 2 || !queries[1].Start.Equal(firstEnd) || !queries[0].Start.Equal(firstEnd.Add(-time.Minute)) || !queries[0].End.Equal(firstEnd) {
		t.Fatalf("restart fetched full window instead of tail and overlap: %+v", queries)
	}
	archived, coverage, err := storage.ReadRange(context.Background(), path, storage.Query{SourceID: cfg.SourceID, Project: cfg.Project, Start: stamp.Add(-time.Minute), End: firstEnd})
	if err != nil || len(archived) != 2 || len(coverage.Gaps) > 0 {
		t.Fatalf("overlap lost late event or duplicated original: %v %+v %+v", err, archived, coverage)
	}
}

func TestIncrementalSaturatedNanosecondStopsWithinBudgetAndKeepsGap(t *testing.T) {
	cfg, _, store := incrementalConfig(t)
	defer store.Close()
	calls := 0
	var start, smallestEnd time.Time
	source := monitorSourceFunc(func(_ context.Context, q loki.Query) (model.FetchResult, error) {
		calls++
		if calls == 1 {
			start = q.Start
		}
		smallestEnd = q.End
		return model.FetchResult{Complete: false}, nil
	})
	if _, _, err := archiveCycle(t, context.Background(), cfg, source, &monitorSender{}, store); err == nil {
		t.Fatal("saturated timestamp was silently accepted")
	}
	if calls > 64 || smallestEnd.Sub(start) != time.Nanosecond {
		t.Fatalf("adaptive subdivision did not terminate at minimum range: %d %s", calls, smallestEnd.Sub(start))
	}
	query := model.LogRange{SourceID: cfg.SourceID, Project: cfg.Project, Start: start, End: start.Add(time.Minute)}
	cursor, err := store.Resume(context.Background(), query, time.Now())
	if err != nil || !cursor.Equal(start) {
		t.Fatalf("saturated interval was skipped: %s %v", cursor, err)
	}
}

func TestIncrementalFailedOverlapIsRetriedAfterRestartBeforeAdvancing(t *testing.T) {
	cfg, path, store := incrementalConfig(t)
	original := time.Now().Add(-40 * time.Second)
	record := model.LogRecord{Project: cfg.Project, Timestamp: original, Line: "original event"}
	source := monitorSourceFunc(func(_ context.Context, q loki.Query) (model.FetchResult, error) {
		result := model.FetchResult{Complete: true}
		if !original.Before(q.Start) && original.Before(q.End) {
			result.Records = []model.LogRecord{record}
		}
		return result, nil
	})
	if _, _, err := archiveCycle(t, context.Background(), cfg, source, &monitorSender{}, store); err != nil {
		t.Fatal(err)
	}
	cursor := readMonitorState(t, cfg).LastComplete
	var failedQuery loki.Query
	source = monitorSourceFunc(func(_ context.Context, q loki.Query) (model.FetchResult, error) {
		failedQuery = q
		return model.FetchResult{}, errors.New("overlap unavailable")
	})
	if _, _, err := archiveCycle(t, context.Background(), cfg, source, &monitorSender{}, store); err == nil {
		t.Fatal("failed overlap accepted")
	}
	if !failedQuery.Start.Equal(cursor.Add(-time.Minute)) || !failedQuery.End.Equal(cursor) {
		t.Fatal("fresh range preceded overlap")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	var err error
	store, err = storage.Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	calls := 0
	source = monitorSourceFunc(func(_ context.Context, q loki.Query) (model.FetchResult, error) {
		calls++
		if calls == 1 {
			if !q.Start.Equal(failedQuery.Start) || !q.End.Equal(failedQuery.End) {
				t.Fatalf("failed overlap skipped after restart: %+v", q)
			}
			late := record
			late.Line = "late event"
			return model.FetchResult{Complete: true, Records: []model.LogRecord{record, late}}, nil
		}
		return model.FetchResult{Complete: true}, nil
	})
	_, _, err = archiveCycle(t, context.Background(), cfg, source, &monitorSender{}, store)
	if err != nil && !strings.Contains(err.Error(), "часть сообщений ожидает доставки") {
		t.Fatal(err)
	}
	records, _, err := storage.ReadRange(context.Background(), path, storage.Query{SourceID: cfg.SourceID, Project: cfg.Project, Start: cursor.Add(-time.Minute), End: cursor})
	if err != nil || len(records) != 2 {
		t.Fatalf("retry missed delayed event: %v %+v", err, records)
	}
}

func TestIncrementalOverlapStillRetriesWhenCursorOlderThanRollingWindow(t *testing.T) {
	cfg, path, store := incrementalConfig(t)
	defer store.Close()
	cursor := time.Now().Add(-2 * time.Hour)
	prior := model.LogRange{SourceID: cfg.SourceID, Project: cfg.Project, Start: cursor.Add(-cfg.Window), End: cursor}
	if err := store.SaveRange(context.Background(), prior, nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	failed := monitorSourceFunc(func(_ context.Context, q loki.Query) (model.FetchResult, error) {
		if !q.Start.Equal(cursor.Add(-time.Minute)) || !q.End.Equal(cursor) {
			t.Fatalf("old overlap skipped before retry: %+v", q)
		}
		return model.FetchResult{}, errors.New("old overlap unavailable")
	})
	if _, _, err := archiveCycle(t, context.Background(), cfg, failed, &monitorSender{}, store); err == nil {
		t.Fatal("failed overlap reported success")
	}
	// Новое окно короче предыдущего: сохранённая обязанность повтора не должна
	// исчезать вслед за скользящей границей после паузы между запусками.
	cfg.Window = time.Minute
	calls := 0
	retry := monitorSourceFunc(func(_ context.Context, q loki.Query) (model.FetchResult, error) {
		calls++
		if calls == 1 {
			if !q.Start.Equal(cursor.Add(-time.Minute)) || !q.End.Equal(cursor) {
				t.Fatalf("old overlap skipped on retry: %+v", q)
			}
			return model.FetchResult{Complete: true, Records: []model.LogRecord{{Project: cfg.Project, Timestamp: cursor.Add(-time.Second), Line: "late old event"}}}, nil
		}
		return model.FetchResult{Complete: true}, nil
	})
	_, _, err := archiveCycle(t, context.Background(), cfg, retry, &monitorSender{}, store)
	if err != nil && !strings.Contains(err.Error(), "часть сообщений ожидает доставки") {
		t.Fatal(err)
	}
	records, _, err := storage.ReadRange(context.Background(), path, storage.Query{SourceID: cfg.SourceID, Project: cfg.Project, Start: cursor.Add(-time.Minute), End: cursor})
	if err != nil || len(records) != 1 {
		t.Fatalf("long outage lost late event: %v %+v", err, records)
	}
}

func TestIncrementalDryRunCapsAggregatePreviewAndWritesNothing(t *testing.T) {
	for _, limit := range []string{"records", "bytes"} {
		t.Run(limit, func(t *testing.T) {
			cfg := monitorConfig(t)
			cfg.DryRun, cfg.ReportOnly, cfg.ChatID = true, true, 0
			cfg.Timeout = 10 * time.Second
			cfg.StateFile = filepath.Join(t.TempDir(), "must-not-exist", "watch.json")
			calls := 0
			// Значения меток тоже занимают память; длинная строка вне Line
			// проверяет, что лимит учитывает весь сырой контент, даже BytesRead=0.
			large := ""
			if limit == "bytes" {
				large = strings.Repeat("x", 22<<20)
			}
			source := monitorSourceFunc(func(_ context.Context, q loki.Query) (model.FetchResult, error) {
				calls++
				count := 40000
				if limit == "bytes" {
					count = 1
				}
				records := make([]model.LogRecord, count)
				for i := range records {
					records[i] = model.LogRecord{Project: q.Project, Timestamp: q.Start, Line: "ordinary event", Metadata: map[string]string{"large": large}}
				}
				return model.FetchResult{Complete: true, Records: records}, nil
			})
			_, diagnostic, err := archiveCycle(t, context.Background(), cfg, source, nil, nil)
			if err == nil || calls != 3 || !strings.Contains(diagnostic, "общий лимит 100000 записей или 64 МиБ") {
				t.Fatalf("dry-run aggregate cap was ignored: err=%v calls=%d diagnostic=%s", err, calls, diagnostic)
			}
			if _, err := os.Stat(filepath.Dir(cfg.StateFile)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("capped dry-run wrote state")
			}
		})
	}
}
