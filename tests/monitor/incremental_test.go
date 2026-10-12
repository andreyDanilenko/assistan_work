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

func TestIncrementalCommitsEveryPortionAndNewSessionSkipsOutageAfterReopen(t *testing.T) {
	cfg, path, store := incrementalConfig(t)
	cfg.Interval = 3 * time.Minute
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
		if calls >= 2 {
			durableEnd = q.Start
			return model.FetchResult{}, errors.New("offline")
		}
		return model.FetchResult{Complete: true, Records: []model.LogRecord{{Project: q.Project, Timestamp: q.Start, Line: repeatedOrderError}}}, nil
	})
	sender := &monitorSender{}
	if _, _, err := archiveCycle(t, context.Background(), cfg, source, sender, store); err == nil {
		t.Fatal("outage must fail the one-shot command")
	}
	if calls != 2 || readMonitorState(t, cfg).NoLogs {
		t.Fatal("failed request was retried or claimed absent logs")
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
	// Перезапуск открывает новую сессию: старый неподтверждённый хвост
	// остаётся пробелом, но не становится обязанностью нового процесса.
	cfg.SessionStart = time.Now().UTC().Add(-30 * time.Second)
	calls = 0
	source = monitorSourceFunc(func(_ context.Context, q loki.Query) (model.FetchResult, error) {
		calls++
		if q.Start.Before(cfg.SessionStart) || (calls == 1 && !q.Start.Equal(cfg.SessionStart)) {
			t.Fatalf("new session backfilled the outage: %s want %s", q.Start, cfg.SessionStart)
		}
		return model.FetchResult{Complete: true}, nil
	})
	_, _, err = archiveCycle(t, context.Background(), cfg, source, &monitorSender{}, store)
	if err != nil && !strings.Contains(err.Error(), "часть сообщений ожидает доставки") {
		t.Fatal(err)
	}
	if readMonitorState(t, cfg).SourceFailed {
		t.Fatal("successful fresh cycle retained source failure")
	}
	_, coverage, err = storage.ReadRange(context.Background(), path, storage.Query{SourceID: cfg.SourceID, Project: cfg.Project, Start: durableEnd, End: cfg.SessionStart})
	if err != nil || len(coverage.Gaps) != 1 || !coverage.Gaps[0].Start.Equal(durableEnd) || !coverage.Gaps[0].End.Equal(cfg.SessionStart) {
		t.Fatalf("new session claimed the skipped outage: %v %+v", err, coverage)
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
	coverage, err := store.Coverage(context.Background(), model.LogRange{SourceID: cfg.SourceID, Project: cfg.Project, Start: firstStart, End: splitEnd.Add(time.Minute)})
	if err != nil || len(coverage.Gaps) != 1 || !coverage.Gaps[0].Start.Equal(splitEnd) || calls != 3 {
		t.Fatalf("partial prefix was lost or failed sibling confirmed: %v %+v calls=%d", err, coverage, calls)
	}
}

func TestLiveEmptyWindowLeavesOlderDowntimeUnconfirmed(t *testing.T) {
	cfg, _, store := incrementalConfig(t)
	defer store.Close()
	now := time.Now().UTC()
	cfg.SessionStart = now.Add(-6 * time.Hour)
	old := model.LogRange{SourceID: cfg.SourceID, Project: cfg.Project, Start: cfg.SessionStart, End: cfg.SessionStart.Add(time.Minute)}
	if err := store.SaveRange(context.Background(), old, nil, now); err != nil {
		t.Fatal(err)
	}
	var queries []loki.Query
	source := monitorSourceFunc(func(_ context.Context, q loki.Query) (model.FetchResult, error) {
		queries = append(queries, q)
		return model.FetchResult{Complete: true}, nil
	})
	sender := &monitorSender{}
	output, _, err := archiveCycle(t, context.Background(), cfg, source, sender, store)
	if err != nil || len(queries) != 1 || !strings.Contains(output, "Текущий сбор полный: true") {
		t.Fatalf("live collection failed or fetched historical backlog: %v queries=%+v %s", err, queries, output)
	}
	if queries[0].Start.Before(now.Add(-10*time.Second-cfg.Interval)) || queries[0].End.Sub(queries[0].Start) != cfg.Interval {
		t.Fatalf("live window grew with historical downtime: %+v", queries)
	}
	state := readMonitorState(t, cfg)
	if state.SourceFailed || state.NoLogs || state.LastComplete.IsZero() || len(sender.messages) != 1 || strings.Contains(sender.messages[0], "🟡 Логи не поступают") || !strings.Contains(sender.messages[0], "Не подтверждено") {
		t.Fatalf("fresh empty window concealed older gaps: %+v %v", state, sender.messages)
	}
	coverage, err := store.Coverage(context.Background(), model.LogRange{SourceID: cfg.SourceID, Project: cfg.Project, Start: old.End, End: queries[0].End})
	if err != nil || len(coverage.Gaps) != 1 || !coverage.Gaps[0].Start.Equal(old.End) || !coverage.Gaps[0].End.Equal(queries[0].Start) {
		t.Fatalf("live collection filled historical downtime: %v %+v", err, coverage)
	}
}

func TestFreshWindowDeduplicatesRepeatedRecords(t *testing.T) {
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
	if len(queries) != 1 || queries[0].End.Sub(queries[0].Start) != cfg.Interval || !queries[0].End.After(firstEnd) {
		t.Fatalf("next cycle did not fetch its fresh rolling window: %+v", queries)
	}
	archived, coverage, err := storage.ReadRange(context.Background(), path, storage.Query{SourceID: cfg.SourceID, Project: cfg.Project, Start: stamp.Add(-time.Minute), End: firstEnd})
	if err != nil || len(archived) != 2 || len(coverage.Gaps) > 0 {
		t.Fatalf("fresh window lost a record or duplicated the original: %v %+v %+v", err, archived, coverage)
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
	coverage, err := store.Coverage(context.Background(), query)
	if err != nil || len(coverage.Gaps) != 1 || !coverage.Gaps[0].Start.Equal(query.Start) || !coverage.Gaps[0].End.Equal(query.End) {
		t.Fatalf("saturated interval was confirmed: %+v %v", coverage, err)
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
