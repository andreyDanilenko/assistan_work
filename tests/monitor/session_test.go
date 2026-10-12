package monitor_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"loki-analyzer/internal/loki"
	"loki-analyzer/internal/model"
	"loki-analyzer/internal/monitor"
	"loki-analyzer/internal/storage"
)

type sessionArchive struct {
	monitor.Archive
	resumes []model.LogRange
	probes  []model.LogRange
}

func (a *sessionArchive) Resume(ctx context.Context, query model.LogRange, now time.Time) (time.Time, error) {
	a.resumes = append(a.resumes, query)
	return time.Time{}, errors.New("live collector must not read a saved cursor")
}

func (a *sessionArchive) Coverage(ctx context.Context, query model.LogRange) (model.Coverage, error) {
	if query.End.Sub(query.Start) == time.Nanosecond {
		a.probes = append(a.probes, query)
	}
	return a.Archive.Coverage(ctx, query)
}

func TestNewSessionSkipsTenHourCursorAndLeavesDowntimeUnconfirmed(t *testing.T) {
	cfg, path, store := incrementalConfig(t)
	defer store.Close()
	now := time.Now().UTC()
	oldEnd := now.Add(-10 * time.Hour)
	old := model.LogRange{SourceID: cfg.SourceID, Project: cfg.Project, Start: oldEnd.Add(-time.Minute), End: oldEnd}
	if err := store.SaveRange(context.Background(), old, []model.LogRecord{{Project: cfg.Project, Timestamp: old.Start, Line: "retained old event"}}, now); err != nil {
		t.Fatal(err)
	}
	cfg.SessionStart = now.Add(-40 * time.Second)
	archive := &sessionArchive{Archive: store}
	var queries []loki.Query
	source := monitorSourceFunc(func(_ context.Context, q loki.Query) (model.FetchResult, error) {
		queries = append(queries, q)
		if q.Start.Before(cfg.SessionStart) {
			t.Fatalf("new session fetched downtime: %+v", q)
		}
		return model.FetchResult{Complete: true}, nil
	})
	if _, _, err := archiveCycle(t, context.Background(), cfg, source, &monitorSender{}, archive); err != nil {
		t.Fatal(err)
	}
	if len(queries) != 1 || !queries[0].Start.Equal(cfg.SessionStart) || len(archive.resumes) != 0 || len(archive.probes) != 0 {
		t.Fatalf("old cursor escaped the session floor: queries=%+v resumes=%+v probes=%+v", queries, archive.resumes, archive.probes)
	}
	coverage, err := store.Coverage(context.Background(), model.LogRange{SourceID: cfg.SourceID, Project: cfg.Project, Start: oldEnd, End: cfg.SessionStart})
	if err != nil || len(coverage.Gaps) != 1 || !coverage.Gaps[0].Start.Equal(oldEnd) || !coverage.Gaps[0].End.Equal(cfg.SessionStart) {
		t.Fatalf("skipped downtime was confirmed: %v %+v", err, coverage)
	}
	rows, _, err := storage.ReadRange(context.Background(), path, storage.Query{SourceID: cfg.SourceID, Project: cfg.Project, Start: old.Start, End: old.End})
	if err != nil || len(rows) != 1 {
		t.Fatalf("starting a session erased retained history: %v %+v", err, rows)
	}
}

func TestRecentSessionWindowIgnoresCursorAndDeduplicates(t *testing.T) {
	for _, prefix := range []time.Duration{time.Nanosecond, 30 * time.Second} {
		t.Run(prefix.String(), func(t *testing.T) {
			cfg, path, store := incrementalConfig(t)
			defer store.Close()
			now := time.Now().UTC()
			cfg.SessionStart = now.Add(-70 * time.Second)
			cursor := cfg.SessionStart.Add(prefix)
			// Ранее сохранённое покрытие пересекает границу текущей сессии.
			prior := model.LogRange{SourceID: cfg.SourceID, Project: cfg.Project, Start: cfg.SessionStart.Add(-time.Minute), End: cursor}
			record := model.LogRecord{Project: cfg.Project, Timestamp: cfg.SessionStart, Line: "same event"}
			if err := store.SaveRange(context.Background(), prior, []model.LogRecord{record}, now); err != nil {
				t.Fatal(err)
			}
			archive := &sessionArchive{Archive: store}
			var queries []loki.Query
			source := monitorSourceFunc(func(_ context.Context, q loki.Query) (model.FetchResult, error) {
				queries = append(queries, q)
				if q.Start.Before(cfg.SessionStart) {
					t.Fatalf("fresh query crossed session start: %+v", q)
				}
				result := model.FetchResult{Complete: true}
				if record.Timestamp.Equal(q.Start) {
					result.Records = []model.LogRecord{record}
				}
				return result, nil
			})
			if _, _, err := archiveCycle(t, context.Background(), cfg, source, &monitorSender{}, archive); err != nil {
				t.Fatal(err)
			}
			if len(queries) != 1 || !queries[0].Start.Equal(cfg.SessionStart) || !queries[0].End.After(cursor) {
				t.Fatalf("recent window followed saved cursor instead of the session floor: %+v", queries)
			}
			if len(archive.probes) != 0 || len(archive.resumes) != 0 {
				t.Fatalf("live collection consulted historical progress: %+v %+v", archive.probes, archive.resumes)
			}
			rows, _, err := storage.ReadRange(context.Background(), path, storage.Query{SourceID: cfg.SourceID, Project: cfg.Project, Start: cfg.SessionStart, End: cursor})
			if err != nil || len(rows) != 1 {
				t.Fatalf("fresh query duplicated saved history: %v %+v", err, rows)
			}
		})
	}
}

func TestSameMonitorNeverBackfillsOldCursorAndNextCycleStartsFresh(t *testing.T) {
	for _, age := range []time.Duration{10 * time.Hour, 30 * time.Minute} {
		t.Run(age.String(), func(t *testing.T) {
			cfg, _, store := incrementalConfig(t)
			defer store.Close()
			now := time.Now().UTC()
			cfg.SessionStart = now.Add(-12 * time.Hour)
			cfg.Window = time.Minute // WATCH_WINDOW не задаёт глубину рабочего сбора.
			old := model.LogRange{SourceID: cfg.SourceID, Project: cfg.Project, Start: now.Add(-age - time.Minute), End: now.Add(-age)}
			if err := store.SaveRange(context.Background(), old, nil, now); err != nil {
				t.Fatal(err)
			}
			archive := &sessionArchive{Archive: store}
			phase := 0
			var queries [2][]loki.Query
			source := monitorSourceFunc(func(_ context.Context, q loki.Query) (model.FetchResult, error) {
				queries[phase] = append(queries[phase], q)
				if q.Start.Before(now.Add(-10*time.Second - cfg.Interval)) {
					t.Fatalf("same session fetched historical downtime: %+v", q)
				}
				if phase == 0 {
					return model.FetchResult{}, errors.New("current request unavailable")
				}
				return model.FetchResult{Complete: true}, nil
			})
			var out, diagnostic bytes.Buffer
			worker, err := monitor.New(cfg, source, &monitorSender{}, archive, &out, &diagnostic)
			if err != nil {
				t.Fatal(err)
			}
			if err := worker.Run(context.Background(), true); err == nil {
				t.Fatal("failed request was accepted")
			}
			phase = 1
			err = worker.Run(context.Background(), true)
			if err != nil && !strings.Contains(err.Error(), "часть сообщений ожидает доставки") {
				t.Fatal(err)
			}
			if len(queries[0]) != 1 || len(queries[1]) != 1 || !queries[1][0].Start.After(queries[0][0].Start) || queries[1][0].End.Sub(queries[1][0].Start) != cfg.Interval || len(archive.resumes) != 0 || len(archive.probes) != 0 {
				t.Fatalf("collector retried across cycles or consulted saved progress: queries=%+v resumes=%+v probes=%+v", queries, archive.resumes, archive.probes)
			}
			coverage, err := store.Coverage(context.Background(), model.LogRange{SourceID: cfg.SourceID, Project: cfg.Project, Start: old.End, End: queries[1][0].End})
			if err != nil || len(coverage.Gaps) != 1 || !coverage.Gaps[0].Start.Equal(old.End) || !coverage.Gaps[0].End.Equal(queries[1][0].Start) {
				t.Fatalf("live cycle incorrectly confirmed skipped history: %v %+v", err, coverage)
			}
		})
	}
}

func TestFreshSessionWaitsWithoutRequestingBeforeStartup(t *testing.T) {
	cfg, _, store := incrementalConfig(t)
	defer store.Close()
	cfg.SessionStart = time.Time{} // New должен один раз зафиксировать реальный запуск.
	archive := &sessionArchive{Archive: store}
	cfg.BuildSnapshot = func(context.Context, time.Time, time.Time) (monitor.Snapshot, error) {
		t.Fatal("fresh startup tried to report an invalid empty session")
		return monitor.Snapshot{}, nil
	}
	source := monitorSourceFunc(func(_ context.Context, q loki.Query) (model.FetchResult, error) {
		t.Fatalf("fresh startup requested pre-session logs: %+v", q)
		return model.FetchResult{}, nil
	})
	sender := &monitorSender{}
	if _, _, err := archiveCycle(t, context.Background(), cfg, source, sender, archive); err != nil {
		t.Fatal(err)
	}
	if len(archive.resumes) != 0 || len(sender.messages) != 0 {
		t.Fatalf("fresh startup advanced a cursor or sent an empty report: %+v %+v", archive.resumes, sender.messages)
	}
}

func TestDryRunStillPreviewsRollingWindowBeforeSessionStart(t *testing.T) {
	cfg := monitorConfig(t)
	cfg.DryRun, cfg.ReportOnly, cfg.ChatID = true, true, 0
	cfg.SessionStart = time.Now().UTC()
	var first, last time.Time
	source := monitorSourceFunc(func(_ context.Context, q loki.Query) (model.FetchResult, error) {
		if first.IsZero() {
			first = q.Start
		}
		last = q.End
		return model.FetchResult{Complete: true}, nil
	})
	if _, _, err := archiveCycle(t, context.Background(), cfg, source, nil, nil); err != nil {
		t.Fatal(err)
	}
	if first.IsZero() || !first.Before(cfg.SessionStart) || last.Sub(first) != cfg.Window {
		t.Fatalf("dry-run lost its rolling preview window: %s — %s", first, last)
	}
}

func TestNewSessionDigestClampsSavedAndPendingReportBeginnings(t *testing.T) {
	for _, saved := range []string{"last report", "failed build", "pending delivery"} {
		t.Run(saved, func(t *testing.T) {
			cfg, _, store := incrementalConfig(t)
			defer store.Close()
			// Состояние уведомлений получаем обычным запуском; SQLite остаётся
			// пустой, поэтому новый процесс начинает сбор с новой границы.
			if _, _, err := monitorCycle(t, context.Background(), cfg, recordsSource(t), &monitorSender{}); err != nil {
				t.Fatal(err)
			}
			state := readMonitorState(t, cfg)
			state.LastReport = time.Now().Add(-time.Hour)
			state.LastReportEnd = time.Now().Add(-time.Hour)
			state.Pending = nil
			switch saved {
			case "failed build":
				state.LastReportEnd = time.Time{}
				state.NextReportStart = time.Now().Add(-2 * time.Hour)
			case "pending delivery":
				state.Pending = []monitor.Message{{Kind: "report", Text: "OLD_REPORT", ReportStart: time.Now().Add(-6 * time.Hour), ReportEnd: state.LastReportEnd, NextTry: time.Now().Add(-time.Minute)}}
			}
			writeMonitorState(t, cfg, state)
			cfg.SessionStart = time.Now().UTC().Add(-30 * time.Second)
			build := cfg.BuildSnapshot
			var reportStart time.Time
			cfg.BuildSnapshot = func(ctx context.Context, start, end time.Time) (monitor.Snapshot, error) {
				reportStart = start
				return build(ctx, start, end)
			}
			sender := &reportSender{}
			source := monitorSourceFunc(func(_ context.Context, q loki.Query) (model.FetchResult, error) {
				return model.FetchResult{Complete: true, Records: []model.LogRecord{{Project: q.Project, Timestamp: q.Start, Line: repeatedOrderError}}}, nil
			})
			if _, _, err := archiveCycle(t, context.Background(), cfg, source, sender, store); err != nil {
				t.Fatal(err)
			}
			if !reportStart.Equal(cfg.SessionStart) || len(sender.starts) != 1 || !sender.starts[0].Equal(cfg.SessionStart) || strings.Contains(sender.messages[0], "OLD_REPORT") || !strings.Contains(sender.messages[0], "С ошибкой: 1") {
				t.Fatalf("saved report state pulled the new digest into downtime: start=%s buttons=%+v messages=%+v", reportStart, sender.starts, sender.messages)
			}
		})
	}
}

func TestFailedCurrentRequestIsNeverRetried(t *testing.T) {
	for _, dryRun := range []bool{false, true} {
		name := "production"
		if dryRun {
			name = "dry run"
		}
		t.Run(name, func(t *testing.T) {
			cfg, path, store := incrementalConfig(t)
			defer store.Close()
			cfg.DryRun = dryRun
			var queries []loki.Query
			source := monitorSourceFunc(func(_ context.Context, q loki.Query) (model.FetchResult, error) {
				queries = append(queries, q)
				if len(queries) == 1 {
					// Даже Complete=true нельзя сохранить вместе с ошибкой.
					return model.FetchResult{Complete: true, Records: []model.LogRecord{{Project: q.Project, Timestamp: q.Start, Line: "discard failed response"}}}, errors.New("temporary transport failure")
				}
				return model.FetchResult{Complete: true}, nil
			})
			_, _, err := archiveCycle(t, context.Background(), cfg, source, &monitorSender{}, store)
			if err == nil || len(queries) != 1 {
				t.Fatalf("failed current request was retried or accepted: calls=%d err=%v", len(queries), err)
			}
			rows, coverage, err := storage.ReadRange(context.Background(), path, storage.Query{SourceID: cfg.SourceID, Project: cfg.Project, Start: queries[0].Start, End: queries[0].End})
			if err != nil || len(rows) != 0 || len(coverage.Gaps) != 1 || !coverage.Gaps[0].Start.Equal(queries[0].Start) || !coverage.Gaps[0].End.Equal(queries[0].End) {
				t.Fatalf("archive saved or confirmed a failed response: %v rows=%+v coverage=%+v", err, rows, coverage)
			}
		})
	}
}

func TestCurrentRequestDoesNotRetryAfterCancellationOrCycleDeadline(t *testing.T) {
	for _, parentCancelled := range []bool{false, true} {
		name := "cycle deadline"
		if parentCancelled {
			name = "parent canceled"
		}
		t.Run(name, func(t *testing.T) {
			cfg := monitorConfig(t)
			cfg.Timeout = 20 * time.Millisecond
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			source := monitorSourceFunc(func(ctx context.Context, _ loki.Query) (model.FetchResult, error) {
				calls++
				if parentCancelled {
					cancel()
				}
				<-ctx.Done()
				return model.FetchResult{}, ctx.Err()
			})
			_, _, err := monitorCycle(t, ctx, cfg, source, &monitorSender{})
			if calls != 1 || err == nil || (parentCancelled && !errors.Is(err, context.Canceled)) {
				t.Fatalf("expired request was retried or accepted: calls=%d err=%v", calls, err)
			}
		})
	}
}

func TestCurrentWindowSplittingSharesOneRequestAndTimeBudget(t *testing.T) {
	cfg := monitorConfig(t)
	// Dry-run не тратит время на SQLite и проверяет тот же collect.
	cfg.DryRun, cfg.ReportOnly = true, true
	cfg.Timeout = time.Second
	calls := 0
	var sharedDeadline time.Time
	source := monitorSourceFunc(func(ctx context.Context, q loki.Query) (model.FetchResult, error) {
		calls++
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > cfg.Timeout || (!sharedDeadline.IsZero() && !deadline.Equal(sharedDeadline)) {
			t.Fatalf("splitting renewed the shared cycle deadline: %s want %s", deadline, sharedDeadline)
		}
		sharedDeadline = deadline
		return model.FetchResult{Complete: q.End.Sub(q.Start) <= time.Second}, nil
	})
	output, _, err := monitorCycle(t, context.Background(), cfg, source, nil)
	if err == nil || calls != 64 || !strings.Contains(output, "Текущий сбор полный: false") {
		t.Fatalf("recursive splitting escaped the current cycle budget: calls=%d err=%v output=%s", calls, err, output)
	}
}
