package monitor_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"loki-analyzer/internal/loki"
	"loki-analyzer/internal/model"
	"loki-analyzer/internal/monitor"
)

// Пустой адаптер сохраняет независимость остальных тестов монитора от SQLite.
// В сценариях архива функции проверяют порядок и содержимое вызовов.
type monitorArchive struct {
	cursor  time.Time
	ranges  []model.TimeRange
	records []model.LogRecord
	save    func(context.Context, string, []model.LogRecord, time.Time) error
	prune   func(context.Context, time.Time) (int64, error)
}

func (a *monitorArchive) Resume(_ context.Context, query model.LogRange, now time.Time) (time.Time, error) {
	if a.cursor.IsZero() || a.cursor.Before(query.Start) {
		a.cursor = query.Start
	}
	if a.cursor.Before(now.Add(-48 * time.Hour)) {
		a.cursor = now.Add(-48 * time.Hour)
	}
	return a.cursor, nil
}
func (a *monitorArchive) SaveRange(ctx context.Context, query model.LogRange, records []model.LogRecord, receivedAt time.Time) error {
	if a.save != nil {
		if err := a.save(ctx, query.SourceID, records, receivedAt); err != nil {
			return err
		}
	}
	for _, record := range records {
		duplicate := false
		for _, stored := range a.records {
			if reflect.DeepEqual(stored, record) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			a.records = append(a.records, record)
		}
	}
	a.ranges = append(a.ranges, model.TimeRange{Start: query.Start, End: query.End})
	sort.Slice(a.ranges, func(i, j int) bool { return a.ranges[i].Start.Before(a.ranges[j].Start) })
	for _, part := range a.ranges {
		if !part.Start.After(a.cursor) && part.End.After(a.cursor) {
			a.cursor = part.End
		}
	}
	return nil
}
func (a *monitorArchive) Coverage(_ context.Context, query model.LogRange) (model.Coverage, error) {
	coverage := model.Coverage{Known: true}
	cursor := query.Start
	for _, part := range a.ranges {
		if !part.End.After(cursor) || !part.Start.Before(query.End) {
			continue
		}
		if part.Start.After(cursor) {
			coverage.Gaps = append(coverage.Gaps, model.TimeRange{Start: cursor, End: part.Start})
		}
		cursor = part.End
		if !cursor.Before(query.End) {
			break
		}
	}
	if cursor.Before(query.End) {
		coverage.Gaps = append(coverage.Gaps, model.TimeRange{Start: cursor, End: query.End})
	}
	return coverage, nil
}
func (a *monitorArchive) Latest(_ context.Context, _, project string, end time.Time) (time.Time, error) {
	var latest time.Time
	for _, record := range a.records {
		if record.Project == project && record.Timestamp.Before(end) && record.Timestamp.After(latest) {
			latest = record.Timestamp
		}
	}
	return latest, nil
}
func (a *monitorArchive) readWindow(_ context.Context, start, end time.Time) ([]model.LogRecord, error) {
	var records []model.LogRecord
	for _, record := range a.records {
		if !record.Timestamp.Before(start) && record.Timestamp.Before(end) {
			records = append(records, record)
		}
	}
	return records, nil
}

func (a *monitorArchive) Prune(ctx context.Context, now time.Time) (int64, error) {
	if a.prune != nil {
		return a.prune(ctx, now)
	}
	return 0, nil
}

type archiveSenderFunc func(context.Context, int64, string) error

func (f archiveSenderFunc) SendMessage(ctx context.Context, chatID int64, text string) error {
	return f(ctx, chatID, text)
}

func archiveCycle(t *testing.T, ctx context.Context, cfg monitor.Config, source monitor.Source, sender monitor.Sender, archive monitor.Archive) (string, string, error) {
	t.Helper()
	var output, diagnostic bytes.Buffer
	if memory, ok := archive.(*monitorArchive); ok {
		cfg.ReadWindow = memory.readWindow
	}
	worker, err := monitor.New(cfg, source, sender, archive, &output, &diagnostic)
	if err == nil {
		err = worker.Run(ctx, true)
	}
	return output.String(), diagnostic.String(), err
}

func TestArchiveIsRequiredForSendingButNotDryRun(t *testing.T) {
	cfg := monitorConfig(t)
	var output, diagnostic bytes.Buffer
	if _, err := monitor.New(cfg, recordsSource(t), &monitorSender{}, nil, &output, &diagnostic); err == nil {
		t.Fatal("monitor allowed production collection without an archive")
	}
	cfg.DryRun, cfg.ChatID = true, 0
	if _, err := monitor.New(cfg, recordsSource(t), nil, nil, &output, &diagnostic); err != nil {
		t.Fatalf("dry-run unexpectedly requires storage: %v", err)
	}
}

func TestArchivePreservesAllCompleteRecordsBeforeAnalysisAndSending(t *testing.T) {
	cfg := monitorConfig(t)
	cfg.Window = 2 * time.Minute
	cfg.SessionStart = time.Now().UTC().Add(-2 * time.Minute)
	cfg.NoLogsAfter = 2 * time.Minute
	cfg.Include, cfg.Exclude = "KEEP", "IGNORE"
	var sequence []string
	var original []model.LogRecord
	var fetchedAt time.Time
	before := time.Now()
	archive := &monitorArchive{
		prune: func(ctx context.Context, now time.Time) (int64, error) {
			sequence = append(sequence, "prune")
			if ctx.Err() != nil || now.Before(before) || now.After(time.Now()) {
				t.Fatal("cleanup did not receive current wall-clock time")
			}
			return 2, nil
		},
		save: func(ctx context.Context, sourceID string, records []model.LogRecord, receivedAt time.Time) error {
			sequence = append(sequence, "save")
			if ctx.Err() != nil || sourceID != cfg.SourceID || !reflect.DeepEqual(records, original) {
				t.Fatal("archive lost source identity, raw records, labels or metadata")
			}
			if receivedAt.Before(fetchedAt) || receivedAt.After(time.Now()) {
				t.Fatal("received_at must be taken after fetch, not from the start of the cycle")
			}
			return nil
		},
	}
	source := monitorSourceFunc(func(ctx context.Context, q loki.Query) (model.FetchResult, error) {
		sequence = append(sequence, "fetch")
		if !q.Start.Equal(cfg.SessionStart) || q.End.Sub(q.Start) > cfg.NoLogsAfter {
			t.Fatal("expected collection within the current session")
		}
		original = []model.LogRecord{
			{Project: q.Project, Timestamp: q.End.Add(-90 * time.Second), Line: `old event with secret payload`, Labels: map[string]string{"pod": "old-pod"}},
			{Project: q.Project, Timestamp: q.End.Add(-time.Second), Line: `{"orderId":"order-a","msg":"FATAL KEEP"}`, Metadata: map[string]string{"trace": "trace-a"}},
			{Project: q.Project, Timestamp: q.End.Add(-2 * time.Second), Line: `{"orderId":"order-b","msg":"FATAL KEEP IGNORE"}`, Labels: map[string]string{"unknown_label": "retained"}},
			{Project: q.Project, Timestamp: q.End.Add(-3 * time.Second), Line: `unsupported non-JSON record`, Metadata: map[string]string{"unknown_metadata": "retained"}},
		}
		fetchedAt = time.Now()
		return model.FetchResult{Complete: true, Records: original}, nil
	})
	sender := archiveSenderFunc(func(context.Context, int64, string) error {
		sequence = append(sequence, "send")
		return nil
	})
	output, _, err := archiveCycle(t, context.Background(), cfg, source, sender, archive)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(sequence, []string{"prune", "fetch", "save", "send"}) {
		t.Fatalf("archive must commit before analysis output and delivery: %v", sequence)
	}
	if !strings.Contains(output, "Ошибок: 2") {
		t.Fatalf("summary must cover the whole period independently of notification filters: %s", output)
	}
}

func TestArchivePrunesIncompleteAndEmptyCyclesButNeverSavesPartialRecords(t *testing.T) {
	for _, kind := range []string{"fetch error", "partial", "empty complete"} {
		t.Run(kind, func(t *testing.T) {
			cfg := monitorConfig(t)
			var sequence []string
			archive := &monitorArchive{
				prune: func(context.Context, time.Time) (int64, error) {
					sequence = append(sequence, "prune")
					return 0, nil
				},
				save: func(_ context.Context, _ string, records []model.LogRecord, _ time.Time) error {
					sequence = append(sequence, "save")
					if kind != "empty complete" || len(records) != 0 {
						t.Fatal("unconfirmed rows reached archive")
					}
					return nil
				},
			}
			source := monitorSourceFunc(func(context.Context, loki.Query) (model.FetchResult, error) {
				sequence = append(sequence, "fetch")
				if kind == "empty complete" {
					return model.FetchResult{Complete: true}, nil
				}
				result := model.FetchResult{Complete: false, Records: []model.LogRecord{{Line: "unconfirmed record"}}}
				if kind == "fetch error" {
					return result, errors.New("source unavailable")
				}
				return result, nil
			})
			for run := 0; run < 2; run++ {
				sequence = nil
				_, _, err := archiveCycle(t, context.Background(), cfg, source, &monitorSender{}, archive)
				if (err == nil) != (kind == "empty complete") {
					t.Fatalf("unexpected one-shot result: %v", err)
				}
				if len(sequence) < 2 || sequence[0] != "prune" || sequence[1] != "fetch" {
					t.Fatalf("cleanup must run before Loki on every startup: %v", sequence)
				}
				if kind != "empty complete" {
					for _, step := range sequence {
						if step == "save" {
							t.Fatalf("partial fetch was saved: %v", sequence)
						}
					}
				}
			}
		})
	}
}

func TestArchiveSaveFailureStopsNewAlertsAndHealthyReports(t *testing.T) {
	for _, line := range []string{`{"msg":"FATAL order failure"}`, `{"msg":"ordinary event"}`} {
		t.Run(line, func(t *testing.T) {
			cfg := monitorConfig(t)
			saved := 0
			archive := &monitorArchive{save: func(context.Context, string, []model.LogRecord, time.Time) error {
				saved++
				return errors.New("archive unavailable")
			}}
			sender := &monitorSender{}
			output, _, err := archiveCycle(t, context.Background(), cfg, recordsSource(t, line), sender, archive)
			if err == nil || saved != 1 || len(sender.messages) != 0 || strings.Contains(output, "Полное окно") {
				t.Fatalf("failed write was reported as a successful observation: err=%v output=%s sent=%v", err, output, sender.messages)
			}
			if _, err := os.Stat(cfg.StateFile); err == nil {
				state := readMonitorState(t, cfg)
				if !state.LastComplete.IsZero() || len(state.Pending) != 0 {
					t.Fatal("uncommitted records advanced monitor state")
				}
			}
		})
	}
}

func TestArchivePruneFailureStopsBeforeFetchingOrSending(t *testing.T) {
	cfg := monitorConfig(t)
	archive := &monitorArchive{
		prune: func(context.Context, time.Time) (int64, error) { return 0, errors.New("cleanup unavailable") },
		save: func(context.Context, string, []model.LogRecord, time.Time) error {
			t.Fatal("save after failed cleanup")
			return nil
		},
	}
	source := monitorSourceFunc(func(context.Context, loki.Query) (model.FetchResult, error) {
		t.Fatal("fetch after failed cleanup")
		return model.FetchResult{}, nil
	})
	sender := &monitorSender{}
	output, _, err := archiveCycle(t, context.Background(), cfg, source, sender, archive)
	if err == nil || len(sender.messages) != 0 || strings.Contains(output, "Полное окно") {
		t.Fatal("cleanup failure did not stop the cycle")
	}
}

func TestArchiveDryRunDoesNotReadOrWriteArchiveAndState(t *testing.T) {
	cfg := monitorConfig(t)
	cfg.DryRun, cfg.ChatID = true, 0
	cfg.StateFile = filepath.Join(filepath.Dir(cfg.StateFile), "must-not-exist", "state.json")
	archive := &monitorArchive{
		prune: func(context.Context, time.Time) (int64, error) { t.Fatal("dry run pruned archive"); return 0, nil },
		save: func(context.Context, string, []model.LogRecord, time.Time) error {
			t.Fatal("dry run saved records")
			return nil
		},
	}
	output, _, err := archiveCycle(t, context.Background(), cfg, recordsSource(t, repeatedOrderError), nil, archive)
	if err != nil || !strings.Contains(output, "Предпросмотр Telegram") {
		t.Fatalf("dry run failed: %v", err)
	}
	if _, err := os.Stat(filepath.Dir(cfg.StateFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("dry run created local state files")
	}
}

func TestArchiveCancellationPreventsDatabaseMutation(t *testing.T) {
	cfg := monitorConfig(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	archive := &monitorArchive{
		prune: func(context.Context, time.Time) (int64, error) { t.Fatal("canceled run pruned archive"); return 0, nil },
		save: func(context.Context, string, []model.LogRecord, time.Time) error {
			t.Fatal("canceled run saved records")
			return nil
		},
	}
	source := monitorSourceFunc(func(context.Context, loki.Query) (model.FetchResult, error) {
		t.Fatal("canceled run fetched records")
		return model.FetchResult{}, nil
	})
	sender := &monitorSender{}
	output, diagnostic, err := archiveCycle(t, ctx, cfg, source, sender, archive)
	if !errors.Is(err, context.Canceled) || output != "" || diagnostic != "" || len(sender.messages) != 0 {
		t.Fatalf("canceled cycle performed work: %v", err)
	}
}
