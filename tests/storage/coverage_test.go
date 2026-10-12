package storage_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	"loki-analyzer/internal/model"
	"loki-analyzer/internal/storage"
)

func saveRange(t *testing.T, store *storage.Store, query model.LogRange, records ...model.LogRecord) {
	t.Helper()
	if err := store.SaveRange(context.Background(), query, records, now); err != nil {
		t.Fatal(err)
	}
}

func assertCoverage(t *testing.T, store *storage.Store, query model.LogRange, gaps ...model.TimeRange) {
	t.Helper()
	coverage, err := store.Coverage(context.Background(), query)
	if err != nil || !coverage.Known || !reflect.DeepEqual(coverage.Gaps, gaps) {
		t.Fatalf("coverage: %+v, want %+v; %v", coverage, gaps, err)
	}
}

func assertCursor(t *testing.T, store *storage.Store, query model.LogRange, want time.Time) {
	t.Helper()
	cursor, err := store.Resume(context.Background(), query, now)
	if err != nil || !cursor.Equal(want) {
		t.Fatalf("resume=%v, want %v; %v", cursor, want, err)
	}
}

func TestResumeSameSessionFloorRetriesUnfinishedRange(t *testing.T) {
	store, _ := openStore(t)
	query := reportQuery()
	assertCursor(t, store, query, query.Start)
	// A failed first fetch saves nothing; the fixed session floor is retried.
	later := query
	later.End = later.End.Add(30 * time.Minute)
	assertCursor(t, store, later, query.Start)
	first := query
	first.End = first.Start.Add(10 * time.Minute)
	saveRange(t, store, first)
	// A later failed fetch resumes at the last confirmed boundary in this session.
	assertCursor(t, store, later, first.End)
	assertCoverage(t, store, later, model.TimeRange{Start: first.End, End: later.End})
}

func TestResumeNewSessionSkipsPriorCursorButPreservesHistoryAndGap(t *testing.T) {
	store, path := openStore(t)
	query := reportQuery()
	assertCursor(t, store, query, query.Start)
	first := query
	first.End = first.Start.Add(10 * time.Minute)
	entry := record(first.Start, "saved in previous session")
	saveRange(t, store, first, entry)
	assertCursor(t, store, query, first.End)
	store.Close()
	reopened, err := storage.Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	later := query
	later.Start = later.Start.Add(30 * time.Minute)
	assertCursor(t, reopened, later, later.Start)
	// Raising the durable cursor neither invents coverage nor modifies saved events.
	assertCursor(t, reopened, query, later.Start)
	assertCoverage(t, reopened, query, model.TimeRange{Start: first.End, End: query.End})
	logs, err := storage.ReadLogs(context.Background(), path, query)
	if err != nil || !reflect.DeepEqual(logs, []model.LogRecord{entry}) {
		t.Fatalf("new session changed saved history: %+v; %v", logs, err)
	}
	saveRange(t, reopened, later)
	assertCursor(t, reopened, later, query.End)
	assertCoverage(t, reopened, query, model.TimeRange{Start: first.End, End: later.Start})
	stats(t, reopened, 1, 1)
}

func TestRangeCoverageEmptyIntervalsContiguousCursorAndScopeIsolation(t *testing.T) {
	store, _ := openStore(t)
	query := reportQuery()
	assertCursor(t, store, query, query.Start)
	later := query
	later.Start = query.Start.Add(20 * time.Minute)
	later.End = query.Start.Add(40 * time.Minute)
	saveRange(t, store, later)
	assertCursor(t, store, query, query.Start)
	assertCoverage(t, store, query,
		model.TimeRange{Start: query.Start, End: later.Start}, model.TimeRange{Start: later.End, End: query.End})
	first := query
	first.End = query.Start.Add(20 * time.Minute)
	saveRange(t, store, first)
	assertCursor(t, store, query, later.End)
	last := query
	last.Start = query.Start.Add(35 * time.Minute)
	saveRange(t, store, last)
	assertCursor(t, store, query, query.End)
	assertCoverage(t, store, query)
	other := query
	other.SourceID = "other-source"
	assertCursor(t, store, other, query.Start)
	assertCoverage(t, store, other, model.TimeRange{Start: query.Start, End: query.End})
	other.SourceID, other.Project = query.SourceID, "other-project"
	assertCursor(t, store, other, query.Start)
	assertCoverage(t, store, other, model.TimeRange{Start: query.Start, End: query.End})
}

func TestSaveRangeOverlapKeepsMultiplicityAndHalfOpenBoundaries(t *testing.T) {
	store, path := openStore(t)
	query := reportQuery()
	entry := record(query.Start.Add(30*time.Minute), "same occurrence")
	first := query
	first.End = query.Start.Add(40 * time.Minute)
	saveRange(t, store, first, entry, entry)
	last := query
	last.Start = query.Start.Add(20 * time.Minute)
	saveRange(t, store, last, entry)
	saveRange(t, store, query, entry, entry, entry)
	logs, coverage, err := storage.ReadRange(context.Background(), path, query)
	if err != nil || len(logs) != 3 || !coverage.Known || len(coverage.Gaps) != 0 {
		t.Fatalf("range: %d %+v %v", len(logs), coverage, err)
	}
	db := rawDB(t, path)
	var intervals int
	if err := db.QueryRow("SELECT count(*) FROM collection_ranges").Scan(&intervals); err != nil || intervals != 1 {
		t.Fatalf("overlaps were not compacted: %d %v", intervals, err)
	}
	for _, bad := range []model.LogRecord{record(query.Start.Add(-time.Nanosecond), "before"), record(query.End, "end"), {Project: "other-project", Timestamp: entry.Timestamp}} {
		if err := store.SaveRange(context.Background(), query, []model.LogRecord{entry, bad}, now); err == nil {
			t.Fatal("invalid range batch accepted")
		}
	}
	stats(t, store, 1, 3)
}

func TestLatestUsesScopeAndExclusiveEnd(t *testing.T) {
	store, _ := openStore(t)
	query := reportQuery()
	entry := record(now.Add(-time.Minute), "latest")
	save(t, store, query.SourceID, now, entry, record(now, "excluded end"))
	save(t, store, "other-source", now, record(now.Add(-time.Second), "other"))
	other := record(now.Add(-time.Second), "other project")
	other.Project = "other-project"
	save(t, store, query.SourceID, now, other)
	got, err := store.Latest(context.Background(), query.SourceID, query.Project, query.End)
	if err != nil || !got.Equal(entry.Timestamp) {
		t.Fatalf("latest: %v %v", got, err)
	}
	got, err = store.Latest(context.Background(), query.SourceID, query.Project, entry.Timestamp)
	if err != nil || !got.IsZero() {
		t.Fatalf("exclusive end: %v %v", got, err)
	}
	assertCoverage(t, store, query, model.TimeRange{Start: query.Start, End: query.End})
}

func TestSaveRangeRollsBackRowsCoverageAndCursorOnDatabaseError(t *testing.T) {
	store, path := openStore(t)
	query := reportQuery()
	assertCursor(t, store, query, query.Start)
	db := rawDB(t, path)
	// The cursor update happens after both row and interval insertion.
	if _, err := db.Exec(`CREATE TRIGGER fail_cursor BEFORE UPDATE ON collection_progress
 WHEN NEW.cursor_ns > OLD.cursor_ns BEGIN SELECT RAISE(ABORT, 'private failure'); END`); err != nil {
		t.Fatal(err)
	}
	err := store.SaveRange(context.Background(), query, []model.LogRecord{record(query.Start, "must roll back")}, now)
	if err == nil {
		t.Fatal("injected write failure ignored")
	}
	if _, err := db.Exec("DROP TRIGGER fail_cursor"); err != nil {
		t.Fatal(err)
	}
	stats(t, store, 0, 0)
	assertCursor(t, store, query, query.Start)
	assertCoverage(t, store, query, model.TimeRange{Start: query.Start, End: query.End})
	// Retry is safe after rollback.
	saveRange(t, store, query, record(query.Start, "must roll back"))
	stats(t, store, 1, 1)
	assertCursor(t, store, query, query.End)
}

func TestSaveRangeFailedCommitDoesNotAdvanceDurableCursor(t *testing.T) {
	store, path := openStore(t)
	query := reportQuery()
	assertCursor(t, store, query, query.Start)
	reader, err := rawDB(t, path).Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Rollback()
	var n int
	if err := reader.QueryRow("SELECT count(*) FROM collection_progress").Scan(&n); err != nil {
		t.Fatal(err)
	}
	// DELETE journaling can write under a reader, but cannot commit until it exits.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	err = store.SaveRange(ctx, query, []model.LogRecord{record(query.Start, "uncommitted")}, now)
	if err == nil {
		t.Fatal("commit succeeded despite the held read snapshot")
	}
	reader.Rollback()
	stats(t, store, 0, 0)
	assertCursor(t, store, query, query.Start)
	assertCoverage(t, store, query, model.TimeRange{Start: query.Start, End: query.End})
}

func TestCoverageRetentionAndAncientResumeNeverClaimDiscardedHistory(t *testing.T) {
	store, path := openStore(t)
	query := reportQuery()
	saveRange(t, store, query, record(query.Start, "expires"), record(query.End.Add(-time.Nanosecond), "stays"))
	later := now.Add(storage.Retention - time.Hour/2)
	cutoff := later.Add(-storage.Retention)
	if _, err := store.Prune(context.Background(), later); err != nil {
		t.Fatal(err)
	}
	logs, coverage, err := storage.ReadRange(context.Background(), path, query)
	expected := []model.TimeRange{{Start: query.Start, End: cutoff}}
	if err != nil || len(logs) != 1 || !coverage.Known || !reflect.DeepEqual(coverage.Gaps, expected) {
		t.Fatalf("retention: %d %+v %v", len(logs), coverage, err)
	}
	later = now.Add(3 * storage.Retention)
	cursor, err := store.Resume(context.Background(), query, later)
	if err != nil || !cursor.Equal(later.Add(-storage.Retention)) {
		t.Fatalf("ancient cursor not clamped: %v %v", cursor, err)
	}
	if _, err := store.Prune(context.Background(), later); err != nil {
		t.Fatal(err)
	}
	assertCoverage(t, store, query, model.TimeRange{Start: query.Start, End: query.End})
	var progress int
	if err := rawDB(t, path).QueryRow("SELECT count(*) FROM collection_progress").Scan(&progress); err != nil || progress != 1 {
		t.Fatalf("durable progress lost: %d %v", progress, err)
	}
}

func TestSaveRangeRetentionTrimsExpiredPartAtomically(t *testing.T) {
	store, _ := openStore(t)
	cutoff := now.Add(-storage.Retention)
	query := model.LogRange{SourceID: "source", Project: "sds-orders", Start: cutoff.Add(-time.Minute), End: cutoff.Add(time.Minute)}
	saveRange(t, store, query, record(query.Start, "expired"), record(cutoff, "boundary"))
	stats(t, store, 1, 1)
	assertCoverage(t, store, query, model.TimeRange{Start: query.Start, End: cutoff})
	assertCursor(t, store, query, query.End)
}

func TestVersionOneReadOnlyUnknownCoverageThenMigrationPreservesRows(t *testing.T) {
	store, path := openStore(t)
	query := reportQuery()
	entry := record(query.Start, "legacy event")
	save(t, store, query.SourceID, now, entry, entry)
	store.Close()
	db := rawDB(t, path)
	if _, err := db.Exec("DROP INDEX log_events_scope_time; DROP TABLE collection_ranges; DROP TABLE collection_progress; PRAGMA user_version=1"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	logs, coverage, err := storage.ReadRange(context.Background(), path, query)
	if err != nil || len(logs) != 2 || coverage.Known || !reflect.DeepEqual(coverage.Gaps, []model.TimeRange{{Start: query.Start, End: query.End}}) {
		t.Fatalf("legacy: %d %+v %v", len(logs), coverage, err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("reading migrated legacy database")
	}
	migrated, err := storage.Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer migrated.Close()
	stats(t, migrated, 1, 2)
	assertCoverage(t, migrated, query, model.TimeRange{Start: query.Start, End: query.End})
	assertCursor(t, migrated, query, query.Start)
	saveRange(t, migrated, query, entry)
	stats(t, migrated, 1, 2)
	assertCoverage(t, migrated, query)
	var version int
	if err := rawDB(t, path).QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != 2 {
		t.Fatalf("migration version: %d %v", version, err)
	}
}

func TestReadRangeSeesRowsAndCoverageInSameSnapshot(t *testing.T) {
	store, path := openStore(t)
	query := reportQuery()
	assertCursor(t, store, query, query.Start)
	const steps = 20
	writer := make(chan error, 1)
	go func() {
		for i := 0; i < steps; i++ {
			part := query
			part.Start = query.Start.Add(time.Duration(i) * time.Minute)
			part.End = part.Start.Add(time.Minute)
			if err := store.SaveRange(context.Background(), part, []model.LogRecord{record(part.Start, "one per minute")}, now); err != nil {
				writer <- err
				return
			}
		}
		writer <- nil
	}()
	for i := 0; i < steps; i++ {
		logs, coverage, err := storage.ReadRange(context.Background(), path, query)
		if err != nil {
			t.Fatal(err)
		}
		boundary := query.Start.Add(time.Duration(len(logs)) * time.Minute)
		want := []model.TimeRange{{Start: boundary, End: query.End}}
		if !coverage.Known || !reflect.DeepEqual(coverage.Gaps, want) {
			t.Fatalf("torn snapshot: rows=%d coverage=%+v", len(logs), coverage)
		}
	}
	if err := <-writer; err != nil {
		t.Fatal(err)
	}
}

func TestCollectionCancellationAndRangeValidation(t *testing.T) {
	store, path := openStore(t)
	query := reportQuery()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.Resume(ctx, query, now); !errors.Is(err, context.Canceled) {
		t.Fatalf("resume cancellation: %v", err)
	}
	if err := store.SaveRange(ctx, query, nil, now); !errors.Is(err, context.Canceled) {
		t.Fatalf("save cancellation: %v", err)
	}
	if _, err := store.Coverage(ctx, query); !errors.Is(err, context.Canceled) {
		t.Fatalf("coverage cancellation: %v", err)
	}
	if _, err := store.Latest(ctx, query.SourceID, query.Project, now); !errors.Is(err, context.Canceled) {
		t.Fatalf("latest cancellation: %v", err)
	}
	if _, _, err := storage.ReadRange(ctx, path, query); !errors.Is(err, context.Canceled) {
		t.Fatalf("read cancellation: %v", err)
	}
	for _, bad := range []model.LogRange{
		{SourceID: query.SourceID, Project: query.Project, Start: now, End: now},
		{SourceID: query.SourceID, Project: query.Project, Start: now.Add(-storage.Retention - time.Nanosecond), End: now},
		{Project: query.Project, Start: query.Start, End: query.End},
		{SourceID: query.SourceID, Start: query.Start, End: query.End},
	} {
		if _, err := store.Resume(context.Background(), bad, now); err == nil {
			t.Fatal("resume accepted invalid range")
		}
		if err := store.SaveRange(context.Background(), bad, nil, now); err == nil {
			t.Fatal("save accepted invalid range")
		}
	}
	future := query
	future.End = now.Add(time.Nanosecond)
	if err := store.SaveRange(context.Background(), future, nil, now); err == nil {
		t.Fatal("confirmed future range")
	}
}
