package storage_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"loki-analyzer/internal/model"
	"loki-analyzer/internal/storage"
)

func reportQuery() storage.Query {
	return storage.Query{Project: "sds-orders", SourceID: "source", Start: now.Add(-time.Hour), End: now}
}

func TestReadLogsPreservesContextMultiplicityAndReadOnlyDatabase(t *testing.T) {
	store, path := openStore(t)
	query := reportQuery()
	first := record(query.Start, "  exact original\n")
	second := record(now.Add(-time.Minute), "second")
	save(t, store, "source", now, first, first, second,
		record(query.Start.Add(-time.Nanosecond), "before start"), record(query.End, "at excluded end"))
	save(t, store, "other-source", now, first)
	other := first
	other.Project = "other-project"
	save(t, store, "source", now, other)
	store.Close()
	if err := os.Chmod(path, 0444); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := storage.ReadLogs(context.Background(), path, query)
	if err != nil || !reflect.DeepEqual(got, []model.LogRecord{first, first, second}) {
		t.Fatalf("read lost boundary, isolation, context or multiplicity: %+v, %v", got, err)
	}
	after, err := os.ReadFile(path)
	info, statErr := os.Stat(path)
	if err != nil || statErr != nil || !bytes.Equal(before, after) || info.Mode().Perm() != 0444 {
		t.Fatal("report modified the database or permissions")
	}
	for _, suffix := range []string{"-journal", "-wal", "-shm"} {
		if _, err := os.Stat(path + suffix); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("report created sidecar %s", suffix)
		}
	}
	query.SourceID = "source' OR 1=1 --"
	if got, err := storage.ReadLogs(context.Background(), path, query); err != nil || len(got) != 0 {
		t.Fatalf("source was not parameterized: %v", err)
	}
	query.SourceID, query.Project = "source", "sds-orders' OR 1=1 --"
	if got, err := storage.ReadLogs(context.Background(), path, query); err != nil || len(got) != 0 {
		t.Fatalf("project was not parameterized: %v", err)
	}
}

func TestReadLogsNeverCreatesOrRepairsDatabase(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing-directory", "missing.sqlite")
	if _, err := storage.ReadLogs(context.Background(), missing, reportQuery()); err == nil {
		t.Fatal("missing database accepted")
	}
	if _, err := os.Stat(filepath.Dir(missing)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("reading created a directory")
	}
	for _, kind := range []string{"empty", "foreign", "version", "schema"} {
		t.Run(kind, func(t *testing.T) {
			store, path := openStore(t)
			store.Close()
			if kind == "empty" {
				if err := os.WriteFile(path, nil, 0644); err != nil {
					t.Fatal(err)
				}
			} else {
				change := map[string]string{"foreign": "PRAGMA application_id=123", "version": "PRAGMA user_version=99", "schema": "DROP INDEX log_events_timestamp"}[kind]
				db := rawDB(t, path)
				if _, err := db.Exec(change); err != nil {
					t.Fatal(err)
				}
				db.Close()
			}
			before, _ := os.ReadFile(path)
			if _, err := storage.ReadLogs(context.Background(), path, reportQuery()); err == nil {
				t.Fatal("unsupported database accepted")
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(before, after) {
				t.Fatal("report repaired an unsupported database")
			}
		})
	}
}

func TestReadLogsOrdersEqualTimestampsConsistently(t *testing.T) {
	first, firstPath := openStore(t)
	second, secondPath := openStore(t)
	a, b := record(now.Add(-time.Minute), "a"), record(now.Add(-time.Minute), "b")
	save(t, first, "source", now, a)
	save(t, first, "source", now, b)
	save(t, second, "source", now, b)
	save(t, second, "source", now, a)
	left, err := storage.ReadLogs(context.Background(), firstPath, reportQuery())
	if err != nil {
		t.Fatal(err)
	}
	right, err := storage.ReadLogs(context.Background(), secondPath, reportQuery())
	if err != nil || len(left) != 2 || !reflect.DeepEqual(left, right) {
		t.Fatalf("same-time ordering depends on insertion order: %v", err)
	}
}

func TestReadLogsValidatesPeriodPathAndCancellation(t *testing.T) {
	_, path := openStore(t)
	query := reportQuery()
	for _, period := range [][2]time.Time{
		{now, now}, {now, now.Add(-time.Minute)}, {now.Add(-storage.Retention - time.Nanosecond), now},
		{time.Date(1600, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(1600, 1, 1, 1, 0, 0, 0, time.UTC)},
	} {
		query.Start, query.End = period[0], period[1]
		if _, err := storage.ReadLogs(context.Background(), path, query); err == nil {
			t.Fatal("invalid report period accepted")
		}
	}
	query = reportQuery()
	query.Start = query.End.Add(-storage.Retention)
	if _, err := storage.ReadLogs(context.Background(), path, query); err != nil {
		t.Fatalf("48-hour boundary rejected: %v", err)
	}
	link := filepath.Join(t.TempDir(), "link.sqlite")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	for _, unsafe := range []string{"", ":memory:", "file:injected?mode=memory", filepath.Dir(path), link} {
		if _, err := storage.ReadLogs(context.Background(), unsafe, query); err == nil {
			t.Fatalf("unsafe path accepted: %q", unsafe)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := storage.ReadLogs(ctx, path, query); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation ignored: %v", err)
	}
}

func TestReadLogsRejectsOversizedReportWithoutPartialData(t *testing.T) {
	for _, kind := range []string{"records", "bytes"} {
		t.Run(kind, func(t *testing.T) {
			store, path := openStore(t)
			entry := record(now.Add(-time.Minute), "x")
			entry.Labels, entry.Metadata = nil, nil
			if kind == "bytes" {
				entry.Line = strings.Repeat("ж", 400) // Объём считаем в байтах, включая кратность.
			}
			save(t, store, "source", now, entry)
			db := rawDB(t, path)
			if _, err := db.Exec("UPDATE log_events SET occurrences=100000"); err != nil {
				t.Fatal(err)
			}
			if kind == "records" {
				if got, err := storage.ReadLogs(context.Background(), path, reportQuery()); err != nil || len(got) != 100000 {
					t.Fatalf("exact record boundary rejected: %d, %v", len(got), err)
				}
				if _, err := db.Exec("UPDATE log_events SET occurrences=100001"); err != nil {
					t.Fatal(err)
				}
			}
			got, err := storage.ReadLogs(context.Background(), path, reportQuery())
			if err == nil || got != nil || !strings.Contains(err.Error(), "сократите период") {
				t.Fatalf("oversized report produced partial data or unclear error: %d, %v", len(got), err)
			}
		})
	}
}
