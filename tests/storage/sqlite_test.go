package storage_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"loki-analyzer/internal/model"
	"loki-analyzer/internal/storage"
)

var now = time.Date(2026, 10, 11, 12, 0, 0, 123456789, time.UTC)

func openStore(t *testing.T) (*storage.Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "private", "logs.sqlite")
	store, err := storage.Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store, path
}

func rawDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	address := url.URL{Scheme: "file", Path: filepath.ToSlash(path)}
	db, err := sql.Open("sqlite", address.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func record(at time.Time, line string) model.LogRecord {
	return model.LogRecord{Project: "sds-orders", Timestamp: at, Line: line,
		Labels:   map[string]string{"pod": "orders-pod", "node_name": "server-a", "namespace": "apps"},
		Metadata: map[string]string{"trace_id": "trace-a", "custom": "unknown metadata"}}
}

func stats(t *testing.T, store *storage.Store, rows, records int64) storage.Stats {
	t.Helper()
	got, err := store.Stats(context.Background())
	if err != nil || got.Rows != rows || got.Records != records {
		t.Fatalf("statistics: %+v, %v", got, err)
	}
	return got
}

func save(t *testing.T, store *storage.Store, source string, at time.Time, records ...model.LogRecord) {
	t.Helper()
	if err := store.Save(context.Background(), source, records, at); err != nil {
		t.Fatal(err)
	}
}

func TestSQLitePreservesRawContextPrecisionAndMultiplicity(t *testing.T) {
	store, path := openStore(t)
	entry := record(now.Add(-time.Hour), "  {\"orderId\":\"order-a\",\"resellerId\":\"reseller-a\",\"extra\":{\"number\":9007199254740993,\"unknown\":[1,true]}}\n")
	save(t, store, "source-a", now, entry, entry)
	stats(t, store, 1, 2)
	var line, labels, metadata string
	var stamp, received, occurrences int64
	if err := rawDB(t, path).QueryRow(`SELECT raw_line, labels_json, metadata_json, timestamp_ns, received_at_ns, occurrences FROM log_events`).Scan(&line, &labels, &metadata, &stamp, &received, &occurrences); err != nil {
		t.Fatal(err)
	}
	var gotLabels, gotMetadata map[string]string
	if json.Unmarshal([]byte(labels), &gotLabels) != nil || json.Unmarshal([]byte(metadata), &gotMetadata) != nil {
		t.Fatal("invalid stored context")
	}
	if line != entry.Line || !reflect.DeepEqual(gotLabels, entry.Labels) || !reflect.DeepEqual(gotMetadata, entry.Metadata) || stamp != entry.Timestamp.UnixNano() || received != now.UnixNano() || occurrences != 2 {
		t.Fatal("raw context or precision changed")
	}
	// Ключи map в другом порядке дают ту же идентичность; меньшая пачка не уменьшает кратность.
	copy := entry
	copy.Labels = map[string]string{"namespace": "apps", "node_name": "server-a", "pod": "orders-pod"}
	save(t, store, "source-a", now.Add(time.Second), copy)
	stats(t, store, 1, 2)
	save(t, store, "source-a", now, entry, entry, entry)
	stats(t, store, 1, 3)
	save(t, store, "source-b", now, entry)
	copy.Project = "other-project"
	save(t, store, "source-a", now, copy)
	copy = entry
	copy.Timestamp = entry.Timestamp.Add(time.Nanosecond)
	save(t, store, "source-a", now, copy)
	copy = entry
	copy.Labels = map[string]string{"pod": "different-pod"}
	save(t, store, "source-a", now, copy)
	copy = entry
	copy.Metadata = map[string]string{"trace_id": "different-trace"}
	save(t, store, "source-a", now, copy)
	copy = entry
	copy.Line += " "
	save(t, store, "source-a", now, copy)
	got := stats(t, store, 7, 9)
	if !got.Oldest.Equal(entry.Timestamp) || !got.Newest.Equal(entry.Timestamp.Add(time.Nanosecond)) {
		t.Fatal("statistic timestamps lost nanoseconds")
	}
}

func TestSQLiteRetentionBoundaryRejectsStaleAndFutureEvents(t *testing.T) {
	store, _ := openStore(t)
	cutoff := now.Add(-storage.Retention)
	save(t, store, "source", now,
		record(cutoff.Add(-time.Nanosecond), "expired"), record(cutoff, "boundary"),
		record(cutoff.Add(time.Nanosecond), "retained"), record(now.Add(time.Nanosecond), "future"))
	stats(t, store, 2, 2)
	removed, err := store.Prune(context.Background(), now.Add(time.Nanosecond))
	if err != nil || removed != 1 {
		t.Fatalf("prune boundary: %d, %v", removed, err)
	}
	if got := stats(t, store, 1, 1); !got.Oldest.Equal(cutoff.Add(time.Nanosecond)) {
		t.Fatal("boundary event was removed early")
	}
	// Save тоже очищает прежние записи и не возвращает устаревшие события при повторном чтении.
	save(t, store, "source", now.Add(time.Minute), record(cutoff, "boundary"))
	got := stats(t, store, 0, 0)
	if !got.Oldest.IsZero() || !got.Newest.IsZero() {
		t.Fatal("empty history must have no times")
	}
}

func TestSQLiteReopensQuotedFilenameAndUsesPrivateFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "quote's ?mode=memory#fragment&name.sqlite")
	store, err := storage.Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	save(t, store, "source", now, record(now, "persisted"))
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		path string
		mode os.FileMode
	}{{path, 0600}, {filepath.Dir(path), 0700}} {
		info, err := os.Stat(item.path)
		if err != nil || info.Mode().Perm() != item.mode {
			t.Fatalf("unsafe file permissions: %v", err)
		}
	}
	store, err = storage.Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	stats(t, store, 1, 1)
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if _, err := os.Stat(path + suffix); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("persistent sidecar %s", suffix)
		}
	}
	var mode string
	if err := rawDB(t, path).QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil || mode != "delete" {
		t.Fatalf("journal mode: %q %v", mode, err)
	}
}

func TestSQLitePrunesSeveralBatchesAndReclaimsPages(t *testing.T) {
	store, path := openStore(t)
	payload := "expired-sensitive-payload" + strings.Repeat("x", 2048)
	entries := make([]model.LogRecord, 0, 1106)
	for i := 0; i < 1105; i++ {
		entries = append(entries, record(now.Add(-time.Hour), fmt.Sprintf("%s-%d", payload, i)))
	}
	entries = append(entries, record(now, "retained"))
	save(t, store, "source", now, entries...)
	before, _ := os.Stat(path)
	removed, err := store.Prune(context.Background(), now.Add(storage.Retention))
	if err != nil || removed != 1105 {
		t.Fatalf("batched deletion: %d %v", removed, err)
	}
	stats(t, store, 1, 1)
	after, _ := os.Stat(path)
	var free int64
	if err := rawDB(t, path).QueryRow("PRAGMA freelist_count").Scan(&free); err != nil {
		t.Fatal(err)
	}
	if after.Size() >= before.Size()/2 || free != 0 {
		t.Fatalf("pages not reclaimed: before=%d after=%d free=%d", before.Size(), after.Size(), free)
	}
	body, err := os.ReadFile(path)
	if err != nil || strings.Contains(string(body), "expired-sensitive-payload") {
		t.Fatal("deleted payload remains in database file")
	}
}

func TestSQLiteRejectsForeignUnsupportedOrChangedSchema(t *testing.T) {
	for _, kind := range []string{"foreign", "foreign-prefix", "version", "schema", "vacuum", "not sqlite"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "private-secret-path.sqlite")
			if kind == "not sqlite" {
				if err := os.WriteFile(path, []byte("private-secret-content"), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				if !strings.HasPrefix(kind, "foreign") {
					store, err := storage.Open(context.Background(), path)
					if err != nil {
						t.Fatal(err)
					}
					store.Close()
				}
				db := rawDB(t, path)
				query := map[string]string{"foreign": "CREATE TABLE private_secret_table(value TEXT)", "foreign-prefix": "CREATE TABLE sqlitecustom(value TEXT)", "version": "PRAGMA user_version=99", "schema": "DROP INDEX log_events_timestamp", "vacuum": "PRAGMA auto_vacuum=NONE; VACUUM"}[kind]
				if _, err := db.Exec(query); err != nil {
					t.Fatal(err)
				}
				db.Close()
			}
			if err := os.Chmod(path, 0644); err != nil {
				t.Fatal(err)
			}
			store, err := storage.Open(context.Background(), path)
			if err == nil {
				store.Close()
				t.Fatal("unrecognized database accepted")
			}
			if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), path) {
				t.Fatal("database details leaked")
			}
			if info, statErr := os.Stat(path); statErr != nil || info.Mode().Perm() != 0644 {
				t.Fatal("unrecognized file permissions changed")
			}
			if strings.HasPrefix(kind, "foreign") {
				var appID int
				if err := rawDB(t, path).QueryRow("PRAGMA application_id").Scan(&appID); err != nil || appID != 0 {
					t.Fatal("foreign database reassigned")
				}
			}
		})
	}
}

func TestSQLiteRejectsMemoryURIAndSymlinkPaths(t *testing.T) {
	target := filepath.Join(t.TempDir(), "target.sqlite")
	if err := os.WriteFile(target, nil, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(filepath.Dir(target), "link.sqlite")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"", ":memory:", "file:injected?mode=memory", filepath.Dir(target), link} {
		store, err := storage.Open(context.Background(), path)
		if err == nil {
			store.Close()
			t.Fatalf("unsafe path accepted: %q", path)
		}
	}
}

func TestSQLiteCancellationAndSafeWriteErrors(t *testing.T) {
	store, _ := openStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := storage.Open(ctx, filepath.Join(t.TempDir(), "never.sqlite")); !errors.Is(err, context.Canceled) {
		t.Fatal("open ignored cancellation")
	}
	if err := store.Save(ctx, "source", []model.LogRecord{record(now, "secret-payload")}, now); !errors.Is(err, context.Canceled) {
		t.Fatalf("save cancellation: %v", err)
	}
	if _, err := store.Prune(ctx, now); !errors.Is(err, context.Canceled) {
		t.Fatalf("prune cancellation: %v", err)
	}
	if _, err := store.Stats(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("stats cancellation: %v", err)
	}
	bad := record(now, "secret-payload")
	bad.Project = ""
	if err := store.Save(context.Background(), "secret-source", []model.LogRecord{record(now, "valid"), bad}, now); err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatal("invalid batch accepted or leaked")
	}
	stats(t, store, 0, 0)
	store.Close()
	if err := store.Save(context.Background(), "secret-source", []model.LogRecord{record(now, "secret-payload")}, now); err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatal("closed store error leaked details")
	}
}
