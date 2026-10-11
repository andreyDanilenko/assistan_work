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

func TestLookupResellersUsesRetainedHistoryWithoutOtherSourcesOrFuture(t *testing.T) {
	store, path := openStore(t)
	query := reportQuery()
	records := []model.LogRecord{
		record(now.Add(-3*time.Hour), `{"context":"orders","id":"a","resellerId":"reseller-a","msg":"creating order"}`),
		record(now.Add(-2*time.Hour), `{"order_id":"a","reseller_id":"reseller-a"}`),
		record(now.Add(-time.Minute), `{"orderId":"a","msg":"ERROR latest order event"}`),
		record(now.Add(-48*time.Hour), `{"context":"orders","id":"boundary","reseller_id":"first","message":"checking order exists"}`),
		record(now.Add(-time.Hour), `{"orderId":"conflict","resellerId":"r2"}`),
		record(now.Add(-2*time.Hour), `{"orderId":"conflict","resellerId":"r1"}`),
		record(now, `{"orderId":"a","resellerId":"future"}`),
		record(now.Add(-47*time.Hour), `{"orderId":"a","resellerId":"too-old"}`),
		record(now.Add(-time.Hour), `{"context":"orders","id":"item","resellerId":"wrong","msg":"create order item"}`),
		record(now.Add(-time.Hour), `{"context":"items","id":"item","resellerId":"wrong","msg":"creating order"}`),
		record(now.Add(-time.Hour), `{"orderId":"unsafe","resellerId":"private@example.org"}`),
		record(now.Add(-time.Hour), `broken json with resellerId and orderId`),
	}
	save(t, store, "source", now, records...)
	save(t, store, "source", now, records[0]) // Повторное окно не меняет связь.
	save(t, store, "other-source", now, record(now.Add(-time.Hour), `{"orderId":"a","resellerId":"other-source"}`))
	otherProject := record(now.Add(-time.Hour), `{"orderId":"a","resellerId":"other-project"}`)
	otherProject.Project = "other-project"
	save(t, store, "source", now, otherProject)
	// Имитируем ещё не очищенную строку, которая старше разрешённой истории.
	db := rawDB(t, path)
	if _, err := db.Exec(`UPDATE log_events SET timestamp_ns=? WHERE raw_line=?`, now.Add(-48*time.Hour-time.Nanosecond).UnixNano(), records[7].Line); err != nil {
		t.Fatal(err)
	}
	db.Close()
	got, err := storage.LookupResellers(context.Background(), path, query, []string{"a", "boundary", "conflict", "item", "unsafe", "missing", "a"})
	want := map[string][]string{"a": {"reseller-a"}, "boundary": {"first"}, "conflict": {"r1", "r2"}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("history lost boundaries, identity or safe context: %+v, %v", got, err)
	}
	for _, malicious := range []storage.Query{
		{SourceID: "source' OR 1=1 --", Project: query.Project, Start: query.Start, End: query.End},
		{SourceID: query.SourceID, Project: "sds-orders' OR 1=1 --", Start: query.Start, End: query.End},
	} {
		if got, err := storage.LookupResellers(context.Background(), path, malicious, []string{"a"}); err != nil || len(got) != 0 {
			t.Fatalf("source or project was not parameterized: %+v, %v", got, err)
		}
	}
}

func TestLookupResellersNeverWritesDatabase(t *testing.T) {
	store, path := openStore(t)
	save(t, store, "source", now, record(now.Add(-3*time.Hour), `{"orderId":"a","resellerId":"r"}`))
	store.Close()
	if err := os.Chmod(path, 0444); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	got, err := storage.LookupResellers(context.Background(), path, reportQuery(), []string{"a"})
	if err != nil || !reflect.DeepEqual(got, map[string][]string{"a": {"r"}}) {
		t.Fatalf("read-only lookup failed: %+v, %v", got, err)
	}
	after, _ := os.ReadFile(path)
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0444 || !bytes.Equal(before, after) {
		t.Fatal("lookup changed database or permissions")
	}
	for _, suffix := range []string{"-journal", "-wal", "-shm"} {
		if _, err := os.Stat(path + suffix); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("lookup created sidecar %s", suffix)
		}
	}
	missing := filepath.Join(t.TempDir(), "missing-dir", "missing.db")
	if _, err := storage.LookupResellers(context.Background(), missing, reportQuery(), []string{"a"}); err == nil {
		t.Fatal("missing file accepted")
	}
	if _, err := os.Stat(filepath.Dir(missing)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("lookup created a directory")
	}
}

func TestLookupResellersRejectsUnsafeInputsAndCancellation(t *testing.T) {
	store, path := openStore(t)
	store.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err := storage.LookupResellers(ctx, path, reportQuery(), []string{"a"}); !errors.Is(err, context.Canceled) || got != nil {
		t.Fatalf("canceled lookup returned partial data: %+v, %v", got, err)
	}
	for _, ids := range [][]string{{""}, {"private@example.org"}, {strings.Repeat("a", 101)}, make([]string, 100001)} {
		if got, err := storage.LookupResellers(context.Background(), path, reportQuery(), ids); err == nil || got != nil {
			t.Fatal("unsafe or unbounded IDs accepted")
		}
	}
	link := filepath.Join(t.TempDir(), "link.db")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	for _, unsafe := range []string{"", ":memory:", "file:database?mode=memory", filepath.Dir(path), link} {
		if _, err := storage.LookupResellers(context.Background(), unsafe, reportQuery(), []string{"a"}); err == nil {
			t.Fatal("unsafe database path accepted")
		}
	}
	query := reportQuery()
	query.End = query.Start
	if _, err := storage.LookupResellers(context.Background(), path, query, []string{"a"}); err == nil {
		t.Fatal("empty interval accepted")
	}
	db := rawDB(t, path)
	if _, err := db.Exec("PRAGMA application_id=123"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	before, _ := os.ReadFile(path)
	if _, err := storage.LookupResellers(context.Background(), path, reportQuery(), []string{"a"}); err == nil {
		t.Fatal("foreign database accepted")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("foreign database was modified")
	}
}
