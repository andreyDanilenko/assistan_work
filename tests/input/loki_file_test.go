package input_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"loki-analyzer/internal/input"
	"loki-analyzer/internal/model"
)

// Public file-source limits documented in the README.
const (
	maxFileBytes = 10 << 20
	maxRecords   = 100_000
)

func TestLokiFileReadsSavedExample(t *testing.T) {
	records, err := input.NewLokiFileSource().Read(context.Background(), "../../examples/loki-query-response.txt")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 5 {
		t.Fatalf("got %d records, want 5", len(records))
	}
	if records[0].Timestamp.UnixNano() != 1791570347171964777 || records[0].Timestamp.Location() != time.UTC {
		t.Fatal("Loki nanosecond timestamp must remain exact and use UTC")
	}
	for _, record := range records {
		if record.Project != "sds-orders" || record.Labels["app"] != record.Project {
			t.Fatal("project must come from the stream's app label")
		}
	}
	first, err := model.ParseOrderLog(records[0].Line)
	if err != nil || first.Message != "creating order" {
		t.Fatal("original application log must be preserved")
	}
}

func TestLokiFilePreservesDuplicatesLabelsAndMetadata(t *testing.T) {
	entry := model.LokiEntry{TimestampNS: 1234567890123456789, Line: "same event", Metadata: map[string]string{"trace_id": "example"}}
	labels := map[string]string{"app": "orders", "pod": "pod-1"}
	body := responseBody(t, []model.LokiStream{{Labels: labels, Values: []model.LokiEntry{entry, entry}}})
	records, err := input.NewLokiFileSource().Read(context.Background(), writeResponse(t, body))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || !reflect.DeepEqual(records[0], records[1]) {
		t.Fatal("source must retain exact duplicate events")
	}
	if !reflect.DeepEqual(records[0].Labels, labels) || !reflect.DeepEqual(records[0].Metadata, entry.Metadata) || records[0].Line != entry.Line {
		t.Fatal("source must retain line, labels and structured metadata")
	}
}

func TestLokiFileAcceptsEmptyResponseAndStream(t *testing.T) {
	for _, streams := range [][]model.LokiStream{
		{},
		{{Labels: map[string]string{"app": "orders"}, Values: []model.LokiEntry{}}},
	} {
		records, err := input.NewLokiFileSource().Read(context.Background(), writeResponse(t, responseBody(t, streams)))
		if err != nil || records == nil || len(records) != 0 {
			t.Fatalf("valid empty response must return an empty collection: %v", err)
		}
	}
}

func TestLokiFileRejectsInvalidResponsesWithoutLeakingContent(t *testing.T) {
	const secret = "private-payload-marker"
	cases := []string{
		secret,
		`null`,
		`{"status":"error","error":"` + secret + `"}`,
		`{"status":"success","data":{"resultType":"matrix","result":[]}}`,
		`{"status":"success","data":{"resultType":"streams"}}`,
		`{"status":"success","data":{"resultType":"streams","result":null}}`,
		`{"status":"success","data":{"resultType":"streams","result":[{"stream":null,"values":[]}]}}`,
		`{"status":"success","data":{"resultType":"streams","result":[{"stream":{},"values":[]}]}}`,
		`{"status":"success","data":{"resultType":"streams","result":[{"stream":{"app":"orders"},"values":null}]}}`,
		`{"status":"success","data":{"resultType":"streams","result":[{"stream":{"app":" "},"values":[]}]}}`,
		`{"status":"success","data":{"resultType":"streams","result":[{"stream":{"app":"orders"},"values":[["` + secret + `","line"]]}]}}`,
		`{"status":"success","data":{"resultType":"streams","result":[{"stream":{"app":"orders"},"values":[["123",null]]}]}}`,
		`{"status":"success","data":{"resultType":"streams","result":[]}} {}`,
		string(responseBody(t, []model.LokiStream{{Labels: map[string]string{"app": strings.Repeat("a", 4097)}, Values: []model.LokiEntry{}}})),
	}
	for i, body := range cases {
		records, err := input.NewLokiFileSource().Read(context.Background(), writeResponse(t, []byte(body)))
		if err == nil || records != nil {
			t.Fatalf("case %d: invalid response must not produce records", i)
		}
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("case %d: error leaked response content", i)
		}
	}
}

func TestLokiFileRejectsMissingAndNonRegularPaths(t *testing.T) {
	const secret = "private-filename-marker"
	dir := t.TempDir()
	for _, path := range []string{"", dir, filepath.Join(dir, secret)} {
		_, err := input.NewLokiFileSource().Read(context.Background(), path)
		if err == nil {
			t.Fatal("invalid file path must be rejected")
		}
		if strings.Contains(err.Error(), dir) || strings.Contains(err.Error(), secret) {
			t.Fatal("error must not expose file paths")
		}
	}
}

func TestLokiFileBoundsSizeAndRecordCount(t *testing.T) {
	path := writeResponse(t, nil)
	if err := os.Truncate(path, maxFileBytes+1); err != nil {
		t.Fatal(err)
	}
	if _, err := input.NewLokiFileSource().Read(context.Background(), path); err == nil {
		t.Fatal("oversize file must be rejected")
	}
	entries := make([]model.LokiEntry, maxRecords+1)
	body := responseBody(t, []model.LokiStream{{Labels: map[string]string{"app": "orders"}, Values: entries}})
	if len(body) > maxFileBytes {
		t.Fatal("record limit fixture must fit within byte limit")
	}
	if records, err := input.NewLokiFileSource().Read(context.Background(), writeResponse(t, body)); err == nil || records != nil {
		t.Fatal("excess records must be rejected without partial output")
	}
}

func TestLokiFileHonorsCancellationBeforeOpening(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := input.NewLokiFileSource().Read(ctx, "missing-file"); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation before I/O, got %v", err)
	}
}

func writeResponse(t *testing.T, body []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "response.txt")
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func responseBody(t *testing.T, streams []model.LokiStream) []byte {
	t.Helper()
	body, err := json.Marshal(model.LokiQueryResponse{
		Status: "success", Data: model.LokiQueryData{ResultType: "streams", Result: streams},
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}
