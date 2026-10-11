package model_test

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"loki-analyzer/internal/model"
)

func TestLokiQueryResponseFromSavedExample(t *testing.T) {
	body, err := os.ReadFile("../../examples/loki-query-response.txt")
	if err != nil {
		t.Fatal(err)
	}
	var response model.LokiQueryResponse
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatal(err)
	}
	if response.Status != "success" || response.Data.ResultType != "streams" || len(response.Data.Result) != 2 {
		t.Fatal("unexpected response structure")
	}
	first := response.Data.Result[0]
	if first.Labels["app"] != "sds-orders" || len(first.Values) != 4 || len(response.Data.Result[1].Values) != 1 {
		t.Fatal("lost streams or entries")
	}
	if first.Values[0].TimestampNS != 1791570347171964777 {
		t.Fatal("nanosecond timestamp was rounded")
	}
	if !json.Valid([]byte(first.Values[0].Line)) {
		t.Fatal("inner JSON message was changed")
	}
	var stats struct {
		Summary struct {
			Returned  int `json:"totalEntriesReturned"`
			Processed int `json:"totalLinesProcessed"`
		} `json:"summary"`
	}
	if json.Unmarshal(response.Data.Stats, &stats) != nil || stats.Summary.Returned != 5 || stats.Summary.Processed != 1742 {
		t.Fatal("query diagnostics were not retained")
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	decode := func(data []byte) any {
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.UseNumber()
		var value any
		if err := decoder.Decode(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	if !reflect.DeepEqual(decode(body), decode(encoded)) {
		t.Fatal("response changed after JSON round trip")
	}
}

func TestLokiEntryRejectsInvalidTuplesWithoutExposingValues(t *testing.T) {
	for _, input := range []string{
		`null`, `{}`, `[]`, `["1"]`, `[1,"secret"]`, `["1",null]`,
		`["secret","line"]`, `["999999999999999999999999","line"]`,
		`["01","line"]`, `["1","line",null]`, `["1","line",{"x":{}}]`,
		`["1","line",{},"extra"]`,
	} {
		var entry model.LokiEntry
		err := json.Unmarshal([]byte(input), &entry)
		if err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatalf("invalid tuple accepted or value leaked: %v", err)
		}
	}
}

func TestLokiEntryRetainsOptionalMetadataAndResetsOnReuse(t *testing.T) {
	var entry model.LokiEntry
	if err := json.Unmarshal([]byte(`["1791570347171964777","text",{"trace_id":"trace"}]`), &entry); err != nil {
		t.Fatal(err)
	}
	if entry.Metadata["trace_id"] != "trace" {
		t.Fatal("metadata lost")
	}
	encoded, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	var other model.LokiEntry
	if json.Unmarshal(encoded, &other) != nil || !reflect.DeepEqual(entry, other) {
		t.Fatal("metadata round trip failed")
	}
	if err := json.Unmarshal([]byte(`["2","new"]`), &entry); err != nil {
		t.Fatal(err)
	}
	if entry.Metadata != nil || entry.TimestampNS != 2 || entry.Line != "new" {
		t.Fatal("stale entry data")
	}
}
