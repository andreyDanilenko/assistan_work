package loki_test

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"loki-analyzer/internal/loki"
)

func TestQueryRangeReturnsModelForSavedExample(t *testing.T) {
	body, err := os.ReadFile("../../examples/loki-query-response.txt")
	if err != nil {
		t.Fatal(err)
	}
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}, nil)
	start := time.Unix(0, 1791570347000000000)
	response, err := client.QueryRange(context.Background(), `{app="sds-orders"}`, start, start.Add(2*time.Second), 5)
	if err != nil {
		t.Fatal(err)
	}
	if response.Query == nil || len(response.Query.Data.Result) != 2 || !response.Truncated {
		t.Fatal("parsed query or truncation marker missing")
	}
	if response.Query.Data.Result[0].Values[0].TimestampNS != 1791570347171964777 {
		t.Fatal("timestamp precision lost")
	}
	if !bytes.Equal(body, response.Body) {
		t.Fatal("original response body changed")
	}
}

func eventServer(t *testing.T, events [][2]string) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		start, _ := strconv.ParseInt(r.URL.Query().Get("start"), 10, 64)
		end, _ := strconv.ParseInt(r.URL.Query().Get("end"), 10, 64)
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		var selected [][2]string
		for _, event := range events {
			ns, _ := strconv.ParseInt(event[0], 10, 64)
			if ns >= start && ns < end && len(selected) < limit {
				selected = append(selected, event)
			}
		}
		writeLogs(t, w, selected)
	}
}

func TestFetchSplitsWithoutBoundaryLossOrDuplicateCounts(t *testing.T) {
	base := testStart.UnixNano()
	events := [][2]string{{strconv.FormatInt(base, 10), "ERROR duplicate"}, {strconv.FormatInt(base, 10), "ERROR duplicate"}, {strconv.FormatInt(base+4, 10), "ERROR middle"}, {strconv.FormatInt(base+7, 10), "ERROR last"}, {strconv.FormatInt(base+8, 10), "excluded end"}}
	client := testClient(t, eventServer(t, events), func(c *loki.Config) { c.PageSize = 3 })
	result, err := client.FetchLogs(context.Background(), loki.Query{Project: "billing", Start: testStart, End: testStart.Add(8 * time.Nanosecond)})
	if err != nil || !result.Complete || len(result.Records) != 4 || result.Requests != 3 {
		t.Fatalf("result %+v, error %v", result, err)
	}
	if result.Records[0].Line != "ERROR duplicate" || result.Records[1].Line != "ERROR duplicate" || result.Records[2].Timestamp.UnixNano() != base+4 {
		t.Fatalf("events changed: %+v", result.Records)
	}
}

func TestFetchSameTimestampCannotBeClaimedComplete(t *testing.T) {
	stamp := strconv.FormatInt(testStart.UnixNano(), 10)
	events := [][2]string{{stamp, "ERROR one"}, {stamp, "ERROR two"}, {stamp, "ERROR three"}}
	client := testClient(t, eventServer(t, events), func(c *loki.Config) { c.PageSize = 2 })
	result, err := client.FetchLogs(context.Background(), loki.Query{Project: "billing", Start: testStart, End: testStart.Add(time.Nanosecond)})
	if err != nil || result.Complete || len(result.Records) != 2 || !strings.Contains(result.Reason, "nanosecond") || result.Requests != 1 {
		t.Fatalf("result %+v, error %v", result, err)
	}
}

func TestFetchBudgetsCountDiscardedPages(t *testing.T) {
	base := testStart.UnixNano()
	events := [][2]string{{strconv.FormatInt(base, 10), "first"}, {strconv.FormatInt(base+3, 10), "second"}}
	client := testClient(t, eventServer(t, events), func(c *loki.Config) { c.PageSize = 2; c.MaxRequests = 1 })
	result, err := client.FetchLogs(context.Background(), loki.Query{Project: "billing", Start: testStart, End: testStart.Add(4 * time.Nanosecond)})
	if err != nil || result.Complete || result.Requests != 1 || result.BytesRead == 0 || len(result.Records) != 0 || !strings.Contains(result.Reason, "request limit") {
		t.Fatalf("result %+v, error %v", result, err)
	}
}

func TestFetchRecordCapAndSafeLogQL(t *testing.T) {
	const project = `billing"} |= "injected`
	const contains = "email=\"user@example.test\" & x"
	seen := ""
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		seen = r.URL.Query().Get("query")
		fmt.Fprintf(w, `{"status":"success","data":{"resultType":"streams","result":[{"stream":{"app":%s},"values":[["%d","first"],["%d","second"]]}]}}`, strconv.Quote(project), testStart.UnixNano(), testStart.UnixNano()+1)
	}, func(c *loki.Config) { c.MaxRecords = 1 })
	result, err := client.FetchLogs(context.Background(), loki.Query{Project: project, Start: testStart, End: testStart.Add(time.Second), Contains: contains, Regex: `error.*`, LevelRegex: `(?i)\bERROR\b`})
	if err != nil || result.Complete || len(result.Records) != 1 {
		t.Fatalf("result %+v, error %v", result, err)
	}
	want := "{app=" + strconv.Quote(project) + "} |~ " + strconv.Quote(`(?i)\bERROR\b`) + " |= " + strconv.Quote(contains) + " |~ " + strconv.Quote(`error.*`)
	if seen != want {
		t.Fatalf("unsafe query: got %q, want %q", seen, want)
	}
}

func TestMalformedStreamsAndMetadata(t *testing.T) {
	stamp := strconv.FormatInt(testStart.UnixNano(), 10)
	for name, data := range map[string]string{
		"wrong-type":      `{"resultType":"matrix","result":[]}`,
		"missing-result":  `{"resultType":"streams"}`,
		"null-result":     `{"resultType":"streams","result":null}`,
		"timestamp":       `{"resultType":"streams","result":[{"stream":{},"values":[["secret-invalid","line"]]}]}`,
		"overflow":        `{"resultType":"streams","result":[{"stream":{},"values":[["99999999999999999999","line"]]}]}`,
		"null-line":       `{"resultType":"streams","result":[{"stream":{},"values":[["` + stamp + `",null]]}]}`,
		"end-boundary":    `{"resultType":"streams","result":[{"stream":{},"values":[["` + strconv.FormatInt(testStart.Add(time.Second).UnixNano(), 10) + `","line"]]}]}`,
		"nested-metadata": `{"resultType":"streams","result":[{"stream":{},"values":[["` + stamp + `","line",{"bad":{}}]]}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			client := testClient(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `{"status":"success","data":`+data+`}`) }, nil)
			response, err := client.QueryRange(context.Background(), `{app="billing"}`, testStart, testStart.Add(time.Second), 10)
			if err == nil || len(response.Body) != 0 || strings.Contains(err.Error(), "secret-invalid") {
				t.Fatalf("invalid response %+v %v", response, err)
			}
		})
	}
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"status":"success","data":{"resultType":"streams","result":[{"stream":{"app":"billing"},"values":[["`+stamp+`","line",{"trace_id":"abc"}]]}]}}`)
	}, nil)
	result, err := client.FetchLogs(context.Background(), loki.Query{Project: "billing", Start: testStart, End: testStart.Add(time.Second)})
	if err != nil || !result.Complete || len(result.Records) != 1 || result.Records[0].Metadata["trace_id"] != "abc" {
		t.Fatalf("metadata lost: %+v %v", result, err)
	}
}

func TestEmptyStreamsAndAcceptedPrefixSurviveLaterError(t *testing.T) {
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"status":"success","data":{"resultType":"streams","result":[]}}`)
	}, nil)
	query := loki.Query{Project: "billing", Start: testStart, End: testStart.Add(4 * time.Nanosecond)}
	result, err := client.FetchLogs(context.Background(), query)
	if err != nil || !result.Complete || len(result.Records) != 0 {
		t.Fatalf("empty response %+v %v", result, err)
	}
	base := testStart.UnixNano()
	client = testClient(t, func(w http.ResponseWriter, r *http.Request) {
		start := r.URL.Query().Get("start")
		end := r.URL.Query().Get("end")
		if start == strconv.FormatInt(base+2, 10) {
			http.Error(w, "secret-server-error", 500)
			return
		}
		entries := [][2]string{{strconv.FormatInt(base, 10), "first"}}
		if end == strconv.FormatInt(base+4, 10) {
			entries = append(entries, [2]string{strconv.FormatInt(base+3, 10), "last"})
		}
		writeLogs(t, w, entries)
	}, func(c *loki.Config) { c.PageSize = 2 })
	result, err = client.FetchLogs(context.Background(), query)
	if err == nil || result.Complete || len(result.Records) != 1 || result.Records[0].Line != "first" || strings.Contains(result.Reason, "secret-server-error") {
		t.Fatalf("partial prefix lost: %+v %v", result, err)
	}
}
