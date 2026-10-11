package loki_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"loki-analyzer/internal/loki"
)

var testStart = time.Unix(1_700_000_000, 0).UTC()

func testClient(t *testing.T, handler http.HandlerFunc, customize func(*loki.Config)) *loki.Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	config := loki.DefaultConfig()
	config.URL, config.Token, config.AllowHTTP = server.URL, "test-secret-token", true
	if customize != nil {
		customize(&config)
	}
	client, err := loki.New(config, &http.Client{
		Timeout:       config.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestRawEndpointsPreserveGrafanaProxyAndHeaders(t *testing.T) {
	const prefix = "/api/datasources/proxy/uid/test-uid"
	const expression = `{app="a\"b"} |= "password=\"x\" & other"`
	requests := 0
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != http.MethodGet {
			t.Errorf("method %s", r.Method)
		}
		if r.Header.Get("Authorization") != "Bearer test-secret-token" || r.Header.Get("X-Grafana-Org-Id") != "1" || r.Header.Get("X-Scope-OrgID") != "" {
			t.Error("wrong authentication headers")
		}
		if r.URL.Query().Get("start") != strconv.FormatInt(testStart.UnixNano(), 10) || r.URL.Query().Get("end") != strconv.FormatInt(testStart.Add(time.Second).UnixNano(), 10) {
			t.Error("wrong time range")
		}
		switch r.URL.Path {
		case prefix + "/loki/api/v1/labels":
			fmt.Fprint(w, `{"status":"success","data":["app","level"]}`)
		case prefix + "/loki/api/v1/label/app/values":
			fmt.Fprint(w, `{"status":"success","data":["billing"]}`)
		case prefix + "/loki/api/v1/query_range":
			if r.URL.Query().Get("query") != expression || r.URL.Query().Get("direction") != "forward" || r.URL.Query().Has("interval") {
				t.Error("query changed or sampled")
			}
			writeLogs(t, w, [][2]string{{strconv.FormatInt(testStart.UnixNano(), 10), "ERROR message"}})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}, func(c *loki.Config) { c.URL += prefix + "/"; c.OrgID = "1" })
	ctx := context.Background()
	labels, err := client.GetLabels(ctx, testStart, testStart.Add(time.Second))
	if err != nil || labels.StatusCode != 200 || !json.Valid(labels.Body) || labels.Truncated {
		t.Fatalf("labels: %+v, %v", labels, err)
	}
	if len(labels.Values) != 2 || labels.Values[0] != "app" || labels.Values[1] != "level" {
		t.Fatalf("decoded labels: %v", labels.Values)
	}
	values, err := client.GetLabelValues(ctx, "app", testStart, testStart.Add(time.Second))
	if err != nil || !strings.Contains(string(values.Body), "billing") {
		t.Fatalf("values: %+v, %v", values, err)
	}
	page, err := client.QueryRange(ctx, expression, testStart, testStart.Add(time.Second), 1)
	if err != nil || !page.Truncated || page.StatusCode != 200 || !json.Valid(page.Body) {
		t.Fatalf("query: %+v, %v", page, err)
	}
	if requests != 3 {
		t.Fatalf("raw API paginated: requests=%d", requests)
	}
}

type httpClientFunc func(*http.Request) (*http.Response, error)

func (f httpClientFunc) Do(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestNewUsesInjectedHTTPClient(t *testing.T) {
	config := loki.DefaultConfig()
	config.URL, config.Token = "https://example.test", "test-secret-token"
	called := false
	transport := httpClientFunc(func(request *http.Request) (*http.Response, error) {
		called = true
		if request.URL.Host != "example.test" || request.URL.Path != "/loki/api/v1/labels" {
			t.Fatal("request did not reach the injected transport")
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"status":"success","data":["app"]}`)),
		}, nil
	})
	client, err := loki.New(config, transport)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.GetLabels(context.Background(), testStart, testStart.Add(time.Second))
	if err != nil || !called || len(response.Values) != 1 || response.Values[0] != "app" {
		t.Fatalf("injected transport: response=%+v, called=%v, error=%v", response, called, err)
	}
}

func TestRequestTimeoutAppliesToInjectedHTTPClient(t *testing.T) {
	config := loki.DefaultConfig()
	config.URL, config.Token = "https://example.test", "test-secret-token"
	config.Timeout = 20 * time.Millisecond
	transport := httpClientFunc(func(request *http.Request) (*http.Response, error) {
		deadline, ok := request.Context().Deadline()
		if !ok || time.Until(deadline) > config.Timeout {
			t.Fatal("request does not have the configured timeout")
		}
		<-request.Context().Done()
		return nil, request.Context().Err()
	})
	client, err := loki.New(config, transport)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.GetLabels(context.Background(), testStart, testStart.Add(time.Second))
	if err == nil || err.Error() != "Loki request timed out" {
		t.Fatalf("timeout: %v", err)
	}
}

func TestNewRequiresHTTPClient(t *testing.T) {
	config := loki.DefaultConfig()
	config.URL, config.Token = "https://example.test", "test-secret-token"
	if _, err := loki.New(config, nil); err == nil {
		t.Fatal("missing HTTP dependency accepted")
	}
}

func TestErrorsNeverExposeBodiesTokensOrQueries(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
	}{
		{"unauthorized", 401, "secret-body-token"},
		{"forbidden", 403, "secret-body-token"},
		{"server", 500, "secret-body-token"},
		{"malformed", 200, `{"secret-body-token"`},
		{"api-error", 200, `{"status":"error","error":"secret-body-token"}`},
		{"missing-data", 200, `{"status":"success"}`},
		{"null-data", 200, `{"status":"success","data":null}`},
		{"invalid-label", 200, `{"status":"success","data":[null]}`},
		{"wrong-data", 200, `{"status":"success","data":{}}`},
		{"extra-json", 200, `{"status":"success","data":[]} {}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := testClient(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(tc.status); fmt.Fprint(w, tc.body) }, nil)
			response, err := client.GetLabels(context.Background(), testStart, testStart.Add(time.Second))
			if err == nil || len(response.Body) != 0 {
				t.Fatalf("unexpected response: %+v, %v", response, err)
			}
			if strings.Contains(err.Error(), "secret-body-token") || strings.Contains(err.Error(), "test-secret-token") || strings.Contains(err.Error(), "http") {
				t.Fatalf("unsafe error: %v", err)
			}
		})
	}
}

func TestRedirectNeverFollowed(t *testing.T) {
	var targetCalls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { targetCalls.Add(1) }))
	defer target.Close()
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/secret", http.StatusFound)
	}, nil)
	response, err := client.GetLabels(context.Background(), testStart, testStart.Add(time.Second))
	if err == nil || response.StatusCode != 302 || len(response.Body) != 0 || targetCalls.Load() != 0 {
		t.Fatalf("redirect leaked: %+v, %v, calls=%d", response, err, targetCalls.Load())
	}
}

func TestNewRejectsUnsafeConfiguration(t *testing.T) {
	tests := map[string]func(*loki.Config){
		"http":                func(c *loki.Config) { c.URL = "http://localhost:3100" },
		"credentials-in-url":  func(c *loki.Config) { c.URL = "https://user:secret@example.test" },
		"query":               func(c *loki.Config) { c.URL = "https://example.test?token=secret" },
		"fragment":            func(c *loki.Config) { c.URL = "https://example.test/#fragment" },
		"bad-label":           func(c *loki.Config) { c.ProjectLabel = `app} |= ""` },
		"missing-token":       func(c *loki.Config) { c.Token = "" },
		"token-newline":       func(c *loki.Config) { c.Token = "test\nsecret" },
		"token-space":         func(c *loki.Config) { c.Token = "test secret" },
		"token-unicode-space": func(c *loki.Config) { c.Token = "test\u00a0secret" },
		"org":                 func(c *loki.Config) { c.OrgID = "-1" },
		"zero-org":            func(c *loki.Config) { c.OrgID = "0" },
		"timeout":             func(c *loki.Config) { c.Timeout = 0 },
		"page-size":           func(c *loki.Config) { c.PageSize = 0 },
		"max-records":         func(c *loki.Config) { c.MaxRecords = 0 },
		"max-requests":        func(c *loki.Config) { c.MaxRequests = 0 },
		"max-range":           func(c *loki.Config) { c.MaxRange = 0 },
		"response-bytes":      func(c *loki.Config) { c.MaxResponseBytes = 0 },
		"total-bytes":         func(c *loki.Config) { c.MaxTotalBytes = 0 },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			config := loki.DefaultConfig()
			config.URL = "https://example.test"
			config.Token = "test-secret-token"
			change(&config)
			if _, err := loki.New(config, &http.Client{
				Timeout:       config.Timeout,
				CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			}); err == nil {
				t.Fatal("invalid config accepted")
			}
		})
	}
}

func TestValidationPrecedesNetwork(t *testing.T) {
	requests := 0
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) { requests++ }, nil)
	ctx := context.Background()
	if _, err := client.GetLabels(ctx, testStart, testStart); err == nil {
		t.Error("empty range accepted")
	}
	if _, err := client.GetLabelValues(ctx, "bad/name", testStart, testStart.Add(time.Second)); err == nil {
		t.Error("bad label accepted")
	}
	if _, err := client.GetLabels(ctx, testStart, testStart.Add(25*time.Hour)); err == nil {
		t.Error("large range accepted")
	}
	if _, err := client.GetLabels(ctx, time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC), testStart); err == nil {
		t.Error("overflowing timestamp accepted")
	}
	if _, err := client.QueryRange(ctx, "", testStart, testStart.Add(time.Second), 1); err == nil {
		t.Error("empty query accepted")
	}
	if _, err := client.QueryRange(ctx, `{app="x"}`, testStart, testStart.Add(time.Second), 0); err == nil {
		t.Error("zero limit accepted")
	}
	if _, err := client.FetchLogs(ctx, loki.Query{Project: "billing", Start: testStart, End: testStart.Add(time.Second), Regex: "["}); err == nil {
		t.Error("invalid regex accepted")
	}
	if requests != 0 {
		t.Fatalf("invalid input caused %d requests", requests)
	}
}

func TestResponseLimitsAndCancellation(t *testing.T) {
	for _, total := range []bool{false, true} {
		t.Run(fmt.Sprint(total), func(t *testing.T) {
			client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, `{"status":"success","data":["value that will not fit"]}`)
			}, func(c *loki.Config) {
				if total {
					c.MaxTotalBytes = 16
				} else {
					c.MaxResponseBytes = 16
				}
			})
			response, err := client.GetLabels(context.Background(), testStart, testStart.Add(time.Second))
			if err == nil || len(response.Body) != 0 {
				t.Fatalf("oversized body returned: %+v %v", response, err)
			}
		})
	}
	serverURL := ""
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }, func(c *loki.Config) {
		c.Timeout = 30 * time.Millisecond
		serverURL = c.URL
	})
	if _, err := client.GetLabels(context.Background(), testStart, testStart.Add(time.Second)); err == nil || strings.Contains(err.Error(), serverURL) {
		t.Fatalf("timeout: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.GetLabels(ctx, testStart, testStart.Add(time.Second)); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
}

func writeLogs(t *testing.T, w http.ResponseWriter, entries [][2]string) {
	t.Helper()
	if entries == nil {
		entries = make([][2]string, 0)
	}
	payload := map[string]any{"status": "success", "data": map[string]any{"resultType": "streams", "result": []any{map[string]any{"stream": map[string]string{"app": "billing"}, "values": entries}}}}
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		t.Error(err)
	}
}
