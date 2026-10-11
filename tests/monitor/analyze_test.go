package monitor_test

import (
	"encoding/json"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"loki-analyzer/internal/model"
	"loki-analyzer/internal/monitor"
)

func event(second int, line string) model.LogRecord {
	return model.LogRecord{Project: "sds-orders", Timestamp: time.Date(2026, 10, 10, 12, 0, second, 123, time.UTC), Line: line}
}

func TestAnalyzeKnownErrorsAndWindowReseller(t *testing.T) {
	records := []model.LogRecord{
		event(0, `{"context":"orders","id":"order-a","resellerId":"reseller-a","msg":"creating order"}`),
		event(1, `{"context":"orders","orderId":"order-a","level":50,"msg":"order create error order not found"}`),
		event(2, `{"context":"orders","orderId":"order-a","level":50,"msg":"order create error order not found"}`),
		event(3, `{"context":"orders","orderId":"order-b","msg":"error provisioned, timeout exceeded when trying to connect"}`),
		event(4, `{"context":"orders","orderId":"order-c","msg":"order create error order still being provision"}`),
		event(5, `{"context":"orders","orderId":"order-a","msg":"order provisioned"}`),
		event(6, `{"context":"orders","id":"order-a","msg":"order received successfully"}`),
	}
	records[1].Labels = map[string]string{"pod": "orders-pod-old", "node_name": "server-a"}
	records[2].Metadata = map[string]string{"pod": "orders-pod-new", "node_name": "server-b"}
	result := monitor.Analyze(records, monitor.Filter{})
	if result.Total != 7 || result.Errors != 4 || result.Filtered != 0 || len(result.Issues) != 3 {
		t.Fatalf("wrong counts: %+v", result)
	}
	kinds := map[string]bool{}
	for _, issue := range result.Issues {
		kinds[issue.Kind] = true
	}
	if !kinds["order_create_error_not_found"] || !kinds["order_provision_error_timeout"] || !kinds["order_create_error_still_provisioning"] {
		t.Fatalf("known error kinds lost: %+v", result.Issues)
	}
	issue := result.Issues[0]
	if issue.Kind != "order_create_error_not_found" || issue.OrderID != "order-a" || issue.ResellerID != "reseller-a" || issue.Count != 2 || issue.Critical {
		t.Fatalf("wrong order issue: %+v", issue)
	}
	if issue.Pod != "orders-pod-new" || issue.Server != "server-b" || !issue.First.Equal(records[1].Timestamp) || !issue.Last.Equal(records[2].Timestamp) {
		t.Fatalf("context or timestamps lost: %+v", issue)
	}
}

func TestAnalyzeLevelsIDsAndPlainText(t *testing.T) {
	records := []model.LogRecord{
		event(0, `{"context":"orders","id":"item-only","msg":"create order item","level":"error"}`),
		event(1, `{"context":"orders","id":"item-a","orderId":"order-real","msg":"create order item","level":"fatal"}`),
		event(2, `{"context":"orders","id":"order-from-id","msg":"creating order","level":"critical"}`),
		event(3, `{"context":"orders","orderId":"order-50","msg":"normal message","level":50}`),
		event(4, `{"context":"orders","orderId":"order-60","msg":"normal message","level":60}`),
		event(5, `{"context":"orders","id":"unknown-id","msg":"ERROR unexpected"}`),
		event(6, `{"level":"info","msg":"request completed","error":null,"token":"error"}`),
		event(7, `ERROR connection refused`),
		event(8, `ERROR_COUNT=5`),
	}
	records[7].Labels = map[string]string{"pod": "plain-pod", "node_name": "plain-server"}
	result := monitor.Analyze(records, monitor.Filter{})
	if result.Errors != 5 || len(result.Issues) != 3 {
		t.Fatalf("wrong classification: %+v", result)
	}
	seen := make(map[string]monitor.Issue)
	for _, issue := range result.Issues {
		seen[issue.OrderID] = issue
	}
	if _, exists := seen["item-only"]; exists {
		t.Fatal("item id incorrectly promoted to order id")
	}
	if _, exists := seen["unknown-id"]; exists {
		t.Fatal("unknown message id incorrectly promoted to order id")
	}
	if !seen["order-real"].Critical || !seen["order-from-id"].Critical || seen[""].Count != 3 || seen[""].Pod != "plain-pod" {
		t.Fatalf("wrong level or context: %+v", seen)
	}
}

func TestAnalyzeFiltersPreserveActivityAndResellerEvidence(t *testing.T) {
	records := []model.LogRecord{
		event(0, `{"context":"orders","id":"a","resellerId":"r","msg":"creating order"}`),
		event(1, `{"context":"orders","orderId":"a","msg":"ERROR custom outage"}`),
		event(2, `{"context":"orders","orderId":"a","msg":"ERROR ignored"}`),
	}
	result := monitor.Analyze(records, monitor.Filter{Include: regexp.MustCompile(`ERROR`), Exclude: regexp.MustCompile(`ignored`), Critical: regexp.MustCompile(`custom outage`)})
	if result.Total != 3 || result.Filtered != 2 || result.Errors != 1 || len(result.Issues) != 1 || !result.Issues[0].Critical || result.Issues[0].ResellerID != "r" {
		t.Fatalf("filters changed activity or context: %+v", result)
	}
	result = monitor.Analyze(records, monitor.Filter{Exclude: regexp.MustCompile(`.`)})
	if result.Total != 3 || result.Filtered != 3 || result.Errors != 0 || len(result.Issues) != 0 {
		t.Fatalf("excluded lines looked like absent activity: %+v", result)
	}
}

func TestAnalyzeUniqueOrdersAcrossKindsAndProjects(t *testing.T) {
	records := []model.LogRecord{
		event(0, `{"context":"orders","id":"a","msg":"creating order"}`),
		event(1, `{"context":"orders","orderId":"a","msg":"order create error order not found"}`),
		event(2, `{"context":"orders","orderId":"a","msg":"error provisioned, timeout exceeded when trying to connect"}`),
		event(3, `{"context":"orders","orderId":"a","msg":"ERROR other project"}`),
		event(4, `{"order_id":"private@example.org","msg":"ERROR unsafe display id"}`),
		event(5, `{"order_id":"private@example.org","msg":"ERROR repeated unsafe display id"}`),
	}
	records[3].Project = "other-project"
	records = append(records, records[1])
	result := monitor.Analyze(records, monitor.Filter{})
	if result.Orders != 3 || result.OrdersWithErrors != 3 || result.Errors != 6 || result.ErrorsWithoutOrder != 0 || len(result.Issues) != 4 {
		t.Fatalf("order totals must deduplicate kinds and records, preserving project and raw id: %+v", result)
	}
}

func TestAnalyzeOrderTotalsBeforeFiltersAndErrorsAfterFilters(t *testing.T) {
	records := []model.LogRecord{
		event(0, `{"context":"orders","id":"normal","msg":"creating order"}`),
		event(1, `{"orderId":"excluded","msg":"ERROR ignored"}`),
		event(2, `{"orderId":"included","msg":"ERROR selected"}`),
		event(3, `{"orderId":"included","msg":"ERROR selected again"}`),
		event(4, `ERROR without order`),
		event(5, `{"context":"orders","id":"item-only","level":"error","msg":"create order item"}`),
		event(6, `{"msg":"ERROR ignored without order"}`),
	}
	result := monitor.Analyze(records, monitor.Filter{Include: regexp.MustCompile(`ERROR|create order item`), Exclude: regexp.MustCompile(`ignored`)})
	if result.Orders != 3 || result.OrdersWithErrors != 1 || result.ErrorsWithoutOrder != 2 || result.Errors != 4 || result.Filtered != 3 {
		t.Fatalf("order activity or filtered error counts are incorrect: %+v", result)
	}
	result = monitor.Analyze(records, monitor.Filter{Exclude: regexp.MustCompile(`.`)})
	if result.Orders != 3 || result.OrdersWithErrors != 0 || result.ErrorsWithoutOrder != 0 || result.Errors != 0 {
		t.Fatalf("excluding errors must preserve all observed orders: %+v", result)
	}
}

func TestAnalyzeCurrentErrorsRequireLaterProvisionConfirmation(t *testing.T) {
	for _, tc := range []struct {
		name                       string
		errorSecond, successSecond int
		resolved                   bool
	}{
		{"success after error", 1, 2, true},
		{"error after success", 2, 1, false},
		{"equal timestamp is ambiguous", 1, 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			records := []model.LogRecord{
				event(tc.errorSecond, `{"context":"orders","orderId":"a","msg":"order create error order not found"}`),
				event(tc.successSecond, `{"context":"orders","orderId":"a","msg":"order provisioned"}`),
			}
			result := monitor.Analyze(records, monitor.Filter{})
			if result.Orders != 1 || result.Errors != 1 || len(result.Issues) != 1 || result.IsResolved(result.Issues[0]) != tc.resolved {
				t.Fatalf("history or strict timestamp correlation lost: %+v", result)
			}
			if tc.resolved && (result.OrdersSucceeded != 1 || result.OrdersWithErrors != 0) || !tc.resolved && (result.OrdersSucceeded != 0 || result.OrdersWithErrors != 1) || result.OrdersOther != 0 {
				t.Fatalf("incorrect current order category: %+v", result)
			}
		})
	}
}

func TestAnalyzeResolvesSavedIssuesByProjectAndKind(t *testing.T) {
	old := monitor.Analyze([]model.LogRecord{
		event(1, `{"context":"orders","orderId":"a","msg":"order create error order item trial lasts"}`),
		event(1, `{"context":"orders","orderId":"a","msg":"order create error order item during the renewal block period"}`),
	}, monitor.Filter{})
	success := event(2, `{"context":"orders","orderId":"a","msg":"order provisioned"}`)
	current := monitor.Analyze([]model.LogRecord{success}, monitor.Filter{})
	if current.OrdersSucceeded != 1 || len(current.Issues) != 0 || len(old.Issues) != 2 {
		t.Fatalf("wrong isolated snapshots: old=%+v current=%+v", old, current)
	}
	kinds := map[string]bool{}
	for _, issue := range old.Issues {
		kinds[issue.Kind] = true
		if !current.IsResolved(issue) {
			t.Fatalf("saved issue without a current error was not resolved: %+v", issue)
		}
	}
	if !kinds["order_create_error_trial_lasts"] || !kinds["order_create_error_renewal_block_period"] {
		t.Fatalf("new concrete errors not recognized: %+v", old.Issues)
	}
	success.Project = "other-project"
	other := monitor.Analyze([]model.LogRecord{success}, monitor.Filter{})
	for _, issue := range old.Issues {
		if other.IsResolved(issue) {
			t.Fatal("same order id from another project resolved a saved issue")
		}
	}
}

func TestAnalyzeOnlyExplicitOrderProvisionedConfirmsSuccess(t *testing.T) {
	for _, line := range []string{
		`{"context":"orders","orderId":"a","msg":"order received successfully"}`,
		`{"context":"orders","orderId":"a","msg":"order items provisioned"}`,
		`{"context":"orders","orderId":"a","msg":"order created"}`,
		`{"context":"other","orderId":"a","msg":"order provisioned"}`,
		`{"context":"orders","id":"a","msg":"order provisioned"}`,
	} {
		result := monitor.Analyze([]model.LogRecord{
			event(1, `{"context":"orders","orderId":"a","msg":"order create error order not found"}`),
			event(2, line),
		}, monitor.Filter{})
		if result.OrdersWithErrors != 1 || result.OrdersSucceeded != 0 || result.IsResolved(result.Issues[0]) {
			t.Fatalf("unrelated event confirmed success: %s: %+v", line, result)
		}
	}
	result := monitor.Analyze([]model.LogRecord{
		event(1, `{"context":"orders","orderId":"a","msg":"order provisioned"}`),
		event(2, `{"context":"orders","orderId":"a","msg":"order create error order still being provision"}`),
		event(3, `{"context":"orders","orderId":"b","msg":"order create error order still being provision"}`),
	}, monitor.Filter{})
	if result.OrdersWithErrors != 0 || result.OrdersSucceeded != 1 || result.OrdersOther != 1 || result.Errors != 2 {
		t.Fatalf("still provisioning was treated as a current failure: %+v", result)
	}
	for _, issue := range result.Issues {
		if !result.IsResolved(issue) {
			t.Fatal("still provisioning must not remain an actionable error")
		}
	}
}

func TestAnalyzeFiltersCannotHideSuccessOrInventSuccess(t *testing.T) {
	records := []model.LogRecord{
		event(1, `{"context":"orders","orderId":"a","msg":"order create error order not found"}`),
		event(2, `{"context":"orders","orderId":"a","msg":"order provisioned"}`),
	}
	result := monitor.Analyze(records, monitor.Filter{Include: regexp.MustCompile(`error`)})
	if result.Filtered != 1 || result.OrdersSucceeded != 1 || result.OrdersWithErrors != 0 || !result.IsResolved(result.Issues[0]) {
		t.Fatalf("filter hid success evidence: %+v", result)
	}
	records = append(records, event(3, `{"context":"orders","orderId":"a","msg":"error provisioned, timeout exceeded when trying to connect"}`))
	result = monitor.Analyze(records, monitor.Filter{Exclude: regexp.MustCompile(`timeout`)})
	if result.Filtered != 1 || result.Errors != 1 || result.OrdersWithErrors != 0 || result.OrdersSucceeded != 0 || result.OrdersOther != 1 {
		t.Fatalf("excluding a later error invented success: %+v", result)
	}
}

func TestAnalyzeOrderTypesUseAllEvidenceAndMarkConflicts(t *testing.T) {
	records := []model.LogRecord{
		event(0, `{"context":"orders","id":"a","type":"new","msg":"creating order"}`),
		event(1, `{"context":"orders","orderId":"a","msg":"order create error order not found"}`),
		event(2, `{"context":"orders","orderId":"a","msg":"order provisioned"}`),
		event(3, `{"context":"orders","orderId":"b","type":"renew","msg":"order create error order item trial lasts"}`),
		event(4, `{"context":"orders","id":"c","type":"cancel","msg":"creating order"}`),
		event(5, `{"context":"orders","id":"d","type":"new","msg":"creating order"}`),
		event(6, `{"context":"orders","orderId":"d","type":"renew","msg":"order create error order not found"}`),
		event(7, `{"context":"orders","orderId":"e","msg":"ERROR something happened"}`),
		event(8, `{"context":"orders","orderId":"f","type":"private unsupported type","msg":"order provisioned"}`),
		event(9, `{"context":"orders","id":"g","msg":"creating order"}`),
	}
	result := monitor.Analyze(records, monitor.Filter{Exclude: regexp.MustCompile(`creating order`)})
	want := []monitor.OrderCounts{
		{Type: "new", Total: 1, Succeeded: 1},
		{Type: "renew", Total: 1, WithErrors: 1},
		{Type: "cancel", Total: 1, Other: 1},
		{Type: "unknown", Total: 4, Succeeded: 1, WithErrors: 2, Other: 1},
	}
	if result.Orders != 7 || result.OrdersSucceeded != 2 || result.OrdersWithErrors != 3 || result.OrdersOther != 2 || !reflect.DeepEqual(result.ByType, want) {
		t.Fatalf("incorrect type/category counts: %+v", result)
	}
	for _, issue := range result.Issues {
		wantType := map[string]string{"a": "new", "b": "renew", "d": "unknown", "e": "unknown"}[issue.OrderID]
		if issue.OrderType != wantType {
			t.Fatalf("issue lost inferred type or type conflict: %+v", issue)
		}
	}
}

func TestAnalyzeNeverReturnsRawSecrets(t *testing.T) {
	record := event(0, `{"context":"orders","orderId":"person@example.org","resellerId":"Bearer secret-reseller","pod":"https://user:password@host","server":"secret@example.org","password":"secret-password","token":"secret-token","msg":"ERROR secret-in-message"}`)
	record.Labels = map[string]string{"authorization": "secret-header", "node_name": strings.Repeat("x", 101)}
	record.Metadata = map[string]string{"token": "secret-metadata"}
	result := monitor.Analyze([]model.LogRecord{record}, monitor.Filter{})
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"secret", "example.org", "password", "Bearer", "https", strings.Repeat("x", 101)} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("sensitive context leaked: %s", data)
		}
	}
	if len(result.Issues) != 1 || len(result.Issues[0].Key) != 64 || result.Issues[0].OrderID != "" {
		t.Fatalf("invalid identifier not safely omitted: %+v", result)
	}
}

func TestAnalyzeStableGroupingProjectsConflictAndSort(t *testing.T) {
	records := []model.LogRecord{
		event(0, `{"context":"orders","id":"a","resellerId":"r1","msg":"creating order"}`),
		event(1, `{"context":"orders","orderId":"a","resellerId":"r2","msg":"ERROR retry 1"}`),
		event(2, `{"context":"orders","orderId":"a","msg":"ERROR retry 2"}`),
		event(3, `{"context":"orders","orderId":"b","msg":"FATAL only once"}`),
		event(4, `{"context":"orders","orderId":"a","resellerId":"other-reseller","msg":"ERROR other project"}`),
	}
	records[4].Project = "other-project"
	records = append(records, records[2]) // Две реальные одинаковые записи сохраняют кратность.
	original := append([]model.LogRecord(nil), records...)
	result := monitor.Analyze(records, monitor.Filter{})
	if !reflect.DeepEqual(records, original) {
		t.Fatal("input was mutated")
	}
	if len(result.Issues) != 3 || result.Errors != 5 || !result.Issues[0].Critical || result.Issues[1].Count != 3 || result.Issues[1].ResellerID != "" || result.Issues[2].ResellerID != "other-reseller" {
		t.Fatalf("wrong grouping, conflict or sorting: %+v", result)
	}
	for i, j := 0, len(records)-1; i < j; i, j = i+1, j-1 {
		records[i], records[j] = records[j], records[i]
	}
	if reversed := monitor.Analyze(records, monitor.Filter{}); !reflect.DeepEqual(result, reversed) {
		t.Fatalf("result depends on input order: %+v != %+v", result, reversed)
	}
	changed := original[1]
	changed.Line = `{"context":"orders","orderId":"a","msg":"ERROR another dynamic detail"}`
	if single := monitor.Analyze([]model.LogRecord{changed}, monitor.Filter{}); single.Issues[0].Key != result.Issues[1].Key {
		t.Fatal("group key depends on dynamic message")
	}
}

func TestEnrichResellersFillsHistoryAndPreservesWindowCounts(t *testing.T) {
	result := monitor.Analyze([]model.LogRecord{
		event(0, `{"orderId":"missing","msg":"ERROR current"}`),
		event(1, `{"orderId":"known","resellerId":"r1","msg":"ERROR current"}`),
		event(2, `{"orderId":"conflict","resellerId":"r1","msg":"ERROR current"}`),
		event(3, `{"orderId":"window-conflict","resellerId":"r1","msg":"ERROR current"}`),
		event(4, `{"orderId":"window-conflict","resellerId":"r2","msg":"normal"}`),
		event(5, `{"orderId":"history-conflict","msg":"ERROR current"}`),
		event(6, `{"orderId":"absent","msg":"ERROR current"}`),
		event(7, `{"orderId":"resolved","msg":"ERROR old"}`),
		event(8, `{"context":"orders","orderId":"resolved","msg":"order provisioned"}`),
	}, monitor.Filter{})
	before := result
	before.Issues = append([]monitor.Issue(nil), result.Issues...)
	monitor.EnrichResellers(&result, map[string][]string{
		"missing": {"r0", "r0", "private@example.org"}, "known": {"r1"},
		"conflict": {"r2"}, "window-conflict": {"r1"},
		"history-conflict": {"r2", "r1"}, "resolved": {"r3"},
	})
	seen := map[string]monitor.Issue{}
	for index, issue := range result.Issues {
		seen[issue.OrderID] = issue
		original := before.Issues[index]
		issue.ResellerID, issue.ResellerConflict = original.ResellerID, original.ResellerConflict
		if !reflect.DeepEqual(issue, original) {
			t.Fatal("history changed an error, its ordering or timestamps")
		}
	}
	if seen["missing"].ResellerID != "r0" || seen["known"].ResellerID != "r1" || seen["absent"].ResellerID != "" || seen["absent"].ResellerConflict {
		t.Fatalf("history did not fill missing context or preserve known ID: %+v", seen)
	}
	for _, id := range []string{"conflict", "window-conflict", "history-conflict"} {
		if !seen[id].ResellerConflict || seen[id].ResellerID != "" {
			t.Fatalf("reseller conflict guessed an owner: %+v", seen[id])
		}
	}
	if seen["resolved"].ResellerID != "" || !result.IsResolved(seen["resolved"]) {
		t.Fatal("history changed a resolved error")
	}
	result.Issues = before.Issues
	if !reflect.DeepEqual(result, before) {
		t.Fatal("history changed period counts or outcomes")
	}
}
