package analyzer_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"loki-analyzer/internal/analyzer"
	"loki-analyzer/internal/model"
)

func TestSavedLokiExample(t *testing.T) {
	body, err := os.ReadFile("../../examples/loki-query-response.txt")
	if err != nil {
		t.Fatal(err)
	}
	var response model.LokiQueryResponse
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatal(err)
	}
	var records []model.LogRecord
	for _, stream := range response.Data.Result {
		for _, entry := range stream.Values {
			records = append(records, model.LogRecord{
				Project: stream.Labels["app"], Timestamp: time.Unix(0, entry.TimestampNS), Line: entry.Line,
			})
		}
	}
	result := analyze(t, records)
	if result.TotalRecords != 5 || len(result.Orders) != 1 || len(result.Skipped) != 0 || result.ErrorEvents != 0 {
		t.Fatalf("unexpected result: %+v", result)
	}
	order := result.Orders[0]
	if order.OrderID != "71640535-1dd6-42b4-ae11-0137503455c0" || order.ResellerID != "490a7b2f-2797-47be-ab24-b63dbc03edf8" {
		t.Fatalf("wrong order attribution: %+v", order)
	}
	if order.State != model.OrderInProgress || order.SourceStatus != "provision" || len(order.Events) != 5 {
		t.Fatalf("wrong order history: %+v", order)
	}
	if order.Events[1].ItemID != "386b2849-a8f3-476f-af99-f30370e25953" {
		t.Fatal("item ID was lost")
	}
	if order.FirstSeen.UnixNano() != 1791570347171964777 || order.LastSeen.UnixNano() != 1791570348650020209 {
		t.Fatal("Loki timestamp precision was lost")
	}
	if len(result.Resellers) != 1 || result.Resellers[0].Orders != 1 || result.Resellers[0].InProgress != 1 {
		t.Fatalf("wrong reseller summary: %+v", result.Resellers)
	}
}

func TestOrderIDsAndItemIDs(t *testing.T) {
	for _, test := range []struct {
		name, message, id, orderID, wantOrder, wantItem string
	}{
		{"order ID fallback", "creating order", "order", "", "order", ""},
		{"explicit order ID wins", "creating order", "other", "parent", "parent", ""},
		{"item parent", "create order item", "item", "parent", "parent", "item"},
		{"item cleanup parent", "remove order field in item", "item", "parent", "parent", "item"},
		{"missing item parent", "create order item", "item", "", "", ""},
		{"ambiguous error ID", "order create error order not found", "ambiguous", "", "", ""},
		{"ambiguous provision ID", "order provisioned", "ambiguous", "", "", ""},
		{"ambiguous timeout ID", "error provisioned, timeout exceeded when trying to connect", "ambiguous", "", "", ""},
		{"ambiguous artifacts ID", "get artifacts skipped, order not completed or expired", "ambiguous", "", "", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			record := orderRecord(t, "project", 1, model.OrderLog{Context: "orders", Message: test.message, ID: test.id, OrderID: test.orderID})
			result := analyze(t, []model.LogRecord{record})
			if test.wantOrder == "" {
				if len(result.Orders) != 0 || result.Skipped["missing_order_id"] != 1 {
					t.Fatalf("ambiguous ID was assigned to an order: %+v", result)
				}
				return
			}
			if len(result.Orders) != 1 || result.Orders[0].OrderID != test.wantOrder || result.Orders[0].Events[0].ItemID != test.wantItem {
				t.Fatalf("unexpected attribution: %+v", result)
			}
		})
	}
}

func TestKnownEventsDoNotImplyFullBusinessOutcome(t *testing.T) {
	for _, message := range []string{
		"getting order", "checking order exists", "creating order", "order created", "sending order to provision",
		"order items provisioned", "order provisioned", "order received successfully",
		"order create error order still being provision", "order create error order not found",
	} {
		t.Run(message, func(t *testing.T) {
			level := 50
			result := analyze(t, []model.LogRecord{orderRecord(t, "p", 1, model.OrderLog{
				Context: "orders", Message: message, OrderID: "o", Status: "success", Level: &level,
			})})
			order := result.Orders[0]
			isError := strings.HasPrefix(message, "order create error")
			wantState := model.OrderInProgress
			if isError || message == "getting order" || message == "checking order exists" || message == "order received successfully" {
				wantState = model.OrderUnknown
			} else if message == "order provisioned" {
				wantState = model.OrderProvisioned
			}
			if order.State != wantState || order.Events[0].IsError != isError || order.SourceStatus != "success" {
				t.Fatalf("unexpected interpretation: %+v", order)
			}
			wantErrors := 0
			if isError {
				wantErrors = 1
			}
			if result.ErrorEvents != wantErrors || order.ErrorCount != wantErrors || result.Resellers[0].ErrorEvents != wantErrors {
				t.Fatalf("wrong error count: %+v", result)
			}
			if result.Resellers[0].Succeeded != 0 || result.Resellers[0].Failed != 0 {
				t.Fatal("known stage events must not imply the full business outcome")
			}
		})
	}
}

func TestProvisioningConfirmationRequiresOrderLevelEvent(t *testing.T) {
	result := analyze(t, []model.LogRecord{
		orderRecord(t, "p", 1, model.OrderLog{Context: "orders", Message: "order items provisioned", OrderID: "confirmed", ResellerID: "r"}),
		orderRecord(t, "p", 2, model.OrderLog{Context: "orders", Message: "order provisioned", OrderID: "confirmed"}),
		orderRecord(t, "p", 3, model.OrderLog{Context: "orders", Message: "order items provisioned", OrderID: "items-only", ResellerID: "r"}),
	})
	if len(result.Orders) != 2 || result.Orders[0].OrderID != "confirmed" || result.Orders[0].State != model.OrderProvisioned || result.Orders[1].State != model.OrderInProgress {
		t.Fatalf("item confirmation must not confirm the whole order: %+v", result.Orders)
	}
	want := []model.ResellerSummary{{Project: "p", ResellerID: "r", Orders: 2, Provisioned: 1, InProgress: 1}}
	if !reflect.DeepEqual(result.Resellers, want) {
		t.Fatalf("unexpected stage totals: %+v", result.Resellers)
	}
}

func TestProvisioningConfirmationSurvivesLaterActivityAndErrors(t *testing.T) {
	records := []model.LogRecord{
		orderRecord(t, "p", 1, model.OrderLog{Context: "orders", Message: "creating order", ID: "o", ResellerID: "r"}),
		orderRecord(t, "p", 2, model.OrderLog{Context: "orders", Message: "order create error order still being provision", OrderID: "o"}),
		orderRecord(t, "p", 3, model.OrderLog{Context: "orders", Message: "order provisioned", OrderID: "o"}),
		orderRecord(t, "p", 4, model.OrderLog{Context: "orders", Message: "getting order", ID: "o"}),
		orderRecord(t, "p", 5, model.OrderLog{Context: "orders", Message: "order received successfully", ID: "o"}),
		orderRecord(t, "p", 6, model.OrderLog{Context: "orders", Message: "order created", ID: "o", Status: "provision"}),
		orderRecord(t, "p", 7, model.OrderLog{Context: "orders", Message: "order create error order not found", OrderID: "o"}),
	}
	confirmed := analyze(t, records[:3]).Orders[0]
	if confirmed.State != model.OrderProvisioned || confirmed.ErrorCount != 1 {
		t.Fatalf("a later confirmation must preserve the earlier operation error: %+v", confirmed)
	}
	result := analyze(t, records)
	order := result.Orders[0]
	if order.State != model.OrderProvisioned || len(order.Events) != len(records) || order.ErrorCount != 2 || result.ErrorEvents != 2 {
		t.Fatalf("confirmation and operation errors must coexist: %+v", result)
	}
	if order.LastSeen.UnixNano() != 7 || order.SourceStatus != "provision" {
		t.Fatal("later observations must remain available after stage confirmation")
	}
	want := []model.ResellerSummary{{Project: "p", ResellerID: "r", Orders: 1, Provisioned: 1, ErrorEvents: 2}}
	if !reflect.DeepEqual(result.Resellers, want) {
		t.Fatalf("confirmation must not erase error counts: %+v", result.Resellers)
	}
	slices.Reverse(records)
	if reversed := analyze(t, records); !reflect.DeepEqual(result, reversed) {
		t.Fatal("observed confirmation must not depend on input order")
	}
}

func TestSuccessfulReadDoesNotProveProcessing(t *testing.T) {
	result := analyze(t, []model.LogRecord{
		orderRecord(t, "p", 1, model.OrderLog{Context: "orders", Message: "getting order", ID: "o"}),
		orderRecord(t, "p", 2, model.OrderLog{Context: "orders", Message: "order received successfully", ID: "o"}),
	})
	if result.Orders[0].State != model.OrderUnknown || result.Resellers[0].Unknown != 1 {
		t.Fatalf("successful read must leave processing state unknown: %+v", result)
	}
}

func TestObservedTimeoutAndSkippedArtifactsEvents(t *testing.T) {
	for _, test := range []struct {
		message, eventType string
		level              int
		errors             int
	}{
		{"error provisioned, timeout exceeded when trying to connect", "order_provision_error_timeout", 50, 1},
		{"get artifacts skipped, order not completed or expired", "order_artifacts_skipped", 30, 0},
	} {
		t.Run(test.eventType, func(t *testing.T) {
			result := analyze(t, []model.LogRecord{orderRecord(t, "p", 1, model.OrderLog{
				Context: "orders", Message: test.message, OrderID: "parent", ID: "unrelated",
				Level: &test.level, Status: "provision",
			})})
			if len(result.Skipped) != 0 || len(result.Orders) != 1 {
				t.Fatalf("observed event was not recognized: %+v", result)
			}
			order := result.Orders[0]
			if order.OrderID != "parent" || order.State != model.OrderUnknown || order.ErrorCount != test.errors {
				t.Fatalf("event must use its explicit parent without inferring processing or failure: %+v", order)
			}
			event := order.Events[0]
			if event.Type != test.eventType || event.IsError != (test.errors > 0) || result.ErrorEvents != test.errors || result.Resellers[0].ErrorEvents != test.errors {
				t.Fatalf("incorrect event interpretation: %+v", result)
			}
		})
	}
}

func TestTimeoutDoesNotEraseObservedProvisioningConfirmation(t *testing.T) {
	for _, test := range []struct {
		name      string
		timestamp int64
	}{
		{"timeout before confirmation", 1},
		{"timeout after confirmation", 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := analyze(t, []model.LogRecord{
				orderRecord(t, "p", test.timestamp, model.OrderLog{Context: "orders", Message: "error provisioned, timeout exceeded when trying to connect", OrderID: "o"}),
				orderRecord(t, "p", 2, model.OrderLog{Context: "orders", Message: "order provisioned", OrderID: "o"}),
			})
			order := result.Orders[0]
			if order.State != model.OrderProvisioned || order.ErrorCount != 1 || len(order.Events) != 2 || result.Resellers[0].Provisioned != 1 || result.Resellers[0].Failed != 0 {
				t.Fatalf("retain both stage confirmation and timeout without inferring final failure: %+v", result)
			}
		})
	}
}

func TestResellerPropagationAndConflict(t *testing.T) {
	for _, conflicting := range []bool{false, true} {
		records := []model.LogRecord{
			orderRecord(t, "p", 3, model.OrderLog{Context: "orders", Message: "getting order", ID: "o"}),
			orderRecord(t, "p", 1, model.OrderLog{Context: "orders", Message: "creating order", ID: "o", ResellerID: "r1"}),
		}
		if conflicting {
			records = append(records, orderRecord(t, "p", 2, model.OrderLog{Context: "orders", Message: "order created", ID: "o", ResellerID: "r2"}))
		}
		result := analyze(t, records)
		wantReseller := "r1"
		if conflicting {
			wantReseller = ""
		}
		order := result.Orders[0]
		if order.ResellerID != wantReseller || order.ResellerConflict != conflicting || result.Resellers[0].ResellerID != wantReseller {
			t.Fatalf("wrong reseller resolution: %+v", result)
		}
		if order.Events[len(order.Events)-1].ResellerID != "" {
			t.Fatal("original event reseller must not be invented")
		}
		slices.Reverse(records)
		if reversed := analyze(t, records); !reflect.DeepEqual(result, reversed) {
			t.Fatal("reseller resolution depends on input order")
		}
	}
}

func TestOrderingProjectScopeAndRepeatedEvents(t *testing.T) {
	level, applicationTime := 30, int64(2000)
	event := model.OrderLog{Context: "orders", Message: "creating order", ID: "o", ResellerID: "r", Level: &level, TimeMS: &applicationTime}
	records := []model.LogRecord{
		orderRecord(t, "b", 2, event),
		orderRecord(t, "a", 2, event),
		orderRecord(t, "a", 2, event),
		orderRecord(t, "a", 1, model.OrderLog{Context: "orders", Message: "getting order", ID: "o", Status: "old"}),
		orderRecord(t, "a", 3, model.OrderLog{Context: "orders", Message: "order created", ID: "o", Status: "provision"}),
		orderRecord(t, "a", 2, model.OrderLog{Context: "orders", Message: "creating order", ID: "o"}),
		orderRecord(t, "a", 2, model.OrderLog{Context: "orders", Message: "creating order", ID: "o", Level: &level}),
	}
	original := slices.Clone(records)
	result := analyze(t, records)
	if !reflect.DeepEqual(records, original) {
		t.Fatal("input records were mutated")
	}
	if len(result.Orders) != 2 || result.Orders[0].Project != "a" || len(result.Orders[0].Events) != 6 || result.Orders[0].SourceStatus != "provision" {
		t.Fatalf("unexpected histories: %+v", result.Orders)
	}
	if len(result.Resellers) != 2 || result.Resellers[0].Project != "a" || result.Resellers[0].Orders != 1 {
		t.Fatalf("resellers from different projects were combined: %+v", result.Resellers)
	}
	slices.Reverse(records)
	if reversed := analyze(t, records); !reflect.DeepEqual(result, reversed) {
		t.Fatal("output depends on input order, including equal timestamps")
	}
}

func TestSkippedRecordsAndNoRawData(t *testing.T) {
	records := []model.LogRecord{
		{Line: "not json"},
		{Line: `{"context":"orders","id":3,"msg":"creating order"}`},
		{Line: `{"context":"billing","id":"o","msg":"creating order"}`},
		{Line: `{"context":"Orders","id":"o","msg":"creating order"}`},
		{Line: `{"context":"orders","orderId":"o","msg":"unknown"}`},
		{Line: `{"context":"orders","id":" ","msg":"creating order"}`},
		{Project: "p", Timestamp: time.Unix(0, 1), Line: `{"context":"orders","id":"o","msg":"creating order","password":"super-secret","ownerId":"private-owner"}`},
	}
	result := analyze(t, records)
	want := map[string]int{"invalid_json": 2, "unrelated_context": 2, "unknown_event": 1, "missing_order_id": 1}
	if result.TotalRecords != 7 || len(result.Orders) != 1 || !reflect.DeepEqual(result.Skipped, want) {
		t.Fatalf("wrong skip diagnostics: %+v", result)
	}
	body, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{"super-secret", "private-owner", "password", "creating order"} {
		if strings.Contains(string(body), private) {
			t.Fatalf("analysis leaks source data %q", private)
		}
	}
}

func TestResellerTotalsCountOrdersAndErrorOccurrencesSeparately(t *testing.T) {
	repeatedError := orderRecord(t, "p", 2, model.OrderLog{
		Context: "orders", Message: "order create error order still being provision", OrderID: "active",
	})
	result := analyze(t, []model.LogRecord{
		orderRecord(t, "p", 1, model.OrderLog{Context: "orders", Message: "creating order", ID: "active", ResellerID: "r"}),
		repeatedError,
		repeatedError,
		orderRecord(t, "p", 3, model.OrderLog{Context: "orders", Message: "getting order", ID: "read", ResellerID: "r"}),
		orderRecord(t, "p", 4, model.OrderLog{Context: "orders", Message: "order create error order not found", OrderID: "unknown"}),
	})
	want := []model.ResellerSummary{
		{Project: "p", ResellerID: "", Orders: 1, Unknown: 1, ErrorEvents: 1},
		{Project: "p", ResellerID: "r", Orders: 2, InProgress: 1, Unknown: 1, ErrorEvents: 2},
	}
	if result.ErrorEvents != 3 || !reflect.DeepEqual(result.Resellers, want) {
		t.Fatalf("order and event totals differ: %+v", result)
	}
	if result.Orders[0].ErrorCount != 2 || len(result.Orders[0].Events) != 3 || result.Orders[0].State != model.OrderInProgress {
		t.Fatalf("repeated errors must not erase activity or count as failed orders: %+v", result.Orders[0])
	}
}

func TestEmptyAndCanceled(t *testing.T) {
	result := analyze(t, nil)
	if result.Orders == nil || result.Resellers == nil || result.Skipped == nil || result.TotalRecords != 0 {
		t.Fatalf("empty result should have initialized collections: %+v", result)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := analyzer.New().Analyze(ctx, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
}

func analyze(t *testing.T, records []model.LogRecord) model.AnalysisResult {
	t.Helper()
	result, err := analyzer.New().Analyze(context.Background(), records)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func orderRecord(t *testing.T, project string, nanoseconds int64, log model.OrderLog) model.LogRecord {
	t.Helper()
	line, err := json.Marshal(log)
	if err != nil {
		t.Fatal(err)
	}
	return model.LogRecord{Project: project, Timestamp: time.Unix(0, nanoseconds), Line: string(line)}
}
