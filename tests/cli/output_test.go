package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"loki-analyzer/internal/app"
	"loki-analyzer/internal/cli"
	"loki-analyzer/internal/model"
)

// Render through the public command entry points, as the executable does.
func renderResponse(output io.Writer, options cli.Options, response model.Response) error {
	options.Timeout = time.Second
	service := executorFunc(func(context.Context, app.Request) (model.Response, error) { return response, nil })
	var diagnostic bytes.Buffer
	if cli.Run(context.Background(), service, options, output, &diagnostic) != 0 {
		return errors.New(diagnostic.String())
	}
	return nil
}

func renderAnalysis(output io.Writer, result model.AnalysisResult, allOrders bool) error {
	service := fileAnalyzerFunc(func(context.Context, string) (model.AnalysisResult, error) { return result, nil })
	var diagnostic bytes.Buffer
	if cli.RunAnalysis(context.Background(), service, cli.Options{Timeout: time.Second, AllOrders: allOrders}, output, &diagnostic) != 0 {
		return errors.New(diagnostic.String())
	}
	return nil
}

const privateLogResponse = `{"status":"success","data":{"resultType":"streams","result":[{"stream":{"app":"private-label"},"values":[["3000000000","private-message\u001b[31m",{"secret":"private-metadata"}],["1000000000","other-private-message"]]},{"stream":{"node":"private-node"},"values":[["2000000000","last-private-message"]]}]}}`

func TestPrintResponseSummaryOmitsPrivateData(t *testing.T) {
	for _, command := range []string{"logs", "query"} {
		var out bytes.Buffer
		err := renderResponse(&out, cli.Options{Request: app.Request{Command: app.Command(command)}}, model.Response{Body: []byte(privateLogResponse), StatusCode: 200, Query: parsedPrivateResponse(t)})
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"Потоков: 2", "Записей в ответе: 3", "1970-01-01T00:00:01Z", "1970-01-01T00:00:03Z"} {
			if !strings.Contains(out.String(), want) {
				t.Fatalf("summary missing %q: %s", want, out.String())
			}
		}
		if strings.Contains(out.String(), "private-") || strings.ContainsRune(out.String(), '\x1b') {
			t.Fatal("summary exposed log text, labels, metadata or terminal controls")
		}
	}
}

func TestPrintResponseRawPreservesJSONData(t *testing.T) {
	var out bytes.Buffer
	if err := renderResponse(&out, cli.Options{Request: app.Request{Command: app.Logs}, Raw: true}, model.Response{Body: []byte(privateLogResponse)}); err != nil {
		t.Fatal(err)
	}
	var before, after any
	if err := json.Unmarshal([]byte(privateLogResponse), &before); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(out.Bytes(), &after); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatal("raw output changed JSON data")
	}
	if strings.ContainsRune(out.String(), '\x1b') {
		t.Fatal("raw JSON must retain escaped control characters")
	}
}

func TestPrintResponseLabelsAreSortedAndQuoted(t *testing.T) {
	var out bytes.Buffer
	body := []byte(`{"status":"success","data":["z-last","a\u001b]0;unsafe\u0007\nvalue"]}`)
	if err := renderResponse(&out, cli.Options{Request: app.Request{Command: app.Values}}, model.Response{Body: body, Values: []string{"z-last", "a\x1b]0;unsafe\x07\nvalue"}}); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out.String(), `"a\x1b]0;unsafe\a\nvalue"`) || !strings.HasSuffix(out.String(), "\"z-last\"\n") {
		t.Fatalf("labels must be sorted with terminal controls escaped: %q", out.String())
	}
	if strings.ContainsAny(out.String(), "\x1b\x07") {
		t.Fatal("label controls were printed directly")
	}
	out.Reset()
	if err := renderResponse(&out, cli.Options{Request: app.Request{Command: app.Check}}, model.Response{Body: body, StatusCode: 200, Values: []string{"z-last", "a\x1b]0;unsafe\x07\nvalue"}}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "unsafe") || !strings.Contains(out.String(), "HTTP 200") || !strings.Contains(out.String(), "Меток: 2") {
		t.Fatal("check should show only HTTP status and label count")
	}
}

func parsedPrivateResponse(t *testing.T) *model.LokiQueryResponse {
	t.Helper()
	var response model.LokiQueryResponse
	if err := json.Unmarshal([]byte(privateLogResponse), &response); err != nil {
		t.Fatal(err)
	}
	return &response
}

func TestAnalysisOutputEscapesFieldsAndShowsResellerConflict(t *testing.T) {
	result := model.AnalysisResult{
		Orders:    []model.OrderState{{OrderID: "order\x1b[31m", Project: "app\n", State: model.OrderUnknown, SourceStatus: "state\x07", ResellerConflict: true}},
		Resellers: []model.ResellerSummary{{Project: "app", ResellerID: "reseller\x1b[31m", Orders: 1}},
	}
	var out bytes.Buffer
	if err := renderAnalysis(&out, result, false); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(out.String(), "\x1b\x07") || !strings.Contains(out.String(), "В событиях указаны разные реселлеры") {
		t.Fatal("output must escape terminal controls and show ambiguous reseller ownership")
	}
}

func TestAnalysisExplainsDemoEventsAndSkips(t *testing.T) {
	result := model.AnalysisResult{
		TotalRecords: 3, SyntheticRecords: 3, ErrorEvents: 1,
		Orders: []model.OrderState{{OrderID: "demo-order", State: model.OrderProvisioned, ErrorCount: 1,
			Events: []model.OrderEvent{
				{Type: "order_create_error_still_provisioning", IsError: true, Timestamp: time.Unix(1, 0)},
				{Type: "order_provisioned", Timestamp: time.Unix(2, 0)},
			}}},
		Skipped: map[string]int{"unknown_event": 1},
	}
	var out bytes.Buffer
	if err := renderAnalysis(&out, result, false); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Демонстрационный пример", "Сервис подтвердил выполнение этапа", "заказ еще обрабатывается", "Тип сообщения пока не поддерживается", "UTC"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("report missing explanation: %s", want)
		}
	}
	for _, unwanted := range []string{"unknown_event", "in_progress", "Исходный статус", `Реселлер: ""`} {
		if strings.Contains(out.String(), unwanted) {
			t.Fatalf("report still exposes unclear internal field: %s", unwanted)
		}
	}
}

func TestShortHistoryStillExplainsOlderError(t *testing.T) {
	events := []model.OrderEvent{{Type: "order_create_error_not_found", IsError: true}}
	for range 5 + 1 {
		events = append(events, model.OrderEvent{Type: "getting_order"})
	}
	var out bytes.Buffer
	err := renderAnalysis(&out, model.AnalysisResult{Orders: []model.OrderState{{ErrorCount: 1, Events: events}}}, false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(out.String(), "Запрошены данные заказа") != 5 || !strings.Contains(out.String(), "показано 5 из 7") || !strings.Contains(out.String(), "заказ не найден") {
		t.Fatal("bounded history must retain a description of an earlier error")
	}
}

func TestMixedExampleIsNotPresentedAsEntirelySynthetic(t *testing.T) {
	var out bytes.Buffer
	if err := renderAnalysis(&out, model.AnalysisResult{TotalRecords: 2, SyntheticRecords: 1}, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Смешанные данные") || strings.Contains(out.String(), "заказы и реселлеры вымышлены") {
		t.Fatal("mixed input must not be described as entirely synthetic")
	}
}

func TestReportLimitsDetailsButPrioritizesErrors(t *testing.T) {
	result := model.AnalysisResult{}
	for i := range 10 + 2 {
		result.Orders = append(result.Orders, model.OrderState{OrderID: fmt.Sprintf("order-%02d", i), State: model.OrderProvisioned})
	}
	result.Orders[len(result.Orders)-1].ErrorCount = 1
	for _, all := range []bool{false, true} {
		var out bytes.Buffer
		if err := renderAnalysis(&out, result, all); err != nil {
			t.Fatal(err)
		}
		want := 10
		if all {
			want = len(result.Orders)
		}
		if strings.Count(out.String(), "\nЗаказ ") != want || !strings.Contains(out.String(), "Этап обработки подтвержден у 12 заказов") {
			t.Fatal("detail limit changed totals or hid all-orders output")
		}
		if strings.Index(out.String(), "order-11") > strings.Index(out.String(), "order-00") {
			t.Fatal("error history must appear before orders without errors")
		}
	}
	if result.Orders[0].OrderID != "order-00" {
		t.Fatal("formatting must not mutate the service result")
	}
}
