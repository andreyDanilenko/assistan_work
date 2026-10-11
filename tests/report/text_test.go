package report_test

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"loki-analyzer/internal/model"
	"loki-analyzer/internal/monitor"
	"loki-analyzer/internal/report"
)

func TestDatabaseReportGroupsOnlyCurrentErrors(t *testing.T) {
	start := time.Date(2026, 10, 11, 12, 0, 0, 0, time.FixedZone("MSK", 3*60*60))
	lines := []string{
		`{"context":"orders","id":"recovered","type":"renew","resellerId":"reseller-a","msg":"creating order","token":"private-token"}`,
		`{"context":"orders","orderId":"recovered","msg":"order create error order not found"}`,
		`{"context":"orders","orderId":"recovered","msg":"order provisioned"}`,
		`{"context":"orders","id":"failed","type":"new","resellerId":"reseller-b","msg":"creating order"}`,
		`{"context":"orders","orderId":"failed","msg":"order create error order item during the renewal block period"}`,
		`{"context":"orders","orderId":"failed","msg":"order create error order item trial lasts"}`,
		`{"context":"orders","id":"reading","type":"cancel","msg":"getting order"}`,
		`{"context":"orders","id":"waiting","type":"renew","msg":"creating order"}`,
		`{"context":"orders","orderId":"waiting","msg":"order create error order still being provision"}`,
	}
	records := make([]model.LogRecord, len(lines))
	for index, line := range lines {
		records[index] = model.LogRecord{Project: "sds-orders", Timestamp: start.Add(time.Duration(index) * time.Second), Line: line, Labels: map[string]string{"secret": "private-label", "pod": "orders-pod", "server": "node-a"}}
	}
	var output bytes.Buffer
	if err := report.WriteDatabase(&output, monitor.Analyze(records, monitor.Filter{}), "sds-orders", start, start.Add(time.Hour), nil); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"11.10.2026 09:00:00 UTC", "только сохранённые логи SQLite", `Проект: "sds-orders"`,
		"Уникальных заказов: 4. Успешно: 1. С актуальной ошибкой: 1. Результат неизвестен: 2.",
		"renew: всего 2 · успешно 1 · с ошибкой 0", "new: всего 1 · успешно 0 · с ошибкой 1", "cancel: всего 1",
		"продление заблокировано", "пробный период ещё действует", "Затронуто уникальных заказов: 1.",
		`Реселлер: "reseller-b". Заказов с этой ошибкой: 1.`, "new · заказов: 1", `pod: "orders-pod"`, `сервер: "node-a"`,
		"В шапке каждый заказ учтён один раз.",
	} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("missing %q in report:\n%s", expected, output.String())
		}
	}
	if strings.Count(output.String(), `ID заказа: "failed"`) != 2 {
		t.Fatal("the same order must appear under each of its two current error kinds")
	}
	for _, forbidden := range []string{"private-token", "private-label", "--all-orders", "события файла", "recovered", "reading", "waiting", "Что происходило", "Последние события", "creating order"} {
		if strings.Contains(output.String(), forbidden) {
			t.Fatalf("database report contains %q", forbidden)
		}
	}
}

func TestDatabaseReportIncludesAllIDsAndCountsOrdersNotRepeatedLogs(t *testing.T) {
	snapshot := monitor.Snapshot{Orders: 12, OrdersWithErrors: 12}
	for index := range 12 {
		issue := monitor.Issue{OrderID: fmt.Sprintf("order-%02d", index), Kind: "order_create_error_not_found", ResellerID: "reseller", OrderType: "renew", Count: 20}
		snapshot.Issues = append(snapshot.Issues, issue)
	}
	// Even a repeated aggregate cannot become a second order in the report.
	snapshot.Issues = append(snapshot.Issues, snapshot.Issues[0])
	var output bytes.Buffer
	if err := report.WriteDatabase(&output, snapshot, "app", time.Time{}, time.Time{}, nil); err != nil {
		t.Fatal(err)
	}
	if strings.Count(output.String(), "• ID заказа:") != 12 || !strings.Contains(output.String(), "Затронуто уникальных заказов: 12.") || !strings.Contains(output.String(), "Заказов с этой ошибкой: 12.") || !strings.Contains(output.String(), "renew · заказов: 12") {
		t.Fatalf("report lost IDs or counted repeated logs as orders:\n%s", output.String())
	}
	for index := range 12 {
		if strings.Count(output.String(), fmt.Sprintf("ID заказа: %q", fmt.Sprintf("order-%02d", index))) != 1 {
			t.Fatalf("order %d must be included once", index)
		}
	}
	// Incoming map/slice order must not change the resulting document.
	for left, right := 0, len(snapshot.Issues)-1; left < right; left, right = left+1, right-1 {
		snapshot.Issues[left], snapshot.Issues[right] = snapshot.Issues[right], snapshot.Issues[left]
	}
	var reversed bytes.Buffer
	if err := report.WriteDatabase(&reversed, snapshot, "app", time.Time{}, time.Time{}, nil); err != nil || output.String() != reversed.String() {
		t.Fatalf("report depends on input order: %v", err)
	}
}

func TestDatabaseReportAddsResellerNamesWithoutMergingIDs(t *testing.T) {
	ids := []string{"reseller-a", "reseller-b", "unknown", ""}
	// Одинаковые названия не объединяют реселлеров, а управляющие символы экранируются.
	name := "Bank \"A\"\n\x1b[31m"
	names := map[string]string{"reseller-a": name, "reseller-b": name, "": "must not use"}
	snapshot := monitor.Snapshot{Orders: 4, OrdersWithErrors: 4}
	for index, id := range ids {
		snapshot.Issues = append(snapshot.Issues, monitor.Issue{OrderID: fmt.Sprintf("order-%d", index), ResellerID: id, Kind: "other_error", Count: 1})
	}
	snapshot.Issues = append(snapshot.Issues, monitor.Issue{Kind: "other_error", Count: 7})
	var output bytes.Buffer
	if err := report.WriteDatabase(&output, snapshot, "app", time.Time{}, time.Time{}, names); err != nil {
		t.Fatal(err)
	}
	for _, label := range []string{
		fmt.Sprintf("%q (ID: %q)", name, "reseller-a"),
		fmt.Sprintf("%q (ID: %q)", name, "reseller-b"),
		`"unknown"`, "не определен",
	} {
		if !strings.Contains(output.String(), "Реселлер: "+label+". Заказов с этой ошибкой: 1.") {
			t.Fatalf("missing separate reseller label %q:\n%s", label, output.String())
		}
	}
	for _, expected := range []string{"Нераспознанный вид ошибки.", "Затронуто уникальных заказов: 4.", "тип не определён · заказов: 1", "Без ID заказа: 7 записей; в число заказов не входят."} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("missing %q:\n%s", expected, output.String())
		}
	}
	if strings.Count(output.String(), "• ID заказа:") != 4 || strings.ContainsRune(output.String(), '\x1b') || strings.Contains(output.String(), "must not use") {
		t.Fatal("report invented an order, emitted controls, or assigned a name without an ID")
	}
}

func TestDatabaseReportStartsWithUniqueResellerTotalsBeforeAllOrderIDs(t *testing.T) {
	snapshot := monitor.Snapshot{Orders: 5, OrdersWithErrors: 5, Issues: []monitor.Issue{
		{Kind: "order_create_error_not_found", OrderID: "order-new", ResellerID: "reseller-a", OrderType: "new", Count: 8},
		{Kind: "order_provision_error_timeout", OrderID: "order-new", ResellerID: "reseller-a", OrderType: "new", Count: 12},
		{Kind: "order_create_error_not_found", OrderID: "order-renew", ResellerID: "reseller-a", OrderType: "renew", Count: 1},
		{Kind: "order_create_error_not_found", OrderID: "order-cancel", ResellerID: "reseller-b", OrderType: "cancel", Count: 1},
		{Kind: "other_error", OrderID: "order-missing", Count: 1},
		{Kind: "other_error", OrderID: "order-conflict", ResellerConflict: true, Count: 1},
	}}
	names := map[string]string{"reseller-a": "Same name", "reseller-b": "Same name"}
	var output bytes.Buffer
	if err := report.WriteDatabase(&output, snapshot, "app", time.Time{}, time.Time{}, names); err != nil {
		t.Fatal(err)
	}
	summary, details, found := strings.Cut(output.String(), "Подробности: категории → реселлеры → заказы")
	if !found || strings.Contains(summary, "ID заказа:") {
		t.Fatal("order IDs must follow the compact overview in an explicitly separated section")
	}
	if strings.Index(summary, "Категории ошибок за период:") > strings.Index(summary, "Реселлеры с актуальными ошибками:") {
		t.Fatal("error categories must precede reseller totals")
	}
	for _, expected := range []string{
		`Реселлер: "Same name" (ID: "reseller-a"). Уникальных заказов с ошибками: 2.`,
		`new: 1 · renew: 1 · cancel: 0 · тип не определён: 0.`,
		`Реселлер: "Same name" (ID: "reseller-b"). Уникальных заказов с ошибками: 1.`,
		`new: 0 · renew: 0 · cancel: 1 · тип не определён: 0.`,
		`Реселлер: не определен. Уникальных заказов с ошибками: 1.`,
		`Реселлер: в сохранённых логах указаны разные ID; принадлежность требует проверки. Уникальных заказов с ошибками: 1.`,
	} {
		if !strings.Contains(summary, expected) {
			t.Fatalf("missing %q in compact overview:\n%s", expected, summary)
		}
	}
	for _, id := range []string{"order-new", "order-renew", "order-cancel", "order-missing", "order-conflict"} {
		if !strings.Contains(details, fmt.Sprintf("ID заказа: %q", id)) {
			t.Fatalf("details lost %q", id)
		}
	}
	if strings.Count(details, `ID заказа: "order-new"`) != 2 {
		t.Fatal("a multi-error order must remain in both detailed error categories")
	}
}

func TestDatabaseReportDoesNotAssignConflictingOrderToTwoResellers(t *testing.T) {
	snapshot := monitor.Snapshot{Orders: 1, OrdersWithErrors: 1, Issues: []monitor.Issue{
		{Kind: "order_create_error_not_found", OrderID: "order", ResellerID: "reseller-a", Count: 1},
		{Kind: "order_provision_error_timeout", OrderID: "order", ResellerID: "reseller-b", Count: 1},
	}}
	var output bytes.Buffer
	if err := report.WriteDatabase(&output, snapshot, "app", time.Time{}, time.Time{}, nil); err != nil {
		t.Fatal(err)
	}
	summary, _, _ := strings.Cut(output.String(), "Подробности: категории → реселлеры → заказы")
	if strings.Count(summary, "Уникальных заказов с ошибками: 1.") != 1 || !strings.Contains(summary, "в сохранённых логах указаны разные ID") {
		t.Fatalf("one conflicting order must be counted once in a separate reseller group:\n%s", summary)
	}
}

func TestDatabaseReportRejectsOversizeBeforeWriting(t *testing.T) {
	snapshot := monitor.Snapshot{Issues: []monitor.Issue{{Kind: "other_error", OrderID: strings.Repeat("a", 8<<20)}}}
	var output bytes.Buffer
	err := report.WriteDatabase(&output, snapshot, "app", time.Time{}, time.Time{}, nil)
	if err == nil || !strings.Contains(err.Error(), "сократите период") || output.Len() != 0 {
		t.Fatal("oversized report must fail without writing a partial document")
	}
}

func TestDatabaseReportSeparatesMissingAndConflictingResellers(t *testing.T) {
	snapshot := monitor.Snapshot{Orders: 2, OrdersWithErrors: 2, Issues: []monitor.Issue{
		{Kind: "order_create_error_not_found", OrderID: "missing", Count: 1},
		{Kind: "order_create_error_not_found", OrderID: "conflict", ResellerConflict: true, Count: 1},
	}}
	var output bytes.Buffer
	if err := report.WriteDatabase(&output, snapshot, "app", time.Time{}, time.Time{}, nil); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"Категории ошибок за период:", "в сохранённых логах указаны разные ID", "Реселлер: не определен", `ID заказа: "missing"`, `ID заказа: "conflict"`} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("missing %q in report", expected)
		}
	}
	if strings.Count(output.String(), "Заказов с этой ошибкой: 1.") != 2 {
		t.Fatal("missing and conflicting reseller identity must remain separate")
	}
}

type failedWriter struct{ err error }

func (w failedWriter) Write([]byte) (int, error) { return 0, w.err }

func TestDatabaseReportReturnsWriterError(t *testing.T) {
	want := errors.New("write failed")
	err := report.WriteDatabase(failedWriter{want}, monitor.Snapshot{}, "app", time.Time{}, time.Time{}, nil)
	if !errors.Is(err, want) {
		t.Fatalf("got %v, want writer error", err)
	}
}

// Даже ненулевые счётчики не должны скрыть пропущенный участок периода.
func TestDatabaseReportDisclosesCoverageAndEveryGap(t *testing.T) {
	start := time.Date(2026, 10, 11, 10, 0, 0, 0, time.UTC)
	gap := func(n int) model.TimeRange {
		return model.TimeRange{Start: start.Add(time.Duration(n) * time.Minute), End: start.Add(time.Duration(n+1) * time.Minute)}
	}
	for _, test := range []struct {
		name     string
		coverage model.Coverage
		want     string
	}{
		{"legacy", model.Coverage{}, "Полнота сбора за период не подтверждена"},
		{"empty but collected", model.Coverage{Known: true}, "Все участки периода получены из Loki"},
		{"gaps", model.Coverage{Known: true, Gaps: []model.TimeRange{gap(1), gap(3), gap(5), gap(7)}}, "НЕПОЛНЫЙ СБОР"},
	} {
		t.Run(test.name, func(t *testing.T) {
			snapshot := monitor.Snapshot{Coverage: test.coverage}
			var out bytes.Buffer
			if err := report.WriteDatabase(&out, snapshot, "orders", start, start.Add(15*time.Minute), nil); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(out.String(), test.want) {
				t.Fatalf("missing coverage status %q: %s", test.want, out.String())
			}
			if (!test.coverage.Known || len(test.coverage.Gaps) > 0) && strings.Contains(out.String(), "Все участки периода получены") {
				t.Fatal("unverified history was advertised as complete")
			}
			for _, missing := range test.coverage.Gaps {
				if !strings.Contains(out.String(), missing.Start.Format("02.01.2006 15:04:05")) || !strings.Contains(out.String(), missing.End.Format("02.01.2006 15:04:05")) {
					t.Fatal("TXT omitted a missing interval")
				}
			}
			if len(test.coverage.Gaps) == 4 {
				if !strings.Contains(snapshot.CoverageText(), "Ещё неподтверждённых участков: 1") {
					t.Fatal("short message hid truncated gap count")
				}
			}
		})
	}
}
