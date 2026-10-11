package input_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"loki-analyzer/internal/input"
)

const grafanaHeaders = ": \"1000 lines shown — 2.89% (5min 13sec) of 3h\"\n" +
	"Total bytes processed: \"1.64  MB\"\n" +
	"Common labels: {\"app\":\"sds-orders\",\"service_name\":\"sds-orders\"}\n\n"

const grafanaRow = "1791578632581\t2026-10-09T20:43:52.581Z\t{\"orderId\":\"example\",\"msg\":\"order provisioned\"}"

func TestGrafanaTextPreservesRecordsAndPayload(t *testing.T) {
	const payload = "message with\ttabs and trailing spaces  "
	row := "1791578632581\t2026-10-09T23:43:52.581123456+03:00\t" + payload
	body := "\xef\xbb\xbf" + grafanaHeaders + row + "\n" + row + "\n"
	records, err := input.NewLokiFileSource().Read(context.Background(), writeResponse(t, []byte(body)))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || !reflect.DeepEqual(records[0], records[1]) {
		t.Fatal("duplicates must be retained")
	}
	record := records[0]
	if record.Line != payload || record.Timestamp.Format(time.RFC3339Nano) != "2026-10-09T20:43:52.581123456Z" {
		t.Fatal("payload and full timestamp precision must be preserved")
	}
	if record.Project != "sds-orders" || record.Labels["service_name"] != "sds-orders" || record.Metadata != nil {
		t.Fatal("common labels must supply the project without inventing metadata")
	}
}

func TestGrafanaTextAcceptsCRLFAndEmptyExport(t *testing.T) {
	for _, body := range []string{grafanaHeaders, strings.ReplaceAll(grafanaHeaders+grafanaRow+"\n", "\n", "\r\n")} {
		records, err := input.NewLokiFileSource().Read(context.Background(), writeResponse(t, []byte(body)))
		if err != nil || records == nil {
			t.Fatalf("valid export rejected: %v", err)
		}
	}
}

func TestGrafanaTextRejectsMalformedRowsAndHeaders(t *testing.T) {
	const secret = "private-payload-marker"
	cases := map[string]string{
		"missing labels":    grafanaRow,
		"empty file":        "\n",
		"unknown header":    "Export: " + secret + "\n" + grafanaHeaders + grafanaRow,
		"invalid header":    ": " + secret + "\n" + grafanaHeaders + grafanaRow,
		"duplicate summary": ": \"summary\"\n" + grafanaHeaders + grafanaRow,
		"duplicate bytes":   "Total bytes processed: \"0\"\n" + grafanaHeaders + grafanaRow,
		"duplicate labels":  grafanaHeaders + "Common labels: {\"app\":\"other\"}\n" + grafanaRow,
		"header after data": grafanaHeaders + grafanaRow + "\n: \"summary\"",
		"unknown line":      grafanaHeaders + grafanaRow + "\n" + secret,
		"missing columns":   grafanaHeaders + "1791578632581\t" + secret,
		"timestamp mismatch": grafanaHeaders + strings.Replace(grafanaRow,
			"1791578632581", "1791578632582", 1),
		"timestamp invalid": grafanaHeaders + "1791578632581\t" + secret + "\tpayload",
		"milliseconds invalid": grafanaHeaders + secret +
			"\t2026-10-09T20:43:52.581Z\tpayload",
		"milliseconds overflow": grafanaHeaders + "9223372036854775808\t2026-10-09T20:43:52.581Z\tpayload",
		"milliseconds max":      grafanaHeaders + "9223372036854775807\t2026-10-09T20:43:52.581Z\tpayload",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			records, err := input.NewLokiFileSource().Read(context.Background(), writeResponse(t, []byte(body)))
			if err == nil || records != nil {
				t.Fatal("malformed export must not produce partial records")
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatal("error must not include source contents")
			}
		})
	}
}

func TestGrafanaTextRejectsInvalidCommonLabels(t *testing.T) {
	for _, labels := range []string{
		`null`, `[]`, `{}`, `{"app":" "}`, `{"app":12}`, `{"app":null}`,
		`{"app":"orders","other":null}`, `{"app":"orders","other":12}`,
		`{"app":"` + strings.Repeat("a", 4097) + `"}`,
		`{"app":"orders"} {}`,
	} {
		body := "Common labels: " + labels + "\n" + grafanaRow
		if records, err := input.NewLokiFileSource().Read(context.Background(), writeResponse(t, []byte(body))); err == nil || records != nil {
			t.Fatal("invalid labels must not produce records")
		}
	}
}

func TestGrafanaTextLimitsRecordsAndReportsLineNumber(t *testing.T) {
	body := "Common labels: {\"app\":\"orders\"}\n" + strings.Repeat("0\t1970-01-01T00:00:00Z\tx\n", maxRecords+1)
	if records, err := input.NewLokiFileSource().Read(context.Background(), writeResponse(t, []byte(body))); err == nil || records != nil {
		t.Fatal("record limit must reject the entire export")
	}
	body = grafanaHeaders + grafanaRow + "\nmalformed"
	_, err := input.NewLokiFileSource().Read(context.Background(), writeResponse(t, []byte(body)))
	if err == nil || !strings.Contains(err.Error(), "строка 6:") {
		t.Fatalf("error must identify the malformed row, got %v", err)
	}
}

func TestGrafanaTextHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if records, err := input.NewLokiFileSource().Read(ctx, writeResponse(t, []byte(grafanaHeaders+grafanaRow))); !errors.Is(err, context.Canceled) || records != nil {
		t.Fatalf("expected cancellation, got %v", err)
	}
}

func TestLokiFileDetectsJSONWithBOMByContent(t *testing.T) {
	body := []byte("\xef\xbb\xbf\n  {\"status\":\"success\",\"data\":{\"resultType\":\"streams\",\"result\":[]}}")
	records, err := input.NewLokiFileSource().Read(context.Background(), writeResponse(t, body))
	if err != nil || records == nil || len(records) != 0 {
		t.Fatalf("JSON detection must not depend on the .txt extension: %v", err)
	}
}
