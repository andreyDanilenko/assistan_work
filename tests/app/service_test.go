package app_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"loki-analyzer/internal/app"
	"loki-analyzer/internal/model"
)

type sourceCall struct {
	method     string
	ctx        context.Context
	label      string
	expression string
	start      time.Time
	end        time.Time
	limit      int
}

type fakeSource struct {
	calls    []sourceCall
	response model.Response
	err      error
}

func (s *fakeSource) GetLabels(ctx context.Context, start, end time.Time) (model.Response, error) {
	s.calls = append(s.calls, sourceCall{method: "labels", ctx: ctx, start: start, end: end})
	return s.response, s.err
}

func (s *fakeSource) GetLabelValues(ctx context.Context, label string, start, end time.Time) (model.Response, error) {
	s.calls = append(s.calls, sourceCall{method: "values", ctx: ctx, label: label, start: start, end: end})
	return s.response, s.err
}

func (s *fakeSource) QueryRange(ctx context.Context, expression string, start, end time.Time, limit int) (model.Response, error) {
	s.calls = append(s.calls, sourceCall{
		method: "query", ctx: ctx, expression: expression, start: start, end: end, limit: limit,
	})
	return s.response, s.err
}

func baseRequest(command app.Command) app.Request {
	start := time.Date(2026, 10, 9, 12, 0, 0, 123, time.UTC)
	return app.Request{Command: command, Start: start, End: start.Add(15 * time.Minute), Limit: 37}
}

func serviceConfig() app.Config {
	return app.Config{DefaultProject: "sds-orders", ProjectLabel: "service"}
}

func TestServiceDispatchesLabelCommands(t *testing.T) {
	cases := []struct {
		command app.Command
		method  string
		label   string
	}{
		{app.Check, "labels", ""},
		{app.Labels, "labels", ""},
		{app.Values, "values", "namespace"},
		{app.Projects, "values", "service"},
	}
	for _, tc := range cases {
		t.Run(string(tc.command), func(t *testing.T) {
			source := &fakeSource{}
			service := app.New(serviceConfig(), source)
			request := baseRequest(tc.command)
			request.Label = "namespace"
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if _, err := service.Execute(ctx, request); err != nil {
				t.Fatal(err)
			}
			want := sourceCall{method: tc.method, ctx: ctx, label: tc.label, start: request.Start, end: request.End}
			if len(source.calls) != 1 || source.calls[0] != want {
				t.Fatalf("incorrect source invocation: %+v", source.calls)
			}
		})
	}
}

func TestServiceBuildsProjectQueriesAndForwardsLiteralQuery(t *testing.T) {
	cases := []struct {
		name       string
		command    app.Command
		project    string
		expression string
		want       string
	}{
		{name: "default project", command: app.Logs, want: `{service="sds-orders"}`},
		{
			name: "literal override", command: app.Logs, project: "orders\"} |= \"secret\\path\n",
			want: `{service="orders\"} |= \"secret\\path\n"}`,
		},
		{
			name: "query unchanged", command: app.Query,
			expression: "  {app=\"sds-orders\"} |= `ERROR` | json  ",
			want:       "  {app=\"sds-orders\"} |= `ERROR` | json  ",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			source := &fakeSource{}
			request := baseRequest(tc.command)
			request.Project, request.Expression = tc.project, tc.expression
			ctx := context.Background()
			if _, err := app.New(serviceConfig(), source).Execute(ctx, request); err != nil {
				t.Fatal(err)
			}
			want := sourceCall{
				method: "query", ctx: ctx, expression: tc.want,
				start: request.Start, end: request.End, limit: request.Limit,
			}
			if len(source.calls) != 1 || source.calls[0] != want {
				t.Fatalf("incorrect query invocation: %+v", source.calls)
			}
		})
	}
}

func TestServicePreservesResponseAndSourceErrors(t *testing.T) {
	wantResponse := model.Response{
		Body: []byte(`{"status":"success","data":["app"]}`), StatusCode: 206, Truncated: true,
		Values: []string{"app"}, Query: &model.LokiQueryResponse{Status: "success"},
	}
	for _, sourceErr := range []error{nil, errors.New("source unavailable")} {
		source := &fakeSource{response: wantResponse, err: sourceErr}
		response, err := app.New(serviceConfig(), source).Execute(context.Background(), baseRequest(app.Check))
		if !errors.Is(err, sourceErr) || !reflect.DeepEqual(response, wantResponse) {
			t.Fatal("service must preserve source errors, HTTP status, truncation and response data")
		}
	}
}

func TestServiceDoesNotCallSourceAfterCancellationOrInvalidRequest(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	source := &fakeSource{}
	service := app.New(serviceConfig(), source)
	if _, err := service.Execute(ctx, baseRequest(app.Logs)); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation: %v", err)
	}
	request := baseRequest(app.Query)
	if _, err := service.Execute(context.Background(), request); err == nil {
		t.Fatal("missing query must be rejected")
	}
	request = baseRequest(app.Logs)
	request.Project = "   "
	if _, err := service.Execute(context.Background(), request); err == nil {
		t.Fatal("blank project must be rejected")
	}
	request.Project = strings.Repeat("x", 4097)
	if _, err := service.Execute(context.Background(), request); err == nil {
		t.Fatal("oversize project must be rejected")
	}
	request.Project = ""
	if _, err := app.New(app.Config{ProjectLabel: "app"}, source).Execute(context.Background(), request); err == nil {
		t.Fatal("missing default project must be rejected")
	}
	if len(source.calls) != 0 {
		t.Fatal("invalid or canceled requests must not reach the source")
	}
}

func TestRequestValidation(t *testing.T) {
	cases := []struct {
		name   string
		change func(*app.Request)
		valid  bool
	}{
		{"valid logs", func(*app.Request) {}, true},
		{"24 hour boundary", func(r *app.Request) { r.End = r.Start.Add(24 * time.Hour) }, true},
		{"minimum limit", func(r *app.Request) { r.Limit = 1 }, true},
		{"maximum limit", func(r *app.Request) { r.Limit = 100000 }, true},
		{"labels need no limit", func(r *app.Request) { r.Command, r.Limit = app.Labels, 0 }, true},
		{"valid values", func(r *app.Request) { r.Command, r.Label = app.Values, "app" }, true},
		{"valid query", func(r *app.Request) { r.Command, r.Expression = app.Query, `{app="orders"}` }, true},
		{"empty period", func(r *app.Request) { r.End = r.Start }, false},
		{"reversed period", func(r *app.Request) { r.End = r.Start.Add(-time.Second) }, false},
		{"period too large", func(r *app.Request) { r.End = r.Start.Add(24*time.Hour + time.Nanosecond) }, false},
		{"zero limit", func(r *app.Request) { r.Limit = 0 }, false},
		{"negative limit", func(r *app.Request) { r.Limit = -1 }, false},
		{"limit too large", func(r *app.Request) { r.Limit = 100001 }, false},
		{"missing label", func(r *app.Request) { r.Command = app.Values }, false},
		{"blank label", func(r *app.Request) { r.Command, r.Label = app.Values, " \t" }, false},
		{"missing query", func(r *app.Request) { r.Command = app.Query }, false},
		{"blank query", func(r *app.Request) { r.Command, r.Expression = app.Query, " \t" }, false},
		{"unknown command", func(r *app.Request) { r.Command = "other" }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request := baseRequest(app.Logs)
			tc.change(&request)
			if err := request.Validate(); (err == nil) != tc.valid {
				t.Fatalf("valid=%v; error=%v", tc.valid, err)
			}
			if !tc.valid {
				source := &fakeSource{}
				if _, err := app.New(serviceConfig(), source).Execute(context.Background(), request); err == nil || len(source.calls) != 0 {
					t.Fatal("invalid request must fail before calling the source")
				}
			}
		})
	}
}
