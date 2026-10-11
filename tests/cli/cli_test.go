package cli_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"loki-analyzer/internal/app"
	"loki-analyzer/internal/cli"
	"loki-analyzer/internal/model"
)

type executorFunc func(context.Context, app.Request) (model.Response, error)

func (f executorFunc) Execute(ctx context.Context, request app.Request) (model.Response, error) {
	return f(ctx, request)
}

func TestRunUsesInjectedExecutorAndKeepsExitCodes(t *testing.T) {
	for _, test := range []struct {
		name           string
		response       model.Response
		err            error
		wantCode       int
		wantDiagnostic string
	}{
		{"success", model.Response{StatusCode: 200, Values: []string{"app"}}, nil, 0, ""},
		{"truncated", model.Response{StatusCode: 200, Values: []string{"app"}, Truncated: true}, nil, 2, "Достигнут лимит"},
		{"forbidden", model.Response{StatusCode: 403}, errors.New("source rejected request"), 1, "Проверьте права"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var out, diagnostic bytes.Buffer
			calls := 0
			executor := executorFunc(func(ctx context.Context, request app.Request) (model.Response, error) {
				calls++
				if request.Command != app.Check {
					t.Fatal("request changed")
				}
				if _, ok := ctx.Deadline(); !ok {
					t.Fatal("operation has no deadline")
				}
				return test.response, test.err
			})
			code := cli.Run(context.Background(), executor, cli.Options{Request: app.Request{Command: app.Check}, Timeout: time.Second}, &out, &diagnostic)
			if code != test.wantCode || calls != 1 {
				t.Fatalf("code %d, calls %d", code, calls)
			}
			if test.err != nil && out.Len() > 0 {
				t.Fatal("failed request printed a successful result")
			}
			if test.wantDiagnostic == "" && diagnostic.Len() != 0 {
				t.Fatal("unexpected diagnostic")
			}
			if !strings.Contains(diagnostic.String(), test.wantDiagnostic) {
				t.Fatal("missing diagnostic")
			}
		})
	}
}

func TestRunCancelsInjectedExecutor(t *testing.T) {
	executor := executorFunc(func(ctx context.Context, _ app.Request) (model.Response, error) {
		<-ctx.Done()
		return model.Response{}, ctx.Err()
	})
	var diagnostic bytes.Buffer
	if cli.Run(context.Background(), executor, cli.Options{Timeout: time.Millisecond}, io.Discard, &diagnostic) != 1 {
		t.Fatal("timeout was not reported")
	}
	if !strings.Contains(diagnostic.String(), context.DeadlineExceeded.Error()) {
		t.Fatal("missing timeout error")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("output unavailable") }

func TestRunReportsOutputFailure(t *testing.T) {
	executor := executorFunc(func(context.Context, app.Request) (model.Response, error) {
		return model.Response{StatusCode: 200, Values: []string{"app"}}, nil
	})
	var diagnostic bytes.Buffer
	code := cli.Run(context.Background(), executor, cli.Options{Request: app.Request{Command: app.Check}, Timeout: time.Second}, failingWriter{}, &diagnostic)
	if code != 1 || !strings.Contains(diagnostic.String(), "Не удалось вывести ответ") {
		t.Fatal("output failure hidden")
	}
}

type fileAnalyzerFunc func(context.Context, string) (model.AnalysisResult, error)

func (f fileAnalyzerFunc) AnalyzeFile(ctx context.Context, path string) (model.AnalysisResult, error) {
	return f(ctx, path)
}

func TestRunAnalysisUsesInjectedService(t *testing.T) {
	service := fileAnalyzerFunc(func(ctx context.Context, path string) (model.AnalysisResult, error) {
		if path != "sample.txt" {
			t.Fatal("file path not forwarded")
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("analysis has no deadline")
		}
		return model.AnalysisResult{TotalRecords: 2, Skipped: map[string]int{"unknown_event": 1, "invalid_json": 1}}, nil
	})
	var out, diagnostic bytes.Buffer
	code := cli.RunAnalysis(context.Background(), service, cli.Options{File: "sample.txt", Timeout: time.Second}, &out, &diagnostic)
	if code != 0 || diagnostic.Len() != 0 || !strings.Contains(out.String(), "не включенных в историю заказов: 2") {
		t.Fatal("analysis output failed")
	}
	if strings.Index(out.String(), "Строка не соответствует") > strings.Index(out.String(), "Тип сообщения пока") {
		t.Fatal("skip reasons must have a deterministic order")
	}
}

func TestRunAnalysisHandlesFailureAndCancellation(t *testing.T) {
	for _, fail := range []bool{true, false} {
		service := fileAnalyzerFunc(func(ctx context.Context, _ string) (model.AnalysisResult, error) {
			if fail {
				return model.AnalysisResult{}, errors.New("safe test error")
			}
			<-ctx.Done()
			return model.AnalysisResult{}, ctx.Err()
		})
		var out, diagnostic bytes.Buffer
		if code := cli.RunAnalysis(context.Background(), service, cli.Options{Timeout: time.Millisecond}, &out, &diagnostic); code != 1 || out.Len() != 0 || diagnostic.Len() == 0 {
			t.Fatal("analysis failure was hidden")
		}
	}
	service := fileAnalyzerFunc(func(context.Context, string) (model.AnalysisResult, error) { return model.AnalysisResult{}, nil })
	if code := cli.RunAnalysis(context.Background(), service, cli.Options{Timeout: time.Second}, failingWriter{}, io.Discard); code != 1 {
		t.Fatal("output failure was hidden")
	}
}
