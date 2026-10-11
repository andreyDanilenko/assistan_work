package app_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"loki-analyzer/internal/app"
	"loki-analyzer/internal/model"
)

type recordSourceFunc func(context.Context, string) ([]model.LogRecord, error)

func (f recordSourceFunc) Read(ctx context.Context, path string) ([]model.LogRecord, error) {
	return f(ctx, path)
}

type orderAnalyzerFunc func(context.Context, []model.LogRecord) (model.AnalysisResult, error)

func (f orderAnalyzerFunc) Analyze(ctx context.Context, records []model.LogRecord) (model.AnalysisResult, error) {
	return f(ctx, records)
}

func TestAnalysisServicePassesSourceRecordsToAnalyzer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	want := []model.LogRecord{{Project: "orders", Line: "event"}}
	wantResult := model.AnalysisResult{TotalRecords: 1, Skipped: map[string]int{"unrecognized": 1}}
	var readCalls, analyzeCalls int
	source := recordSourceFunc(func(gotCtx context.Context, path string) ([]model.LogRecord, error) {
		readCalls++
		if gotCtx != ctx || path != "example.txt" {
			t.Fatal("source must receive original context and path")
		}
		return want, nil
	})
	analyzer := orderAnalyzerFunc(func(gotCtx context.Context, records []model.LogRecord) (model.AnalysisResult, error) {
		analyzeCalls++
		if gotCtx != ctx || !reflect.DeepEqual(records, want) {
			t.Fatal("analyzer must receive original context and source records")
		}
		return wantResult, nil
	})
	result, err := app.NewAnalysisService(source, analyzer).AnalyzeFile(ctx, "example.txt")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(result, wantResult) {
		t.Fatal("service must return the analyzer result unchanged")
	}
	if readCalls != 1 || analyzeCalls != 1 {
		t.Fatal("each dependency must be called once")
	}
}

func TestAnalysisServicePropagatesErrorsAndStopsAfterReadFailure(t *testing.T) {
	readErr, analyzeErr := errors.New("read failed"), errors.New("analysis failed")
	for _, sourceErr := range []error{nil, readErr} {
		analyzeCalls := 0
		source := recordSourceFunc(func(context.Context, string) ([]model.LogRecord, error) {
			return nil, sourceErr
		})
		analyzer := orderAnalyzerFunc(func(context.Context, []model.LogRecord) (model.AnalysisResult, error) {
			analyzeCalls++
			return model.AnalysisResult{}, analyzeErr
		})
		_, err := app.NewAnalysisService(source, analyzer).AnalyzeFile(context.Background(), "example.txt")
		wantErr, wantCalls := analyzeErr, 1
		if sourceErr != nil {
			wantErr, wantCalls = readErr, 0
		}
		if !errors.Is(err, wantErr) || analyzeCalls != wantCalls {
			t.Fatal("dependency error must propagate without invoking later steps")
		}
	}
}

func TestAnalysisServiceCountsExplicitSyntheticMarkers(t *testing.T) {
	marked := model.LogRecord{Labels: map[string]string{"dataset": "synthetic-example"}}
	for _, test := range []struct {
		name    string
		records []model.LogRecord
		want    int
	}{
		{"all marked, including a skipped message", []model.LogRecord{marked, marked}, 2},
		{"mixed sources", []model.LogRecord{marked, {}}, 1},
		{"demo name without marker", []model.LogRecord{{Line: `{"id":"demo-order-001"}`}}, 0},
		{"marker must match exactly", []model.LogRecord{{Labels: map[string]string{"dataset": "synthetic-example "}}}, 0},
		{"empty file", nil, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := recordSourceFunc(func(context.Context, string) ([]model.LogRecord, error) {
				return test.records, nil
			})
			want := model.AnalysisResult{TotalRecords: len(test.records)}
			if len(test.records) > 0 {
				want.Skipped = map[string]int{"unknown_event": 1}
			}
			analyzer := orderAnalyzerFunc(func(context.Context, []model.LogRecord) (model.AnalysisResult, error) {
				return want, nil
			})
			result, err := app.NewAnalysisService(source, analyzer).AnalyzeFile(context.Background(), "examples/orders-analysis.txt")
			if err != nil {
				t.Fatal(err)
			}
			want.SyntheticRecords = test.want
			if !reflect.DeepEqual(result, want) {
				t.Fatalf("got %+v, want %+v", result, want)
			}
		})
	}
}

func TestAnalysisServiceHonorsCancellationBetweenSteps(t *testing.T) {
	for _, cancelBeforeRead := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		if cancelBeforeRead {
			cancel()
		}
		readCalls := 0
		source := recordSourceFunc(func(context.Context, string) ([]model.LogRecord, error) {
			readCalls++
			cancel()
			return nil, nil
		})
		analyzer := orderAnalyzerFunc(func(context.Context, []model.LogRecord) (model.AnalysisResult, error) {
			t.Fatal("analyzer must not run after cancellation")
			return model.AnalysisResult{}, nil
		})
		_, err := app.NewAnalysisService(source, analyzer).AnalyzeFile(ctx, "example.txt")
		cancel()
		if !errors.Is(err, context.Canceled) || (cancelBeforeRead && readCalls != 0) {
			t.Fatal("cancellation must stop work before the next dependency")
		}
	}
}
