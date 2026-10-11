package telegram_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"loki-analyzer/internal/telegram"
)

func TestGetUpdatesPreservesOffsetAndNonMessageEvents(t *testing.T) {
	client, _ := telegram.New(telegram.Config{Token: testToken}, fakeHTTPClient(func(req *http.Request) (*http.Response, error) {
		query := req.URL.Query()
		if req.Method != http.MethodGet || req.URL.Path != "/bot"+testToken+"/getUpdates" || query.Get("offset") != "5000000001" || query.Get("limit") != "100" || query.Get("timeout") != "0" || query.Get("allowed_updates") != `["message","callback_query"]` {
			t.Fatal("unexpected updates request")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"ok":true,"result":[
			{"update_id":5000000001,"message":{"message_id":32,"date":1791691200,"text":"/report","chat":{"id":-1005000000001},"from":{"is_bot":false}}},
			{"update_id":5000000002,"my_chat_member":{"chat":{"id":-1005000000001}}},
			{"update_id":5000000003,"message":{"message_id":33,"date":1791691201,"chat":{"id":-1005000000001},"from":{"is_bot":true}}},
			{"update_id":5000000004,"callback_query":{"id":"click-1","data":"r:test","from":{"id":321},"message":{"message_id":34,"date":1791691201,"chat":{"id":-1005000000001},"from":{"id":42,"is_bot":true}}}}]}`))}, nil
	}))
	updates, err := client.GetUpdates(context.Background(), 5000000001)
	if err != nil {
		t.Fatal(err)
	}
	if len(updates) != 4 || updates[0].ID != 5000000001 || updates[0].Message.Text != "/report" || updates[0].Message.Chat.ID != -1005000000001 || updates[1].Message != nil || updates[1].ID != 5000000002 || !updates[2].Message.From.IsBot {
		t.Fatalf("updates lost their identity or message: %#v", updates)
	}
	if updates[3].Callback == nil || updates[3].Callback.ID != "click-1" || updates[3].Callback.Message.From.ID != 42 || updates[3].Callback.From.ID != 321 {
		t.Fatal("callback lost its sender or originating message")
	}
}

func TestGetUpdatesBoundsAndValidatesResponse(t *testing.T) {
	for _, body := range []string{
		`{"ok":true,"result":{}}`,
		`{"ok":true,"result":[{}]}`,
		`{"ok":true,"result":[{"update_id":1,"message":{"message_id":1,"date":1,"chat":{"id":0}}}]}`,
		`{"ok":true,"result":[` + strings.TrimSuffix(strings.Repeat(`{"update_id":1},`, 101), ",") + `]}`,
		strings.Repeat("x", (2<<20)+1),
	} {
		client, _ := telegram.New(telegram.Config{Token: testToken}, fakeHTTPClient(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}, nil
		}))
		if _, err := client.GetUpdates(context.Background(), 0); err == nil {
			t.Fatal("invalid update response accepted")
		}
	}
}

func TestGetUpdatesRejectsCanceledOrNegativeOffset(t *testing.T) {
	client, _ := telegram.New(telegram.Config{Token: testToken}, fakeHTTPClient(func(*http.Request) (*http.Response, error) {
		t.Fatal("invalid request reached transport")
		return nil, nil
	}))
	if _, err := client.GetUpdates(context.Background(), -1); err == nil {
		t.Fatal("negative offset could discard unread updates")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.GetUpdates(ctx, 0); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
}
