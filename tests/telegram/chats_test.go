package telegram_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"loki-analyzer/internal/telegram"
)

func TestDiscoverChatsDoesNotAcknowledgeUpdates(t *testing.T) {
	calls := 0
	client, _ := telegram.New(telegram.Config{Token: testToken}, fakeHTTPClient(func(req *http.Request) (*http.Response, error) {
		calls++
		if req.Method != http.MethodGet {
			t.Fatal("discovery must only read")
		}
		body := `{"ok":true,"result":{"url":""}}`
		switch calls {
		case 1:
			if req.URL.Path != "/bot"+testToken+"/getWebhookInfo" {
				t.Fatal("webhook must be checked first")
			}
		case 2:
			if req.URL.Path != "/bot"+testToken+"/getUpdates" || req.URL.Query().Get("limit") != "100" || req.URL.Query().Get("timeout") != "0" {
				t.Fatal("unexpected updates request")
			}
			if len(req.URL.Query()) != 2 {
				t.Fatal("discovery must not send offset or change allowed_updates")
			}
			body = `{"ok":true,"result":[
			{"update_id":1,"message":{"chat":{"id":-1005000000001,"title":"Ops","type":"supergroup"},"from":{"id":5000000002},"text":"private-message"}},
			{"update_id":2,"my_chat_member":{"chat":{"id":-1005000000001,"title":"Ops","type":"supergroup"},"from":{"id":5000000002}}},
			{"update_id":3,"message":{"chat":{"id":5000000002,"first_name":"Andrei","type":"private"},"from":{"id":5000000002}}},
			{"update_id":4,"callback_query":{"data":"private-data"}}]}`
		default:
			t.Fatal("discovery must read only one page")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}, nil
	}))
	chats, err := client.DiscoverChats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || len(chats) != 2 || chats[0].ID != -1005000000001 || chats[0].UserID != 5000000002 || chats[0].Type != "supergroup" || chats[0].Title != "Ops" || chats[1].Title != "Andrei" {
		t.Fatalf("unexpected chats: %#v", chats)
	}
	encoded, _ := json.Marshal(chats)
	if strings.Contains(string(encoded), "private-message") || strings.Contains(string(encoded), "private-data") {
		t.Fatal("discovery exposed message text")
	}
}

func TestDiscoverChatsRefusesActiveOrInvalidWebhook(t *testing.T) {
	for _, body := range []string{`{"ok":true,"result":{"url":"https://private.example/secret"}}`, `{"ok":true,"result":{}}`, `{"ok":true,"result":{"url":null}}`} {
		calls := 0
		client, _ := telegram.New(telegram.Config{Token: testToken}, fakeHTTPClient(func(*http.Request) (*http.Response, error) {
			calls++
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}, nil
		}))
		_, err := client.DiscoverChats(context.Background())
		if err == nil || calls != 1 || strings.Contains(err.Error(), "private.example") {
			t.Fatalf("unsafe webhook handling: %v (%d calls)", err, calls)
		}
	}
}

func TestDiscoverChatsBoundsAndValidatesUpdates(t *testing.T) {
	for _, body := range []string{
		`{"ok":true,"result":null}`,
		`{"ok":true,"result":{}}`,
		`{"ok":true,"result":[{"message":{"chat":{"id":0,"type":"private"}}}]}`,
		`{"ok":true,"result":[{"message":{"chat":{"id":1}}}]}`,
		`{"ok":true,"result":[` + strings.TrimSuffix(strings.Repeat(`{},`, 101), ",") + `]}`,
		strings.Repeat("x", (256<<10)+1),
	} {
		calls := 0
		client, _ := telegram.New(telegram.Config{Token: testToken}, fakeHTTPClient(func(*http.Request) (*http.Response, error) {
			calls++
			text := body
			if calls == 1 {
				text = `{"ok":true,"result":{"url":""}}`
			}
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(text))}, nil
		}))
		if _, err := client.DiscoverChats(context.Background()); err == nil {
			t.Fatal("invalid updates accepted")
		}
	}
}
