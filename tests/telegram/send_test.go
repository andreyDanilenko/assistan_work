package telegram_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"loki-analyzer/internal/telegram"
)

func TestSendMessageUsesPlainTextAndPreservesChatID(t *testing.T) {
	const chatID int64 = -1005000000001
	text := strings.Repeat("я", 4096)
	calls := 0
	body := &trackedBody{Reader: strings.NewReader(`{"ok":true,"result":{"message_id":52,"chat":{"id":-1005000000001}}}`)}
	client, err := telegram.New(telegram.Config{Token: testToken}, fakeHTTPClient(func(req *http.Request) (*http.Response, error) {
		calls++
		if req.Method != http.MethodPost || req.URL.Path != "/bot"+testToken+"/sendMessage" || req.Header.Get("Content-Type") != "application/json" {
			t.Fatal("invalid sendMessage request")
		}
		var payload map[string]json.RawMessage
		if json.NewDecoder(req.Body).Decode(&payload) != nil {
			t.Fatal("request is not JSON")
		}
		var gotText string
		var gotChat int64
		var preview struct {
			Disabled bool `json:"is_disabled"`
		}
		if json.Unmarshal(payload["text"], &gotText) != nil || gotText != text || json.Unmarshal(payload["chat_id"], &gotChat) != nil || gotChat != chatID {
			t.Fatal("text or negative 64-bit chat ID changed")
		}
		if _, found := payload["parse_mode"]; found {
			t.Fatal("plain text must not enable markup")
		}
		if json.Unmarshal(payload["link_preview_options"], &preview) != nil || !preview.Disabled {
			t.Fatal("link previews must be disabled")
		}
		return &http.Response{StatusCode: 200, Body: body}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.SendMessage(context.Background(), chatID, text); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || !body.closed {
		t.Fatal("request retried or body leaked")
	}
}

func TestSendMessageRejectsInvalidInputBeforeHTTP(t *testing.T) {
	client, _ := telegram.New(telegram.Config{Token: testToken}, fakeHTTPClient(func(*http.Request) (*http.Response, error) {
		t.Fatal("invalid input reached transport")
		return nil, nil
	}))
	for _, test := range []struct {
		chat int64
		text string
	}{
		{0, "hello"}, {1, ""}, {1, strings.Repeat("я", 4097)}, {1, string([]byte{0xff})},
	} {
		if err := client.SendMessage(context.Background(), test.chat, test.text); err == nil {
			t.Fatal("invalid message accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := client.SendMessage(ctx, 1, "hello"); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost")
	}
}

func TestSendMessageErrorsAreSafeAndTyped(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		body   string
		code   int
		delay  time.Duration
	}{
		{"rate limit", 429, `{"ok":false,"error_code":429,"description":"` + testToken + `","parameters":{"retry_after":17}}`, 429, 17 * time.Second},
		{"API rate limit on HTTP 200", 200, `{"ok":false,"error_code":429,"parameters":{"retry_after":4}}`, 429, 4 * time.Second},
		{"excessive delay", 429, `{"ok":false,"parameters":{"retry_after":9223372036854775807}}`, 429, 0},
		{"negative delay", 429, `{"ok":false,"parameters":{"retry_after":-1}}`, 429, 0},
		{"wrong delay type", 429, `{"ok":false,"parameters":{"retry_after":"secret"}}`, 429, 0},
		{"permanent", 403, `{"ok":false,"error_code":403,"description":"` + testToken + `"}`, 403, 0},
		{"HTTP failure", 502, testToken, 502, 0},
		{"bad request on HTTP 200", 200, `{"ok":false,"error_code":400}`, 400, 0},
		{"malformed", 200, testToken, 0, 0},
		{"missing result", 200, `{"ok":true}`, 0, 0},
		{"missing ok", 200, `{"result":{"message_id":1,"chat":{"id":1}}}`, 0, 0},
		{"invalid error code", 200, `{"ok":false,"error_code":123}`, 0, 0},
		{"missing message ID", 200, `{"ok":true,"result":{"chat":{"id":1}}}`, 0, 0},
		{"wrong chat", 200, `{"ok":true,"result":{"message_id":1,"chat":{"id":99}}}`, 0, 0},
		{"oversize", 200, strings.Repeat("x", maxResponseBytes+1), 0, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			client, _ := telegram.New(telegram.Config{Token: testToken}, fakeHTTPClient(func(*http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: test.status, Body: io.NopCloser(strings.NewReader(test.body))}, nil
			}))
			err := client.SendMessage(context.Background(), 1, "private log message")
			if err == nil || strings.Contains(err.Error(), testToken) || strings.Contains(err.Error(), "private log") || strings.Contains(err.Error(), "https:") {
				t.Fatalf("unsafe/missing error: %v", err)
			}
			if calls != 1 {
				t.Fatal("client retried sendMessage")
			}
			var apiErr *telegram.APIError
			if test.code == 0 {
				if errors.As(err, &apiErr) {
					t.Fatal("malformed reply masquerades as API rejection")
				}
			} else if !errors.As(err, &apiErr) || apiErr.Code != test.code || apiErr.RetryAfter != test.delay {
				t.Fatalf("unexpected API error: %#v", apiErr)
			}
		})
	}
}

func TestSendMessageWithReportKeepsExactPeriodAndPlainText(t *testing.T) {
	start := time.Date(2026, 10, 11, 10, 0, 0, 123456789, time.UTC)
	end := start.Add(10 * time.Minute)
	client, _ := telegram.New(telegram.Config{Token: testToken}, fakeHTTPClient(func(req *http.Request) (*http.Response, error) {
		var payload struct {
			Text   string `json:"text"`
			ChatID int64  `json:"chat_id"`
		}
		var raw map[string]json.RawMessage
		data, _ := io.ReadAll(req.Body)
		if json.Unmarshal(data, &payload) != nil || json.Unmarshal(data, &raw) != nil || payload.Text != "Таймаут — 3 заказа" || payload.ChatID != -42 {
			t.Fatal("message changed")
		}
		if _, ok := raw["parse_mode"]; ok {
			t.Fatal("must remain plain text")
		}
		var keyboard struct {
			Buttons [][]struct {
				Text string `json:"text"`
				Data string `json:"callback_data"`
			} `json:"inline_keyboard"`
		}
		if json.Unmarshal(raw["reply_markup"], &keyboard) != nil || len(keyboard.Buttons) != 2 || len(keyboard.Buttons[0]) != 1 || len(keyboard.Buttons[1]) != 2 {
			t.Fatal("missing report period buttons")
		}
		buttons := append(keyboard.Buttons[0], keyboard.Buttons[1]...)
		for i, expected := range []struct {
			text  string
			start time.Time
		}{
			{"📄 За этот период", start},
			{"📄 За 1 час", end.Add(-time.Hour)},
			{"📄 За 2 часа", end.Add(-2 * time.Hour)},
		} {
			button := buttons[i]
			bounds := fmt.Sprintf(":%d:%d", expected.start.UnixNano(), end.UnixNano())
			if button.Text != expected.text || len(button.Data) > 64 || !strings.HasSuffix(button.Data, bounds) || strings.Contains(button.Data, "source-private") {
				t.Fatalf("unexpected button: %+v", button)
			}
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"ok":true,"result":{"message_id":1,"chat":{"id":-42}}}`))}, nil
	}))
	if err := client.SendMessageWithReport(context.Background(), -42, "Таймаут — 3 заказа", "source-private|orders", start, end); err != nil {
		t.Fatal(err)
	}
}

func TestReportButtonRejectsInvalidInputBeforeHTTP(t *testing.T) {
	client, _ := telegram.New(telegram.Config{Token: testToken}, fakeHTTPClient(func(*http.Request) (*http.Response, error) { t.Fatal("invalid request reached HTTP"); return nil, nil }))
	now := time.Now()
	for _, test := range []struct {
		chat        int64
		text, scope string
		start, end  time.Time
	}{
		{-42, "text", "", now.Add(-time.Minute), now},
		{-42, "text", "scope", now, now},
		{-42, "text", "scope", now.Add(-49 * time.Hour), now},
		{0, "text", "scope", now.Add(-time.Minute), now},
		{-42, strings.Repeat("я", 4097), "scope", now.Add(-time.Minute), now},
	} {
		if err := client.SendMessageWithReport(context.Background(), test.chat, test.text, test.scope, test.start, test.end); err == nil {
			t.Fatal("invalid report button accepted")
		}
	}
}

func TestAnswerCallbackQueryUsesSafeJSONAndChecksConfirmation(t *testing.T) {
	for _, result := range []string{"true", "false", `{}`} {
		client, _ := telegram.New(telegram.Config{Token: testToken}, fakeHTTPClient(func(req *http.Request) (*http.Response, error) {
			var payload map[string]any
			if req.Method != http.MethodPost || !strings.HasSuffix(req.URL.Path, "/answerCallbackQuery") || json.NewDecoder(req.Body).Decode(&payload) != nil || payload["callback_query_id"] != "callback-123" || payload["text"] != "Готовлю отчёт" {
				t.Fatal("invalid callback acknowledgement")
			}
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"ok":true,"result":` + result + `}`))}, nil
		}))
		err := client.AnswerCallbackQuery(context.Background(), "callback-123", "Готовлю отчёт")
		if (err == nil) != (result == "true") {
			t.Fatalf("wrong confirmation for %s: %v", result, err)
		}
	}
}
