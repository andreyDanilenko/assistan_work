package telegram_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"loki-analyzer/internal/telegram"
)

// The Telegram response limit is 64 KiB.
const maxResponseBytes = 64 << 10

const testToken = "123456:fake_Bot-token"

type fakeHTTPClient func(*http.Request) (*http.Response, error)

func (f fakeHTTPClient) Do(req *http.Request) (*http.Response, error) { return f(req) }

func TestNew(t *testing.T) {
	httpClient := fakeHTTPClient(func(*http.Request) (*http.Response, error) {
		t.Fatal("New must not make a network request")
		return nil, nil
	})
	for _, token := range []string{"", "no-colon", "id:token", "123:", "123:token/other", "123:token?query", "123:token\n", "123:токен"} {
		t.Run(token, func(t *testing.T) {
			if _, err := telegram.New(telegram.Config{Token: token}, httpClient); err == nil {
				t.Fatal("expected invalid token error")
			}
		})
	}
	if _, err := telegram.New(telegram.Config{Token: testToken}, nil); err == nil {
		t.Fatal("expected missing HTTP client error")
	}
	if _, err := telegram.New(telegram.Config{Token: testToken}, httpClient); err != nil {
		t.Fatal(err)
	}
}

func TestGetMe(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	body := &trackedBody{Reader: strings.NewReader(`{"ok":true,"result":{"id":5000000001,"is_bot":true,"first_name":"Order monitor","username":"order_monitor_bot"}}`)}
	client, err := telegram.New(telegram.Config{Token: testToken}, fakeHTTPClient(func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodGet || req.URL.String() != "https://api.telegram.org/bot"+testToken+"/getMe" {
			t.Fatal("unexpected request method or endpoint")
		}
		if req.Header.Get("Accept") != "application/json" || req.Context() != ctx {
			t.Fatal("request did not preserve headers or context")
		}
		return &http.Response{StatusCode: http.StatusOK, Body: body}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	bot, err := client.GetMe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if bot.ID != 5000000001 || !bot.IsBot || bot.FirstName != "Order monitor" || bot.Username != "order_monitor_bot" {
		t.Fatalf("unexpected bot: %#v", bot)
	}
	if !body.closed {
		t.Fatal("response body was not closed")
	}
}

func TestGetMeInvalidResponse(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
	}{
		{"unauthorized", http.StatusUnauthorized, testToken},
		{"rate limited", http.StatusTooManyRequests, testToken},
		{"redirect", http.StatusFound, testToken},
		{"malformed", http.StatusOK, testToken},
		{"too large", http.StatusOK, strings.Repeat("x", maxResponseBytes+1)},
		{"rejected", http.StatusOK, `{"ok":false,"description":"` + testToken + `"}`},
		{"missing identity", http.StatusOK, `{"ok":true}`},
		{"not a bot", http.StatusOK, `{"ok":true,"result":{"id":123,"is_bot":false}}`},
		{"zero ID", http.StatusOK, `{"ok":true,"result":{"id":0,"is_bot":true}}`},
		{"negative ID", http.StatusOK, `{"ok":true,"result":{"id":-1,"is_bot":true}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := &trackedBody{Reader: strings.NewReader(tc.body)}
			client, err := telegram.New(telegram.Config{Token: testToken}, fakeHTTPClient(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: tc.status, Body: body}, nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.GetMe(context.Background()); err == nil || strings.Contains(err.Error(), testToken) {
				t.Fatalf("expected safe response error, got %v", err)
			}
			if !body.closed {
				t.Fatal("response body was not closed")
			}
		})
	}
}

func TestGetMeTransportErrors(t *testing.T) {
	for _, cause := range []error{errors.New("network failure: " + testToken), context.DeadlineExceeded} {
		client, err := telegram.New(telegram.Config{Token: testToken}, fakeHTTPClient(func(req *http.Request) (*http.Response, error) {
			return nil, &url.Error{Op: "Get", URL: req.URL.String(), Err: cause}
		}))
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.GetMe(context.Background())
		if err == nil || strings.Contains(err.Error(), testToken) || strings.Contains(err.Error(), "https://") {
			t.Fatalf("expected safe transport error, got %v", err)
		}
		if errors.Is(cause, context.DeadlineExceeded) && err.Error() != "Telegram request timed out" {
			t.Fatalf("expected timeout error, got %v", err)
		}
	}
}

func TestGetMeCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client, err := telegram.New(telegram.Config{Token: testToken}, fakeHTTPClient(func(*http.Request) (*http.Response, error) {
		t.Fatal("canceled request must not reach transport")
		return nil, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetMe(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestGetMeDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	client, err := telegram.New(telegram.Config{Token: testToken}, fakeHTTPClient(func(req *http.Request) (*http.Response, error) {
		<-req.Context().Done()
		return nil, &url.Error{Op: "Get", URL: req.URL.String(), Err: req.Context().Err()}
	}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetMe(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded, got %v", err)
	}
}

func TestGetMeBodyReadError(t *testing.T) {
	client, err := telegram.New(telegram.Config{Token: testToken}, fakeHTTPClient(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(brokenReader{})}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetMe(context.Background()); err == nil || strings.Contains(err.Error(), testToken) {
		t.Fatalf("expected safe body read error, got %v", err)
	}
}

type trackedBody struct {
	*strings.Reader
	closed bool
}

func (b *trackedBody) Close() error { b.closed = true; return nil }

type brokenReader struct{}

func (brokenReader) Read([]byte) (int, error) { return 0, errors.New(testToken) }
