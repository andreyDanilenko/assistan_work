package telegram_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"loki-analyzer/internal/telegram"
)

func TestSendDocumentUploadsPlainText(t *testing.T) {
	const report = "Отчёт по заказам\nВсего: 3\n"
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	body := &trackedBody{Reader: strings.NewReader(`{"ok":true,"result":{"message_id":17,"chat":{"id":-1005000000001},"document":{"file_id":"report-file"}}}`)}
	calls := 0
	client, _ := telegram.New(telegram.Config{Token: testToken}, fakeHTTPClient(func(req *http.Request) (*http.Response, error) {
		calls++
		if req.Method != http.MethodPost || req.URL.Path != "/bot"+testToken+"/sendDocument" || req.Context() != ctx {
			t.Fatal("unexpected upload request or context")
		}
		reader, err := req.MultipartReader()
		if err != nil {
			t.Fatal(err)
		}
		chat, err := reader.NextPart()
		if err != nil {
			t.Fatal(err)
		}
		chatID, _ := io.ReadAll(chat)
		if chat.FormName() != "chat_id" || string(chatID) != "-1005000000001" {
			t.Fatal("negative 64-bit chat ID was changed")
		}
		file, err := reader.NextPart()
		if err != nil {
			t.Fatal(err)
		}
		content, _ := io.ReadAll(file)
		if file.FormName() != "document" || file.FileName() != "orders-2026-10-11.txt" || file.Header.Get("Content-Type") != "text/plain; charset=utf-8" || string(content) != report {
			t.Fatal("document metadata or text was changed")
		}
		if _, err := reader.NextPart(); err != io.EOF {
			t.Fatal("unexpected extra multipart fields")
		}
		return &http.Response{StatusCode: 200, Body: body}, nil
	}))
	if err := client.SendDocument(ctx, -1005000000001, "orders-2026-10-11.txt", []byte(report)); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || !body.closed {
		t.Fatal("upload retried or response body leaked")
	}
}

func TestSendDocumentValidatesInputBeforeUpload(t *testing.T) {
	client, _ := telegram.New(telegram.Config{Token: testToken}, fakeHTTPClient(func(*http.Request) (*http.Response, error) {
		t.Fatal("invalid document reached transport")
		return nil, nil
	}))
	for _, filename := range []string{"", "../report.txt", `dir\report.txt`, "report.txt\r\nX: secret", "report.pdf", ".env", strings.Repeat("a", 130) + ".txt"} {
		if err := client.SendDocument(context.Background(), 1, filename, []byte("report")); err == nil {
			t.Fatal("unsafe filename accepted")
		}
	}
	for _, document := range [][]byte{nil, {0xff}, make([]byte, (8<<20)+1)} {
		if err := client.SendDocument(context.Background(), 1, "report.txt", document); err == nil {
			t.Fatal("invalid document accepted")
		}
	}
	if err := client.SendDocument(context.Background(), 0, "report.txt", []byte("report")); err == nil {
		t.Fatal("missing chat accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := client.SendDocument(ctx, 1, "report.txt", []byte("report")); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
}

func TestSendDocumentChecksConfirmationAndRedactsErrors(t *testing.T) {
	for _, body := range []string{
		`{"ok":true,"result":{"message_id":17,"chat":{"id":1}}}`,
		`{"ok":true,"result":{"message_id":17,"chat":{"id":2},"document":{"file_id":"file"}}}`,
		`{"ok":true,"result":{"chat":{"id":1},"document":{"file_id":"file"}}}`,
		`{"ok":false,"error_code":403,"description":"` + testToken + ` private-report"}`,
		strings.Repeat("x", maxResponseBytes+1),
	} {
		client, _ := telegram.New(telegram.Config{Token: testToken}, fakeHTTPClient(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}, nil
		}))
		err := client.SendDocument(context.Background(), 1, "report.txt", []byte("private-report"))
		if err == nil || strings.Contains(err.Error(), testToken) || strings.Contains(err.Error(), "private-report") {
			t.Fatalf("missing or unsafe upload error: %v", err)
		}
		if strings.Contains(body, `"error_code":403`) {
			var apiErr *telegram.APIError
			if !errors.As(err, &apiErr) || apiErr.Code != 403 {
				t.Fatalf("API rejection lost its code: %v", err)
			}
		}
	}
}

func TestSendDocumentPreservesDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	client, _ := telegram.New(telegram.Config{Token: testToken}, fakeHTTPClient(func(req *http.Request) (*http.Response, error) {
		<-req.Context().Done()
		return nil, req.Context().Err()
	}))
	if err := client.SendDocument(ctx, 1, "report.txt", []byte("report")); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline lost: %v", err)
	}
}
