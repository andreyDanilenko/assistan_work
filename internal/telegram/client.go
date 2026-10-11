// Package telegram выполняет ограниченные запросы Bot API без фоновых повторов.
package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/textproto"
	"regexp"
	"strconv"
	"time"
	"unicode/utf8"

	"loki-analyzer/internal/model"
)

const maxResponseBytes = 64 << 10
const maxUpdatesBytes = 256 << 10
const maxDocumentBytes = 8 << 20

var tokenPattern = regexp.MustCompile(`^[0-9]+:[A-Za-z0-9_-]+$`)
var documentNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,120}\.txt$`)

// Config содержит полный токен бота в формате «цифры:секретная часть».
type Config struct {
	Token string
}

// HTTPClient передается с таймаутом, проверкой TLS и запретом перенаправлений.
type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

// APIError сообщает безопасный код отказа и задержку, не сохраняя текст ответа.
// Решение о повторе принимает вызывающий сценарий; 400/401/403 требуют исправления настроек.
type APIError struct {
	Code       int
	RetryAfter time.Duration
}

func (e *APIError) Error() string { return fmt.Sprintf("Telegram API error %d", e.Code) }

// Client хранит токен и HTTP-зависимость; сам не запускает фоновые запросы.
type Client struct {
	token string
	http  HTTPClient
}

// New проверяет настройки без сетевого запроса и не включает токен в ошибки.
func New(config Config, httpClient HTTPClient) (*Client, error) {
	if config.Token == "" {
		return nil, errors.New("TELEGRAM_BOT_TOKEN is required")
	}
	if !tokenPattern.MatchString(config.Token) {
		return nil, errors.New("TELEGRAM_BOT_TOKEN has an invalid format")
	}
	if httpClient == nil {
		return nil, errors.New("HTTP client is required")
	}
	return &Client{token: config.Token, http: httpClient}, nil
}

// GetMe проверяет токен и возвращает сведения о боте без отправки сообщений.
func (c *Client) GetMe(ctx context.Context) (model.BotInfo, error) {
	var bot model.BotInfo
	body, err := c.call(ctx, "getMe", nil, maxResponseBytes)
	if err != nil {
		return bot, err
	}
	if json.Unmarshal(body, &bot) != nil || !bot.IsBot || bot.ID <= 0 {
		return model.BotInfo{}, errors.New("Telegram did not confirm the bot identity")
	}
	return bot, nil
}

// SendMessage отправляет один подготовленный текст; права адресата проверяет сценарий.
// При потере ответа результат доставки неизвестен: скрытый повтор мог бы создать дубль.
func (c *Client) SendMessage(ctx context.Context, chatID int64, text string) error {
	return c.sendMessage(ctx, chatID, text, nil)
}

// SendMessageWithReport закрепляет периоды кнопок за концом исходной сводки.
// Scope связывает кнопку с текущим источником логов и проектом.
func (c *Client) SendMessageWithReport(ctx context.Context, chatID int64, text, scope string, start, end time.Time) error {
	buttons := make([]reportButton, 0, 3)
	for _, period := range []struct {
		label string
		start time.Time
	}{
		{"📄 За этот период", start},
		{"📄 За 1 час", end.Add(-time.Hour)},
		{"📄 За 2 часа", end.Add(-2 * time.Hour)},
	} {
		data, err := reportCallbackData(scope, period.start, end)
		if err != nil {
			return err
		}
		buttons = append(buttons, reportButton{Text: period.label, Data: data})
	}
	keyboard := &reportKeyboard{Buttons: [][]reportButton{buttons[:1], buttons[1:]}}
	return c.sendMessage(ctx, chatID, text, keyboard)
}

func (c *Client) sendMessage(ctx context.Context, chatID int64, text string, keyboard *reportKeyboard) error {
	length := utf8.RuneCountInString(text)
	if chatID == 0 || !utf8.ValidString(text) || length == 0 || length > 4096 {
		return errors.New("Telegram message requires a chat ID and 1..4096 valid text characters")
	}
	payload := struct {
		ChatID      int64  `json:"chat_id"`
		Text        string `json:"text"`
		LinkPreview struct {
			Disabled bool `json:"is_disabled"`
		} `json:"link_preview_options"`
		ReplyMarkup *reportKeyboard `json:"reply_markup,omitempty"`
	}{ChatID: chatID, Text: text, ReplyMarkup: keyboard}
	// Обычный текст не интерпретируется как Markdown или HTML; предпросмотр ссылок отключен.
	payload.LinkPreview.Disabled = true
	body, err := c.call(ctx, "sendMessage", payload, maxResponseBytes)
	if err != nil {
		return err
	}
	var message struct {
		ID   int64 `json:"message_id"`
		Chat struct {
			ID int64 `json:"id"`
		} `json:"chat"`
	}
	if json.Unmarshal(body, &message) != nil || message.ID <= 0 || message.Chat.ID != chatID {
		return errors.New("Telegram did not confirm message delivery")
	}
	return nil
}

type reportButton struct {
	Text string `json:"text"`
	Data string `json:"callback_data"`
}

type reportKeyboard struct {
	Buttons [][]reportButton `json:"inline_keyboard"`
}

// AnswerCallbackQuery снимает индикатор ожидания и показывает краткий статус нажатия.
func (c *Client) AnswerCallbackQuery(ctx context.Context, id, text string) error {
	if id == "" || len(id) > 256 || !utf8.ValidString(id) || !utf8.ValidString(text) || utf8.RuneCountInString(text) > 200 {
		return errors.New("invalid Telegram callback answer")
	}
	payload := struct {
		ID   string `json:"callback_query_id"`
		Text string `json:"text"`
	}{ID: id, Text: text}
	body, err := c.call(ctx, "answerCallbackQuery", payload, maxResponseBytes)
	if err != nil {
		return err
	}
	var accepted bool
	if json.Unmarshal(body, &accepted) != nil || !accepted {
		return errors.New("Telegram did not confirm callback answer")
	}
	return nil
}

// GetUpdates читает одну пачку; offset подтверждает только уже обработанные события.
// Сценарий хранит offset и задает частоту опроса. Клиент не запускает повторы сам.
func (c *Client) GetUpdates(ctx context.Context, offset int64) ([]model.TelegramUpdate, error) {
	if offset < 0 {
		return nil, errors.New("Telegram update offset must not be negative")
	}
	// Явный фильтр не наследует настройки другого клиента, который мог исключить команды.
	method := "getUpdates?timeout=0&limit=100&allowed_updates=%5B%22message%22,%22callback_query%22%5D&offset=" + strconv.FormatInt(offset, 10)
	body, err := c.call(ctx, method, nil, 2<<20)
	if err != nil {
		return nil, err
	}
	var updates []model.TelegramUpdate
	if json.Unmarshal(body, &updates) != nil || updates == nil || len(updates) > 100 {
		return nil, errors.New("invalid Telegram updates response")
	}
	for _, update := range updates {
		if update.ID <= 0 {
			return nil, errors.New("invalid Telegram update identity")
		}
		if message := update.Message; message != nil && (message.ID <= 0 || message.Date <= 0 || message.Chat.ID == 0) {
			return nil, errors.New("invalid Telegram message identity")
		}
	}
	return updates, nil
}

// SendDocument отправляет подготовленный TXT одним запросом, не создавая файл на диске.
// Допускается только простое имя файла: путь и управляющие символы сюда не попадают.
func (c *Client) SendDocument(ctx context.Context, chatID int64, filename string, document []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if chatID == 0 || !documentNamePattern.MatchString(filename) || len(document) == 0 || len(document) > maxDocumentBytes || !utf8.Valid(document) {
		return errors.New("Telegram document requires a chat ID, a safe .txt filename and nonempty UTF-8 text up to 8 MiB")
	}
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if err := writer.WriteField("chat_id", strconv.FormatInt(chatID, 10)); err != nil {
		return errors.New("could not encode Telegram document")
	}
	header := make(textproto.MIMEHeader)
	header.Set("Content-Disposition", `form-data; name="document"; filename="`+filename+`"`)
	header.Set("Content-Type", "text/plain; charset=utf-8")
	part, err := writer.CreatePart(header)
	if err != nil {
		return errors.New("could not encode Telegram document")
	}
	if _, err := part.Write(document); err != nil {
		return errors.New("could not encode Telegram document")
	}
	if err := writer.Close(); err != nil {
		return errors.New("could not encode Telegram document")
	}
	result, err := c.request(ctx, http.MethodPost, "sendDocument", &body, writer.FormDataContentType(), maxResponseBytes)
	if err != nil {
		return err
	}
	var message struct {
		ID   int64 `json:"message_id"`
		Chat struct {
			ID int64 `json:"id"`
		} `json:"chat"`
		Document struct {
			FileID string `json:"file_id"`
		} `json:"document"`
	}
	if json.Unmarshal(result, &message) != nil || message.ID <= 0 || message.Chat.ID != chatID || message.Document.FileID == "" {
		return errors.New("Telegram did not confirm document delivery")
	}
	return nil
}

// DiscoverChats читает одну пачку для локальной настройки: очередь не подтверждается,
// webhook не меняется, сообщения не отправляются. Второй приемщик запускать нельзя.
func (c *Client) DiscoverChats(ctx context.Context) ([]model.TelegramChat, error) {
	body, err := c.call(ctx, "getWebhookInfo", nil, maxResponseBytes)
	if err != nil {
		return nil, err
	}
	var webhook struct {
		URL *string `json:"url"`
	}
	if json.Unmarshal(body, &webhook) != nil || webhook.URL == nil {
		return nil, errors.New("invalid Telegram webhook response")
	}
	if *webhook.URL != "" {
		return nil, errors.New("Telegram webhook is active; chat discovery was not started")
	}
	// Без offset прочитанные обновления остаются неподтвержденными в Telegram.
	body, err = c.call(ctx, "getUpdates?timeout=0&limit=100", nil, maxUpdatesBytes)
	if err != nil {
		return nil, err
	}
	type updateChat struct {
		Chat struct {
			ID        int64  `json:"id"`
			Title     string `json:"title"`
			Type      string `json:"type"`
			FirstName string `json:"first_name"`
		} `json:"chat"`
		From struct {
			ID int64 `json:"id"`
		} `json:"from"`
	}
	var updates []struct {
		Message    *updateChat `json:"message"`
		Membership *updateChat `json:"my_chat_member"`
	}
	if json.Unmarshal(body, &updates) != nil || updates == nil || len(updates) > 100 {
		return nil, errors.New("invalid Telegram updates response")
	}
	chats := make([]model.TelegramChat, 0)
	seen := make(map[[2]int64]bool)
	for _, update := range updates {
		for _, item := range []*updateChat{update.Message, update.Membership} {
			if item == nil {
				continue
			}
			if item.Chat.ID == 0 || item.Chat.Type == "" || item.From.ID < 0 {
				return nil, errors.New("invalid Telegram chat identity")
			}
			key := [2]int64{item.Chat.ID, item.From.ID}
			if seen[key] {
				continue
			}
			seen[key] = true
			title := item.Chat.Title
			if title == "" {
				title = item.Chat.FirstName
			}
			chats = append(chats, model.TelegramChat{ID: item.Chat.ID, Title: title, Type: item.Chat.Type, UserID: item.From.ID})
		}
	}
	return chats, nil
}

// call ограничивает чтение и скрывает URL с токеном и содержимое ошибок API.
func (c *Client) call(ctx context.Context, method string, payload any, maxBytes int64) (json.RawMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	verb := http.MethodGet
	var requestBody io.Reader
	var contentType string
	if payload != nil {
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, errors.New("could not encode Telegram request")
		}
		requestBody, verb = bytes.NewReader(body), http.MethodPost
		contentType = "application/json"
	}
	return c.request(ctx, verb, method, requestBody, contentType, maxBytes)
}

// request одинаково проверяет ответы JSON-запросов и загрузки файла.
func (c *Client) request(ctx context.Context, verb, method string, requestBody io.Reader, contentType string, maxBytes int64) (json.RawMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, verb, "https://api.telegram.org/bot"+c.token+"/"+method, requestBody)
	if err != nil {
		return nil, errors.New("could not construct Telegram request")
	}
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, connectionError(ctx, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, errors.New("could not read Telegram response")
	}
	if int64(len(body)) > maxBytes {
		return nil, errors.New("Telegram response exceeds size limit")
	}
	var response struct {
		OK         *bool           `json:"ok"`
		Result     json.RawMessage `json:"result"`
		Code       int             `json:"error_code"`
		Parameters struct {
			RetryAfter int64 `json:"retry_after"`
		} `json:"parameters"`
	}
	decodeErr := json.Unmarshal(body, &response)
	if resp.StatusCode != http.StatusOK || decodeErr == nil && response.OK != nil && !*response.OK {
		code := resp.StatusCode
		if code == http.StatusOK {
			if response.Code < 400 || response.Code > 599 {
				return nil, errors.New("invalid Telegram API error")
			}
			code = response.Code
		}
		apiErr := &APIError{Code: code}
		if decodeErr == nil && code == 429 && response.Parameters.RetryAfter > 0 && response.Parameters.RetryAfter <= 86400 {
			apiErr.RetryAfter = time.Duration(response.Parameters.RetryAfter) * time.Second
		}
		return nil, apiErr
	}
	if decodeErr != nil || response.OK == nil || len(response.Result) == 0 || bytes.Equal(response.Result, []byte("null")) {
		return nil, errors.New("invalid Telegram response")
	}
	return response.Result, nil
}

// connectionError сохраняет отмену и таймаут, скрывая детали транспортной ошибки.
func connectionError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		return errors.New("Telegram request timed out")
	}
	return errors.New("Telegram connection failed")
}
