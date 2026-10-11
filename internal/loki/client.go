// Package loki получает данные из HTTP API Loki с ограничениями времени и объема.
package loki

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"loki-analyzer/internal/model"
)

// HTTPClient передается снаружи: это HTTP-клиент приложения или подмена в тестах.
// При его создании нужно запретить редиректы и сохранить проверку сертификатов TLS.
type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

// Client хранит настройки подключения; получение логов не зависит от CLI и анализатора.
type Client struct {
	config   Config
	endpoint *url.URL
	http     HTTPClient
}

// New проверяет настройки и принимает готовый HTTP-клиент, не выполняя запросов.
// DefaultConfig задает начальные лимиты; адрес и токен заполняет вызывающий код.
func New(config Config, httpClient HTTPClient) (*Client, error) {
	endpoint, err := config.validate()
	if err != nil {
		return nil, err
	}
	if httpClient == nil {
		return nil, errors.New("HTTP client is required")
	}
	return &Client{config: config, endpoint: endpoint, http: httpClient}, nil
}

// GetLabels запрашивает имена меток за выбранный период.
func (c *Client) GetLabels(ctx context.Context, start, end time.Time) (model.Response, error) {
	return c.labelRequest(ctx, "/loki/api/v1/labels", start, end)
}

// GetLabelValues запрашивает значения метки; ее имя проверяется до вставки в URL.
func (c *Client) GetLabelValues(ctx context.Context, label string, start, end time.Time) (model.Response, error) {
	if !labelName.MatchString(label) {
		return model.Response{}, errors.New("invalid label name")
	}
	return c.labelRequest(ctx, "/loki/api/v1/label/"+label+"/values", start, end)
}

// labelRequest возвращает исходный JSON и разобранные значения только после проверки ответа.
func (c *Client) labelRequest(ctx context.Context, path string, start, end time.Time) (model.Response, error) {
	if err := c.validateRange(start, end); err != nil {
		return model.Response{}, err
	}
	body, code, err := c.get(ctx, path, rangeParams(start, end), &budget{})
	if err != nil {
		return model.Response{StatusCode: code}, err
	}
	values, err := decodeLabels(body)
	if err != nil {
		return model.Response{StatusCode: code}, err
	}
	return model.Response{Body: body, StatusCode: code, Values: values}, nil
}

// decodeLabels принимает только массив строк: null и значения других типов — ошибка.
func decodeLabels(body []byte) ([]string, error) {
	data, err := successfulData(body)
	if err != nil {
		return nil, err
	}
	var labels []json.RawMessage
	if json.Unmarshal(data, &labels) != nil || labels == nil {
		return nil, errors.New("invalid Loki label list")
	}
	values := make([]string, 0, len(labels))
	for _, item := range labels {
		var value string
		if len(item) == 0 || item[0] != '"' || json.Unmarshal(item, &value) != nil {
			return nil, errors.New("invalid Loki label value")
		}
		values = append(values, value)
	}
	return values, nil
}

// GetProjects сортирует значения метки проекта, указанной в настройках.
// Loki может расширить период поиска меток; это не полный каталог проектов за все время.
func (c *Client) GetProjects(ctx context.Context, start, end time.Time) ([]string, error) {
	response, err := c.GetLabelValues(ctx, c.config.ProjectLabel, start, end)
	if err != nil {
		return nil, err
	}
	projects := response.Values
	sort.Strings(projects)
	return projects, nil
}

// envelope описывает общую оболочку ответа; формат data проверяется отдельно.
type envelope struct {
	Status string          `json:"status"`
	Data   json.RawMessage `json:"data"`
}

// successfulData проверяет статус API: одного HTTP 200 недостаточно для успеха.
func successfulData(body []byte) (json.RawMessage, error) {
	var result envelope
	if json.Unmarshal(body, &result) != nil {
		return nil, errors.New("invalid Loki JSON response")
	}
	if result.Status != "success" {
		return nil, errors.New("Loki response did not report success")
	}
	if len(result.Data) == 0 || string(result.Data) == "null" {
		return nil, errors.New("Loki response has no data")
	}
	return result.Data, nil
}

// budget общий для всех запросов одной операции, включая страницы, которые затем делятся.
type budget struct {
	requests int
	bytes    int64
}

// limitError означает остановку по лимиту; FetchLogs возвращает ее как признак неполноты.
type limitError string

func (e limitError) Error() string { return string(e) }

// get выполняет один GET с общим бюджетом операции и отдельным тайм-аутом запроса.
func (c *Client) get(ctx context.Context, path string, params url.Values, used *budget) ([]byte, int, error) {
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	if used.requests >= c.config.MaxRequests {
		return nil, 0, limitError("request limit reached")
	}
	remaining := c.config.MaxTotalBytes - used.bytes
	if remaining <= 0 {
		return nil, 0, limitError("total response byte limit reached")
	}
	requestCtx, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()
	req, err := c.newRequest(requestCtx, path, params)
	if err != nil {
		return nil, 0, err
	}
	used.requests++
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, requestError(ctx, requestCtx, err)
	}
	defer resp.Body.Close()
	// Тело ошибки сервера может содержать секреты: наружу передаем только HTTP-код.
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, fmt.Errorf("Loki returned HTTP %d", resp.StatusCode)
	}
	body, err := c.readBody(requestCtx, resp.Body, remaining, used)
	return body, resp.StatusCode, err
}

// newRequest сохраняет базовый путь Grafana proxy и передает токен только в заголовке.
func (c *Client) newRequest(ctx context.Context, path string, params url.Values) (*http.Request, error) {
	u := *c.endpoint
	u.Path = strings.TrimRight(u.Path, "/") + path
	u.RawPath = ""
	u.RawQuery = params.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, errors.New("could not construct Loki request")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.config.Token)
	if c.config.OrgID != "" {
		req.Header.Set("X-Grafana-Org-Id", c.config.OrgID)
	}
	return req, nil
}

// readBody соблюдает меньший из лимитов: на один ответ и на оставшуюся часть операции.
func (c *Client) readBody(ctx context.Context, body io.Reader, remaining int64, used *budget) ([]byte, error) {
	maxBytes := min(c.config.MaxResponseBytes, remaining)
	// Дополнительный байт позволяет отличить полный ответ от превышения лимита.
	data, err := io.ReadAll(io.LimitReader(body, maxBytes+1))
	used.bytes += int64(len(data))
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("could not read Loki response")
	}
	if int64(len(data)) > maxBytes {
		if remaining < c.config.MaxResponseBytes {
			return nil, limitError("total response byte limit reached")
		}
		return nil, limitError("single response byte limit reached")
	}
	return data, nil
}

// requestError различает отмену, тайм-аут и сбой соединения, скрывая детали транспорта.
func requestError(parent, request context.Context, err error) error {
	if parent.Err() != nil {
		return parent.Err()
	}
	var timeout net.Error
	if errors.Is(request.Err(), context.DeadlineExceeded) || errors.As(err, &timeout) && timeout.Timeout() {
		return errors.New("Loki request timed out")
	}
	// Исходная ошибка транспорта может содержать URL, LogQL и учетные данные.
	return errors.New("Loki connection failed")
}
