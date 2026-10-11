package loki

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"loki-analyzer/internal/model"
)

// QueryRange получает одну страницу для ручной проверки API и сохраняет исходный JSON.
// Принимает готовый LogQL; ответы с метриками вместо логов отклоняются.
func (c *Client) QueryRange(ctx context.Context, expression string, start, end time.Time, limit int) (model.Response, error) {
	if err := c.validateRange(start, end); err != nil {
		return model.Response{}, err
	}
	if strings.TrimSpace(expression) == "" || len(expression) > 65536 || !utf8.ValidString(expression) {
		return model.Response{}, errors.New("LogQL expression must be nonempty UTF-8 and at most 65536 bytes")
	}
	if limit <= 0 || limit > c.config.MaxRecords {
		return model.Response{}, errors.New("query limit must be positive and at most the configured record limit")
	}
	body, code, err := c.queryPage(ctx, expression, start, end, limit, &budget{})
	if err != nil {
		return model.Response{StatusCode: code}, err
	}
	queryResponse, err := decodeQueryResponse(body)
	if err != nil {
		return model.Response{StatusCode: code}, err
	}
	count, err := validateStreams(queryResponse.Data.Result, "", "", start, end)
	if err != nil {
		return model.Response{StatusCode: code}, err
	}
	// Полная страница означает возможное ограничение выдачи, даже если других записей нет.
	return model.Response{Body: body, StatusCode: code, Truncated: count >= limit, Query: &queryResponse}, nil
}

// queryPage задает направление от старых событий к новым и использует бюджет вызывающего кода.
func (c *Client) queryPage(ctx context.Context, expression string, start, end time.Time, limit int, used *budget) ([]byte, int, error) {
	params := rangeParams(start, end)
	params.Set("query", expression)
	params.Set("limit", strconv.Itoa(limit))
	params.Set("direction", "forward")
	return c.get(ctx, "/loki/api/v1/query_range", params, used)
}

// buildExpression собирает LogQL из проекта и необязательных фильтров.
// Значения экранируются как строки; регулярные выражения проверяются до сетевого запроса.
func (c *Client) buildExpression(query Query) (string, error) {
	if query.Project == "" || !utf8.ValidString(query.Project) || len(query.Project) > 4096 {
		return "", errors.New("project must be nonempty UTF-8 and at most 4096 bytes")
	}
	expression := "{" + c.config.ProjectLabel + "=" + strconv.Quote(query.Project) + "}"
	for _, pattern := range []string{query.LevelRegex, query.Regex} {
		if len(pattern) > 16384 {
			return "", errors.New("regex exceeds 16384 bytes")
		}
		if pattern != "" {
			if _, err := regexp.Compile(pattern); err != nil {
				return "", errors.New("invalid log filter regex")
			}
		}
	}
	if len(query.Contains) > 16384 || !utf8.ValidString(query.Contains) {
		return "", errors.New("substring must be UTF-8 and at most 16384 bytes")
	}
	if query.LevelRegex != "" {
		expression += " |~ " + strconv.Quote(query.LevelRegex)
	}
	if query.Contains != "" {
		expression += " |= " + strconv.Quote(query.Contains)
	}
	if query.Regex != "" {
		expression += " |~ " + strconv.Quote(query.Regex)
	}
	return expression, nil
}

// FetchLogs дочитывает период, деля заполненные страницы на непересекающиеся интервалы.
// После последней метки времени нельзя просто сдвинуться вперед: там могут быть другие события.
func (c *Client) FetchLogs(ctx context.Context, query Query) (model.FetchResult, error) {
	result := model.FetchResult{Complete: true}
	if err := c.validateRange(query.Start, query.End); err != nil {
		result.Complete = false
		return result, err
	}
	expression, err := c.buildExpression(query)
	if err != nil {
		result.Complete = false
		return result, err
	}
	used := &budget{}
	err = c.fetchInterval(ctx, query, expression, query.Start, query.End, used, &result)
	result.Requests, result.BytesRead = used.requests, used.bytes
	if err != nil {
		result.Complete = false
		result.Reason = err.Error()
		// Достигнутый лимит возвращаем через Complete и Reason вместе с уже собранными данными.
		var cap limitError
		if errors.As(err, &cap) {
			return result, nil
		}
	}
	return result, err
}

// fetchInterval добавляет записи интервала [start, end): начало включено, конец исключен.
func (c *Client) fetchInterval(ctx context.Context, query Query, expression string, start, end time.Time, used *budget, result *model.FetchResult) error {
	if len(result.Records) >= c.config.MaxRecords {
		return limitError("record limit reached")
	}
	body, _, err := c.queryPage(ctx, expression, start, end, c.config.PageSize, used)
	if err != nil {
		return err
	}
	records, err := decodeRecords(body, query.Project, c.config.ProjectLabel, start, end)
	if err != nil {
		return err
	}
	if len(records) >= c.config.PageSize && end.Sub(start) > time.Nanosecond {
		// Два дочерних интервала заменяют исходную страницу, чтобы не посчитать записи дважды.
		body, records = nil, nil
		middle := start.Add(end.Sub(start) / 2)
		if err = c.fetchInterval(ctx, query, expression, start, middle, used, result); err != nil {
			return err
		}
		return c.fetchInterval(ctx, query, expression, middle, end, used, result)
	}
	remaining := c.config.MaxRecords - len(result.Records)
	result.Records = append(result.Records, records[:min(len(records), remaining)]...)
	if len(records) > remaining {
		return limitError("record limit reached")
	}
	// Одну наносекунду уже нельзя разделить; при полной странице полнота не доказана.
	if len(records) >= c.config.PageSize {
		return limitError("single nanosecond contains at least one full page; complete retrieval cannot be established")
	}
	return nil
}

// decodeRecords преобразует проверенный ответ Loki в общую модель событий приложения.
func decodeRecords(body []byte, project, projectLabel string, start, end time.Time) ([]model.LogRecord, error) {
	response, err := decodeQueryResponse(body)
	if err != nil {
		return nil, err
	}
	return recordsFromResponse(response, project, projectLabel, start, end)
}

// decodeQueryResponse проверяет успешный ответ с потоками; значения записей разбирает модель.
func decodeQueryResponse(body []byte) (model.LokiQueryResponse, error) {
	var response model.LokiQueryResponse
	// Ошибка JSON может содержать данные ответа, поэтому возвращаем безопасное общее сообщение.
	if json.Unmarshal(body, &response) != nil || response.Status != "success" || response.Data.ResultType != "streams" || response.Data.Result == nil {
		return model.LokiQueryResponse{}, errors.New("invalid Loki streams response")
	}
	return response, nil
}

// recordsFromResponse объединяет потоки в хронологический список, сохраняя метки и metadata.
func recordsFromResponse(response model.LokiQueryResponse, project, projectLabel string, start, end time.Time) ([]model.LogRecord, error) {
	count, err := validateStreams(response.Data.Result, project, projectLabel, start, end)
	if err != nil {
		return nil, err
	}
	// TimestampNS уже разобран как int64: преобразование во время сохраняет наносекунды.
	records := make([]model.LogRecord, 0, count)
	for _, stream := range response.Data.Result {
		for _, entry := range stream.Values {
			records = append(records, model.LogRecord{
				Timestamp: time.Unix(0, entry.TimestampNS).UTC(),
				Project:   project,
				Line:      entry.Line,
				Labels:    stream.Labels,
				Metadata:  entry.Metadata,
			})
		}
	}
	sort.SliceStable(records, func(i, j int) bool {
		if !records[i].Timestamp.Equal(records[j].Timestamp) {
			return records[i].Timestamp.Before(records[j].Timestamp)
		}
		return records[i].Line < records[j].Line
	})
	return records, nil
}

// validateStreams проверяет проект и границы периода без копирования и сортировки записей.
func validateStreams(streams []model.LokiStream, project, projectLabel string, start, end time.Time) (int, error) {
	count := 0
	for _, stream := range streams {
		if stream.Labels == nil || stream.Values == nil {
			return 0, errors.New("invalid Loki stream")
		}
		if project != "" && stream.Labels[projectLabel] != project {
			return 0, errors.New("Loki returned an unexpected project")
		}
		for _, entry := range stream.Values {
			when := time.Unix(0, entry.TimestampNS).UTC()
			if when.Before(start) || !when.Before(end) {
				return 0, errors.New("Loki returned an event outside the requested time range")
			}
		}
		count += len(stream.Values)
	}
	return count, nil
}

// validateRange исключает переполнение UnixNano и проверяет длительность до отправки запроса.
func (c *Client) validateRange(start, end time.Time) error {
	if !time.Unix(0, start.UnixNano()).Equal(start) || !time.Unix(0, end.UnixNano()).Equal(end) {
		return errors.New("timestamps must fit Unix nanoseconds")
	}
	if !start.Before(end) {
		return errors.New("start must precede end")
	}
	if end.After(start.Add(c.config.MaxRange)) {
		return errors.New("time range exceeds configured maximum")
	}
	return nil
}

// rangeParams передает время целыми наносекундами без потери точности через float64.
func rangeParams(start, end time.Time) url.Values {
	return url.Values{"start": {strconv.FormatInt(start.UnixNano(), 10)}, "end": {strconv.FormatInt(end.UnixNano(), 10)}}
}
