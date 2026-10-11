package input

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"loki-analyzer/internal/model"
)

// Ограничения защищают память при чтении недоверенного локального файла.
const (
	maxFileBytes = 10 << 20
	maxRecords   = 100_000
)

// LokiFileSource читает сохраненный JSON-ответ Loki или текстовый экспорт Grafana.
// Наличие файла не означает, что в нем есть все события выбранного периода.
type LokiFileSource struct{}

// NewLokiFileSource создает источник без сетевых запросов и настроек доступа.
func NewLokiFileSource() *LokiFileSource { return &LokiFileSource{} }

// Read определяет формат по содержимому, независимо от расширения файла.
func (s *LokiFileSource) Read(ctx context.Context, path string) ([]model.LogRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	body, err := readFile(path)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// BOM допустим в текстовом экспорте и перед JSON; содержимое сообщений не меняем.
	body = bytes.TrimPrefix(body, []byte("\xef\xbb\xbf"))
	if bytes.HasPrefix(bytes.TrimSpace(body), []byte("{")) {
		return readLokiJSON(ctx, body)
	}
	return readGrafanaText(ctx, body)
}

// readLokiJSON принимает только успешный ответ с потоками логов и обязательными полями.
// При ошибке возвращает отказ целиком, без частично разобранной выборки.
func readLokiJSON(ctx context.Context, body []byte) ([]model.LogRecord, error) {
	var response model.LokiQueryResponse
	if json.Unmarshal(body, &response) != nil {
		return nil, errors.New("файл должен содержать корректный JSON-ответ Loki")
	}
	if response.Status != "success" || response.Data.ResultType != "streams" || response.Data.Result == nil {
		return nil, errors.New("ожидается успешный ответ Loki с resultType=streams и массивом result")
	}

	records := make([]model.LogRecord, 0)
	for _, stream := range response.Data.Result {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		project := stream.Labels["app"]
		if stream.Labels == nil || stream.Values == nil || strings.TrimSpace(project) == "" || len(project) > 4096 {
			return nil, errors.New("поток Loki должен содержать метки с непустой app и массив values")
		}
		if len(stream.Values) > maxRecords-len(records) {
			return nil, errors.New("файл содержит больше 100000 записей")
		}
		// Сохраняем каждую исходную строку, метки потока и доступные metadata без дедупликации.
		for _, entry := range stream.Values {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			records = append(records, model.LogRecord{
				Timestamp: time.Unix(0, entry.TimestampNS).UTC(),
				Project:   project,
				Line:      entry.Line,
				Labels:    stream.Labels,
				Metadata:  entry.Metadata,
			})
		}
	}
	return records, ctx.Err()
}

// readFile ограничивает размер чтения; ошибки не раскрывают путь или содержимое файла.
func readFile(path string) ([]byte, error) {
	// До открытия отсеиваем каталоги и именованные каналы: ожидается обычный файл.
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("не удалось открыть обычный файл с ответом Loki")
	}
	if info.Size() > maxFileBytes {
		return nil, errors.New("файл ответа Loki превышает 10 МиБ")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("не удалось открыть файл с ответом Loki")
	}
	defer file.Close()
	// Повторно проверяем уже открытый файл, затем ограничиваем фактическое чтение.
	info, err = file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("не удалось открыть обычный файл с ответом Loki")
	}
	body, err := io.ReadAll(io.LimitReader(file, maxFileBytes+1))
	if err != nil {
		return nil, errors.New("не удалось прочитать файл с ответом Loki")
	}
	if len(body) > maxFileBytes {
		return nil, errors.New("файл ответа Loki превышает 10 МиБ")
	}
	return body, nil
}

// readGrafanaText читает заголовки и строки экспорта, не пропуская поврежденные записи.
// Доступные общие метки переносим в события; индивидуальные метки из них не восстанавливаем.
func readGrafanaText(ctx context.Context, body []byte) ([]model.LogRecord, error) {
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 4096), maxFileBytes+1)
	records := make([]model.LogRecord, 0)
	var labels map[string]string
	seenHeaders := make(map[string]bool)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		// Заголовки допустимы только до данных и не должны повторяться.
		if prefix := grafanaHeader(line); prefix != "" {
			if len(records) > 0 || seenHeaders[prefix] {
				return nil, textLineError(lineNumber, "повторный заголовок или заголовок после записей")
			}
			seenHeaders[prefix] = true
			value := strings.TrimPrefix(line, prefix)
			if prefix == "Common labels: " {
				var err error
				labels, err = parseCommonLabels(value)
				if err != nil {
					return nil, textLineError(lineNumber, err.Error())
				}
			} else {
				var text string
				if json.Unmarshal([]byte(value), &text) != nil || strings.TrimSpace(text) == "" {
					return nil, textLineError(lineNumber, "некорректный заголовок")
				}
			}
			continue
		}
		if labels == nil {
			return nil, textLineError(lineNumber, "ожидается заголовок Common labels с меткой app")
		}
		if len(records) == maxRecords {
			return nil, errors.New("файл содержит больше 100000 записей")
		}
		record, err := parseGrafanaRecord(line, labels)
		if err != nil {
			return nil, textLineError(lineNumber, err.Error())
		}
		records = append(records, record)
	}
	if scanner.Err() != nil {
		return nil, textLineError(lineNumber+1, "не удалось прочитать строку")
	}
	if labels == nil {
		return nil, errors.New("экспорт Grafana должен содержать Common labels с непустой меткой app")
	}
	return records, ctx.Err()
}

// grafanaHeader распознает только известные заголовки формата Grafana.
func grafanaHeader(line string) string {
	for _, prefix := range []string{": ", "Total bytes processed: ", "Common labels: "} {
		if strings.HasPrefix(line, prefix) {
			return prefix
		}
	}
	return ""
}

// parseCommonLabels требует строковые значения и непустую app для привязки к проекту.
func parseCommonLabels(value string) (map[string]string, error) {
	// Указатели позволяют отличить JSON null от допустимой пустой строки.
	var values map[string]*string
	if json.Unmarshal([]byte(value), &values) != nil {
		return nil, errors.New("Common labels должен содержать строковые метки и непустую app")
	}
	labels := make(map[string]string, len(values))
	for name, value := range values {
		if value == nil {
			return nil, errors.New("Common labels должен содержать строковые метки и непустую app")
		}
		labels[name] = *value
	}
	if strings.TrimSpace(labels["app"]) == "" || len(labels["app"]) > 4096 {
		return nil, errors.New("Common labels должен содержать строковые метки и непустую app")
	}
	return labels, nil
}

// parseGrafanaRecord сверяет два представления времени и сохраняет точность даты.
func parseGrafanaRecord(line string, labels map[string]string) (model.LogRecord, error) {
	// Разделяем только первые две табуляции, оставляя текст сообщения без изменений.
	fields := strings.SplitN(line, "\t", 3)
	if len(fields) != 3 {
		return model.LogRecord{}, errors.New("ожидаются миллисекунды, дата и сообщение через табуляцию")
	}
	milliseconds, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil {
		return model.LogRecord{}, errors.New("некорректное время в миллисекундах")
	}
	timestamp, err := time.Parse(time.RFC3339Nano, fields[1])
	if err != nil || timestamp.UnixMilli() != milliseconds {
		return model.LogRecord{}, errors.New("дата некорректна или не совпадает с миллисекундами")
	}
	return model.LogRecord{
		Timestamp: timestamp.UTC(),
		Project:   labels["app"],
		Line:      fields[2],
		Labels:    labels,
	}, nil
}

// textLineError указывает проблемную строку, не включая ее исходное содержимое.
func textLineError(line int, message string) error {
	return fmt.Errorf("экспорт Grafana, строка %d: %s", line, message)
}
